// sysinfo 行为测试:文件读取根目录重定向到 testdata、命令执行与磁盘用量
// 全部注入,在无 rpm/dnf/ip 的开发机上做确定性断言。
package sysinfo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// testRoot 返回 testdata 下指定根目录的绝对路径(如 "root"、"emptyroot")。
func testRoot(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("无法定位本测试文件")
	}
	p := filepath.Join(filepath.Dir(thisFile), "testdata", name)
	return p
}

// fakeExec 记录调用并按脚本返回(耗尽后重复最后一步)。
type fakeExec struct {
	calls [][]string
	steps []fakeStep
	idx   int
}

type fakeStep struct {
	stdout, stderr string
	code           int
	err            error
}

func (f *fakeExec) run(_ context.Context, name string, args []string) (string, string, int, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	s := f.steps[f.idx]
	if f.idx < len(f.steps)-1 {
		f.idx++
	}
	return s.stdout, s.stderr, s.code, s.err
}

func (f *fakeExec) wantCommands(t *testing.T, want ...[]string) {
	t.Helper()
	if !slices.EqualFunc(f.calls, want, slices.Equal) {
		t.Errorf("调用序列 = %v,\nwant       %v", f.calls, want)
	}
}

// —— os_release(py:21-55)——

func TestOSRelease_ParsesQuotesCommentsAndSkipsMalformed(t *testing.T) {
	svc := NewService(nil, testRoot(t, "root"), nil)
	got := svc.OSRelease()

	wants := map[string]string{
		"NAME":           "Daedalus OS",
		"VERSION":        "0.1.0 (beta)", // 双引号去除
		"ID":             "daedalus",     // 无引号原样
		"ID_LIKE":        "almalinux fedora",
		"VERSION_ID":     "42",
		"BUILD_ID":       "single-quoted", // 单引号去除(py:50)
		"PRETTY_NAME":    "Daedalus OS 0.1.0",
		"NOQUOTE":        "simple",
		"EMPTY":          "",
		"DANGLING_QUOTE": "",     // 落单引号 py v[1:-1] 切空(怪癖逐字复刻)
		"ANSI_COLOR":     "0;35", // 含 ';' 的未引号值不属本工具职责
	}
	for k, want := range wants {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
	// 注释行与无 '=' 行必须被跳过(py:45)。
	if _, ok := got["#"]; ok {
		t.Error("注释行未被跳过")
	}
	for k := range got {
		if strings.HasPrefix(k, "这一行") {
			t.Errorf("无等号行未被跳过: key=%q", k)
		}
	}
	if _, ok := got["error"]; ok {
		t.Errorf("正常样本不应有 error 键: %v", got["error"])
	}
}

func TestOSRelease_NoTargetReturnsErrorKey(t *testing.T) {
	svc := NewService(nil, testRoot(t, "emptyroot"), nil)
	got := svc.OSRelease()
	// py:38 错误串逐字。
	if want := "Neither /etc/os-release nor /usr/lib/os-release found"; got["error"] != want {
		t.Errorf("error = %v, want %q", got["error"], want)
	}
	if len(got) != 1 {
		t.Errorf("error 之外不应有其他键: %v", got)
	}
}

func TestOSRelease_FallsBackToUsrLib(t *testing.T) {
	root := t.TempDir()
	mkdirUsrLibRelease(t, root)
	svc := NewService(nil, root, nil)
	got := svc.OSRelease()
	if got["ID"] != "fallback-os" {
		t.Errorf("未回退到 /usr/lib/os-release: %v", got)
	}
}

// mkdirUsrLibRelease 在给定根下只造 /usr/lib/os-release(无 /etc 版本)。
func mkdirUsrLibRelease(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, "usr", "lib")
	if err := writeFile(dir, "os-release", "ID=fallback-os\nNAME=\"Fallback\"\n"); err != nil {
		t.Fatal(err)
	}
}

func writeFile(dir, name, content string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)
}

// —— hardware_info(py:58-129)——

func TestHardwareInfo_CpuMemoryDiskFromInjectedFixtures(t *testing.T) {
	fakeDisk := func(path string) (DiskUsage, error) {
		if path != "/" {
			t.Errorf("磁盘统计路径 = %q, want %q", path, "/")
		}
		return DiskUsage{
			Total: 100 * 1024 * 1024 * 1024, // 恰好 100 GiB
			Used:  31.25 * 1024 * 1024 * 1024,
			Free:  68.75 * 1024 * 1024 * 1024,
		}, nil
	}
	svc := NewService(nil, testRoot(t, "root"), fakeDisk)
	got := svc.HardwareInfo()

	cpu, ok := got["cpu"].(map[string]any)
	if !ok {
		t.Fatalf("cpu 结构异常: %T", got["cpu"])
	}
	// 首个 model name 生效、"processor" 行计数(testdata 有 3 个 processor)。
	if cpu["model"] != "Fake Test CPU @ 3.50GHz" || cpu["cores"] != 3 {
		t.Errorf("cpu = %v, want model=Fake Test CPU @ 3.50GHz cores=3", cpu)
	}

	mem, ok := got["memory"].(map[string]any)
	if !ok {
		t.Fatalf("memory 结构异常: %T", got["memory"])
	}
	// py:106 白名单五键,Buffers/SwapCached/Dirty/HugePages_Total 必须被过滤。
	wantKeys := []string{"MemAvailable", "MemFree", "MemTotal", "SwapFree", "SwapTotal"}
	keys := make([]string, 0, len(mem))
	for k := range mem {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, wantKeys) {
		t.Errorf("memory 键集 = %v, want %v", keys, wantKeys)
	}
	if mem["MemTotal"] != "16384000 kB" {
		t.Errorf("MemTotal = %v, want %q", mem["MemTotal"], "16384000 kB")
	}

	disk, ok := got["disk"].(map[string]any)
	if !ok {
		t.Fatalf("disk 结构异常: %T", got["disk"])
	}
	if disk["path"] != "/" ||
		disk["total_bytes"] != int64(100*1024*1024*1024) ||
		disk["used_bytes"] != int64(31.25*1024*1024*1024) ||
		disk["free_bytes"] != int64(68.75*1024*1024*1024) ||
		disk["total_gb"] != 100.0 || disk["used_gb"] != 31.25 || disk["free_gb"] != 68.75 {
		t.Errorf("disk = %v, want path=/ + 上面注入值的字节/GB 双形态", disk)
	}
}

func TestHardwareInfo_MissingProcFilesYieldErrorKeys(t *testing.T) {
	svc := NewService(nil, testRoot(t, "emptyroot"), okDisk(0, 0, 0))
	got := svc.HardwareInfo()
	cpu := got["cpu"].(map[string]any)
	mem := got["memory"].(map[string]any)
	// py:94、py:112 文案逐字。
	if cpu["error"] != "/proc/cpuinfo not available" {
		t.Errorf("cpu.error = %v", cpu["error"])
	}
	if mem["error"] != "/proc/meminfo not available" {
		t.Errorf("memory.error = %v", mem["error"])
	}
}

func TestHardwareInfo_DiskErrorIsolated(t *testing.T) {
	// 磁盘失败只污染 disk 子字典,cpu/memory 照常(py:126-127 的局部 except)。
	svc := NewService(nil, testRoot(t, "root"), func(string) (DiskUsage, error) {
		return DiskUsage{}, errors.New("statfs /: no such file or directory")
	})
	got := svc.HardwareInfo()
	disk := got["disk"].(map[string]any)
	if _, ok := disk["error"]; !ok {
		t.Errorf("disk 应含 error 键: %v", disk)
	}
	cpu := got["cpu"].(map[string]any)
	if cpu["model"] != "Fake Test CPU @ 3.50GHz" {
		t.Errorf("disk 失败串扰 cpu: %v", cpu)
	}
}

func TestRound2_BankerSemantics(t *testing.T) {
	// 与 CPython round(x, 2) 逐点对照(含二进制误差怪癖)。
	cases := []struct{ in, want float64 }{
		{2.675, 2.67}, // double 实为 2.67499... → 向下
		{2.125, 2.12}, // 恰好 .5 → 偶数
		{2.135, 2.13}, // double 真值为 2.134999999...978 → 向下(CPython 实测 2.13)
		{0.125, 0.12}, // .5 且下位偶
		{0.135, 0.14},
		{100.0, 100.0},
		{31.25499999, 31.25},
	}
	for _, tc := range cases {
		if got := round2(tc.in); got != tc.want {
			t.Errorf("round2(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// okDisk 返回一个恒定用量注入(空盘三零即全零)。
func okDisk(total, used, free int64) DiskUsageFunc {
	return func(string) (DiskUsage, error) {
		return DiskUsage{Total: total, Used: used, Free: free}, nil
	}
}

// —— network_status(py:132-196)——

func TestNetworkStatus_JsonLevelHit(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{{stdout: `[{"ifname":"lo","addr_info":[]}]`, code: 0}}}
	svc := NewService(fe.run, testRoot(t, "root"), nil)
	got := svc.NetworkStatus(context.Background())
	if _, ok := got["error"]; ok {
		t.Fatalf("不应出错: %v", got)
	}
	list, ok := got["interfaces"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("interfaces 结构异常: %v", got["interfaces"])
	}
	if m := list[0].(map[string]any); m["ifname"] != "lo" {
		t.Errorf("interfaces[0] = %v", m)
	}
	fe.wantCommands(t, []string{"ip", "-j", "addr", "show"}) // 命中即止,无第 2/3 级
}

func TestNetworkStatus_JsonDecodeFailFallsToRawText(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{
		{stdout: "not json at all", code: 0}, // py:154 JSONDecodeError → pass
		{stdout: "1: lo: <LOOPBACK>\n", code: 0},
	}}
	svc := NewService(fe.run, testRoot(t, "emptyroot"), nil)
	got := svc.NetworkStatus(context.Background())
	if want := "1: lo: <LOOPBACK>"; got["raw_output"] != want {
		t.Errorf("raw_output = %v, want %q", got["raw_output"], want)
	}
	if _, ok := got["interfaces"]; ok {
		t.Error("raw 回退层不应有 interfaces 键")
	}
	fe.wantCommands(t,
		[]string{"ip", "-j", "addr", "show"},
		[]string{"ip", "addr", "show"},
	)
}

func TestNetworkStatus_SpawnErrorFallsThroughAllLevels(t *testing.T) {
	// 一级"命令不存在"异常(py:156 except pass)→ 二级同样异常 → 三级 /proc/net/dev。
	fe := &fakeExec{steps: []fakeStep{{err: errors.New(`exec: "ip": executable file not found in $PATH`)}}}
	svc := NewService(fe.run, testRoot(t, "root"), nil)
	got := svc.NetworkStatus(context.Background())
	if _, ok := got["error"]; ok {
		t.Fatalf("应回退到 /proc/net/dev 而非报错: %v", got)
	}
	// 三级回退都发生:两次 ip 调用后落到 testdata 样本。
	fe.wantCommands(t,
		[]string{"ip", "-j", "addr", "show"},
		[]string{"ip", "addr", "show"},
	)
	// py:184-191 列位:rx=stats[0], tx=stats[8];veth-short 列数不足 tx 兜底 0。
	ifaces := got["interfaces"].(map[string]any)
	lo := ifaces["lo"].(map[string]any)
	if lo["rx_bytes"] != int64(11111) || lo["tx_bytes"] != int64(22222) {
		t.Errorf("lo = %v, want rx=11111 tx=22222", lo)
	}
	eth := ifaces["eth0"].(map[string]any)
	if eth["rx_bytes"] != int64(3333333333) || eth["tx_bytes"] != int64(4444444444) {
		t.Errorf("eth0 = %v", eth)
	}
	short := ifaces["veth-short"].(map[string]any)
	if short["rx_bytes"] != int64(999) || short["tx_bytes"] != int64(0) {
		t.Errorf("veth-short = %v, want rx=999 tx=0", short)
	}
}

func TestNetworkStatus_NonZeroIpExitFallsToProcNetDev(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{
		{stderr: "RTNETLINK answers: Operation not permitted", code: 2},
		{stderr: "RTNETLINK answers: Operation not permitted", code: 2},
	}}
	svc := NewService(fe.run, testRoot(t, "root"), nil)
	got := svc.NetworkStatus(context.Background())
	if _, ok := got["interfaces"].(map[string]any); !ok {
		t.Fatalf("非零退出应逐级回退到 /proc/net/dev: %v", got)
	}
}

func TestNetworkStatus_AllLevelsFailYieldsSentinelError(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{{code: 127, stderr: "command not found"}}}
	svc := NewService(fe.run, testRoot(t, "emptyroot"), nil)
	got := svc.NetworkStatus(context.Background())
	// py:196 兜底错误串逐字。
	if want := "Unable to determine network status"; got["error"] != want {
		t.Errorf("error = %v, want %q", got["error"], want)
	}
}

func TestNetworkStatus_BadIntInNetDevYieldsPrefixedError(t *testing.T) {
	root := t.TempDir()
	body := "Inter-| Receive | Transmit\n face |bytes |bytes\n bad0: not-a-number 1 2 3 4 5 6 7 8\n"
	if err := os.MkdirAll(filepath.Join(root, "proc", "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc", "net", "dev"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	fe := &fakeExec{steps: []fakeStep{{err: execNotFound}}}
	svc := NewService(fe.run, root, nil)
	got := svc.NetworkStatus(context.Background())
	// py:193-194 —— f"Failed reading /proc/net/dev: {e}" 的 Go 等价外壳。
	msg, _ := got["error"].(string)
	if !strings.HasPrefix(msg, "Failed reading /proc/net/dev: ") {
		t.Errorf("坏整数 error = %q, want 前缀 %q", msg, "Failed reading /proc/net/dev: ")
	}
}

var execNotFound = errors.New(`exec: "ip": executable file not found in $PATH`)
