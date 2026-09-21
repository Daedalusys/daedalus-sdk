// state 包测试:全部经 t.Setenv(DAEDALUS_STATE_PATH, 临时目录) 隔离,
// 绝不触碰真实 /var/lib/daedalus(round-3 fold 新检出安全纪律)。
// 唯一例外是兜底测试:它验证的正是 dirs 解析链在 env/系统候选均不可写时
// 落 $HOME 的行为,夹具带 root DAC 绕过 skip 守卫。
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Daedalusys/daedalus-sdk/dirs"
)

var baseTime = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

// newStateFile 把状态文件钉到测试私有临时目录(env 覆盖即链首候选)。
func newStateFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state.jsonl")
	t.Setenv(dirs.EnvStatePath, p)
	return p
}

// mustLog 写一条 service 观测;helper 可能被并发 goroutine 调用,
// 故用 Errorf(非 Fatalf),失败由后续断言兜住。
func mustLog(t *testing.T, kind, name string, at time.Time, payload string) {
	t.Helper()
	err := Log(StateEntry{Kind: kind, Name: name, ObservedAt: at, Payload: json.RawMessage(payload)})
	if err != nil {
		t.Errorf("Log(%s/%s) 失败: %v", kind, name, err)
	}
}

func TestState_DefaultPathDelegatesEnv(t *testing.T) {
	// Given: env 覆盖指向临时文件。When: DefaultPath。Then: 原样透传 dirs.StateFile()。
	p := newStateFile(t)
	got, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath 报错: %v", err)
	}
	if got != p {
		t.Fatalf("DefaultPath 应透传 env 路径 %q,实得 %q", p, got)
	}
}

func TestState_RoundTrip(t *testing.T) {
	newStateFile(t)
	// Given: 按时间升序追加 5 条观测。
	want := make([]StateEntry, 0, 5)
	for i := 0; i < 5; i++ {
		e := StateEntry{
			Kind: "service", Name: fmt.Sprintf("u%d.service", i),
			ObservedAt: baseTime.Add(time.Duration(i) * time.Second),
			Payload:    json.RawMessage(fmt.Sprintf(`{"i":%d}`, i)),
		}
		mustLog(t, e.Kind, e.Name, e.ObservedAt, string(e.Payload))
		want = append(want, e)
	}

	// When: 零值 since 全量读。
	got, err := Read(time.Time{})
	if err != nil {
		t.Fatalf("Read 报错: %v", err)
	}

	// Then: 条数、字段、ObservedAt 升序逐条一致。
	if len(got) != 5 {
		t.Fatalf("应读到 5 条,实得 %d", len(got))
	}
	for i := range want {
		if got[i].Kind != want[i].Kind || got[i].Name != want[i].Name {
			t.Fatalf("第 %d 条键值不符: %+v vs %+v", i, got[i], want[i])
		}
		if !got[i].ObservedAt.Equal(want[i].ObservedAt) {
			t.Fatalf("第 %d 条 ObservedAt 不符: %v vs %v", i, got[i].ObservedAt, want[i].ObservedAt)
		}
		if string(got[i].Payload) != string(want[i].Payload) {
			t.Fatalf("第 %d 条载荷不符: %s vs %s", i, got[i].Payload, want[i].Payload)
		}
		if i > 0 && got[i].ObservedAt.Before(got[i-1].ObservedAt) {
			t.Fatalf("读回顺序未按 ObservedAt 递增: 第 %d 条 %v", i, got[i].ObservedAt)
		}
	}
}

func TestState_LogLineShape(t *testing.T) {
	p := newStateFile(t)
	// Given: 非 UTC 时区 + 纳秒 + 含 HTML 敏感字符的载荷。
	loc := time.FixedZone("CST", 8*60*60)
	at := time.Date(2026, 9, 6, 12, 5, 6, 123456789, loc)
	mustLog(t, "service", "x.service", at, `{"tag":"<b>&","i": 1}`)

	// Then: 单行 = compact JSON + \n;ObservedAt 归一 UTC RFC3339Nano;
	// 载荷紧凑且不做 HTML 二次转义(SetEscapeHTML(false))。
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("读原始文件失败: %v", err)
	}
	want := `{"kind":"service","name":"x.service","observed_at":"2026-09-06T04:05:06.123456789Z","payload":{"tag":"<b>&","i":1}}` + "\n"
	if string(raw) != want {
		t.Fatalf("落盘行不符:\n实得 %q\n期望 %q", string(raw), want)
	}
}

func TestState_ReadSince(t *testing.T) {
	newStateFile(t)
	for i := 0; i < 5; i++ {
		mustLog(t, "service", fmt.Sprintf("u%d.service", i), baseTime.Add(time.Duration(i)*time.Second), `{}`)
	}

	// Given: since = 第 3 条(t+2s)。When: Read(since)。
	got, err := Read(baseTime.Add(2 * time.Second))
	if err != nil {
		t.Fatalf("Read 报错: %v", err)
	}

	// Then: >= since 边界含等号,过滤后为 u2..u4 共 3 条。
	if len(got) != 3 || got[0].Name != "u2.service" {
		t.Fatalf("since 过滤结果不符: %d 条,首条 %+v", len(got), got)
	}
}

func TestState_LatestByKindNewestWins(t *testing.T) {
	newStateFile(t)
	// Given: append-only 混序夹具 —— a 两次观测(后者更新)、b 一次、
	// package/a 与 a 同名不同 kind(必须不串扰)。
	mustLog(t, "service", "a.service", baseTime, `{"v":1}`)
	mustLog(t, "service", "b.service", baseTime.Add(time.Second), `{"v":1}`)
	mustLog(t, "package", "a.service", baseTime.Add(2*time.Second), `{"v":9}`)
	mustLog(t, "service", "a.service", baseTime.Add(3*time.Second), `{"v":2}`)

	got, err := LatestByKind("service")
	if err != nil {
		t.Fatalf("LatestByKind 报错: %v", err)
	}
	// Then: 每 Name 保最新一条,按 name 字典序,package 条目不出现。
	if len(got) != 2 || got[0].Name != "a.service" || got[1].Name != "b.service" {
		t.Fatalf("结果集不符: %+v", got)
	}
	if string(got[0].Payload) != `{"v":2}` || !got[0].ObservedAt.Equal(baseTime.Add(3*time.Second)) {
		t.Fatalf("a.service 未取最新观测: %+v", got[0])
	}

	empty, err := LatestByKind("nonexistent")
	if err != nil || len(empty) != 0 {
		t.Fatalf("未知 kind 应返回空,实得 %d 条, err=%v", len(empty), err)
	}
}

func TestState_TolerantReaderSkipsMalformed(t *testing.T) {
	p := newStateFile(t)
	mustLog(t, "service", "ok1", baseTime, `{}`)
	// Given: 文件中部注入各类坏行(非法 JSON / 截断对象 / 空行 / 合法 JSON 非对象 /
	// 时间字段类型错),均须被容忍跳过。
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("追加夹具失败: %v", err)
	}
	for _, junk := range []string{
		"not-json\n",
		`{"kind":"broken` + "\n", // 截断对象(带换行定界)
		"\n",                     // 空行
		"[1,2]\n",                // 合法 JSON,非对象
		`{"kind":"svc","observed_at":"nope"}` + "\n", // 字段类型错
	} {
		if _, err := f.WriteString(junk); err != nil {
			t.Fatalf("写入夹具失败: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("关闭夹具失败: %v", err)
	}
	mustLog(t, "service", "ok2", baseTime.Add(time.Second), `{}`)
	// 末行合法但**无尾随换行**(文件 EOF 定界,ReadBytes 的 EOF 分支)。
	tail, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("追加末行夹具失败: %v", err)
	}
	if _, err := tail.WriteString(`{"kind":"service","name":"ok-tail","observed_at":"2026-09-06T12:00:00Z","payload":{}}`); err != nil {
		t.Fatalf("追加末行夹具失败: %v", err)
	}
	if err := tail.Close(); err != nil {
		t.Fatalf("关闭末行夹具失败: %v", err)
	}

	// When: 容错读。Then: 仅 3 条合法在场且顺序正确。
	got, err := Read(time.Time{})
	if err != nil {
		t.Fatalf("单行损坏绝不应让 Read 报错: %v", err)
	}
	if len(got) != 3 || got[0].Name != "ok1" || got[1].Name != "ok2" || got[2].Name != "ok-tail" {
		names := make([]string, 0, len(got))
		for _, e := range got {
			names = append(names, e.Name)
		}
		t.Fatalf("容错读取结果不符: %v", names)
	}
}

// systemStateUsable 探测宿主系统态候选(/var/lib/daedalus)是否可写。
// 非 root 的正常宿主上必为 false;若某主机真可写,兜底夹具不成立 → 调用方 skip。
func systemStateUsable() bool {
	dir := filepath.Dir(dirs.StateSystemFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false
	}
	f, err := os.CreateTemp(dir, ".daedalus-state-probe-*")
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = os.Remove(f.Name())
	return true
}

func TestState_FallbackToHomeWhenPrimaryUnwritable(t *testing.T) {
	// Given: root 绕过 DAC(chmod 夹具失效)→ skip;宿主系统态候选意外可写 → skip。
	if os.Geteuid() == 0 {
		t.Skip("root 绕过 DAC 权限位,不可写夹具不适用")
	}
	if systemStateUsable() {
		t.Skip("/var/lib/daedalus 在本宿主可写,fallback 前提不成立")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	ro := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(ro, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) }) // 恢复权限以便 TempDir 回收
	// env 主候选存在但父目录不可写 → dirs 链下探系统候选(不可写)→ 落 $HOME。
	t.Setenv(dirs.EnvStatePath, filepath.Join(ro, "state.jsonl"))

	// When: 路径解析 + 一次真实写入读回。
	want := filepath.Join(home, dirs.StateHomeRel)
	got, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath 报错: %v", err)
	}
	if got != want {
		t.Fatalf("应兜底到 $HOME 路径 %q,实得 %q", want, got)
	}
	mustLog(t, "service", "fb.service", baseTime, `{}`)
	entries, err := Read(time.Time{})
	if err != nil {
		t.Fatalf("Read 报错: %v", err)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("状态文件应已落在 $HOME: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("兜底路径应可读写回 1 条,实得 %d", len(entries))
	}
}

func TestState_ConcurrentWrites(t *testing.T) {
	p := newStateFile(t)
	// Given: 10 个 goroutine 并发 Log 互异条目(flock LOCK_EX 串行化写入)。
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			mustLog(t, "service", fmt.Sprintf("c%d.service", i),
				baseTime.Add(time.Duration(i)*time.Millisecond), fmt.Sprintf(`{"g":%d}`, i))
		}(i)
	}
	wg.Wait()

	// Then: 10 条全部在场,无丢失、无交错坏行(flock 无丢失写证明)。
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("读文件失败: %v", err)
	}
	if n := strings.Count(string(raw), "\n"); n != 10 {
		t.Fatalf("文件应恰有 10 行,实得 %d(存在交错/丢失写)", n)
	}
	entries, err := Read(time.Time{})
	if err != nil {
		t.Fatalf("Read 报错: %v", err)
	}
	if len(entries) != 10 {
		t.Fatalf("应读到全部 10 条,实得 %d", len(entries))
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name, "c") || !strings.HasSuffix(e.Name, ".service") || seen[e.Name] {
			t.Fatalf("出现意外/重复条目: %+v", e)
		}
		seen[e.Name] = true
	}
}
