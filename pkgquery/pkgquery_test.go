// pkgquery 的行为测试:全部经由 ExecRunner 注入完成,
// 不依赖开发机上的 rpm/dnf;断言错误串与 pkg_server.py 逐字一致。
package pkgquery

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// —— 测试替身:记录调用序列并按脚本返回结果 ——

type recordedCall struct {
	name string
	args []string
}

// scriptedRunner 依次弹出 steps 中的脚本结果;耗尽后重复最后一步。
type scriptedRunner struct {
	calls []recordedCall
	steps []scriptStep
	idx   int
}

type scriptStep struct {
	stdout, stderr string
	code           int
	err            error // 非 nil 表示"进程无法启动"(py 异常路径)
}

func newRunner(steps ...scriptStep) *scriptedRunner {
	return &scriptedRunner{steps: steps}
}

func (r *scriptedRunner) run(_ context.Context, name string, args []string) (string, string, int, error) {
	r.calls = append(r.calls, recordedCall{name: name, args: slices.Clone(args)})
	step := r.steps[r.idx]
	if r.idx < len(r.steps)-1 {
		r.idx++
	}
	return step.stdout, step.stderr, step.code, step.err
}

// wantCalls 断言调用序列(命令 + argv)逐字一致。
func (r *scriptedRunner) wantCalls(t *testing.T, want ...[]string) {
	t.Helper()
	if len(r.calls) != len(want) {
		t.Fatalf("调用次数 = %d, want %d(calls=%v)", len(r.calls), len(want), r.calls)
	}
	for i, c := range r.calls {
		got := append([]string{c.name}, c.args...)
		if !slices.Equal(got, want[i]) {
			t.Errorf("第 %d 次调用 = %v, want %v", i+1, got, want[i])
		}
	}
}

var spawnErr = errors.New(`exec: "rpm": executable file not found in $PATH`)

// —— 注入与校验(镜像 py:18-24 的 ValueError)——

func TestSanitize_RejectsInjectionAndEmpty(t *testing.T) {
	cases := []struct {
		in   string
		want string // 期望错误消息(逐字对齐 py:21/py:23)
	}{
		{";rm -rf", "Invalid package name or pattern: ;rm -rf"},
		{"", "Package name/pattern cannot be empty."},
		{"   ", "Package name/pattern cannot be empty."}, // py strip 后为空
		{"bash;id", "Invalid package name or pattern: bash;id"},
		{"a|b", "Invalid package name or pattern: a|b"},
		{"$(evil)", "Invalid package name or pattern: $(evil)"},
		{"a b", "Invalid package name or pattern: a b"},
		{"/etc/shadow", "Invalid package name or pattern: /etc/shadow"},
		{"a\x00b", "Invalid package name or pattern: a\x00b"},
		{"back`tick", "Invalid package name or pattern: back`tick"},
	}
	for _, tc := range cases {
		_, err := sanitizeQuery(tc.in)
		if err == nil || err.Error() != tc.want {
			t.Errorf("sanitizeQuery(%q) err = %v, want %q", tc.in, err, tc.want)
		}
	}
}

func TestSanitize_AcceptsLegalCharset(t *testing.T) {
	// py:15 字符集 [a-zA-Z0-9_-.:*+] 全族覆盖。
	for _, s := range []string{"kernel", "python3", "systemd-libs-252.1.el9.x86_64", "foo*bar", "podman:latest", "c++", "under_score", "a:b+c*d-e.f"} {
		got, err := sanitizeQuery(s)
		if err != nil || got != s {
			t.Errorf("sanitizeQuery(%q) = (%q, %v), want 原样通过", s, got, err)
		}
	}
}

// —— dnf_query(py:27-68)——

func TestDnfQuery_RpmHitWhenInstalled(t *testing.T) {
	r := newRunner(scriptStep{stdout: "  :bash-5.2.15-5.el9.x86_64\nRelease : 5\n"})
	svc := NewService(r.run)
	got, err := svc.DnfQuery(context.Background(), "bash")
	if err != nil {
		t.Fatal(err)
	}
	if want := ":bash-5.2.15-5.el9.x86_64\nRelease : 5"; got != want {
		t.Errorf("结果 = %q, want %q(strip 后逐字)", got, want)
	}
	// argv 直发、无 shell 包装:精确断言。
	r.wantCalls(t, []string{"rpm", "-q", "--info", "bash"})
}

func TestDnfQuery_FallbackToDnfWhenRpmMiss(t *testing.T) {
	r := newRunner(
		scriptStep{stderr: "package nope not installed\n", code: 1}, // rpm 退出码非 0
		scriptStep{stdout: "nope-1.0-1  @baseos\n"},                 // dnf 命中
	)
	svc := NewService(r.run)
	got, err := svc.DnfQuery(context.Background(), "nope")
	if err != nil {
		t.Fatal(err)
	}
	if want := "nope-1.0-1  @baseos"; got != want {
		t.Errorf("回退结果 = %q, want %q", got, want)
	}
	// 回退序列:rpm 先、dnf 后,argv 逐字。
	r.wantCalls(t,
		[]string{"rpm", "-q", "--info", "nope"},
		[]string{"dnf", "repoquery", "--info", "nope"},
	)
}

func TestDnfQuery_FallbackWhenRpmZeroButEmptyStdout(t *testing.T) {
	// py:50 条件是 returncode==0 AND stdout 非空:零码空输出同样落回退。
	r := newRunner(
		scriptStep{stdout: "", code: 0},
		scriptStep{stdout: "hit\n", code: 0},
	)
	svc := NewService(r.run)
	got, _ := svc.DnfQuery(context.Background(), "zsh")
	if got != "hit" {
		t.Errorf("零码空输出未触发回退: got %q", got)
	}
	r.wantCalls(t,
		[]string{"rpm", "-q", "--info", "zsh"},
		[]string{"dnf", "repoquery", "--info", "zsh"},
	)
}

func TestDnfQuery_NotFoundInBoth(t *testing.T) {
	r := newRunner(
		scriptStep{code: 1, stderr: "not installed"},
		scriptStep{code: 1, stderr: "No match found.\n"},
	)
	svc := NewService(r.run)
	got, _ := svc.DnfQuery(context.Background(), "ghost")
	// py:66 逐字外壳 + stderr strip。
	if want := "Package 'ghost' not found locally or in repositories. No match found."; got != want {
		t.Errorf("未命中串 = %q,\nwant         %q", got, want)
	}
}

func TestDnfQuery_NotFoundWithEmptyStderrCollapsesSpace(t *testing.T) {
	// py:66 末尾的 `.strip()` 把 "repositories. " 的悬空空格收敛掉。
	r := newRunner(
		scriptStep{code: 1},
		scriptStep{code: 1, stderr: ""},
	)
	svc := NewService(r.run)
	got, _ := svc.DnfQuery(context.Background(), "ghost")
	if want := "Package 'ghost' not found locally or in repositories."; got != want {
		t.Errorf("未命中串 = %q, want %q", got, want)
	}
}

func TestDnfQuery_RpmSpawnErrorSkipsDnfFallback(t *testing.T) {
	// py:52-53 —— rpm 启动异常直接 return,不会走到 dnf(等价行为关键测试)。
	r := newRunner(scriptStep{err: spawnErr})
	svc := NewService(r.run)
	got, err := svc.DnfQuery(context.Background(), "bash")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "Error executing rpm query: ") || !strings.Contains(got, "rpm") {
		t.Errorf("rpm 启动失败串 = %q, want 前缀 %q", got, "Error executing rpm query: ")
	}
	r.wantCalls(t, []string{"rpm", "-q", "--info", "bash"}) // 仅一次,无 dnf
}

func TestDnfQuery_DnfSpawnError(t *testing.T) {
	r := newRunner(
		scriptStep{code: 1},
		scriptStep{err: errors.New(`exec: "dnf": executable file not found in $PATH`)},
	)
	svc := NewService(r.run)
	got, _ := svc.DnfQuery(context.Background(), "bash")
	if !strings.HasPrefix(got, "Error executing dnf repoquery: ") {
		t.Errorf("dnf 启动失败串 = %q, want 前缀 %q", got, "Error executing dnf repoquery: ")
	}
	r.wantCalls(t,
		[]string{"rpm", "-q", "--info", "bash"},
		[]string{"dnf", "repoquery", "--info", "bash"},
	)
}

func TestDnfQuery_RejectsInjection(t *testing.T) {
	r := newRunner(scriptStep{})
	svc := NewService(r.run)
	_, err := svc.DnfQuery(context.Background(), ";rm -rf")
	if err == nil || err.Error() != "Invalid package name or pattern: ;rm -rf" {
		t.Errorf("注入包名未被拒绝: %v", err)
	}
	if len(r.calls) != 0 {
		t.Errorf("校验失败却执行了命令: %v", r.calls)
	}
}

// —— dnf_list_installed(py:71-102)——

func TestDnfListInstalled_SortsStripsAndDropsBlanks(t *testing.T) {
	r := newRunner(scriptStep{stdout: "zsh-5.9-1\n  bash-5.2-5  \n\naaa-1.0\n"})
	svc := NewService(r.run)
	got, err := svc.DnfListInstalled(context.Background(), "*")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"aaa-1.0", "bash-5.2-5", "zsh-5.9-1"}
	if !slices.Equal(got, want) {
		t.Errorf("列表 = %v, want %v", got, want)
	}
	r.wantCalls(t, []string{"rpm", "-qa", "*"})
}

func TestDnfListInstalled_EmptyOutputReturnsEmptyList(t *testing.T) {
	r := newRunner(scriptStep{stdout: "\n  \n"})
	svc := NewService(r.run)
	got, _ := svc.DnfListInstalled(context.Background(), "nomatch*")
	if len(got) != 0 {
		t.Errorf("空输出应为空列表: %v", got)
	}
}

func TestDnfListInstalled_NonZeroExitIsSingleErrorElement(t *testing.T) {
	// py:92-94 —— 错误以单元素列表返回而非异常。
	r := newRunner(scriptStep{code: 2, stderr: "rpm: bad pattern\n"})
	svc := NewService(r.run)
	got, err := svc.DnfListInstalled(context.Background(), "*")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Error listing packages: rpm: bad pattern"}; !slices.Equal(got, want) {
		t.Errorf("错误列表 = %v, want %v", got, want)
	}
}

func TestDnfListInstalled_SpawnError(t *testing.T) {
	r := newRunner(scriptStep{err: errors.New(`exec: "rpm": executable file not found in $PATH`)})
	svc := NewService(r.run)
	got, _ := svc.DnfListInstalled(context.Background(), "*")
	if len(got) != 1 || !strings.HasPrefix(got[0], "Error executing rpm -qa: ") {
		t.Errorf("启动失败列表 = %v, want 单元素 Error executing rpm -qa 前缀", got)
	}
}

func TestDnfListInstalled_RejectsEmptyPattern(t *testing.T) {
	// 显式空 pattern(客户端传 "")必须走 py 空名拒绝,而不是默认 "*"。
	svc := NewService(newRunner(scriptStep{}).run)
	_, err := svc.DnfListInstalled(context.Background(), "")
	if err == nil || err.Error() != "Package name/pattern cannot be empty." {
		t.Errorf("空 pattern 未被拒绝: %v", err)
	}
}
