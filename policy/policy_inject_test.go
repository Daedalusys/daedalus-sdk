// policy 包注入缝测试:证明 shellpolicy.WithPolicy / pathguard.WithAllowedDirs
// 真实改变校验器的生效策略(含深拷贝、nil 防御与测试后还原)。
// 与 policy_test.go 同属外部测试包 policy_test,可无环导入被注入的两个包。
package policy_test

import (
	"os"
	"slices"
	"testing"
	"time"

	"github.com/Daedalusys/daedalus-sdk/pathguard"
	"github.com/Daedalusys/daedalus-sdk/policy"
	"github.com/Daedalusys/daedalus-sdk/shellpolicy"
)

// TestWithPolicy_InjectsAndRestores 证明注入缝真实生效:
// shellpolicy 的解析函数在 WithPolicy 后跟随策略值;测试结束还原。
func TestWithPolicy_InjectsAndRestores(t *testing.T) {
	t.Cleanup(func() {
		shellpolicy.WithPolicy(policy.Default()) // 全量还原包级策略值。
	})

	p, err := policy.Load(testdataPath(t, "valid.toml"))
	if err != nil {
		t.Fatal(err)
	}
	shellpolicy.WithPolicy(p)

	if got := shellpolicy.ResolveAllowCommands(""); len(got) != 2 {
		t.Errorf("注入后默认白名单大小 = %d, want 2: %v", len(got), got)
	}
	if !slices.Equal(shellpolicy.AllowedPathPrefixes, []string{"/tmp"}) {
		t.Errorf("前缀未注入: %v", shellpolicy.AllowedPathPrefixes)
	}
	if !slices.Equal(shellpolicy.BlockedPaths, []string{"/root"}) {
		t.Errorf("blocked 未注入: %v", shellpolicy.BlockedPaths)
	}
	wantCleanEnv := []string{"LANG=C", "PATH=/usr/bin:/bin"} // 键升序确定性输出
	if !slices.Equal(shellpolicy.CleanEnv, wantCleanEnv) {
		t.Errorf("clean_env 未注入: %v, want %v", shellpolicy.CleanEnv, wantCleanEnv)
	}
	if shellpolicy.Timeout != 5*time.Second {
		t.Errorf("timeout 未注入: %v", shellpolicy.Timeout)
	}
	if _, err := shellpolicy.ValidateCommand("echo", shellpolicy.ResolveAllowCommands("")); err != nil {
		t.Errorf("注入后的 echo 应通过命令校验: %v", err)
	}
	if _, err := shellpolicy.ValidateCommand("uname", shellpolicy.ResolveAllowCommands("")); err == nil {
		t.Error("注入后 uname 不再于策略白名单,应被拒")
	}
}

// TestWithPolicy_DeepCopiesAndNil 证明注入做深拷贝(外部改动不渗透)、
// nil 策略为无害 no-op。
func TestWithPolicy_DeepCopiesAndNil(t *testing.T) {
	origBlocked := slices.Clone(shellpolicy.BlockedPaths)
	origPrefixes := slices.Clone(shellpolicy.AllowedPathPrefixes)
	t.Cleanup(func() {
		shellpolicy.WithPolicy(policy.Default())
	})

	p := policy.Default()
	shellpolicy.WithPolicy(p)
	p.Shell.BlockedPaths[0] = "/mutated"
	p.Shell.AllowedPathPrefixes[0] = "/mutated"
	if !slices.Equal(shellpolicy.BlockedPaths, origBlocked) {
		t.Errorf("外部改动渗透了 BlockedPaths: %v", shellpolicy.BlockedPaths)
	}
	if !slices.Equal(shellpolicy.AllowedPathPrefixes, origPrefixes) {
		t.Errorf("外部改动渗透了 AllowedPathPrefixes: %v", shellpolicy.AllowedPathPrefixes)
	}

	shellpolicy.WithPolicy(nil) // no-op,不改任何策略值
	if !slices.Equal(shellpolicy.BlockedPaths, origBlocked) {
		t.Errorf("nil 策略改动了 BlockedPaths: %v", shellpolicy.BlockedPaths)
	}
}

// TestWithAllowedDirs_InjectsAndDeepCopies 证明 pathguard 注入口生效。
func TestWithAllowedDirs_InjectsAndDeepCopies(t *testing.T) {
	orig := slices.Clone(pathguard.AllowedDirs)
	t.Cleanup(func() { pathguard.WithAllowedDirs(orig) })

	dirs := []string{"/tmp"}
	pathguard.WithAllowedDirs(dirs)
	dirs[0] = "/mutated" // 深拷贝后外部改动不得渗透

	if !slices.Equal(pathguard.AllowedDirs, []string{"/tmp"}) {
		t.Fatalf("WithAllowedDirs 未生效或被渗透: %v", pathguard.AllowedDirs)
	}
	if _, err := pathguard.ValidatePath("/etc/passwd", false); err == nil {
		t.Error("注入 /tmp-only 后 /etc/passwd 应被拒")
	}
	base, err := os.MkdirTemp("/tmp", "daedalus-policy-guard-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if _, err := pathguard.ValidatePath(base, false); err != nil {
		t.Errorf("注入 /tmp-only 后 /tmp 路径应放行: %v", err)
	}
}
