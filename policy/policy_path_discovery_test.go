// policy 包开发态路径回溯测试:锁住"回溯命中与仓目录名无关"这条契约。
//
// 病根:开发态从仓副本跑控制面时,副本目录不一定叫 daedalus-core
// (~/daedalus-e2e/core 这类命名很常见),只认 daedalus-core/ 前缀的候选会
// 全部落空 → ErrNotFound → 控制面 fail-closed 拒跑,验收被迫改用
// DAEDALUS_POLICY_PATH 手工指路径,等于"验的是手工指的文件,不是真生产策略"。
//
// 三个用例分别钉:新候选生效(改名仓能命中)、缺失仍 fail-closed(不退化成内置
// 默认)、旧候选优先级不变(向后兼容)。
package policy_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Daedalusys/daedalus-sdk/policy"
)

// chdir 切换工作目录,并在测试结束(含 panic/Fatal)时还原。
//
// 用 t.Cleanup 而不是 t.Chdir:Cleanup 是 LIFO,t.TempDir 的删除回调先注册、
// 本还原后注册,故还原先跑,不会出现"在待删目录里删目录"的失败。
func chdir(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("读取当前工作目录失败: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("切换到 %s 失败: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(prev); err != nil {
			t.Fatalf("还原工作目录到 %s 失败: %v", prev, err)
		}
	})
}

// skipIfProductionPolicyPresent 在真机(已装 /opt/daedalus/shared/policy.toml)
// 上跳过回溯演练:生产路径优先于开发态回溯,演练无意义。
func skipIfProductionPolicyPresent(t *testing.T) {
	t.Helper()
	if st, err := os.Stat(policy.ProductionPath); err == nil && !st.IsDir() {
		t.Skipf("本机存在 %s,生产路径优先,无法演练开发态回溯", policy.ProductionPath)
	}
}

// writePolicyFixture 把生产一致的夹具写到 dst(含父目录),返回 dst。
func writePolicyFixture(t *testing.T, dst string) string {
	t.Helper()
	data, err := os.ReadFile(testdataPath(t, "policy.toml"))
	if err != nil {
		t.Fatalf("读取夹具失败: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("建目录 %s 失败: %v", filepath.Dir(dst), err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("写夹具 %s 失败: %v", dst, err)
	}
	return dst
}

// TestLoad_RenameIndependentRepoLayout 是本次修复的主验收:
// 仓副本目录改名(此处叫 whatever)后,开发态回溯仍必须命中仓内
// files/system/opt/daedalus/shared/policy.toml。
//
// 改前该用例必然红:候选只有 daedalus-core/... 与 testdata/policy.toml,
// 从 whatever/sub 逐级上溯到根都匹配不到 → ErrNotFound。
func TestLoad_RenameIndependentRepoLayout(t *testing.T) {
	skipIfProductionPolicyPresent(t)
	t.Setenv(policy.EnvPolicyPath, "")

	root := t.TempDir()
	// 故意不叫 daedalus-core:这是病根场景的最小复刻。
	repo := filepath.Join(root, "whatever")
	want := writePolicyFixture(t, filepath.Join(repo, "files", "system", "opt", "daedalus", "shared", "policy.toml"))

	// 从仓内子目录启动:控制面真实起点是某个子目录,不是仓根。
	sub := filepath.Join(repo, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("建子目录失败: %v", err)
	}
	chdir(t, sub)

	got, err := policy.ResolvePath()
	if err != nil {
		t.Fatalf("改名仓副本竟然回溯不到策略文件(病根未除): %v", err)
	}
	if filepath.Clean(got) != want {
		t.Errorf("命中路径不对: got %s, want %s", got, want)
	}

	p, err := policy.Load("")
	if err != nil {
		t.Fatalf("Load 改名仓副本失败: %v", err)
	}
	if len(p.Shell.AllowedCommands) == 0 {
		t.Error("解析出的策略为空,未真正加载仓内 policy.toml")
	}
}

// TestLoad_NoCandidateFailClosed 锁住 fail-closed:任何候选都不存在时,
// Load 必须返回 ErrNotFound 哨兵,绝不悄悄换成内置 Default()
// (否则"生产策略没被验"会伪装成"验过了")。
func TestLoad_NoCandidateFailClosed(t *testing.T) {
	skipIfProductionPolicyPresent(t)
	t.Setenv(policy.EnvPolicyPath, "")

	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatalf("建空目录失败: %v", err)
	}
	chdir(t, empty)

	// 显式路径注入清空后才轮到回溯;此处连 testdata 也不存在。
	if _, err := policy.Load(""); !errors.Is(err, policy.ErrNotFound) {
		t.Fatalf("全缺失必须返回 ErrNotFound(fail-closed), got %v", err)
	}

	// 报错文案必须给出解法:调用方可自带 DAEDALUS_POLICY_PATH。
	_, err := policy.Load("")
	if err == nil || !strings.Contains(err.Error(), policy.EnvPolicyPath) {
		t.Errorf("ErrNotFound 文案未提示解法 %s: %v", policy.EnvPolicyPath, err)
	}
}

// TestLoad_LegacyCrossRepoCandidateStillWins 锁住向后兼容:
// 老布局(仓副本仍叫 daedalus-core)必须继续命中原候选,且**优先于**
// 与仓名无关的新候选——否则既有多仓工作流会静默换源。
func TestLoad_LegacyCrossRepoCandidateStillWins(t *testing.T) {
	skipIfProductionPolicyPresent(t)
	t.Setenv(policy.EnvPolicyPath, "")

	root := t.TempDir()
	legacy := writePolicyFixture(t, filepath.Join(root, "daedalus-core", "files", "system", "opt", "daedalus", "shared", "policy.toml"))
	// 同时在仓根放一份新候选形态:若顺序写反,下面就会命中它。
	writePolicyFixture(t, filepath.Join(root, "files", "system", "opt", "daedalus", "shared", "policy.toml"))

	chdir(t, root)

	got, err := policy.ResolvePath()
	if err != nil {
		t.Fatalf("老布局竟然回溯不到策略文件: %v", err)
	}
	if filepath.Clean(got) != legacy {
		t.Errorf("老候选优先级被新候选挤掉了: got %s, want %s", got, legacy)
	}
	if _, err := policy.Load(""); err != nil {
		t.Fatalf("Load 老布局失败: %v", err)
	}
}
