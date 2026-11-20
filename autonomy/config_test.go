// 严格加载的行为测试:未知键/非法 tier/relaxed 误用/TOML 语法错/非法作用域/
// 文件缺失/只覆盖用户规则/路径解析链。
package autonomy_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Daedalusys/daedalus-sdk/autonomy"
)

// writeTemp 把内容写入临时文件并返回路径:加载测试只关心文件内容。
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	return path
}

// TestLoadRejectsUnknownKey 钉住 fail-closed:拼写错误不得被静默忽略。
func TestLoadRejectsUnknownKey(t *testing.T) {
	path := writeTemp(t, "autonomy.toml", "typo_key = 1\n")
	cfg, err := autonomy.Load(path)
	if err == nil {
		t.Fatalf("含未知键的文件竟然加载成功: %+v", cfg)
	}
	if !strings.Contains(err.Error(), "未知键") {
		t.Fatalf("错误信息应点明未知键: %v", err)
	}
}

// TestLoadRejectsBadTier 钉住档位取值封闭:表外档位不得退回默认。
func TestLoadRejectsBadTier(t *testing.T) {
	path := writeTemp(t, "autonomy.toml", `
[[rule]]
scope = "systemd:user:start:myapp.service"
tier = "sometimes"
`)
	cfg, err := autonomy.Load(path)
	if err == nil {
		t.Fatalf("非法 tier 竟然加载成功: %+v", cfg)
	}
	if !strings.Contains(err.Error(), "tier") {
		t.Fatalf("错误信息应点明 tier: %v", err)
	}
}

// TestLoadRejectsRelaxedOutsideConfirm 钉住 relaxed 是"显式放宽"标记,只允许落在 confirm 上。
func TestLoadRejectsRelaxedOutsideConfirm(t *testing.T) {
	for _, tier := range []string{"auto", "human"} {
		t.Run(tier, func(t *testing.T) {
			path := writeTemp(t, "autonomy.toml", fmt.Sprintf(`
[[rule]]
scope = "systemd:user:start:myapp.service"
tier = %q
relaxed = true
`, tier))
			cfg, err := autonomy.Load(path)
			if err == nil {
				t.Fatalf("relaxed=true + tier=%q 竟然加载成功: %+v", tier, cfg)
			}
			if !strings.Contains(err.Error(), "relaxed") {
				t.Fatalf("错误信息应点明 relaxed: %v", err)
			}
		})
	}
}

// TestLoadRejectsBrokenToml 钉住 TOML 语法错:直接报错,不退默认。
func TestLoadRejectsBrokenToml(t *testing.T) {
	path := writeTemp(t, "autonomy.toml", "[[rule]\nscope = \"systemd:user:start:myapp.service\"\n")
	cfg, err := autonomy.Load(path)
	if err == nil {
		t.Fatalf("TOML 语法错竟然加载成功: %+v", cfg)
	}
	if !strings.Contains(err.Error(), "解析") {
		t.Fatalf("错误信息应点明解析失败: %v", err)
	}
	// 类型不匹配也会落到这条错误,不得再统称"TOML 损坏"误导排障方向。
	if strings.Contains(err.Error(), "损坏") {
		t.Fatalf("解析失败不应统称 TOML 损坏: %v", err)
	}
}

// TestLoadRejectsBadScope 钉住作用域/名单的加载期校验:坏条目不得静默丢弃。
func TestLoadRejectsBadScope(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"rule 段数错", "[[rule]]\nscope = \"systemd:user:start\"\ntier = \"human\"\n"},
		{"deny 运行时不在词表", "deny = [\"notaruntime:start:x\"]\n"},
		{"deny 动作不在词表", "deny = [\"systemd:user:frobnicate:x\"]\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, "autonomy.toml", tc.content)
			cfg, err := autonomy.Load(path)
			if err == nil {
				t.Fatalf("非法作用域竟然加载成功: %+v", cfg)
			}
		})
	}
}

// TestNonSystemdPatternRequiresAction 钉住非 systemd 名单必须写 action:target,
// 不接受只写目标的"任意动作"宽松形态。
func TestNonSystemdPatternRequiresAction(t *testing.T) {
	bad := writeTemp(t, "bad.toml", "deny = [\"podman:test-*\"]\n")
	if cfg, err := autonomy.Load(bad); err == nil {
		t.Fatalf("非 systemd 名单只写目标竟然加载成功: %+v", cfg)
	}

	good := writeTemp(t, "good.toml", "deny = [\"podman:stop:test-*\"]\n")
	if _, err := autonomy.Load(good); err != nil {
		t.Fatalf("非 systemd 名单写 action:target 应通过: %v", err)
	}
}

// TestLoadRejectsDuplicateSigner 钉住同名签发者只允许一条:
// 「首条即胜」会让后来加的收紧条目静默失效(配置更严、行为更松)。
func TestLoadRejectsDuplicateSigner(t *testing.T) {
	path := writeTemp(t, "autonomy.toml", `
[[signer]]
user = "alice"
max_scope = ["systemd:user:restart:*"]
max_ttl = "1h"
max_uses = 5

[[signer]]
user = "alice"
max_scope = ["systemd:user:restart:nginx.service"]
max_ttl = "10m"
max_uses = 1
`)
	cfg, err := autonomy.Load(path)
	if err == nil {
		t.Fatalf("同名签发者竟然加载成功: %+v", cfg)
	}
	if !strings.Contains(err.Error(), "重复") || !strings.Contains(err.Error(), "第 2 个") {
		t.Fatalf("错误信息应指到重复的那一条 signer: %v", err)
	}
}

// TestLoadRejectsZeroSignerBounds 钉住上限必须显式写正数:
// 若「缺省/0 = 不限制」,少写一个字段就变成了放宽权限。
func TestLoadRejectsZeroSignerBounds(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"缺 max_ttl", `
[[signer]]
user = "alice"
max_scope = ["systemd:user:restart:*"]
max_uses = 2
`, "max_ttl"},
		{"max_ttl 为 0s", `
[[signer]]
user = "alice"
max_scope = ["systemd:user:restart:*"]
max_ttl = "0s"
max_uses = 2
`, "max_ttl"},
		{"缺 max_uses", `
[[signer]]
user = "alice"
max_scope = ["systemd:user:restart:*"]
max_ttl = "1h"
`, "max_uses"},
		{"max_uses 为 0", `
[[signer]]
user = "alice"
max_scope = ["systemd:user:restart:*"]
max_ttl = "1h"
max_uses = 0
`, "max_uses"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, "autonomy.toml", tc.content)
			cfg, err := autonomy.Load(path)
			if err == nil {
				t.Fatalf("上限缺失/为 0 竟然加载成功: %+v", cfg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("错误信息应点明 %s: %v", tc.want, err)
			}
		})
	}
}

// TestLoadRejectsLaxMaxScope 钉住 max_scope 与消费侧用同一套严格语法:
// 省略动作段(= 缺目标段)的宽松形态要在加载期就拒,否则会变成
// 「配置合法、签发永远失败」的静默死配置。
func TestLoadRejectsLaxMaxScope(t *testing.T) {
	bad := writeTemp(t, "bad.toml", `
[[signer]]
user = "alice"
max_scope = ["systemd:user:restart"]
max_ttl = "1h"
max_uses = 2
`)
	cfg, err := autonomy.Load(bad)
	if err == nil {
		t.Fatalf("缺目标段的宽松 max_scope 竟然加载成功: %+v", cfg)
	}
	if !strings.Contains(err.Error(), "max_scope") {
		t.Fatalf("错误信息应点明 max_scope: %v", err)
	}

	good := writeTemp(t, "good.toml", `
[[signer]]
user = "alice"
max_scope = ["systemd:user:restart:*"]
max_ttl = "1h"
max_uses = 2
`)
	if _, err := autonomy.Load(good); err != nil {
		t.Fatalf("严格形态的 max_scope 应加载通过: %v", err)
	}
}

// TestLoadMissingReturnsErrNotFound 钉住哨兵:缺失由调用方决定回退。
func TestLoadMissingReturnsErrNotFound(t *testing.T) {
	_, err := autonomy.Load(filepath.Join(t.TempDir(), "absent.toml"))
	if !errors.Is(err, autonomy.ErrNotFound) {
		t.Fatalf("文件不存在应返回 ErrNotFound: %v", err)
	}
}

// TestLoadOverridesRulesOnly 钉住覆盖范围:文件只写用户面,预设恒来自 Default()。
func TestLoadOverridesRulesOnly(t *testing.T) {
	path := writeTemp(t, "autonomy.toml", `
deny = ["systemd:user:db-*"]
deny_names = ["sshd"]
deny_signers = ["mallory"]

[[rule]]
scope = "systemd:user:start:myapp.service"
tier = "confirm"
relaxed = true
`)
	cfg, err := autonomy.Load(path)
	if err != nil {
		t.Fatalf("合法文件加载失败: %v", err)
	}
	if !reflect.DeepEqual(cfg.Presets, autonomy.Default().Presets) {
		t.Fatalf("文件不得覆盖出厂预设: %+v", cfg.Presets)
	}
	wantRules := []autonomy.Rule{{
		Scope:   "systemd:user:start:myapp.service",
		Tier:    autonomy.TierConfirm,
		Relaxed: true,
	}}
	if !reflect.DeepEqual(cfg.Rules, wantRules) {
		t.Fatalf("用户规则未按文件落地: %+v", cfg.Rules)
	}
	if !reflect.DeepEqual(cfg.Deny, []string{"systemd:user:db-*"}) {
		t.Fatalf("deny 未按文件落地: %+v", cfg.Deny)
	}
	if !reflect.DeepEqual(cfg.DenyNames, []string{"sshd"}) {
		t.Fatalf("deny_names 未按文件落地: %+v", cfg.DenyNames)
	}
	if !reflect.DeepEqual(cfg.DenySigners, []string{"mallory"}) {
		t.Fatalf("deny_signers 未按文件落地: %+v", cfg.DenySigners)
	}
}

// TestLoadConfiguredEnvOverride 钉住路径解析链:env 优先且必须是绝对路径。
func TestLoadConfiguredEnvOverride(t *testing.T) {
	path := writeTemp(t, "autonomy.toml", "deny = [\"systemd:user:db-*\"]\n")
	t.Setenv(autonomy.EnvPath, path)
	cfg, err := autonomy.LoadConfigured()
	if err != nil {
		t.Fatalf("env 指向的合法文件加载失败: %v", err)
	}
	if len(cfg.Deny) != 1 {
		t.Fatalf("env 覆盖未生效: %+v", cfg.Deny)
	}

	// 相对路径必须被点名为"非法覆盖值",不能靠"读生产路径失败"碰巧满足断言。
	t.Setenv(autonomy.EnvPath, "relative.toml")
	if _, err := autonomy.LoadConfigured(); !errors.Is(err, autonomy.ErrEnvNotAbsolute) {
		t.Fatalf("env 为相对路径应返回 ErrEnvNotAbsolute,得到: %v", err)
	}

	t.Setenv(autonomy.EnvPath, "")
	if _, err := autonomy.LoadConfigured(); !errors.Is(err, autonomy.ErrEnvNotAbsolute) {
		t.Fatalf("env 为空值应返回 ErrEnvNotAbsolute,得到: %v", err)
	}
}

// TestLoadConfiguredFallsBackToProductionPath 钉住路径链的第三段:env 未设 ⇒ 读生产路径。
func TestLoadConfiguredFallsBackToProductionPath(t *testing.T) {
	old, had := os.LookupEnv(autonomy.EnvPath)
	if err := os.Unsetenv(autonomy.EnvPath); err != nil {
		t.Fatalf("清除 %s 失败: %v", autonomy.EnvPath, err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(autonomy.EnvPath, old)
			return
		}
		_ = os.Unsetenv(autonomy.EnvPath)
	})

	_, err := autonomy.LoadConfigured()
	if _, statErr := os.Stat(autonomy.ProductionPath); os.IsNotExist(statErr) {
		if !errors.Is(err, autonomy.ErrNotFound) {
			t.Fatalf("env 未设且 %s 不存在时应返回 ErrNotFound: %v", autonomy.ProductionPath, err)
		}
		return
	}
	// 生产文件存在时,必须是真的读了它:不该再报 ErrNotFound。
	if errors.Is(err, autonomy.ErrNotFound) {
		t.Fatalf("env 未设时应读生产路径 %s: %v", autonomy.ProductionPath, err)
	}
}
