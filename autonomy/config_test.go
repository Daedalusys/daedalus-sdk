// 严格加载的行为测试:未知键/非法 tier/文件缺失/只覆盖用户规则/路径解析链。
package autonomy_test

import (
	"errors"
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

	t.Setenv(autonomy.EnvPath, "relative.toml")
	if _, err := autonomy.LoadConfigured(); err == nil {
		t.Fatal("env 为相对路径时应报错,不得静默忽略")
	}
}
