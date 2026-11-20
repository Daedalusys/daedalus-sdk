package autonomy_test

import (
	"reflect"
	"testing"

	"github.com/Daedalusys/daedalus-sdk/autonomy"
)

// mustScope 解析失败即测试失败:作用域是判定的前提,不该在用例里出现非法值。
func mustScope(t *testing.T, s string) autonomy.Scope {
	t.Helper()
	scope, err := autonomy.ParseScope(s)
	if err != nil {
		t.Fatalf("解析作用域 %q 失败: %v", s, err)
	}
	return scope
}

// userAttrs 是属性已知的用户域样本;需要别的组合时在其副本上覆写字段。
func userAttrs() autonomy.Attributes {
	return autonomy.Attributes{Domain: "user", Known: true}
}

func TestClassifyOrder(t *testing.T) {
	known := userAttrs()

	// (a) 危险名单优先于一切:命中即第三档。
	cfg := autonomy.Default()
	cfg.Deny = []string{"systemd:user:db-*"}
	got := cfg.Classify(mustScope(t, "systemd:user:start:db-1.service"), known)
	if got.Tier != autonomy.TierHuman || got.Reason != autonomy.ReasonDeny {
		t.Fatalf("危险名单命中判定漂移: %+v", got)
	}

	// (b) systemd:system 域不可放宽。
	defaults := autonomy.Default()
	got = defaults.Classify(mustScope(t, "systemd:system:restart:nginx.service"), known)
	if got.Tier != autonomy.TierHuman || got.Reason != autonomy.ReasonDomain {
		t.Fatalf("system 域判定漂移: %+v", got)
	}

	// (c) 用户规则命中即取其档位。
	cfg = autonomy.Default()
	cfg.Rules = []autonomy.Rule{{Scope: "systemd:user:start:myapp.service", Tier: autonomy.TierConfirm}}
	got = cfg.Classify(mustScope(t, "systemd:user:start:myapp.service"), known)
	if got.Tier != autonomy.TierConfirm || got.Reason != autonomy.ReasonUserRule {
		t.Fatalf("用户规则判定漂移: %+v", got)
	}
	if len(got.RequiredScope) != 1 || got.RequiredScope[0] != "systemd:user:start:myapp.service" {
		t.Fatalf("confirm 档未给出所需作用域原文: %+v", got.RequiredScope)
	}

	// (d) 出厂预设命中即取其档位。
	got = defaults.Classify(mustScope(t, "systemd:user:restart:web.service"), known)
	if got.Tier != autonomy.TierConfirm || got.Reason != autonomy.ReasonPreset {
		t.Fatalf("预设判定漂移: %+v", got)
	}

	// (e) 都没命中 ⇒ fail-closed 到第三档。
	got = defaults.Classify(mustScope(t, "systemd:user:install:myapp.service"), known)
	if got.Tier != autonomy.TierHuman || got.Reason != autonomy.ReasonFallback {
		t.Fatalf("兜底判定漂移: %+v", got)
	}
}

func TestAutoRequiresStartEnabledNotRunning(t *testing.T) {
	cfg := autonomy.Default()
	target := mustScope(t, "systemd:user:start:myapp.service")

	attrs := userAttrs()
	attrs.Enabled = true
	got := cfg.Classify(target, attrs)
	if got.Tier != autonomy.TierAuto {
		t.Fatalf("enabled && !running 应落到第一档: %+v", got)
	}
	if got.Reason != autonomy.ReasonPreset {
		t.Fatalf("第一档应记预设来源: %+v", got)
	}

	got = cfg.Classify(target, userAttrs())
	if got.Tier == autonomy.TierAuto {
		t.Fatalf("enabled=false 不得落第一档: %+v", got)
	}
	if got.Tier != autonomy.TierConfirm {
		t.Fatalf("enabled=false 应至少落到第二档: %+v", got)
	}

	attrs = userAttrs()
	attrs.Enabled, attrs.Running = true, true
	got = cfg.Classify(target, attrs)
	if got.Tier == autonomy.TierAuto {
		t.Fatalf("running=true 不得落第一档: %+v", got)
	}
}

func TestUserRuleAutoStillNeedsDowngradeCondition(t *testing.T) {
	cfg := autonomy.Default()
	cfg.Rules = []autonomy.Rule{{Scope: "podman:restart:test-*", Tier: autonomy.TierAuto}}
	attrs := userAttrs()
	attrs.Running = true
	got := cfg.Classify(mustScope(t, "podman:restart:test-web"), attrs)
	if got.Tier != autonomy.TierConfirm {
		t.Fatalf("用户规则写 auto 但不满足降档条件时应为第二档: %+v", got)
	}
}

func TestUnknownAttributesAreMostRestrictive(t *testing.T) {
	cfg := autonomy.Default()
	got := cfg.Classify(mustScope(t, "systemd:user:start:myapp.service"), autonomy.Attributes{Domain: "user", Known: false})
	if got.Tier != autonomy.TierHuman {
		t.Fatalf("属性查不到必须按最严处理: %+v", got)
	}
	if got.Reason != autonomy.ReasonFallback {
		t.Fatalf("属性查不到应记 fail-closed 来源: %+v", got)
	}
}

// TestUnknownAttributesBlockUserRules 钉住属性未知的无条件性:用户规则也不例外。
func TestUnknownAttributesBlockUserRules(t *testing.T) {
	cfg := autonomy.Default()
	cfg.Rules = []autonomy.Rule{{Scope: "systemd:user:start:myapp.service", Tier: autonomy.TierConfirm}}
	got := cfg.Classify(mustScope(t, "systemd:user:start:myapp.service"), autonomy.Attributes{Domain: "user", Known: false})
	if got.Tier != autonomy.TierHuman {
		t.Fatalf("属性未知时用户规则不得落到第二档: %+v", got)
	}
	if got.Reason != autonomy.ReasonFallback {
		t.Fatalf("属性未知应记 fail-closed 来源: %+v", got)
	}
}

// TestNonUserAttributeDomainIsHuman 钉住属性域只认字面 "user":其余取值一律第三档。
func TestNonUserAttributeDomainIsHuman(t *testing.T) {
	cfg := autonomy.Default()
	target := mustScope(t, "systemd:user:start:myapp.service")
	for _, domain := range []string{"", "system", "User", "root"} {
		attrs := autonomy.Attributes{Domain: domain, Known: true, Enabled: true}
		got := cfg.Classify(target, attrs)
		if got.Tier != autonomy.TierHuman || got.Reason != autonomy.ReasonDomain {
			t.Errorf("属性域 %q 应按最严处理: %+v", domain, got)
		}
	}

	// 字面 "user" 才放行到预设(auto 仍需降档条件)。
	got := cfg.Classify(target, autonomy.Attributes{Domain: "user", Known: true, Enabled: true})
	if got.Tier != autonomy.TierAuto || got.Reason != autonomy.ReasonPreset {
		t.Fatalf("字面 user 域应走预设: %+v", got)
	}
}

// TestMalformedRuleFailsClosed 钉住坏规则不得静默跳过:与坏名单条目同向 fail-closed。
func TestMalformedRuleFailsClosed(t *testing.T) {
	target := mustScope(t, "systemd:user:start:myapp.service")
	cases := []struct {
		name string
		rule autonomy.Rule
	}{
		{"scope 非法", autonomy.Rule{Scope: "systemd:user:start", Tier: autonomy.TierConfirm}},
		{"tier 非法", autonomy.Rule{Scope: "systemd:user:start:myapp.service", Tier: autonomy.Tier("bogus")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := autonomy.Default()
			cfg.Rules = []autonomy.Rule{tc.rule}
			got := cfg.Classify(target, userAttrs())
			if got.Tier != autonomy.TierHuman || got.Reason != autonomy.ReasonFallback {
				t.Fatalf("坏规则应 fail-closed 到第三档,不得落到预设: %+v", got)
			}
		})
	}
}

// TestPresetTablePinned 逐行钉死出厂预设表(scope + 档位),改坏任何一行都会变红。
func TestPresetTablePinned(t *testing.T) {
	want := []autonomy.Rule{
		{Scope: "systemd:user:start:*", Tier: autonomy.TierAuto},
		{Scope: "systemd:user:stop:*", Tier: autonomy.TierConfirm},
		{Scope: "systemd:user:restart:*", Tier: autonomy.TierConfirm},
		{Scope: "systemd:user:enable:*", Tier: autonomy.TierConfirm},
		{Scope: "systemd:user:disable:*", Tier: autonomy.TierConfirm},
		{Scope: "systemd:system:start:*", Tier: autonomy.TierHuman},
		{Scope: "systemd:system:stop:*", Tier: autonomy.TierHuman},
		{Scope: "systemd:system:restart:*", Tier: autonomy.TierHuman},
		{Scope: "systemd:system:enable:*", Tier: autonomy.TierHuman},
		{Scope: "systemd:system:disable:*", Tier: autonomy.TierHuman},
		{Scope: "systemd:system:remove:*", Tier: autonomy.TierHuman},
		{Scope: "systemd:system:update:*", Tier: autonomy.TierHuman},
		{Scope: "systemd:system:install:*", Tier: autonomy.TierHuman},
		{Scope: "sysvinit:start:*", Tier: autonomy.TierConfirm},
		{Scope: "sysvinit:stop:*", Tier: autonomy.TierConfirm},
		{Scope: "sysvinit:restart:*", Tier: autonomy.TierConfirm},
		{Scope: "podman:start:*", Tier: autonomy.TierConfirm},
		{Scope: "podman:stop:*", Tier: autonomy.TierConfirm},
		{Scope: "podman:restart:*", Tier: autonomy.TierConfirm},
		{Scope: "podman:remove:*", Tier: autonomy.TierHuman},
		{Scope: "podman:update:*", Tier: autonomy.TierHuman},
		{Scope: "docker:start:*", Tier: autonomy.TierConfirm},
		{Scope: "docker:stop:*", Tier: autonomy.TierConfirm},
		{Scope: "docker:restart:*", Tier: autonomy.TierConfirm},
		{Scope: "docker:remove:*", Tier: autonomy.TierHuman},
		{Scope: "docker:update:*", Tier: autonomy.TierHuman},
		{Scope: "flatpak:update:*", Tier: autonomy.TierHuman},
		{Scope: "flatpak:install:*", Tier: autonomy.TierHuman},
		{Scope: "flatpak:remove:*", Tier: autonomy.TierHuman},
		{Scope: "snap:update:*", Tier: autonomy.TierHuman},
		{Scope: "snap:install:*", Tier: autonomy.TierHuman},
		{Scope: "snap:remove:*", Tier: autonomy.TierHuman},
	}
	if got := autonomy.Default().Presets; !reflect.DeepEqual(got, want) {
		t.Fatalf("出厂预设表漂移:\n得到 %+v\n期望 %+v", got, want)
	}
}

// TestPresetClassifyRowByRow 逐行断言预设经 Classify 的实际档位与来源。
func TestPresetClassifyRowByRow(t *testing.T) {
	sys := func() autonomy.Attributes { return autonomy.Attributes{Domain: "system", Known: true} }
	cases := []struct {
		scope      string
		attrs      autonomy.Attributes
		wantTier   autonomy.Tier
		wantReason string
	}{
		// systemd:user:start 存 auto,实际档位由降档条件决定。
		{"systemd:user:start:myapp.service", autonomy.Attributes{Domain: "user", Known: true, Enabled: true}, autonomy.TierAuto, autonomy.ReasonPreset},
		{"systemd:user:start:myapp.service", userAttrs(), autonomy.TierConfirm, autonomy.ReasonPreset},
		{"systemd:user:stop:myapp.service", userAttrs(), autonomy.TierConfirm, autonomy.ReasonPreset},
		{"systemd:user:restart:myapp.service", userAttrs(), autonomy.TierConfirm, autonomy.ReasonPreset},
		{"systemd:user:enable:myapp.service", userAttrs(), autonomy.TierConfirm, autonomy.ReasonPreset},
		{"systemd:user:disable:myapp.service", userAttrs(), autonomy.TierConfirm, autonomy.ReasonPreset},
		// systemd:system 全部 8 个动作:域闸门先于预设,一律第三档。
		{"systemd:system:start:nginx.service", sys(), autonomy.TierHuman, autonomy.ReasonDomain},
		{"systemd:system:stop:nginx.service", sys(), autonomy.TierHuman, autonomy.ReasonDomain},
		{"systemd:system:restart:nginx.service", sys(), autonomy.TierHuman, autonomy.ReasonDomain},
		{"systemd:system:enable:nginx.service", sys(), autonomy.TierHuman, autonomy.ReasonDomain},
		{"systemd:system:disable:nginx.service", sys(), autonomy.TierHuman, autonomy.ReasonDomain},
		{"systemd:system:remove:nginx.service", sys(), autonomy.TierHuman, autonomy.ReasonDomain},
		{"systemd:system:update:nginx.service", sys(), autonomy.TierHuman, autonomy.ReasonDomain},
		{"systemd:system:install:nginx.service", sys(), autonomy.TierHuman, autonomy.ReasonDomain},
		// sysvinit。
		{"sysvinit:start:nginx", userAttrs(), autonomy.TierConfirm, autonomy.ReasonPreset},
		{"sysvinit:stop:nginx", userAttrs(), autonomy.TierConfirm, autonomy.ReasonPreset},
		{"sysvinit:restart:nginx", userAttrs(), autonomy.TierConfirm, autonomy.ReasonPreset},
		// podman。
		{"podman:start:test-web", userAttrs(), autonomy.TierConfirm, autonomy.ReasonPreset},
		{"podman:stop:test-web", userAttrs(), autonomy.TierConfirm, autonomy.ReasonPreset},
		{"podman:restart:test-web", userAttrs(), autonomy.TierConfirm, autonomy.ReasonPreset},
		{"podman:remove:test-web", userAttrs(), autonomy.TierHuman, autonomy.ReasonPreset},
		{"podman:update:test-web", userAttrs(), autonomy.TierHuman, autonomy.ReasonPreset},
		// docker。
		{"docker:start:test-web", userAttrs(), autonomy.TierConfirm, autonomy.ReasonPreset},
		{"docker:stop:test-web", userAttrs(), autonomy.TierConfirm, autonomy.ReasonPreset},
		{"docker:restart:test-web", userAttrs(), autonomy.TierConfirm, autonomy.ReasonPreset},
		{"docker:remove:test-web", userAttrs(), autonomy.TierHuman, autonomy.ReasonPreset},
		{"docker:update:test-web", userAttrs(), autonomy.TierHuman, autonomy.ReasonPreset},
		// flatpak / snap 的版本类动作一律第三档。
		{"flatpak:update:org.mozilla.firefox", userAttrs(), autonomy.TierHuman, autonomy.ReasonPreset},
		{"flatpak:install:org.mozilla.firefox", userAttrs(), autonomy.TierHuman, autonomy.ReasonPreset},
		{"flatpak:remove:org.mozilla.firefox", userAttrs(), autonomy.TierHuman, autonomy.ReasonPreset},
		{"snap:update:firefox", userAttrs(), autonomy.TierHuman, autonomy.ReasonPreset},
		{"snap:install:firefox", userAttrs(), autonomy.TierHuman, autonomy.ReasonPreset},
		{"snap:remove:firefox", userAttrs(), autonomy.TierHuman, autonomy.ReasonPreset},
		// 兜底:词表内动作但预设未覆盖。
		{"systemd:user:install:myapp.service", userAttrs(), autonomy.TierHuman, autonomy.ReasonFallback},
		{"podman:enable:test-web", userAttrs(), autonomy.TierHuman, autonomy.ReasonFallback},
	}
	for _, tc := range cases {
		cfg := autonomy.Default()
		got := cfg.Classify(mustScope(t, tc.scope), tc.attrs)
		if got.Tier != tc.wantTier || got.Reason != tc.wantReason {
			t.Errorf("%s ⇒ 得到 %s/%s,期望 %s/%s", tc.scope, got.Tier, got.Reason, tc.wantTier, tc.wantReason)
		}
	}
}

// TestPresetStartStoredAutoButClassifyDowngrades 把「预设存 auto、实际档位由降档条件决定」
// 的取舍固化成契约:导出字段 Presets 看到的是请求档位,不是最终档位。
func TestPresetStartStoredAutoButClassifyDowngrades(t *testing.T) {
	var stored autonomy.Tier
	for _, rule := range autonomy.Default().Presets {
		if rule.Scope == "systemd:user:start:*" {
			stored = rule.Tier
		}
	}
	if stored != autonomy.TierAuto {
		t.Fatalf("systemd:user:start 预设应存 TierAuto(实际档位由降档条件决定),得到 %q", stored)
	}
	target := mustScope(t, "systemd:user:start:myapp.service")
	cfg := autonomy.Default()
	if got := cfg.Classify(target, autonomy.Attributes{Domain: "user", Known: true, Enabled: true}); got.Tier != autonomy.TierAuto {
		t.Fatalf("满足降档条件时应为第一档: %+v", got)
	}
	if got := cfg.Classify(target, userAttrs()); got.Tier != autonomy.TierConfirm {
		t.Fatalf("不满足降档条件时应降为第二档: %+v", got)
	}
}

func TestHumanCannotBeRelaxedToAuto(t *testing.T) {
	cfg := autonomy.Default()
	cfg.Deny = []string{"systemd:user:db-*"}
	cfg.Rules = []autonomy.Rule{{Scope: "systemd:user:start:db-*", Tier: autonomy.TierAuto}}
	attrs := userAttrs()
	attrs.Enabled = true
	got := cfg.Classify(mustScope(t, "systemd:user:start:db-1.service"), attrs)
	if got.Tier != autonomy.TierHuman {
		t.Fatalf("危险名单对象不得被放宽: %+v", got)
	}
	if got.Reason != autonomy.ReasonDeny {
		t.Fatalf("危险名单应先于用户规则命中: %+v", got)
	}
}

// TestDenyNamesPrefixHit 钉住裸名前缀语义:与 fleet 的 high_risk_services 同形。
func TestDenyNamesPrefixHit(t *testing.T) {
	cfg := autonomy.Default()
	cfg.DenyNames = []string{"sshd"}
	got := cfg.Classify(mustScope(t, "systemd:user:restart:sshd.service"), userAttrs())
	if got.Tier != autonomy.TierHuman || got.Reason != autonomy.ReasonDeny {
		t.Fatalf("裸名前缀命中漂移: %+v", got)
	}
	got = cfg.Classify(mustScope(t, "systemd:user:restart:web.service"), userAttrs())
	if got.Tier == autonomy.TierHuman {
		t.Fatalf("裸名前缀不应误伤无关单元: %+v", got)
	}
}

// TestMalformedDenyEntryFailsClosed 钉住坏名单条目按命中处理:安全名单不得静默失效。
func TestMalformedDenyEntryFailsClosed(t *testing.T) {
	cfg := autonomy.Default()
	cfg.Deny = []string{"systemd:unknown-runtime:db-*"}
	got := cfg.Classify(mustScope(t, "systemd:user:restart:web.service"), userAttrs())
	if got.Tier != autonomy.TierHuman || got.Reason != autonomy.ReasonDeny {
		t.Fatalf("坏名单条目必须按命中处理: %+v", got)
	}
}

// TestHighRiskAttributeIsHuman 钉住机器高危属性:不可放宽。
func TestHighRiskAttributeIsHuman(t *testing.T) {
	cfg := autonomy.Default()
	attrs := userAttrs()
	attrs.HighRisk = true
	got := cfg.Classify(mustScope(t, "systemd:user:restart:web.service"), attrs)
	if got.Tier != autonomy.TierHuman {
		t.Fatalf("高危属性必须落到第三档: %+v", got)
	}
}
