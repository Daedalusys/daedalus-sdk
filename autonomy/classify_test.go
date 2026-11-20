package autonomy_test

import (
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

func TestClassifyOrder(t *testing.T) {
	known := autonomy.Attributes{Known: true}

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

	got := cfg.Classify(target, autonomy.Attributes{Known: true, Enabled: true, Running: false})
	if got.Tier != autonomy.TierAuto {
		t.Fatalf("enabled && !running 应落到第一档: %+v", got)
	}
	if got.Reason != autonomy.ReasonPreset {
		t.Fatalf("第一档应记预设来源: %+v", got)
	}

	got = cfg.Classify(target, autonomy.Attributes{Known: true, Enabled: false, Running: false})
	if got.Tier == autonomy.TierAuto {
		t.Fatalf("enabled=false 不得落第一档: %+v", got)
	}
	if got.Tier != autonomy.TierConfirm {
		t.Fatalf("enabled=false 应至少落到第二档: %+v", got)
	}

	got = cfg.Classify(target, autonomy.Attributes{Known: true, Enabled: true, Running: true})
	if got.Tier == autonomy.TierAuto {
		t.Fatalf("running=true 不得落第一档: %+v", got)
	}
}

func TestUserRuleAutoStillNeedsDowngradeCondition(t *testing.T) {
	cfg := autonomy.Default()
	cfg.Rules = []autonomy.Rule{{Scope: "podman:restart:test-*", Tier: autonomy.TierAuto}}
	got := cfg.Classify(mustScope(t, "podman:restart:test-web"), autonomy.Attributes{Known: true, Running: true})
	if got.Tier != autonomy.TierConfirm {
		t.Fatalf("用户规则写 auto 但不满足降档条件时应为第二档: %+v", got)
	}
}

func TestUnknownAttributesAreMostRestrictive(t *testing.T) {
	cfg := autonomy.Default()
	got := cfg.Classify(mustScope(t, "systemd:user:start:myapp.service"), autonomy.Attributes{Known: false})
	if got.Tier != autonomy.TierHuman {
		t.Fatalf("属性查不到必须按最严处理: %+v", got)
	}
}

func TestHumanCannotBeRelaxedToAuto(t *testing.T) {
	cfg := autonomy.Default()
	cfg.Deny = []string{"systemd:user:db-*"}
	cfg.Rules = []autonomy.Rule{{Scope: "systemd:user:start:db-*", Tier: autonomy.TierAuto}}
	got := cfg.Classify(mustScope(t, "systemd:user:start:db-1.service"), autonomy.Attributes{Known: true, Enabled: true, Running: false})
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
	got := cfg.Classify(mustScope(t, "systemd:user:restart:sshd.service"), autonomy.Attributes{Known: true})
	if got.Tier != autonomy.TierHuman || got.Reason != autonomy.ReasonDeny {
		t.Fatalf("裸名前缀命中漂移: %+v", got)
	}
	got = cfg.Classify(mustScope(t, "systemd:user:restart:web.service"), autonomy.Attributes{Known: true})
	if got.Tier == autonomy.TierHuman {
		t.Fatalf("裸名前缀不应误伤无关单元: %+v", got)
	}
}

// TestMalformedDenyEntryFailsClosed 钉住坏名单条目按命中处理:安全名单不得静默失效。
func TestMalformedDenyEntryFailsClosed(t *testing.T) {
	cfg := autonomy.Default()
	cfg.Deny = []string{"systemd:unknown-runtime:db-*"}
	got := cfg.Classify(mustScope(t, "systemd:user:restart:web.service"), autonomy.Attributes{Known: true})
	if got.Tier != autonomy.TierHuman || got.Reason != autonomy.ReasonDeny {
		t.Fatalf("坏名单条目必须按命中处理: %+v", got)
	}
}

// TestHighRiskAttributeIsHuman 钉住机器高危属性:不可放宽。
func TestHighRiskAttributeIsHuman(t *testing.T) {
	cfg := autonomy.Default()
	got := cfg.Classify(mustScope(t, "systemd:user:restart:web.service"), autonomy.Attributes{Known: true, HighRisk: true})
	if got.Tier != autonomy.TierHuman {
		t.Fatalf("高危属性必须落到第三档: %+v", got)
	}
}
