package objectmodel

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestPlan_IsNotAResourceKind 钉住架构裁决:Plan 是下发动作,不是被管理资源。
// 任何把 "plan" 塞进 kindRegistry 的改动都会在这里变绿——那是回归。
func TestPlan_IsNotAResourceKind(t *testing.T) {
	if len(AllKinds()) != 7 {
		t.Fatalf("AllKinds 数量 = %d, want 7(Plan 不得进封闭枚举)", len(AllKinds()))
	}
	p := Plan{Intents: []Intent{{Kind: Kind("plan"), RiskClass: RiskClassLow}}}
	if err := p.Validate(); err == nil {
		t.Fatal(`Kind("plan") 必须被拒——Plan 不是资源类别`)
	}
}

// TestPlan_Validate_Rejects_IntentSpecNotJSON 钉住 Intent.Spec 的 JSON 合法性:
// 消费方(daedalus-core 计划 C 的 Dispatch)按契约把 Spec 原样塞进
// ApplyIntentRequest.spec_json,不再二次序列化——所以非法 JSON 必须在
// Plan.Validate 处挡下(镜像 Object.Validate 对 spec 的处理,空值放过)。
func TestPlan_Validate_Rejects_IntentSpecNotJSON(t *testing.T) {
	p := Plan{
		ID:          "0123456789abcdef",
		Intents:     []Intent{{Kind: KindService, Target: "nginx", Spec: json.RawMessage(`{"desired_state":`), RiskClass: RiskClassLow}},
		Machines:    []Machine{{MachineID: "ubuntu-24.04-a", Kind: MachineKindAgent, SupportLevel: SupportLevelSupported}},
		Batching:    Batching{Strategy: BatchingCount, Size: 1},
		BlastRadius: BlastRadius{Count: 1, MaxRisk: RiskClassLow},
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("非法 spec JSON 必须被拒")
	}
	if !strings.Contains(err.Error(), "intents[0].spec") {
		t.Errorf("报错未点名 intents[].spec, got: %s", err)
	}
}
