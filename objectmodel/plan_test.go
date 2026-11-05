package objectmodel

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestPlan_IsNotAResourceKind 钉住架构裁决:Plan 是下发动作,不是被管理资源。
// 任何把 "plan" 塞进 kindRegistry 的改动都会在这里变绿——那是回归。
func TestPlan_IsNotAResourceKind(t *testing.T) {
	if len(AllKinds()) != 7 {
		t.Fatalf("AllKinds 数量 = %d, want 7(Plan 不得进封闭枚举)", len(AllKinds()))
	}
	if slices.Contains(AllKinds(), Kind("plan")) {
		t.Fatal(`"plan" 出现在资源 Kind 注册表里——Plan 不是资源类别`)
	}
	if validKind(Kind("plan")) {
		t.Fatal(`validKind("plan") = true——"plan" 不得进 kindRegistry`)
	}

	// 端到端:除 intents[0].kind 外全字段合法的 Plan,必须且仅因该字段被拒。
	// (裸 Plan 会在 id/batching/max_risk 上先报错,证明不了 kind 这一条。)
	p := validPlan()
	p.Intents[0].Kind = Kind("plan")
	err := p.Validate()
	if err == nil {
		t.Fatal(`Kind("plan") 必须被拒——Plan 不是资源类别`)
	}
	if !strings.Contains(err.Error(), "intents[0].kind") {
		t.Errorf("报错未点名 intents[0].kind, got: %s", err)
	}
}

// TestPlan_Validate_NilReceiver 钉住 nil 走 fail-closed 而非 panic:
// 校验器是被喂畸形输入的那一层,自己不能先崩。
func TestPlan_Validate_NilReceiver(t *testing.T) {
	var p *Plan
	if err := p.Validate(); err == nil {
		t.Fatal("nil Plan 必须被拒,而不是 panic")
	}
}

// TestPlan_Validate_Rejects_AddressingKeys 钉住寻址键的必填与唯一性:
// machine_id 是控制面查节点注册表的唯一键,也是 intent_id 的组成部分,
// 空值或重复会让两次下发撞同一个审计键;intent 缺 target 则无施力对象。
func TestPlan_Validate_Rejects_AddressingKeys(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Plan)
		wantSub string // 错误消息必须点名的字段
	}{
		{"空 target", func(p *Plan) { p.Intents[0].Target = "" }, `intents[0].target`},
		{"空 machine_id", func(p *Plan) { p.Machines[0].MachineID = "" }, `machines[].machine_id`},
		{"重复 machine_id", func(p *Plan) { p.Machines[1].MachineID = p.Machines[0].MachineID }, `machines[].machine_id`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validPlan()
			tc.mutate(&p)
			err := p.Validate()
			if err == nil {
				t.Fatal("应拒绝")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("报错未点名 %q, got: %s", tc.wantSub, err)
			}
		})
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

// TestPlan_MaxRisk_DerivedFromIntents 钉住 MaxRisk 的聚合语义:
// Plan.max_risk 是 intents 实际风险的派生值,不是可独立填写的声明。
func TestPlan_MaxRisk_DerivedFromIntents(t *testing.T) {
	p := Plan{Intents: []Intent{
		{Kind: KindService, Target: "nginx", RiskClass: RiskClassLow},
		{Kind: KindPackage, Target: "kernel-core", RiskClass: RiskClassHigh},
	}}
	if got := p.MaxRisk(); got != RiskClassHigh {
		t.Errorf("MaxRisk() = %q, want %q", got, RiskClassHigh)
	}
}

// TestPlan_Validate_Rejects 覆盖 Plan 的等式类拒绝分支:
// blast_radius.max_risk / blast_radius.count 与 intents/machines 的实际值脱钩
// 会让调度器按错误的风险半径行事,必须红;另有批处理尺寸、负停机时间、
// 支持等级、节点形态与空 intents 的形态拒绝。
func TestPlan_Validate_Rejects(t *testing.T) {
	cases := []struct {
		name    string
		plan    Plan
		wantSub string // 错误消息必须点名的字段
	}{
		{"max_risk 低于 intents 实际最大", lowRadiusPlan(), `blast_radius.max_risk`},
		{"count 与 machines 不符", mismatchedCountPlan(), `blast_radius.count`},
		{"count 策略缺 Size", zeroSizePlan(), `batching.size`},
		{"负 max_downtime", negativeDowntimePlan(), `blast_radius.max_downtime_ns`},
		{"非法 support_level", badSupportLevelPlan(), `support_level`},
		{"machine.kind 用资源枚举值", badMachineKindPlan("service"), `machines[].kind`},
		{"machine.kind 空串", badMachineKindPlan(""), `machines[].kind`},
		{"空 intents", Plan{}, `intents`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.plan.Validate()
			if err == nil {
				t.Fatal("应拒绝")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("报错未点名 %q, got: %s", tc.wantSub, err)
			}
		})
	}
}

// validPlan 是拒绝用例的基例:一个形状完整、自洽、可过校验的 Plan。
func validPlan() Plan {
	return Plan{
		ID: "0123456789abcdef",
		Intents: []Intent{
			{Kind: KindService, Target: "nginx", RiskClass: RiskClassLow},
			{Kind: KindPackage, Target: "kernel-core", RiskClass: RiskClassHigh},
		},
		Machines: []Machine{
			{MachineID: "ubuntu-24.04-a", Kind: MachineKindAgent, SupportLevel: SupportLevelSupported},
			{MachineID: "ubuntu-24.04-b", Kind: MachineKindAgent, SupportLevel: SupportLevelSupported},
			{MachineID: "debian-12-a", Kind: MachineKindAgent, SupportLevel: SupportLevelSupported},
		},
		Batching:    Batching{Strategy: BatchingCount, Size: 2},
		BlastRadius: BlastRadius{Count: 3, MaxRisk: RiskClassHigh, MaxDowntime: 30 * time.Second},
	}
}

// lowRadiusPlan 把声明风险压到 low,而 intents 里有一枚 high —— 等式必须拒绝。
func lowRadiusPlan() Plan {
	p := validPlan()
	p.BlastRadius.MaxRisk = RiskClassLow
	return p
}

// mismatchedCountPlan 让爆炸半径计数少于实际机器数。
func mismatchedCountPlan() Plan {
	p := validPlan()
	p.BlastRadius.Count = 2
	return p
}

// zeroSizePlan 破坏 strategy=count 对 Size>0 的约束。
func zeroSizePlan() Plan {
	p := validPlan()
	p.Batching.Size = 0
	return p
}

// negativeDowntimePlan 给出负停机时间。
func negativeDowntimePlan() Plan {
	p := validPlan()
	p.BlastRadius.MaxDowntime = -1
	return p
}

// badSupportLevelPlan 把首台机器的支持等级写成词表外的值。
func badSupportLevelPlan() Plan {
	p := validPlan()
	p.Machines[0].SupportLevel = "beta"
	return p
}

// badMachineKindPlan 把首台机器的节点形态换成入参(资源 Kind 值或空串都非法)。
func badMachineKindPlan(kind MachineKind) Plan {
	p := validPlan()
	p.Machines[0].Kind = kind
	return p
}

// TestPlan_Status_Vocabulary 钉住 Plan 状态的封闭词表:三态 + 空值。
// 空值必须放过——调度器用"尚未收尾"表达进行中的 Plan,把空值判非法会让
// 运行中的 Plan 无法表达自身状态;表外词必须拒(VISION 展示面只有三态)。
func TestPlan_Status_Vocabulary(t *testing.T) {
	for _, s := range []PlanStatus{"", PlanStatusPaused, PlanStatusDirty, PlanStatusComplete} {
		p := validPlan()
		p.Status = s
		if err := p.Validate(); err != nil {
			t.Errorf("status %q 应放过, got %v", s, err)
		}
	}
	for _, s := range []PlanStatus{"queued", "running", "advanced", "succeeded", "paused_dirty"} {
		p := validPlan()
		p.Status = s
		if err := p.Validate(); err == nil {
			t.Errorf("status %q 必须拒(表外词),got nil", s)
		}
	}
}
