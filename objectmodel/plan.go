// Plan 是控制面下发的动作形状,不是被管理资源——故不入 kindRegistry 的
// 7 类资源枚举,也没有对应 Kind 常量。字段逐字来自 fleet 控制面设计
// §4.3 决策流;线上键名为 snake_case 契约,一经发布不得改名(控制面与
// agent 双侧按字面键解析)。本文件只定义形态,不承载调度或分派逻辑。
package objectmodel

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// RiskClass 是单条 intent 与整批 Plan 的操作风险等级词表(线协议 token，
// 小写;与 proto/agent/v1 的 RiskClass 枚举同源,仅不含 UNSPECIFIED)。
// low 允许控制面自动重试 transient 失败;high 任何失败立即暂停待人工裁决。
type RiskClass string

const (
	RiskClassLow  RiskClass = "low"
	RiskClassHigh RiskClass = "high"
)

// validRiskClass 报告 r 是否命中风险词表。闭集线性扫描,与 validKind 同款:
// 词表外的 token 不得被 MaxRisk 当成 low 悄悄降级。
func validRiskClass(r RiskClass) bool {
	return r == RiskClassLow || r == RiskClassHigh
}

// SupportLevel 是节点的分级诚实度(spec §7.2 待拍 #1 人类已拍 a):
// 走完 best-effort 五件套 = supported,支撑不完整 = experimental。
type SupportLevel string

const (
	SupportLevelSupported    SupportLevel = "supported"
	SupportLevelExperimental SupportLevel = "experimental"
)

func validSupportLevel(l SupportLevel) bool {
	return l == SupportLevelSupported || l == SupportLevelExperimental
}

// BatchingStrategy 是控制面把 Plan 切成子批的策略词表(spec §4.3)。
type BatchingStrategy string

const (
	BatchingCount      BatchingStrategy = "count"
	BatchingImportance BatchingStrategy = "importance"
	BatchingCustom     BatchingStrategy = "custom"
)

func validBatchingStrategy(s BatchingStrategy) bool {
	switch s {
	case BatchingCount, BatchingImportance, BatchingCustom:
		return true
	}
	return false
}

// PlanStatus 是 Plan 的收尾三态(VISION 展示面只有这三态)。空值表示尚未
// 收尾,是调度过程中的合法中间态,不得判非法。
type PlanStatus string

const (
	PlanStatusPaused   PlanStatus = "paused"
	PlanStatusDirty    PlanStatus = "dirty"
	PlanStatusComplete PlanStatus = "complete"
)

func validPlanStatus(s PlanStatus) bool {
	switch s {
	case PlanStatusPaused, PlanStatusDirty, PlanStatusComplete:
		return true
	}
	return false
}

// MachineKind 是**节点形态**词表,与资源 Kind 封闭枚举无关:前者的取值来自
// spec §4.4 的两套部署形态,后者是 objectmodel.go 里被 kindRegistry 守住的 7 类
// 资源。把 machine.kind 写成 objectmodel.Kind 会让每台机器都过不了 validKind。
type MachineKind string

const (
	MachineKindAtomic MachineKind = "atomic" // daedalus-atomic:自我管理 + 听 Plan(spec 附录 d)
	MachineKindAgent  MachineKind = "agent"  // daedalus-agent:异构被控
)

// Valid 报告 k 是否命中节点形态词表。
func (k MachineKind) Valid() bool {
	return k == MachineKindAtomic || k == MachineKindAgent
}

// Intent 是一条下发意图:对某类资源的具名目标施加期望状态。Kind 复用资源
// 类别封闭枚举(校验走 validKind),Spec 是 provider 领域的原始 JSON。
type Intent struct {
	Kind         Kind            `json:"kind"`
	Target       string          `json:"target"`
	Spec         json.RawMessage `json:"spec,omitempty"`
	ExpectedDiff string          `json:"expected_diff,omitempty"`
	RiskClass    RiskClass       `json:"risk_class"`
}

// Machine 是 Plan 的一条执行目标节点。Kind 是节点形态(MachineKind),
// 不是资源类别;SupportLevel 是控制面对该节点的诚实度标注。
type Machine struct {
	MachineID    string       `json:"machine_id"`
	Kind         MachineKind  `json:"kind"`
	SupportLevel SupportLevel `json:"support_level"`
}

// Batching 描述控制面如何把 Plan 切成子批。Size 仅在 strategy=count 时
// 必须为正;importance / custom 由调度器自行决定批量,Size 可留零。
type Batching struct {
	Strategy BatchingStrategy `json:"strategy"`
	Size     int              `json:"size,omitempty"`
}

// BlastRadius 是 Plan 的爆炸半径声明。MaxDowntime 用非负纳秒,键恒在
// (与 controller.Result.requeue_after_ns 同款惯例)。KindBreakdown 的键是
// intent 的资源 kind,不是 machine kind —— 一个 Plan 里多台机器形态相同却
// 可能改多类资源,breakdown 统计的是后者。
type BlastRadius struct {
	Count         int            `json:"count"`
	KindBreakdown map[string]int `json:"kind_breakdown,omitempty"`
	MaxDowntime   time.Duration  `json:"max_downtime_ns"`
	MaxRisk       RiskClass      `json:"max_risk"`
}

// Plan 是控制面一次下发的动作集合。
type Plan struct {
	ID          string      `json:"id"`
	Intents     []Intent    `json:"intents"`
	Machines    []Machine   `json:"machines"`
	Batching    Batching    `json:"batching"`
	BlastRadius BlastRadius `json:"blast_radius"`
	Status      PlanStatus  `json:"status,omitempty"`
}

// MaxRisk 返回 intents 的实际最大风险(序:low < high),遇到 high 短路。
// 空 Intents 返回 ""——空 intents 由 Validate 拒绝,MaxRisk 不兜底。
func (p Plan) MaxRisk() RiskClass {
	if len(p.Intents) == 0 {
		return ""
	}
	for _, in := range p.Intents {
		if in.RiskClass == RiskClassHigh {
			return RiskClassHigh
		}
	}
	return RiskClassLow
}

// Validate 聚合 Plan 全部缺陷一次性返回(fail-closed,与 Resource.Validate /
// Object.Validate 同风格)。校验次序钉死:
// ID → Intents → Machines → Batching → BlastRadius → Status。
func (p *Plan) Validate() error {
	if p == nil {
		return fmt.Errorf("objectmodel: Plan 缺失:不得为 nil")
	}

	var problems []string

	if p.ID == "" {
		problems = append(problems, `字段 "id" 缺失:必填`)
	}

	if len(p.Intents) == 0 {
		problems = append(problems, `字段 "intents" 缺失:Plan 至少含一条意图`)
	}
	for i, in := range p.Intents {
		prefix := fmt.Sprintf("intents[%d]", i)
		if in.Kind == "" {
			problems = append(problems, fmt.Sprintf(`字段 "%s.kind" 缺失:必填,取值为已定义资源类别`, prefix))
		} else if !validKind(in.Kind) {
			problems = append(problems, fmt.Sprintf(`字段 "%s.kind" 非法:%q 不在资源类别枚举内`, prefix, in.Kind))
		}
		if in.Target == "" {
			problems = append(problems, fmt.Sprintf(`字段 "%s.target" 缺失:必填,取值为被施力的资源名`, prefix))
		}
		if !validRiskClass(in.RiskClass) {
			problems = append(problems, fmt.Sprintf(`字段 "%s.risk_class" 非法:%q 不在风险词表内(low|high)`, prefix, in.RiskClass))
		}
		if len(in.Spec) > 0 && !json.Valid(in.Spec) {
			problems = append(problems, fmt.Sprintf(`字段 "%s.spec" 非法:非合法 JSON`, prefix))
		}
	}

	seenMachines := make(map[string]struct{}, len(p.Machines))
	for _, m := range p.Machines {
		// machine_id 是控制面查节点注册表的唯一键,也是 intent_id 的组成段:
		// 空值让查询落空,重复值让两次下发撞同一个审计键,二者都 fail-closed。
		switch {
		case m.MachineID == "":
			problems = append(problems, `字段 "machines[].machine_id" 缺失:必填`)
		default:
			if _, dup := seenMachines[m.MachineID]; dup {
				problems = append(problems, fmt.Sprintf(`字段 "machines[].machine_id" 非法:machine_id %q 重复`, m.MachineID))
			}
			seenMachines[m.MachineID] = struct{}{}
		}
		if !m.Kind.Valid() {
			problems = append(problems, fmt.Sprintf(`字段 "machines[].kind" 非法:%q 不在节点形态词表内(atomic|agent)`, m.Kind))
		}
		if !validSupportLevel(m.SupportLevel) {
			problems = append(problems, fmt.Sprintf(`字段 "machines[].support_level" 非法:%q 不在支持等级词表内(supported|experimental)`, m.SupportLevel))
		}
	}

	if !validBatchingStrategy(p.Batching.Strategy) {
		problems = append(problems, fmt.Sprintf(`字段 "batching.strategy" 非法:%q 不在批处理策略词表内(count|importance|custom)`, p.Batching.Strategy))
	}
	// strategy=count 时批量由 Size 决定:零/负值会让调度器无桶可切,
	// 其余策略的批量归调度器自决,不校验 Size。
	if p.Batching.Strategy == BatchingCount && p.Batching.Size <= 0 {
		problems = append(problems, `字段 "batching.size" 在 strategy=count 下必须为正`)
	}

	if p.BlastRadius.MaxDowntime < 0 {
		problems = append(problems, fmt.Sprintf(`字段 "blast_radius.max_downtime_ns" 非法:%d 不得为负`, p.BlastRadius.MaxDowntime))
	}
	// max_risk 是派生值(spec §4.3 的等式 Plan.max_risk = max(intents.risk_class)):
	// 允许声明低于实际的风险,等于让调度器按 low 自动重试高危 Plan。
	if want := p.MaxRisk(); p.BlastRadius.MaxRisk != want {
		problems = append(problems, fmt.Sprintf(`字段 "blast_radius.max_risk" 与 intents 实际最大风险不一致(got %q, want %q)`, p.BlastRadius.MaxRisk, want))
	}
	// count 是爆炸半径的声明值,必须等于实际执行机器集,二者脱钩会漏报影响面。
	if want := len(p.Machines); p.BlastRadius.Count != want {
		problems = append(problems, fmt.Sprintf(`字段 "blast_radius.count" 与 machines 数量不一致(got %d, want %d)`, p.BlastRadius.Count, want))
	}

	// 空值表示"尚未收尾",是调度过程中的合法中间态;非空必须是收尾三态之一。
	if p.Status != "" && !validPlanStatus(p.Status) {
		problems = append(problems, fmt.Sprintf(`字段 "status" 非法:%q 不在 Plan 状态词表内(paused|dirty|complete,空值表示未收尾)`, p.Status))
	}

	if len(problems) > 0 {
		return fmt.Errorf("objectmodel: Plan 校验失败: %s", strings.Join(problems, "; "))
	}
	return nil
}
