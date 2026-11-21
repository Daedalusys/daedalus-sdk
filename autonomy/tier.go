// 档位三态与判定结果:档位语义与"随时可往严压"的属性模型。
package autonomy

// Tier 是自主档位:第一档自行执行,第二档需有效条子,第三档只出提案。
type Tier string

const (
	// TierAuto 允许 AI 自行 apply,但仍受降档条件约束。
	TierAuto Tier = "auto"
	// TierConfirm 需要一张匹配作用域的有效条子才 apply。
	TierConfirm Tier = "confirm"
	// TierHuman 不 apply(有条子也不行),只返回提案。
	TierHuman Tier = "human"
)

// 判定来源:命中哪一条规则决定了最终档位,审计据此回溯。
const (
	ReasonDeny     = "deny"
	ReasonDomain   = "domain"
	ReasonUserRule = "user-rule"
	ReasonPreset   = "preset"
	// ReasonFallback 是 fail-closed 兜底:什么都没命中、属性未知或规则损坏都归它。
	ReasonFallback = "fallback"
)

// Attributes 是机器自动查得的对象属性,调用方探好后传入。
// 属性权限是单向的:随时可往严压,只有一处组合允许往松。
type Attributes struct {
	// Domain 只有字面 "user" 才算用户域,其余取值(含空串)一律按最严处理。
	Domain   string
	HighRisk bool
	Enabled  bool
	Running  bool
	// Known 为 false 时一律第三档,用户规则也不例外。
	Known bool
}

// Decision 是一次判定的结果。
type Decision struct {
	Tier Tier
	// Reason 是命中的规则来源(见 Reason* 常量)。
	Reason string
	// RequiredScope 在 Tier==confirm 时给出所需作用域原文,供错误信息与条子签发用。
	RequiredScope []string
}
