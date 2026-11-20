// 档位三态与判定结果:档位语义与"随时可往严压"的属性模型。
package autonomy

// Tier 是自主档位:第一档自行执行,第二档需有效条子,第三档只出提案。
type Tier string

const (
	// TierAuto 允许 AI 自行 apply(仍受降档条件约束)。
	TierAuto Tier = "auto"
	// TierConfirm 需要一张匹配作用域的有效条子才 apply。
	TierConfirm Tier = "confirm"
	// TierHuman 不 apply(有条子也不行),只返回提案。
	TierHuman Tier = "human"
)

// 判定来源:命中哪一条规则决定了最终档位,审计据此回溯。
const (
	// ReasonDeny 命中危险名单(用户 deny 作用域模式、裸名前缀或机器高危标记)。
	ReasonDeny = "deny"
	// ReasonDomain 命中 systemd:system 域或属性判定为 system 域。
	ReasonDomain = "domain"
	// ReasonUserRule 命中用户规则表的第一条规则。
	ReasonUserRule = "user-rule"
	// ReasonPreset 命中出厂预设的第一条规则。
	ReasonPreset = "preset"
	// ReasonFallback 什么都没命中(fail-closed)。
	ReasonFallback = "fallback"
)

// Attributes 是机器自动查得的对象属性,调用方探好后传入。
// 属性权限是单向的:随时可往严压,只有一处组合允许往松。
type Attributes struct {
	// Domain 是对象所在域(user/system)。
	Domain string
	// HighRisk 命中危险名单(含 fleet 高危清单)⇒ 第三档且不可放宽。
	HighRisk bool
	// Enabled 表示对象已配置为开机/常驻。
	Enabled bool
	// Running 表示对象当前在跑。
	Running bool
	// Known 表示属性查到了;查不到一律按最严处理。
	Known bool
}

// Decision 是一次判定的结果。
type Decision struct {
	// Tier 是最终档位。
	Tier Tier
	// Reason 是命中的规则来源(见 Reason* 常量)。
	Reason string
	// RequiredScope 在 Tier==confirm 时给出所需作用域原文,供错误信息与条子签发用。
	RequiredScope []string
}
