// 档位判定:纯函数,判定顺序即规则优先级(first match wins)。
package autonomy

import "strings"

// Classify 判定目标作用域的自主档位。顺序固定:危险名单(含机器高危属性)→
// 域闸门 → 属性未知闸门 → 用户规则 → 出厂预设 → 兜底第三档,前几层任何配置都放宽不了。
// auto 只有 start + enabled + !running + 属性已知才成立,否则降为第二档,
// 出厂预设与用户规则一视同仁。
func (c *Config) Classify(target Scope, attrs Attributes) Decision {
	if c == nil {
		return Decision{Tier: TierHuman, Reason: ReasonFallback}
	}
	if c.hitDeny(target) || attrs.HighRisk {
		return Decision{Tier: TierHuman, Reason: ReasonDeny}
	}
	// 越过用户域的对象不可放宽:运行时的 system 域先拦,属性域只要不是字面 "user"
	// (含空串、大小写变体与其他取值)同样按最严处理。
	if target.Runtime == "systemd" && target.Domain == "system" {
		return Decision{Tier: TierHuman, Reason: ReasonDomain}
	}
	if attrs.Domain != "user" {
		return Decision{Tier: TierHuman, Reason: ReasonDomain}
	}
	// 属性查不到一律第三档:这是规格里唯一的无条件 fail-closed 边界,用户规则也不例外。
	if !attrs.Known {
		return Decision{Tier: TierHuman, Reason: ReasonFallback}
	}
	if d, ok := c.matchRules(c.Rules, target, attrs, ReasonUserRule); ok {
		return d
	}
	if d, ok := c.matchRules(c.Presets, target, attrs, ReasonPreset); ok {
		return d
	}
	return Decision{Tier: TierHuman, Reason: ReasonFallback}
}

// hitDeny 判定目标是否落在危险名单里:作用域模式逐段匹配,裸名前缀按前缀命中
// (与 fleet 的 high_risk_services 同语义)。坏条目按命中处理:安全名单宁可误伤,
// 不可静默失效。
func (c *Config) hitDeny(target Scope) bool {
	for _, raw := range c.Deny {
		p, err := parsePattern(raw)
		if err != nil {
			return true
		}
		if p.matches(target) {
			return true
		}
	}
	for _, name := range c.DenyNames {
		if strings.HasPrefix(target.Target, name) {
			return true
		}
	}
	return false
}

// matchRules 按规则序逐条匹配,首命中生效;auto 档还要过降档条件这一关。
// 坏规则(作用域解析失败或档位不在三值内)按 fail-closed 处理:直接落第三档,
// 与 hitDeny 对坏条目的处理同向 —— 静默跳过等于放宽。
func (c *Config) matchRules(rules []Rule, target Scope, attrs Attributes, reason string) (Decision, bool) {
	for _, rule := range rules {
		pattern, err := ParseScope(rule.Scope)
		if err != nil {
			return Decision{Tier: TierHuman, Reason: ReasonFallback}, true
		}
		switch rule.Tier {
		case TierAuto, TierConfirm, TierHuman:
		default:
			return Decision{Tier: TierHuman, Reason: ReasonFallback}, true
		}
		if !pattern.Matches(target) {
			continue
		}
		tier := rule.Tier
		if tier == TierAuto && !canDowngrade(target, attrs) {
			tier = TierConfirm
		}
		d := Decision{Tier: tier, Reason: reason}
		if tier == TierConfirm {
			d.RequiredScope = []string{target.String()}
		}
		return d, true
	}
	return Decision{}, false
}

// canDowngrade 是唯一的降档条件:start + enabled + !running + 属性已知。
func canDowngrade(target Scope, attrs Attributes) bool {
	return target.Action == "start" && attrs.Enabled && !attrs.Running && attrs.Known
}
