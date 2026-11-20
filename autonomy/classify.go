// 档位判定:纯函数,判定顺序即规则优先级(first match wins)。
package autonomy

import "strings"

// Classify 判定目标作用域的自主档位。顺序固定:危险名单(含机器高危属性)→
// system 域 → 用户规则 → 出厂预设 → 兜底第三档,前两层任何配置都放宽不了。
// auto 只有 start + enabled + !running + 属性已知才成立,否则降为第二档,
// 出厂预设与用户规则一视同仁;属性查不到仅在机器默认值这一层按最严处理
// (用户规则是人写的显式授权,照用;其中写 auto 的仍过降档条件,不会自主)。
func (c *Config) Classify(target Scope, attrs Attributes) Decision {
	if c == nil {
		return Decision{Tier: TierHuman, Reason: ReasonFallback}
	}
	if c.hitDeny(target) || attrs.HighRisk {
		return Decision{Tier: TierHuman, Reason: ReasonDeny}
	}
	// 越过用户域的对象不可放宽。
	if target.Runtime == "systemd" && target.Domain == "system" {
		return Decision{Tier: TierHuman, Reason: ReasonDomain}
	}
	if attrs.Domain == "system" {
		return Decision{Tier: TierHuman, Reason: ReasonDomain}
	}
	if d, ok := c.matchRules(c.Rules, target, attrs, ReasonUserRule); ok {
		return d
	}
	if d, ok := c.matchRules(c.Presets, target, attrs, ReasonPreset); ok {
		if !attrs.Known {
			return Decision{Tier: TierHuman, Reason: ReasonPreset}
		}
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
func (c *Config) matchRules(rules []Rule, target Scope, attrs Attributes, reason string) (Decision, bool) {
	for _, rule := range rules {
		pattern, err := ParseScope(rule.Scope)
		if err != nil {
			continue
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
