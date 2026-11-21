// Package autonomy 是外部 AI agent 受控变更通道的档位表:作用域寻址、三档判定,
// 以及档位表文件的严格加载。
//
// 判定是纯函数:作用域与对象属性都由调用方给定,本包不查系统、不写文件,
// 保证同一输入永远得到同一档位(审计可复现)。
package autonomy

import (
	"fmt"
	"path"
	"strings"
)

// 词表封闭:表外运行时/动作一律拒绝("不认识就不做"),新增须同步改出厂预设。
var (
	runtimeVocabulary = []string{"systemd", "sysvinit", "podman", "docker", "flatpak", "snap"}
	actionVocabulary  = []string{"start", "stop", "restart", "enable", "disable", "remove", "update", "install"}
	domainVocabulary  = []string{"user", "system"}
)

// Scope 是一次受控变更的寻址:运行时(可带域)+ 动作 + 目标。
type Scope struct {
	Runtime string
	Domain  string
	Action  string
	Target  string
}

// ParseScope 解析严格形态的作用域串:systemd 四段(runtime:domain:action:target),
// 其余运行时三段(runtime:action:target)。名单里 systemd 那种"省略动作段"的宽松形态
// 由内部模式解析器承担,不进公开 API。
func ParseScope(s string) (Scope, error) {
	if s == "" {
		return Scope{}, fmt.Errorf("autonomy: 作用域为空")
	}
	parts := strings.Split(s, ":")
	for _, p := range parts {
		if p == "" {
			return Scope{}, fmt.Errorf("autonomy: 作用域 %q 含空段", s)
		}
	}
	rt := parts[0]
	if !contains(runtimeVocabulary, rt) {
		return Scope{}, fmt.Errorf("autonomy: 作用域 %q 的运行时 %q 不在词表内", s, rt)
	}
	if rt == "systemd" {
		if len(parts) != 4 {
			return Scope{}, fmt.Errorf("autonomy: systemd 作用域 %q 必须是四段(runtime:domain:action:target)", s)
		}
		if !contains(domainVocabulary, parts[1]) {
			return Scope{}, fmt.Errorf("autonomy: 作用域 %q 的域 %q 只能是 user 或 system", s, parts[1])
		}
		if !contains(actionVocabulary, parts[2]) {
			return Scope{}, fmt.Errorf("autonomy: 作用域 %q 的动作 %q 不在词表内", s, parts[2])
		}
		return Scope{Runtime: rt, Domain: parts[1], Action: parts[2], Target: parts[3]}, nil
	}
	if len(parts) != 3 {
		return Scope{}, fmt.Errorf("autonomy: %s 作用域 %q 必须是三段(runtime:action:target)", rt, s)
	}
	if !contains(actionVocabulary, parts[1]) {
		return Scope{}, fmt.Errorf("autonomy: 作用域 %q 的动作 %q 不在词表内", s, parts[1])
	}
	return Scope{Runtime: rt, Action: parts[1], Target: parts[2]}, nil
}

// String 按段数还原作用域串:带域四段,其余三段。
func (s Scope) String() string {
	if s.Domain != "" {
		return strings.Join([]string{s.Runtime, s.Domain, s.Action, s.Target}, ":")
	}
	return strings.Join([]string{s.Runtime, s.Action, s.Target}, ":")
}

// Matches 判断本作用域(可含目标通配)是否覆盖另一作用域:运行时/域/动作逐字相等,
// 只有目标走 path.Match 通配(不支持 **)。
func (s Scope) Matches(o Scope) bool {
	if s.Runtime != o.Runtime || s.Domain != o.Domain || s.Action != o.Action {
		return false
	}
	ok, err := path.Match(s.Target, o.Target)
	return err == nil && ok
}

// pattern 是名单用的宽松作用域:只有 systemd 允许省略动作段(此时匹配任意动作),
// 其余运行时与 ParseScope 一样必须写 action:target,不开放"任意动作"的自创宽松面。
type pattern struct {
	runtime string
	domain  string
	action  string
	target  string
}

// parsePattern 解析名单作用域。systemd:domain[:action]:target;
// 其余运行时:action:target。
func parsePattern(s string) (pattern, error) {
	if s == "" {
		return pattern{}, fmt.Errorf("作用域为空")
	}
	parts := strings.Split(s, ":")
	for _, p := range parts {
		if p == "" {
			return pattern{}, fmt.Errorf("作用域 %q 含空段", s)
		}
	}
	rt := parts[0]
	if !contains(runtimeVocabulary, rt) {
		return pattern{}, fmt.Errorf("作用域 %q 的运行时 %q 不在词表内", s, rt)
	}
	p := pattern{runtime: rt}
	rest := parts[1:]
	if rt == "systemd" {
		switch len(rest) {
		case 2:
			p.domain, p.target = rest[0], rest[1]
			if !contains(domainVocabulary, p.domain) {
				return pattern{}, fmt.Errorf("作用域 %q 的域 %q 只能是 user 或 system", s, p.domain)
			}
		case 3:
			p.domain, p.action, p.target = rest[0], rest[1], rest[2]
			if !contains(domainVocabulary, p.domain) {
				return pattern{}, fmt.Errorf("作用域 %q 的域 %q 只能是 user 或 system", s, p.domain)
			}
			if !contains(actionVocabulary, p.action) {
				return pattern{}, fmt.Errorf("作用域 %q 的动作 %q 不在词表内", s, p.action)
			}
		default:
			return pattern{}, fmt.Errorf("systemd 作用域 %q 必须是三段或四段", s)
		}
		return p, nil
	}
	switch len(rest) {
	case 2:
		p.action, p.target = rest[0], rest[1]
		if !contains(actionVocabulary, p.action) {
			return pattern{}, fmt.Errorf("作用域 %q 的动作 %q 不在词表内", s, p.action)
		}
	default:
		return pattern{}, fmt.Errorf("%s 作用域 %q 必须是三段(runtime:action:target)", rt, s)
	}
	return p, nil
}

// matches 判断名单模式是否覆盖目标作用域:动作段缺省时匹配任意动作。
func (p pattern) matches(t Scope) bool {
	if p.runtime != t.Runtime || p.domain != t.Domain {
		return false
	}
	if p.action != "" && p.action != t.Action {
		return false
	}
	ok, err := path.Match(p.target, t.Target)
	return err == nil && ok
}

// validPattern 校验目标通配可被 path.Match 解析,避免坏模式在运行时静默失配。
func validPattern(target string) error {
	if _, err := path.Match(target, ""); err != nil {
		return fmt.Errorf("目标通配 %q 非法: %w", target, err)
	}
	return nil
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
