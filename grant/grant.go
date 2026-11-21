// Package grant 实现条子(grant)的数据形态、签发者授权判定与用量记账。
//
// 校验的唯一权威在消费侧:签发身份取文件属主 uid,JSON 里的 issued_by 只作线索;
// 范围/有效期/次数一律按签发者名单与全局硬上限重新判定,伪造字段或绕过签发
// 命令直接塞文件都无效。依赖方向单一:本包依赖 autonomy,autonomy 不认识本包。
package grant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/Daedalusys/daedalus-sdk/autonomy"
)

const (
	// GlobalMaxTTL 是条子有效期的全局硬上限:防止签出一张近乎永久的条子。
	GlobalMaxTTL = 24 * time.Hour
	// GlobalMaxUses 是单张条子可用次数的全局硬上限。
	GlobalMaxUses = 10
)

// Grant 是一张条子:对若干作用域的一次性授权。
// IssuedBy 只是线索,权威身份由调用方给的属主 uid/属主名决定。
// 读条子文件必须走 Parse(它做严格校验并归一时间),不要用 json.Unmarshal:
// 后者会静默产出零值字段的空壳。
type Grant struct {
	ID        string
	Scope     []string
	IssuedBy  string
	IssuedAt  time.Time
	ExpiresAt time.Time
	MaxUses   int
	Note      string
	// ForUser 是「这张条子给谁用」。只有当条子文件**属主是 root** 时它才被采信:
	// root 拥有的文件别人改不动,所以这句话可信。属主不是 root 时这个字段一律忽略
	// (属主与执行者相同才用得上)。
	ForUser string
}

// wireGrant 是条子文件的 JSON 形态:时间用 RFC3339 字符串,便于人工审阅。
// Parse 与 MarshalJSON 共用它,读写两端不另立事实源。
type wireGrant struct {
	ID        string   `json:"id"`
	Scope     []string `json:"scope"`
	IssuedBy  string   `json:"issued_by"`
	IssuedAt  string   `json:"issued_at"`
	ExpiresAt string   `json:"expires_at"`
	MaxUses   int      `json:"max_uses"`
	Note      string   `json:"note"`
	ForUser   string   `json:"for_user,omitempty"`
}

// Parse 解析条子文件内容。缺字段/时间非法/作用域非法/未知键一律拒绝:
// 条子文件是授权凭据,解析宽松等于把伪造空间留给写文件的人。
func Parse(data []byte) (*Grant, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var w wireGrant
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("grant: 解析条子失败: %w", err)
	}
	// 残余内容不能用 dec.More() 判:它对紧跟的 ] / } 会返回 false,尾串就被放过了。
	// 再解码一次拿到 io.EOF 才算 JSON 真的结束。
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("grant: 条子 JSON 之后有多余内容")
	}
	if err := validateID(w.ID); err != nil {
		return nil, fmt.Errorf("grant: 条子 id 非法: %w", err)
	}
	if len(w.Scope) == 0 {
		return nil, fmt.Errorf("grant: 条子范围为空")
	}
	for _, raw := range w.Scope {
		sc, err := autonomy.ParseScope(raw)
		if err != nil {
			return nil, fmt.Errorf("grant: 条子范围 %q 非法: %w", raw, err)
		}
		// 目标段是通配模式:写坏了会让条子在消费侧静默不匹配,不如解析期就拒。
		if _, err := path.Match(sc.Target, ""); err != nil {
			return nil, fmt.Errorf("grant: 条子范围 %q 的目标通配非法: %w", raw, err)
		}
	}
	issuedAt, err := parseTime(w.IssuedAt)
	if err != nil {
		return nil, fmt.Errorf("grant: 条子签发时间非法: %w", err)
	}
	expiresAt, err := parseTime(w.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("grant: 条子到期时间非法: %w", err)
	}
	if !expiresAt.After(issuedAt) {
		return nil, fmt.Errorf("grant: 条子到期时间 %s 不晚于签发时间 %s", expiresAt, issuedAt)
	}
	if w.MaxUses <= 0 {
		return nil, fmt.Errorf("grant: 条子次数 %d 非法(至少 1 次)", w.MaxUses)
	}
	if err := validateForUser(w.ForUser); err != nil {
		return nil, fmt.Errorf("grant: 条子 for_user 非法: %w", err)
	}
	return &Grant{
		ID:        w.ID,
		Scope:     w.Scope,
		IssuedBy:  w.IssuedBy,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		MaxUses:   w.MaxUses,
		Note:      w.Note,
		ForUser:   w.ForUser,
	}, nil
}

// validateForUser 校验 for_user:它会进「谁拿到这张条子」的判定,形态必须收窄。
// 只允许常见的用户名形态(字母数字与少量符号),拒绝路径分隔符、控制字符与空串。
func validateForUser(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > 64 {
		return fmt.Errorf("用户名过长(最多 64 字节): %q", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == '@':
		default:
			return fmt.Errorf("用户名含非法字符 %q", r)
		}
	}
	return nil
}

// MarshalJSON 输出条子文件内容:时间恒 UTC RFC3339,与 Parse 互为逆运算。
func (g Grant) MarshalJSON() ([]byte, error) {
	w := wireGrant{
		ID:        g.ID,
		Scope:     g.Scope,
		IssuedBy:  g.IssuedBy,
		IssuedAt:  formatTime(g.IssuedAt),
		ExpiresAt: formatTime(g.ExpiresAt),
		MaxUses:   g.MaxUses,
		Note:      g.Note,
		ForUser:   g.ForUser,
	}
	data, err := json.Marshal(w)
	if err != nil {
		return nil, fmt.Errorf("grant: 序列化条子失败: %w", err)
	}
	return data, nil
}

// Covers 判断条子是否覆盖给定作用域:任一条范围逐段匹配即算覆盖。
// 范围条目解析不了时整张条子作废(fail-closed),坏条目不得被静默跳过。
func (g *Grant) Covers(s autonomy.Scope) bool {
	scopes, err := g.parsedScopes()
	if err != nil {
		return false
	}
	for _, sc := range scopes {
		if sc.Matches(s) {
			return true
		}
	}
	return false
}

// Expired 判断条子是否已过期:到期瞬间即算过期。
func (g *Grant) Expired(now time.Time) bool {
	if g == nil {
		return true
	}
	return !g.ExpiresAt.After(now)
}

// Authorize 判定条子能否被消费:签发者是否合法、范围/有效期/次数是否在其上限内。
//
// 权威身份是调用方给的属主 uid 与属主名(文件的属主),条子自称的 issued_by 一律不看。
// 闸门顺序:条子自身合法性 → 全局硬上限 → 过期 → 危险名单 → root 放行 → 签发者闸门。
// 全局硬上限、过期、危险名单刻意排在 root 放行之前:它们约束的是条子与目标本身,
// 不是"谁签的",root 也不能用身份绕开(危险对象本就不该有自主条子)。
func Authorize(cfg *autonomy.Config, g *Grant, ownerUID uint32, ownerName string, now time.Time) error {
	if g == nil {
		return fmt.Errorf("grant: 条子为空")
	}
	scopes, err := g.parsedScopes()
	if err != nil {
		return fmt.Errorf("grant: %w", err)
	}
	if g.MaxUses <= 0 {
		return fmt.Errorf("grant: 条子次数 %d 非法(至少 1 次)", g.MaxUses)
	}
	if g.MaxUses > GlobalMaxUses {
		return fmt.Errorf("grant: 条子次数 %d 超过全局上限 %d", g.MaxUses, GlobalMaxUses)
	}
	if !g.ExpiresAt.After(now) {
		return fmt.Errorf("grant: 条子已过期(expires_at=%s, now=%s)", formatTime(g.ExpiresAt), formatTime(now))
	}
	ttl := g.ExpiresAt.Sub(now)
	if ttl > GlobalMaxTTL {
		return fmt.Errorf("grant: 条子有效期 %s 超过全局上限 %s", ttl, GlobalMaxTTL)
	}
	// 危险对象不该有自主条子:root 也不例外,所以这道闸门在 root 放行之前。
	if err := checkDangerous(cfg, scopes); err != nil {
		return err
	}
	if ownerUID == 0 {
		return nil
	}
	if deniedSigner(cfg, ownerName) {
		return fmt.Errorf("grant: 无权签发:用户 %q 在禁用签发者名单内", ownerName)
	}
	signer, err := findSigner(cfg, ownerName)
	if err != nil {
		return err
	}
	// 上限为 0 只可能来自程序内构造的配置(加载期已要求必填):按 fail-closed 拒,
	// 绝不把"少写字段"解释成"不限制"。
	if signer.MaxTTL <= 0 {
		return fmt.Errorf("grant: 签发者 %q 的 max_ttl 未配置,拒绝授权", ownerName)
	}
	if signer.MaxUses <= 0 {
		return fmt.Errorf("grant: 签发者 %q 的 max_uses 未配置,拒绝授权", ownerName)
	}
	for _, sc := range scopes {
		if !coveredBy(signer.MaxScope, sc) {
			return fmt.Errorf("grant: 条子范围 %q 超出授权范围:签发者 %q 的 max_scope 未覆盖", sc.String(), ownerName)
		}
	}
	if ttl > signer.MaxTTL {
		return fmt.Errorf("grant: 条子有效期 %s 超过签发者 %q 的上限 %s", ttl, ownerName, signer.MaxTTL)
	}
	if g.MaxUses > signer.MaxUses {
		return fmt.Errorf("grant: 条子次数 %d 超过签发者 %q 的上限 %d", g.MaxUses, ownerName, signer.MaxUses)
	}
	return nil
}

// BindExecutor 判断「这张条子能不能给这个执行者用」。
//
// 签发者是文件属主,执行者是真正跑消费侧的那个身份(agent 进程的用户)。
// 两者必须分开:一张没绑执行者的条子就是**节点级通行证** —— 任何本地用户的
// agent 都能拿去用,而动作发生在**使用者**自己的 user 域里,于是「人类点头的
// 那件事」和人真正做的事对不上号。
//
// 判定只信两样东西:文件属主(来自 stat,不可伪造)与 root 拥有文件里的 for_user
// (root 的文件别人改不动,所以这句话可信)。JSON 里其它自报字段一律不认。
//
//	属主 == 执行者            → 自己的条子自己用
//	属主 == root 且 for_user 匹配 → root 签给你
//	属主 == root 且没有 for_user → 拒(root 必须写明给谁)
//	其余                       → 拒(条子属于别人)
func BindExecutor(g *Grant, ownerUID uint32, ownerName string, executorUID uint32, executorName string) error {
	if g == nil {
		return fmt.Errorf("grant: 条子为空")
	}
	if ownerUID == executorUID {
		return nil
	}
	if ownerUID != 0 {
		return fmt.Errorf("grant: 条子属于 %q,不能给 %q 用", ownerName, executorName)
	}
	if g.ForUser == "" {
		return fmt.Errorf("grant: root 签的条子必须写明给谁(for_user),否则任何人都能拿去用")
	}
	if g.ForUser != executorName {
		return fmt.Errorf("grant: 这张条子是给 %q 的,不是给 %q 的", g.ForUser, executorName)
	}
	return nil
}

// parsedScopes 解析条子里的全部范围;任一条坏 ⇒ 整张条子作废。
func (g *Grant) parsedScopes() ([]autonomy.Scope, error) {
	if g == nil {
		return nil, fmt.Errorf("条子为空")
	}
	if len(g.Scope) == 0 {
		return nil, fmt.Errorf("条子范围为空")
	}
	out := make([]autonomy.Scope, 0, len(g.Scope))
	for _, raw := range g.Scope {
		sc, err := autonomy.ParseScope(raw)
		if err != nil {
			return nil, fmt.Errorf("条子范围 %q 非法: %w", raw, err)
		}
		out = append(out, sc)
	}
	return out, nil
}

// checkDangerous 判定条子范围是否命中危险名单。
// 命中判定复用 autonomy 的公开判定入口:Classify 的第一道闸门就是危险名单,
// 高危属性在此不参与,所以 Reason==deny 等价于命中名单。
// 不在本包另写一份名单匹配,避免两套语义漂移。
func checkDangerous(cfg *autonomy.Config, scopes []autonomy.Scope) error {
	for _, sc := range scopes {
		// 属性域必须显式赋值(契约:只有字面 "user" 才是用户域),这里取 user;
		// 危险名单只看作用域,其余属性字段在此无关。
		d := cfg.Classify(sc, autonomy.Attributes{Domain: "user", Known: true})
		if d.Reason == autonomy.ReasonDeny {
			return fmt.Errorf("grant: 条子范围 %q 命中危险名单,拒绝授权", sc.String())
		}
	}
	return nil
}

// coveredBy 判断条子范围是否落在签发者的 max_scope 内。
// max_scope 条目按严格作用域解析;解析不了的条目当"没覆盖"(fail-closed)。
func coveredBy(maxScope []string, sc autonomy.Scope) bool {
	for _, raw := range maxScope {
		pat, err := autonomy.ParseScope(raw)
		if err != nil {
			continue
		}
		if pat.Matches(sc) {
			return true
		}
	}
	return false
}

// deniedSigner 判断用户是否在禁用签发者名单内。
func deniedSigner(cfg *autonomy.Config, name string) bool {
	if cfg == nil {
		return false
	}
	for _, denied := range cfg.DenySigners {
		if denied == name {
			return true
		}
	}
	return false
}

// findSigner 找签发者:没有 = 无权签发;同名多条 = 配置非法。
// 多条时绝不挑一条:挑首条会让后加的收紧条目静默失效(配置更严、行为更松)。
func findSigner(cfg *autonomy.Config, name string) (autonomy.Signer, error) {
	if cfg == nil {
		return autonomy.Signer{}, fmt.Errorf("grant: 无权签发:用户 %q 不在签发者名单内", name)
	}
	var found autonomy.Signer
	matches := 0
	for _, signer := range cfg.Signers {
		if signer.User == name {
			matches++
			found = signer
		}
	}
	switch {
	case matches == 0:
		return autonomy.Signer{}, fmt.Errorf("grant: 无权签发:用户 %q 不在签发者名单内", name)
	case matches > 1:
		return autonomy.Signer{}, fmt.Errorf("grant: 配置非法:签发者名单里用户 %q 重复出现 %d 次,拒绝授权", name, matches)
	}
	return found, nil
}

// validateID 校验条子 id:它会被用作文件名,所以不许带路径分隔符、控制字符
// 或相对路径记号,否则一次越界就能把文件写到目录之外。
func validateID(id string) error {
	if id == "" {
		return fmt.Errorf("为空")
	}
	if len(id) > 128 {
		return fmt.Errorf("过长(最多 128 字节)")
	}
	if id == "." || id == ".." {
		return fmt.Errorf("不得是相对路径记号")
	}
	if strings.ContainsAny(id, "/\\\x00") {
		return fmt.Errorf("不得含路径分隔符")
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("不得含控制字符")
		}
	}
	return nil
}

// parseTime 解析 RFC3339 时间并归一到 UTC。
func parseTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("为空")
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q 非法: %w", value, err)
	}
	return t.UTC(), nil
}

// formatTime 把时间输出成 UTC RFC3339。
func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
