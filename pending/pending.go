// Package pending 是第三档人工闸门的跨仓线上契约:待办(AI 写、人读)与
// 批准记录(root 写、AI 读)的形状,以及两者共用的严格解析、序列化规范与校验。
//
// 为什么要有这个包:core 与 plugins 各持一份副本时,加一个字段要改两处,
// 漂移了没人拦;argv 指纹与 id 派生规则也各存一份。唯一事实源放在这里,
// 两个仓都 import 它。
//
// 解析一律 fail-closed。待办落在任何本地用户可写的目录里,批准记录决定机器
// 是否执行动作,宽松解析等于把伪造空间留给写文件的人 —— 未知键、缺失的必填项、
// JSON 之后的残余内容都算坏文件。
package pending

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Daedalusys/daedalus-sdk/autonomy"
)

// Pending 是一份待办的线上形状(AI 写,人读)。
// 时间字段用 time.Time,线上是 RFC3339 字符串:公开面带类型,序列化走内部
// wire 结构体并归一到 UTC,与 grant 包同款。
//
// 待办里没有「请求者」字段:JSON 是自报,谁都能写;请求者的权威是待办文件的
// stat 属主,由写批准记录的 root 侧从文件系统取,不从这份文档里读。
type Pending struct {
	ID           string
	Kind         string
	Name         string
	DesiredState string
	Argv         []string
	Scope        string
	Reason       string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// Approval 是一份批准记录的线上形状(root 写,AI 读)。
type Approval struct {
	ID         string
	ArgvSHA256 string
	// RequestedByUID 是「这份批准批的是谁的请求」。指针是故意的:uid 0 是 root
	// 自己,用 0 兼任「未指定」会让「批给 root」与「没写是谁」长得一样,而这两种
	// 的判定完全相反。解析时 nil(字段缺失)一律拒 —— 缺失不是 root。
	RequestedByUID *uint32
	// RequestedBy 只作展示(账号会改名、会被复用,uid 不会)。
	RequestedBy string
	ApprovedBy  string
	ApprovedAt  time.Time
}

// wirePending 是待办文件的 JSON 形态:时间用 RFC3339 字符串,便于人工审阅。
// Parse 与 MarshalJSON 共用它,读写两端不另立事实源。
type wirePending struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Name         string   `json:"name"`
	DesiredState string   `json:"desired_state"`
	Argv         []string `json:"argv"`
	Scope        string   `json:"scope"`
	Reason       string   `json:"reason"`
	CreatedAt    string   `json:"created_at"`
	ExpiresAt    string   `json:"expires_at"`
}

// wireApproval 是批准记录的 JSON 形态。requested_by_uid 不加 omitempty:
// 这个键必须恒在,写出 null 与根本没写一样都会被读侧拒,不给「省略即 root」留口子。
type wireApproval struct {
	ID             string  `json:"id"`
	ArgvSHA256     string  `json:"argv_sha256"`
	RequestedByUID *uint32 `json:"requested_by_uid"`
	RequestedBy    string  `json:"requested_by,omitempty"`
	ApprovedBy     string  `json:"approved_by"`
	ApprovedAt     string  `json:"approved_at"`
}

// ParsePending 严格解析一份待办文件。
//
// 缺字段 / 未知键 / 尾串 / argv 不可执行 / 时间非法或倒置 / scope 形态非法 /
// id 不过形状门,一律拒绝。待办目录对本地用户可写,宽松解析就是给伪造留门。
func ParsePending(data []byte) (*Pending, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var w wirePending
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("pending: 解析待办失败: %w", err)
	}
	// 残余内容不能用 dec.More() 判:它对紧跟的 ] / } 会返回 false,尾串就被放过了。
	// 再解码一次拿到 io.EOF 才算 JSON 真的结束。
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("pending: 待办 JSON 之后有多余内容")
	}
	if err := ValidateID(w.ID); err != nil {
		return nil, fmt.Errorf("pending: %w", err)
	}
	if missing := missingPendingFields(w); len(missing) != 0 {
		return nil, fmt.Errorf("pending: 待办缺少必填字段 %v", missing)
	}
	// scope 是消费侧判定档位的产物:形态非法说明待办已被篡改或写坏。
	if _, err := autonomy.ParseScope(w.Scope); err != nil {
		return nil, fmt.Errorf("pending: 待办 scope %q 非法: %w", w.Scope, err)
	}
	if len(w.Argv) == 0 {
		return nil, fmt.Errorf("pending: 待办 argv 为空(没有可执行的命令)")
	}
	if w.Argv[0] == "" {
		return nil, fmt.Errorf("pending: 待办 argv[0] 为空(没有可执行的程序)")
	}
	for i, arg := range w.Argv {
		if strings.IndexByte(arg, 0) >= 0 {
			return nil, fmt.Errorf("pending: 待办 argv[%d] 含 NUL 字节(指纹会产生歧义)", i)
		}
	}
	createdAt, err := parseTime(w.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("pending: 待办创建时间非法: %w", err)
	}
	expiresAt, err := parseTime(w.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("pending: 待办到期时间非法: %w", err)
	}
	// 到期不晚于创建等于「出生即死」:这种待办不该进入人工审查队列。
	if !expiresAt.After(createdAt) {
		return nil, fmt.Errorf("pending: 待办到期时间 %s 不晚于创建时间 %s", expiresAt, createdAt)
	}
	return &Pending{
		ID:           w.ID,
		Kind:         w.Kind,
		Name:         w.Name,
		DesiredState: w.DesiredState,
		Argv:         w.Argv,
		Scope:        w.Scope,
		Reason:       w.Reason,
		CreatedAt:    createdAt,
		ExpiresAt:    expiresAt,
	}, nil
}

// ParseApproval 严格解析一份批准记录。
//
// requested_by_uid 必须存在:读侧靠它与执行者比对,缺失时如果当成 root,
// 就等于让所有「没写请求者」的记录对 root 的 agent 生效。
func ParseApproval(data []byte) (*Approval, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var w wireApproval
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("pending: 解析批准失败: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("pending: 批准 JSON 之后有多余内容")
	}
	if err := ValidateID(w.ID); err != nil {
		return nil, fmt.Errorf("pending: %w", err)
	}
	if missing := missingApprovalFields(w); len(missing) != 0 {
		return nil, fmt.Errorf("pending: 批准缺少必填字段 %v", missing)
	}
	if err := validateArgvSHA256(w.ArgvSHA256); err != nil {
		return nil, fmt.Errorf("pending: 批准 argv_sha256 非法: %w", err)
	}
	if w.RequestedByUID == nil {
		return nil, fmt.Errorf("pending: 批准缺少 requested_by_uid(缺失不等于 root;root 自己是请求者时写 0)")
	}
	approvedAt, err := parseTime(w.ApprovedAt)
	if err != nil {
		return nil, fmt.Errorf("pending: 批准时间非法: %w", err)
	}
	return &Approval{
		ID:             w.ID,
		ArgvSHA256:     w.ArgvSHA256,
		RequestedByUID: w.RequestedByUID,
		RequestedBy:    w.RequestedBy,
		ApprovedBy:     w.ApprovedBy,
		ApprovedAt:     approvedAt,
	}, nil
}

// MarshalJSON 输出待办文件内容:时间恒 UTC RFC3339,与 ParsePending 互为逆运算。
func (p Pending) MarshalJSON() ([]byte, error) {
	w := wirePending{
		ID:           p.ID,
		Kind:         p.Kind,
		Name:         p.Name,
		DesiredState: p.DesiredState,
		Argv:         p.Argv,
		Scope:        p.Scope,
		Reason:       p.Reason,
		CreatedAt:    formatTime(p.CreatedAt),
		ExpiresAt:    formatTime(p.ExpiresAt),
	}
	data, err := json.Marshal(w)
	if err != nil {
		return nil, fmt.Errorf("pending: 序列化待办失败: %w", err)
	}
	return data, nil
}

// MarshalJSON 输出批准记录内容:时间恒 UTC RFC3339,requested_by 为空时省略。
func (a Approval) MarshalJSON() ([]byte, error) {
	w := wireApproval{
		ID:             a.ID,
		ArgvSHA256:     a.ArgvSHA256,
		RequestedByUID: a.RequestedByUID,
		RequestedBy:    a.RequestedBy,
		ApprovedBy:     a.ApprovedBy,
		ApprovedAt:     formatTime(a.ApprovedAt),
	}
	data, err := json.Marshal(w)
	if err != nil {
		return nil, fmt.Errorf("pending: 序列化批准失败: %w", err)
	}
	return data, nil
}

// missingPendingFields 汇总缺的必填项:一次列全比逐个报错更适合人工排查。
func missingPendingFields(w wirePending) []string {
	fields := []struct {
		name  string
		value string
	}{
		{"id", w.ID}, {"kind", w.Kind}, {"name", w.Name},
		{"desired_state", w.DesiredState}, {"scope", w.Scope},
		{"created_at", w.CreatedAt}, {"expires_at", w.ExpiresAt},
	}
	var missing []string
	for _, f := range fields {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	return missing
}

// missingApprovalFields 汇总批准缺的必填项;requested_by_uid 单独判(见 ParseApproval)。
func missingApprovalFields(w wireApproval) []string {
	fields := []struct {
		name  string
		value string
	}{
		{"id", w.ID}, {"argv_sha256", w.ArgvSHA256},
		{"approved_by", w.ApprovedBy}, {"approved_at", w.ApprovedAt},
	}
	var missing []string
	for _, f := range fields {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	return missing
}

// validateArgvSHA256 要求 64 位小写十六进制:大小写混写说明写侧换了实现,
// 而消费侧按逐字比对,放过它只会让「指纹不符」在运行时才出现。
func validateArgvSHA256(value string) error {
	if len(value) != 64 {
		return fmt.Errorf("需 64 位十六进制, 实得 %d 位", len(value))
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return fmt.Errorf("含非小写十六进制字符 %q", r)
		}
	}
	return nil
}

// parseTime 解析 RFC3339 时间并归一到 UTC:内部比较一律在 UTC 上做,
// 避免同一份文件因时区写法不同得到不同结论。
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
