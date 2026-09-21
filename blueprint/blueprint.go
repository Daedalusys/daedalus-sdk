// Package blueprint 是 daedalus.blueprint 能力插件的基础类型层。
//
// 本包只承载插件各工具之间共享的类型定义与蓝图自身的校验逻辑,
// 不含注册表(todo 3)、secret 引用解析(todo 4)、confirm_token 契约(todo 5)
// 与 MCP 服务器(todo 16)——它们分别由同目录下的独立文件承载。
package blueprint

import (
	"errors"
	"strings"
)

// Blueprint 是单个蓝图的运行时描述。
//
// 蓝图 = 一段可复用、参数化的配置生成脚本:渲染模板 + 校验 + reload。
// 实例由 manifest.json 经 New 构造并校验后产生。
type Blueprint struct {
	// ID 是蓝图 id(=目录名,如 "nginx-vhost")。
	ID string
	// DisplayName 是展示名(来自 manifest)。
	DisplayName string
	// Version 是 semver 版本(来自 manifest)。
	Version string
	// Description 是用途说明(copilot 提示用)。
	Description string
	// Category 是蓝图分类(web / database 等)。
	Category string
	// OutputPathTmpl 是输出路径模板,如 "/etc/nginx/conf.d/{domain}.conf"。
	// 必须含至少一个 {param} 占位符;渲染时用蓝图参数替换。
	OutputPathTmpl string
	// ReloadService 是 reload 服务名,如 "nginx"。
	ReloadService string
	// RequiredTools 是必需工具,如 ["nginx", "systemctl"]。
	// 应用前由插件核对系统内是否齐备。
	RequiredTools []string
}

// BlueprintManifest 是 manifest.json 的反序列化形态。
//
// 字段与蓝图目录下 manifest.json 的 JSON 键一一对应(源码侧定义见
// daedalus/plugin/blueprint/blueprints/<name>/manifest.json)。
type BlueprintManifest struct {
	ID             string   `json:"id"`
	DisplayName    string   `json:"display_name"`
	Version        string   `json:"version"`
	Description    string   `json:"description"`
	Category       string   `json:"category"`
	OutputPathTmpl string   `json:"output_path_template"`
	ReloadService  string   `json:"reload_service"`
	RequiredTools  []string `json:"required_tools"`
}

// ParamSchema 是 schema.json 的反序列化形态。
//
// 惰性校验设计:仅持有原始 JSON 字节,不在此处解析。Resolve 时(todo 后续
// 的 render 路径)才用 jsonschema-go 编译校验参数,避免每个蓝图加载即编译。
type ParamSchema struct {
	// Raw 是原始 schema.json 内容。
	Raw []byte
}

// RenderResult 是 blueprint_render 工具的输出。
type RenderResult struct {
	// PlanID 是 plan_id,供后续 apply 引用。
	PlanID string
	// RenderedContent 是渲染后的配置内容。
	RenderedContent string
	// Diff 是相对现状的差异(若无现状则为空)。
	Diff string
	// Warnings 是渲染告警(如明文 secret 检测)。
	Warnings []string
	// TargetPath 是输出目标路径。
	TargetPath string
}

// ApplyResult 是 blueprint_apply 工具的输出。
type ApplyResult struct {
	// TxID 是关联的 daedalus-tx 事务 id。
	TxID string
	// AppliedAt 是 ISO 时间戳。
	AppliedAt string
	// ConfigPath 是写入的配置文件路径。
	ConfigPath string
	// PostCheckOK 是 post_check 是否通过。
	PostCheckOK bool
	// ReloadOK 是 reload 是否成功。
	ReloadOK bool
}

// ConfirmToken 是 confirm_token 契约的类型。
//
// 单次有效的确认令牌:apply 前必须由用户提供,与 plan_id 配对校验。
type ConfirmToken struct {
	// Token 是单次有效的确认令牌。
	Token string
	// PlanID 是关联的 plan_id。
	PlanID string
	// Expires 是 Unix 毫秒过期时间。
	Expires int64
}

// New 从 manifest 构造 Blueprint 并执行校验。
//
// 返回的 Blueprint.RequiredTools 是独立拷贝,不共享 manifest 的底层数组,
// 防止调用方后续修改 manifest 影响已构造的实例。
func New(m *BlueprintManifest) (*Blueprint, error) {
	b := &Blueprint{
		ID:             m.ID,
		DisplayName:    m.DisplayName,
		Version:        m.Version,
		Description:    m.Description,
		Category:       m.Category,
		OutputPathTmpl: m.OutputPathTmpl,
		ReloadService:  m.ReloadService,
		RequiredTools:  append([]string(nil), m.RequiredTools...),
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// Validate 校验蓝图的必填字段与输出路径模板的占位符约束。
//
// 校验项:ID / Version 非空、RequiredTools 非空、OutputPathTmpl 必须含
// 至少一个非空 {param} 占位符。任一不满足即返回描述性错误(fail-closed)。
func (b *Blueprint) Validate() error {
	if b == nil {
		return errors.New("blueprint: 蓝图为空(nil)")
	}
	if b.ID == "" {
		return errors.New("blueprint: 蓝图 ID 不能为空")
	}
	if b.Version == "" {
		return errors.New("blueprint: 蓝图版本不能为空")
	}
	if len(b.RequiredTools) == 0 {
		return errors.New("blueprint: 蓝图必需工具列表不能为空")
	}
	if !hasParamPlaceholder(b.OutputPathTmpl) {
		return errors.New("blueprint: 输出路径模板必须含至少一个 {param} 占位符")
	}
	return nil
}

// hasParamPlaceholder 报告路径模板是否含至少一个非空 {param} 占位符。
//
// 形如 "{domain}" 或 "{domain}.conf" 均命中;空占位符 "{}" 视为无效
// (无参数名可替换),"{" 后无 "}" 或模板为空则视为不含。
func hasParamPlaceholder(tmpl string) bool {
	for i := 0; i < len(tmpl); i++ {
		if tmpl[i] != '{' {
			continue
		}
		// 从 "{" 之后找最近的 "}",其间至少一个字符才算有效占位符。
		if j := strings.IndexByte(tmpl[i+1:], '}'); j > 0 {
			return true
		}
	}
	return false
}
