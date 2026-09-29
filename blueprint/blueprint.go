// Package blueprint 是 daedalus.blueprint 能力插件的基础类型层。
//
// 本包只承载插件各工具之间共享的类型定义与蓝图自身的校验逻辑,
// 不含注册表、secret 引用解析、confirm_token 契约与 MCP 服务器——
// 它们分别由同目录下的独立文件承载。
package blueprint

import (
	"errors"
	"strings"
)

// Blueprint 是单个蓝图的运行时描述:一段可复用、参数化的配置生成脚本
// (渲染模板 + 校验 + reload),由 manifest.json 经 New 构造并校验后产生。
type Blueprint struct {
	// ID 是蓝图 id,等于目录名(如 "nginx-vhost")。
	ID          string
	DisplayName string
	Version     string
	Description string
	Category    string
	// OutputPathTmpl 如 "/etc/nginx/conf.d/{domain}.conf",必须含至少一个
	// {param} 占位符;渲染时用蓝图参数替换。
	OutputPathTmpl string
	ReloadService  string
	// RequiredTools 由插件在应用前核对系统内是否齐备。
	RequiredTools []string
}

// BlueprintManifest 是 manifest.json 的反序列化形态。
//
// 字段与蓝图目录下 manifest.json 的 JSON 键一一对应。
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
// 惰性校验设计:仅持有原始 JSON 字节,不在此处解析。render 路径才用
// jsonschema-go 编译校验参数,避免每个蓝图加载即编译。
type ParamSchema struct {
	Raw []byte
}

type RenderResult struct {
	PlanID          string
	RenderedContent string
	Diff            string
	Warnings        []string
	TargetPath      string
}

type ApplyResult struct {
	TxID        string
	AppliedAt   string
	ConfigPath  string
	PostCheckOK bool
	ReloadOK    bool
}

// ConfirmToken 是 confirm_token 契约的类型。
//
// 单次有效的确认令牌:apply 前必须由用户提供,与 plan_id 配对校验。
type ConfirmToken struct {
	// Token 单次有效,校验通过后即失效。
	Token string
	// PlanID/Expires 是对外展示形态;校验依据是 SDK 签发登记表
	// (confirm_token.go),自报字段既不能伪造配对也不能放宽有效期。
	PlanID string
	// Expires 是 Unix 毫秒过期时间。
	Expires int64
}

// New 从 manifest 构造 Blueprint 并执行校验。RequiredTools 是独立拷贝,防止
// 调用方后续修改 manifest 影响已构造的实例。
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

// Validate 校验必填字段(ID / Version / RequiredTools 非空)与输出路径模板的
// 占位符约束(至少一个非空 {param}),任一不满足即拒绝(fail-closed)。
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
		if j := strings.IndexByte(tmpl[i+1:], '}'); j > 0 {
			return true
		}
	}
	return false
}
