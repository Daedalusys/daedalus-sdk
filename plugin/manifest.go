// Package plugin 定义 daedalus-plugin 插件格式:manifest schema、zip 打包器与校验器。
//
// 本包实现计划 todo 6 的插件容器格式(类比 VSIX 的 extension.vsixmanifest):
//   - manifest.go  : daedalus.plugin.json 的结构体与逐条字段校验;
//   - pack.go      : 目录 → zip 包,自动注入逐条目 sha256 checksums;
//   - verify.go    : 带 zip-slip 防护的解压 + manifest/checksum/可执行位校验。
//
// 设计边界(决策 21/22、Metis M2/M5):
//   - permissions 是"请求能力"的声明式字段,校验器只检查其 JSON 形态,
//     不与 policy.toml 的强制执行值比对;
//   - resources(Object Model 资源声明)的 schema 单一事实源在
//     daedalus/core/internal/objectmodel/objectmodel.go(计划
//     .omo/plans/aios-object-model-alignment.md 的 Object Model 段与决策 25),
//     本包只逐条目委托校验,不复制形态规则;
//   - 完整性仅 sha256,不做签名;不做运行时联网安装。
package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/Daedalusys/daedalus-sdk/objectmodel"
)

// ManifestFileName 是插件清单在包根目录的固定文件名。
const ManifestFileName = "daedalus.plugin.json"

// type/runtime 的合法枚举值(计划草案决策 10/21)。
const (
	TypeCopilot    = "copilot"    // Copilot CLI 插件
	TypeCapability = "capability" // OS 能力服务器插件
	TypeController = "controller" // 声明性预留 v1.5：校验放行即全部语义，runtime 无分支（惰性=宿主 type-agnostic，见 internal/controller/doc.go）
)

// Runtime 枚举值:以 Runtime 值声明,宿主 switch 可直接与 m.Runtime 比较。
var (
	RuntimeNative     = Runtime{Name: "native"}     // Go 静态二进制,直接 exec
	RuntimeDeno       = Runtime{Name: "deno"}       // Deno 脚本,entrypoint 给出 deno run 参数
	RuntimeController = Runtime{Name: "controller"} // 声明性预留:与 TypeController 配套
)

// idPattern 是插件 id 的文法:小写字母/数字段,以单个 '.' 分层。
var idPattern = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9]+)*$`)

// ValidID 报告 s 是否为合法插件 id(文法与 Manifest.Validate 的 id 规则同源)。
// 宿主 daedalus-host 用它把关 CLI 传入的 <id>,拒绝 '../' 等路径注入,
// 避免文法在两个包里各写一份而漂移。
func ValidID(s string) bool { return idPattern.MatchString(s) }

// semverPattern 是语义化版本 2.0.0 的完整文法(major.minor.patch[-prerelease][+build])。
var semverPattern = regexp.MustCompile(
	`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
		`(-((0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)` +
		`(\.(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?` +
		`(\+([0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*))?$`)

// apiVersionPattern 是 api_version 的宽松语义化版本校验(major.minor.patch 前缀,
// 允许可选 v 前缀;不引第三方 semver 库)。
var apiVersionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+`)

// spdxPattern 是 SPDX 标识的宽松格式校验(字母数字与 .- 组合)。
var spdxPattern = regexp.MustCompile(`^[A-Za-z0-9.\-]+$`)

// emailPattern 是 maintainer 邮箱的宽松格式校验(含 @ 与 .)。
var emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// Permissions 是声明式权限请求(read/write/run 路径与可执行白名单)。
// 非强制:宿主据此生成 systemd sandbox/Deno 权限标志,本包只校验其形态。
type Permissions struct {
	Read  []string `json:"read"`
	Write []string `json:"write"`
	Run   []string `json:"run"`
}

// Runtime 声明插件的运行时:Name 枚举 {deno, native, controller},
// Version 可选(运行时版本号,如 Deno 2.1.4)。
type Runtime struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// String 返回可读形式:仅 Name,或 "Name Version"(Version 非空时)。
// 宿主/打包器的 %s 打印自动经此方法,无需逐处改调用点。
func (r Runtime) String() string {
	if r.Version == "" {
		return r.Name
	}
	return r.Name + " " + r.Version
}

// Manifest 对应 daedalus.plugin.json 的完整 schema。
// Checksums 由打包器自动注入(条目路径 → "sha256:<hex>"),手写清单可省略。
type Manifest struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Version     string                  `json:"version"`
	Type        string                  `json:"type"`
	Runtime     Runtime                 `json:"runtime"`
	Executable  string                  `json:"executable"`
	Entrypoint  []string                `json:"entrypoint,omitempty"`
	Permissions *Permissions            `json:"permissions,omitempty"`
	Tools       []string                `json:"tools,omitempty"`
	Resources   []*objectmodel.Resource `json:"resources,omitempty"` // 条目 schema 单一事实源见 daedalus/core/internal/objectmodel/objectmodel.go
	I18N        []string                `json:"i18n,omitempty"`
	Checksums   map[string]string       `json:"checksums,omitempty"`
	APIVersion  string                  `json:"api_version"` // 插件格式 schema 版本(semver,必填)
	License     string                  `json:"license"`     // SPDX 标识(必填)
	Maintainer  string                  `json:"maintainer"`  // 维护者邮箱(必填)
}

// UnmarshalJSON 兼容 runtime 字段的两种形态:
//   - 老形态(字符串):"runtime": "deno" → Runtime{Name: "deno"};
//   - 新形态(对象):"runtime": {"name": "deno", "version": "2.1.4"}。
//
// 其余字段与 ParseManifest 的 DisallowUnknownFields 语义一致(未知键拒绝),
// 因为类型实现 json.Unmarshaler 后外层 Decoder 不再做字段匹配,必须在此自守。
func (m *Manifest) UnmarshalJSON(data []byte) error {
	type manifestAlias struct {
		ID          string                  `json:"id"`
		Name        string                  `json:"name"`
		Version     string                  `json:"version"`
		Type        string                  `json:"type"`
		Runtime     json.RawMessage         `json:"runtime"`
		Executable  string                  `json:"executable"`
		Entrypoint  []string                `json:"entrypoint,omitempty"`
		Permissions *Permissions            `json:"permissions,omitempty"`
		Tools       []string                `json:"tools,omitempty"`
		Resources   []*objectmodel.Resource `json:"resources,omitempty"`
		I18N        []string                `json:"i18n,omitempty"`
		Checksums   map[string]string       `json:"checksums,omitempty"`
		APIVersion  string                  `json:"api_version"`
		License     string                  `json:"license"`
		Maintainer  string                  `json:"maintainer"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var a manifestAlias
	if err := dec.Decode(&a); err != nil {
		return err
	}
	*m = Manifest{
		ID: a.ID, Name: a.Name, Version: a.Version, Type: a.Type,
		Executable: a.Executable, Entrypoint: a.Entrypoint, Permissions: a.Permissions,
		Tools: a.Tools, Resources: a.Resources, I18N: a.I18N, Checksums: a.Checksums,
		APIVersion: a.APIVersion, License: a.License, Maintainer: a.Maintainer,
	}
	if len(a.Runtime) == 0 {
		return nil
	}
	// 老形态:字符串 "deno" → Runtime{Name: "deno"}
	if a.Runtime[0] == '"' {
		var name string
		if err := json.Unmarshal(a.Runtime, &name); err != nil {
			return err
		}
		m.Runtime = Runtime{Name: name}
		return nil
	}
	// 新形态:对象 {"name": ..., "version": ...}
	var rt Runtime
	if err := json.Unmarshal(a.Runtime, &rt); err != nil {
		return err
	}
	m.Runtime = rt
	return nil
}

// ParseManifest 从 JSON 字节解析 manifest。除标准语法检查外,
// 拒绝未知字段(拼写错误的键必须报错,不能静默丢弃)、
// 拒绝 JSON 尾部垃圾,并要求顶层为对象。
func ParseManifest(data []byte) (*Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest 解析失败: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, fmt.Errorf("manifest 解析失败: JSON 文档后存在尾随内容")
	}
	return &m, nil
}

// LoadManifestFile 读取并解析磁盘上的 manifest 文件(打包器入口用)。
func LoadManifestFile(path string) (*Manifest, error) {
	data, err := readFileLimited(path, MaxManifestSize)
	if err != nil {
		return nil, err
	}
	m, err := ParseManifest(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ManifestFileName, err)
	}
	return m, nil
}

// Validate 逐条执行计划规定的校验规则;所有错误消息含字段名与原因。
//
// 规则清单:
//  1. id 必填且匹配 ^[a-z0-9]+(\.[a-z0-9]+)*$;
//  2. name 必填;
//  3. version 必填且为合法语义化版本;
//  4. type ∈ {copilot, capability, controller};
//  5. runtime.name ∈ {native, deno, controller};
//  6. api_version 必填且为语义化版本(major.minor.patch);
//  7. license 必填且为 SPDX 标识格式;
//  8. maintainer 必填且为邮箱格式;
//  9. executable 必填、相对路径、不得含 '..'/空字节/绝对路径/以 '/' 开头;
//  10. entrypoint 元素非空且不含空字节;
//  11. tools 元素为非空字符串;
//  12. resources(若存在)逐条目经 objectmodel.ValidateResource 校验
//      (schema 见 daedalus/core/internal/objectmodel/objectmodel.go);
//  13. checksums(若存在)键为安全相对路径、值为 "sha256:<64hex>"。
func (m *Manifest) Validate() error {
	if m.ID == "" {
		return fmt.Errorf("字段 id 缺失:必填,如 \"daedalus.copilot\"")
	}
	if !idPattern.MatchString(m.ID) {
		return fmt.Errorf("字段 id 非法:%q 不匹配 ^[a-z0-9]+(\\.[a-z0-9]+)*$(仅允许小写字母数字段以点分层)", m.ID)
	}
	if m.Name == "" {
		return fmt.Errorf("字段 name 缺失:必填,插件显示名")
	}
	if m.Version == "" {
		return fmt.Errorf("字段 version 缺失:必填,语义化版本 x.y.z")
	}
	if !semverPattern.MatchString(m.Version) {
		return fmt.Errorf("字段 version 非法:%q 不是合法语义化版本(要求 major.minor.patch)", m.Version)
	}
	if m.Type != TypeCopilot && m.Type != TypeCapability && m.Type != TypeController {
		return fmt.Errorf("字段 type 非法:%q 不在枚举 {%s, %s, %s} 内", m.Type, TypeCopilot, TypeCapability, TypeController)
	}
	if m.Runtime.Name != RuntimeNative.Name && m.Runtime.Name != RuntimeDeno.Name && m.Runtime.Name != RuntimeController.Name {
		return fmt.Errorf("字段 runtime 非法:%q 不在枚举 {%s, %s, %s} 内", m.Runtime.Name, RuntimeNative.Name, RuntimeDeno.Name, RuntimeController.Name)
	}
	if m.APIVersion == "" {
		return fmt.Errorf("字段 api_version 缺失:必填,语义化版本 x.y.z")
	}
	if !apiVersionPattern.MatchString(m.APIVersion) {
		return fmt.Errorf("字段 api_version 非法:%q 不是合法语义化版本(要求 major.minor.patch)", m.APIVersion)
	}
	if m.License == "" {
		return fmt.Errorf("字段 license 缺失:必填,SPDX 标识")
	}
	if !spdxPattern.MatchString(m.License) {
		return fmt.Errorf("字段 license 非法:%q 不是合法 SPDX 标识", m.License)
	}
	if m.Maintainer == "" {
		return fmt.Errorf("字段 maintainer 缺失:必填,维护者邮箱")
	}
	if !emailPattern.MatchString(m.Maintainer) {
		return fmt.Errorf("字段 maintainer 非法:%q 不是合法邮箱格式", m.Maintainer)
	}
	if err := ValidateRelativePath("executable", m.Executable); err != nil {
		return err
	}
	for i, arg := range m.Entrypoint {
		if arg == "" {
			return fmt.Errorf("字段 entrypoint[%d] 非法:元素不得为空字符串", i)
		}
		if strings.IndexByte(arg, 0) >= 0 {
			return fmt.Errorf("字段 entrypoint[%d] 非法:不得包含空字节(\\0)", i)
		}
	}
	for i, tool := range m.Tools {
		if tool == "" {
			return fmt.Errorf("字段 tools[%d] 非法:工具名必须是非空字符串", i)
		}
	}
	// resources 逐条目委托 objectmodel.ValidateResource 校验(形态规则归
	// 资源模式层,单一事实源:daedalus/core/internal/objectmodel/objectmodel.go,
	// 计划 .omo/plans/aios-object-model-alignment.md 决策 25);错误消息统一带
	// resources[i] 字段路径,与 tools 同风格。
	// 字段缺席/为空数组时零迭代,旧清单行为完全不变(向后兼容)。
	for i, res := range m.Resources {
		if err := objectmodel.ValidateResource(res); err != nil {
			return fmt.Errorf("字段 resources[%d] 非法:%w", i, err)
		}
	}
	if err := validatePermList("permissions.read", m.permissionsRead()); err != nil {
		return err
	}
	if err := validatePermList("permissions.write", m.permissionsWrite()); err != nil {
		return err
	}
	if err := validatePermList("permissions.run", m.permissionsRun()); err != nil {
		return err
	}
	for entry, sum := range m.Checksums {
		if err := ValidateRelativePath("checksums 键", entry); err != nil {
			return err
		}
		if !validChecksum(sum) {
			return fmt.Errorf("字段 checksums[%q] 非法:%q 不是 \"sha256:<64位十六进制>\" 格式", entry, sum)
		}
	}
	return nil
}

func (m *Manifest) permissionsRead() []string {
	if m.Permissions == nil {
		return nil
	}
	return m.Permissions.Read
}

func (m *Manifest) permissionsWrite() []string {
	if m.Permissions == nil {
		return nil
	}
	return m.Permissions.Write
}

func (m *Manifest) permissionsRun() []string {
	if m.Permissions == nil {
		return nil
	}
	return m.Permissions.Run
}

// validatePermList 校验权限数组元素:非空且不含空字节(声明式字段,只做形态检查)。
func validatePermList(field string, list []string) error {
	for i, p := range list {
		if p == "" {
			return fmt.Errorf("字段 %s[%d] 非法:权限路径不得为空字符串", field, i)
		}
		if strings.IndexByte(p, 0) >= 0 {
			return fmt.Errorf("字段 %s[%d] 非法:权限路径不得包含空字节(\\0)", field, i)
		}
	}
	return nil
}

// ValidateRelativePath 校验包内相对路径:必填、不得为空字节/'..'/绝对路径。
// 供 executable、checksums 键与 zip 条目名共用(逐条规则错误消息含字段名)。
func ValidateRelativePath(field, path string) error {
	if path == "" {
		return fmt.Errorf("字段 %s 缺失:必填相对路径", field)
	}
	if strings.IndexByte(path, 0) >= 0 {
		return fmt.Errorf("字段 %s 非法:%q 包含空字节(\\0)", field, path)
	}
	if strings.HasPrefix(path, "/") {
		return fmt.Errorf("字段 %s 非法:%q 是绝对路径,必须以包根为基准的相对路径", field, path)
	}
	if strings.Contains(path, `\`) {
		return fmt.Errorf("字段 %s 非法:%q 包含反斜杠,包内路径仅允许 POSIX '/' 分隔", field, path)
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == ".." {
			return fmt.Errorf("字段 %s 非法:%q 包含 '..' 路径穿越段", field, path)
		}
	}
	if strings.HasSuffix(path, "/") {
		return fmt.Errorf("字段 %s 非法:%q 以 '/' 结尾,必须是文件路径", field, path)
	}
	return nil
}
