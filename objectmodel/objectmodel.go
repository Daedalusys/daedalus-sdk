// Package objectmodel 定义 AIOS 对象模型的类型化资源模式(C1 基础层)。
//
// Agent 对 OS 的每次变更都作用于一个"资源"(Resource)——由
// kind + name + desired_state 三元组描述,而不是散落的裸命令。资源经
// daedalus.plugin.json 的 `resources` 数组声明,按 kind 路由到对应能力
// 服务器;每个 kind 是否放行由 policy.toml `[objectmodel].enabled_kinds`
// 网关强制。本包拥有声明类型 Resource(manifest 声明)与 ServiceState
// (service.query / service.list / 状态载荷共用的查询结果),以及 envelope.go
// 的 spec/status 信封 Object —— 两类载荷都投影进同一信封,是对象模型的
// 唯一形状来源。
//
// 校验与 internal/policy 同风格:Validate 聚合全部缺陷后一次性报错
// (fail-closed,配置事故不得静默放宽);本包只做形态校验,不感知
// enabled_kinds 网关——"验证器接受保留 kind、策略层拒绝未启用 kind"
// 是刻意的双层设计,与 shellpolicy/policy 的 fail-closed 分层一致。
package objectmodel

import (
	"fmt"
	"slices"
	"strings"
)

// Kind 是资源类别的封闭枚举(线协议 token,小写,与 manifest JSON
// 及 policy.toml enabled_kinds 的取值逐字一致)。
type Kind string

// 七类资源常量。v1 仅 KindService 有 provider;其余为保留枚举位,校验器接受
// 只是类型层开放,实际放行由 enabled_kinds 策略网关 fail-closed 决定。
const (
	KindService     Kind = "service" // systemd 单元(v1 唯一有 provider 的类别: daedalus.service / daedalus-tx)
	KindPackage     Kind = "package"
	KindContainer   Kind = "container"
	KindCapability  Kind = "capability"
	KindTask        Kind = "task"
	KindTransaction Kind = "transaction"
	KindPolicy      Kind = "policy"
)

// kindRegistry 是 Kind 常量的唯一注册表(AllKinds 与校验共用,新增常量
// 必须同步登记,否则跨包三点漂移测试拒绝)。
var kindRegistry = []Kind{
	KindService, KindPackage, KindContainer, KindCapability,
	KindTask, KindTransaction, KindPolicy,
}

// AllKinds 返回全部已定义 Kind 常量的副本(顺序稳定;改动返回值不影响内部注册表)。
func AllKinds() []Kind {
	return slices.Clone(kindRegistry)
}

// validKind 报告 k 是否命中注册表。O(7) 线性扫描:常量集极小,
// 不值得引入 map 的初始化与共享状态成本。
func validKind(k Kind) bool {
	for _, v := range kindRegistry {
		if k == v {
			return true
		}
	}
	return false
}

// Resource 是 manifest `resources` 数组的条目类型:插件声明"我管理哪类
// 资源的哪些实例、期望什么状态"。DesiredState 的取值词汇由各 provider
// 定义(如 service 的 active/inactive),本层不枚举。
type Resource struct {
	Kind         Kind   `json:"kind"`          // 资源类别(必须是已定义常量之一)
	Name         string `json:"name"`          // 资源名(单段,无路径语义;"*" 表示全类通配)
	DesiredState string `json:"desired_state"` // 期望状态(provider 层词汇表,允许为空)
}

// ServiceState 是 service 资源的查询/状态载荷类型(service.query、service.list
// 与 state.jsonl 共用)。Properties 键为 systemctl 属性名原文;Kind 用裸字符串
// 而非强类型 Kind,反序列化端零转换。Conditions 是 Properties 之上的派生语义层
// (由 provider 在观测后生成),不替代 Properties。
type ServiceState struct {
	Kind         string            `json:"kind"`                 // 恒为 "service"(与 Resource.Kind 序列化值同词表)
	Name         string            `json:"name"`                 // 单元名(如 "sshd.service")
	DesiredState string            `json:"desired_state"`        // 期望状态;查询结果可为空(观测态无期望)
	Properties   map[string]string `json:"properties"`           // systemctl 属性原文键值对
	Conditions   []Condition       `json:"conditions,omitempty"` // Properties 之上的派生语义,由 provider 观测后生成
}

// Validate 逐字段校验资源声明,聚合全部缺陷后一次性报错(fail-closed):
// Kind 必填且命中封闭注册表;Name 必填、不含空字节、不含 '/' 或 ".."
// (资源名是单段标识,堵住消费方把 Name 拼进路径/单元名时的遍历通道)。
// DesiredState 不做枚举校验:取值词汇属于各 provider 的领域,本层只钉形态
// (允许空串)。
func (r *Resource) Validate() error {
	if r == nil {
		return fmt.Errorf("objectmodel: resource 条目缺失:数组元素不得为 null")
	}
	var problems []string
	if r.Kind == "" {
		problems = append(problems, `字段 "kind" 缺失:必填,取值为已定义资源类别`)
	} else if !validKind(r.Kind) {
		problems = append(problems, fmt.Sprintf(`字段 "kind" 非法:%q 不在资源类别枚举内`, r.Kind))
	}
	switch {
	case r.Name == "":
		problems = append(problems, `字段 "name" 缺失:必填,资源名或 "*" 通配`)
	default:
		if strings.IndexByte(r.Name, 0) >= 0 {
			problems = append(problems, `字段 "name" 非法:不得包含空字节(\0)`)
		}
		if strings.ContainsRune(r.Name, '/') {
			problems = append(problems, `字段 "name" 非法:不得包含路径分隔符 '/'`)
		}
		if strings.Contains(r.Name, "..") {
			problems = append(problems, `字段 "name" 非法:不得包含路径回溯段 ".."`)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("objectmodel: Resource 校验失败: %s", strings.Join(problems, "; "))
	}
	return nil
}

// ValidateResource 是 (*Resource).Validate 的包级函数形态,供 manifest 校验
// 对 `resources` 数组逐条目调用;nil 条目同样拒绝。
func ValidateResource(r *Resource) error {
	return r.Validate()
}
