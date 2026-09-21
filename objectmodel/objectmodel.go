// Package objectmodel 定义 AIOS 对象模型的类型化资源模式(C1 基础层)。
//
// 设计(计划 aios-object-model-alignment todo 1 / 决策 Q1.A):
// Agent 对 OS 的每次变更都作用于一个"资源"(Resource)——由
// kind(资源类别)+ name(资源名)+ desired_state(期望状态)三元组
// 描述,而不是散落的裸命令。资源经 daedalus.plugin.json 的可选
// `resources` 数组声明(todo 2 接线),按 kind 路由到对应能力服务器;
// 每个 kind 是否放行由 policy.toml `[objectmodel].enabled_kinds`
// 网关强制(todo 3/4 漂移钉)。
//
// 本包拥有两个类型(计划第 3/4 轮评审 pin 的所有权决议):
//   - Resource     : manifest 声明用的三字段类型,绝不掺入 systemctl 字段;
//   - ServiceState : service.query / service.list / 状态载荷(todo 6/7/20)
//     共用的查询结果类型,Properties 键为 systemctl 属性名原文。
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

// 七类资源常量。v1 仅 KindService 有 provider;其余六个为保留枚举位,
// 未来经 policy.toml `[objectmodel].enabled_kinds` 逐个激活
// (保留:当前无 provider——校验器接受它们只是类型层的开放,
// 实际放行与否由策略网关 fail-closed 决定)。
const (
	KindService     Kind = "service"     // systemd 单元(v1 唯一有 provider 的类别: daedalus.service / daedalus-tx)
	KindPackage     Kind = "package"     // 软件包资源(保留:当前无 provider)
	KindContainer   Kind = "container"   // 容器资源(保留:当前无 provider)
	KindCapability  Kind = "capability"  // OS 能力资源(保留:当前无 provider)
	KindTask        Kind = "task"        // 任务资源(保留:当前无 provider)
	KindTransaction Kind = "transaction" // 事务资源(保留:当前无 provider,tx 原语在 todo 14 落位)
	KindPolicy      Kind = "policy"      // 策略资源(保留:当前无 provider)
)

// kindRegistry 是 Kind 常量的唯一注册表(AllKinds 与校验共用,
// 新增常量必须同步登记,否则 todo 4 的三点漂移测试拒绝)。
var kindRegistry = []Kind{
	KindService, KindPackage, KindContainer, KindCapability,
	KindTask, KindTransaction, KindPolicy,
}

// AllKinds 返回全部已定义 Kind 常量的副本(顺序稳定,供 todo 4
// 漂移测试与消费方枚举比对;改动返回值不影响内部注册表)。
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

// Resource 是 manifest `resources` 数组的条目类型:插件声明
// "我管理哪类资源的哪些实例、期望什么状态"。DesiredState 的
// 取值词汇由各 provider 定义(如 service 的 active/inactive),
// 本层不枚举。
type Resource struct {
	Kind         Kind   `json:"kind"`          // 资源类别(必须是已定义常量之一)
	Name         string `json:"name"`          // 资源名(单段,无路径语义;"*" 表示全类通配)
	DesiredState string `json:"desired_state"` // 期望状态(provider 层词汇表,允许为空)
}

// ServiceState 是 service 资源的查询/状态载荷类型(todo 6 的
// service.query、todo 7 的 service.list 与 todo 20 的 state.jsonl
// 共用;所有权:本文件)。Properties 的键为 systemctl 属性名原文
// (如 "ActiveState"/"SubState",计划第 4 轮评审 pin),值为对应
// 字符串。字段 Kind 是线协议 token 的裸字符串形态,与本包 JSON
// 序列化契约保持一致(不做强类型 Kind 以便反序列化端零转换)。
type ServiceState struct {
	Kind         string            `json:"kind"`          // 恒为 "service"(与 Resource.Kind 序列化值同词表)
	Name         string            `json:"name"`          // 单元名(如 "sshd.service")
	DesiredState string            `json:"desired_state"` // 期望状态;查询结果可为空(观测态无期望)
	Properties   map[string]string `json:"properties"`    // systemctl 属性原文键值对
}

// Validate 逐字段校验资源声明,聚合全部缺陷后一次性报错
// (与 internal/policy 的 validate 同风格)。拒绝:
//  1. Kind 为空(必填);
//  2. Kind 不在常量注册表内(封闭枚举,未知即拒);
//  3. Name 为空(必填);
//  4. Name 含空字节(注入防线,与 manifest entrypoint 规则同源);
//  5. Name 含 '/' 或 ".."(资源名是单段标识,不得携带路径语义,
//     堵住后续消费方把 Name 拼进路径/单元名时的遍历通道)。
//
// DesiredState 不做枚举校验:取值词汇属于各 provider 的领域,
// 本层只钉形态(允许空串)。
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

// ValidateResource 是 (*Resource).Validate 的包级函数形态,
// 供 manifest 校验(todo 2)对 `resources` 数组逐条目调用;
// nil 条目(数组元素为 JSON null)同样拒绝。
func ValidateResource(r *Resource) error {
	return r.Validate()
}
