// Package objectmodel 的信封层:Object 是期望(spec)与观测(status)的统一容器,
// Resource 声明与 ServiceState 观测都投影进它。
//
// 本文件是信封形状的唯一事实源;daedalus-core 的 controller 契约类型是本包
// 的别名,不得出现第二份定义。线上契约由 envelope_test.go 金样往返逐字节
// 锁定(键序 = 字段声明序)。
package objectmodel

import (
	"encoding/json"
	"maps"
	"slices"
	"time"
)

// Object 是顶层契约对象:kind + metadata 定位资源,spec 承载期望,status 承载观测。
// Spec 是 provider 领域的原始 JSON,本包不理解也不校验其内部形态。
type Object struct {
	APIVersion string          `json:"api_version"`
	Kind       Kind            `json:"kind"`
	Metadata   Metadata        `json:"metadata"`
	Spec       json.RawMessage `json:"spec"`
	Status     Status          `json:"status"`
}

// Metadata 是对象的名字与标签维度。Generation 是期望版本计数,由改动 spec 的
// 一方递增,观测方回写 Status.ObservedGeneration 与之比对。UID 与 ResourceVersion
// 是 controller 调和循环可读可填的可选字段:v1 范围 = 字段 + 校验,实际填充
// 由各 provider 在 set/apply 后回写,BumpGeneration 仅递增 Generation 不动
// ResourceVersion(后者由版本调和方管理,语义切分)。
type Metadata struct {
	Name            string            `json:"name"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
	Generation      int64             `json:"generation"`
	UID             string            `json:"uid,omitempty"`
	ResourceVersion string            `json:"resource_version,omitempty"`
}

// Status 是观测态载荷:版本比对 + 条件列表 + provider 原始属性
// (如 systemctl 键值原文)。
type Status struct {
	ObservedGeneration int64             `json:"observed_generation"`
	Conditions         []Condition       `json:"conditions,omitempty"`
	Properties         map[string]string `json:"properties,omitempty"`
}

// Condition 是三态条件条目,Status 字段取值为 ConditionTrue/False/Unknown。
// 本层只钉形态不校验取值,判定归消费方。
type Condition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"`
	Reason             string    `json:"reason,omitempty"`
	Message            string    `json:"message,omitempty"`
	LastTransitionTime time.Time `json:"last_transition_time"`
}

// 条件三态 token(线协议值,首字母大写与布尔语义区分)。
const (
	ConditionTrue    = "True"
	ConditionFalse   = "False"
	ConditionUnknown = "Unknown"
)

// ResourceSpec 是声明投影进 Object.Spec 的形态。DesiredState 的取值词汇归各
// provider 领域,本包不枚举。
type ResourceSpec struct {
	DesiredState string `json:"desired_state,omitempty"`
}

// Object 把 manifest 声明投影为信封。Labels/Annotations/Generation 一律留空:
// 它们由改 spec 的一方填充,声明侧预先造值只会得到无人维护的空格。
func (r Resource) Object() Object {
	spec, _ := json.Marshal(ResourceSpec{DesiredState: r.DesiredState})
	return Object{
		Kind:     r.Kind,
		Metadata: Metadata{Name: r.Name},
		Spec:     spec,
	}
}

// Object 把查询/状态载荷投影为信封:期望进 spec,原始属性与条件进 status。
// 观测无版本比对来源,ObservedGeneration 留零值待调和方回填。条件与属性都做
// 拷贝:消费方在信封上写回,不得回灌观测载荷本身。
func (s ServiceState) Object() Object {
	spec, _ := json.Marshal(ResourceSpec{DesiredState: s.DesiredState})
	return Object{
		Kind:     Kind(s.Kind),
		Metadata: Metadata{Name: s.Name},
		Spec:     spec,
		Status: Status{
			Conditions: slices.Clone(s.Conditions),
			Properties: maps.Clone(s.Properties),
		},
	}
}

// GetCondition 按 Type 查找条件条目。
func (s Status) GetCondition(condType string) (Condition, bool) {
	for _, c := range s.Conditions {
		if c.Type == condType {
			return c, true
		}
	}
	return Condition{}, false
}

// UpsertCondition 按 Type 覆盖写入条件,无同型条目则追加。返回值是"是否发生了
// 状态转换":同 Status 的重复写回只更新 reason/message,保留原
// LastTransitionTime —— 转换时刻不得被无变化的轮询伪造。
func (s *Status) UpsertCondition(c Condition) bool {
	for i := range s.Conditions {
		if s.Conditions[i].Type != c.Type {
			continue
		}
		if s.Conditions[i].Status == c.Status {
			c.LastTransitionTime = s.Conditions[i].LastTransitionTime
			s.Conditions[i] = c
			return false
		}
		s.Conditions[i] = c
		return true
	}
	s.Conditions = append(s.Conditions, c)
	return true
}

// Label 读取单个标签值。
func (m Metadata) Label(key string) (string, bool) {
	v, ok := m.Labels[key]
	return v, ok
}

// MatchLabels 报告标签是否覆盖 sel 的每个键值对;sel 为空恒真。
// 这是调和循环按标签筛选资源的读侧入口。
func (m Metadata) MatchLabels(sel map[string]string) bool {
	for k, v := range sel {
		if got, ok := m.Labels[k]; !ok || got != v {
			return false
		}
	}
	return true
}

// BumpGeneration 递增期望版本并返回新值。ResourceVersion 由版本调和方管理,
// 不在本方法动 —— 期望方写 Generation,观测方写 Status.ObservedGeneration 与之
// 比对;ResourceVersion 是 apiserver 内部单调号,提供者写 spec 时由 provider
// 自行回填。两者职责切分,BumpGeneration 不得越界。
func (m *Metadata) BumpGeneration() int64 {
	m.Generation++
	return m.Generation
}
