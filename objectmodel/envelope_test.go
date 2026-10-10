// 信封层测试:Object 线上契约金样逐字节锁定 + 两类载荷的投影形态 +
// 条件写回与标签筛选语义。
package objectmodel

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// TestObject_GoldenRoundTrip 锁定 Object 全字段 JSON 逐字节形态(键序 = 字段
// 声明序),与 daedalus-core controller 侧金样同源同值。
func TestObject_GoldenRoundTrip(t *testing.T) {
	t.Parallel()
	obj := Object{
		APIVersion: "v1",
		Kind:       KindService,
		Metadata: Metadata{
			Name:        "sshd.service",
			Labels:      map[string]string{"app": "sshd", "tier": "system"},
			Annotations: map[string]string{"owner": "daedalus", "policy": "default"},
			Generation:  7,
		},
		Spec: json.RawMessage(`{"desired":"active"}`),
		Status: Status{
			ObservedGeneration: 7,
			Conditions: []Condition{{
				Type:               "Ready",
				Status:             ConditionTrue,
				Reason:             "AsExpected",
				Message:            "unit active",
				LastTransitionTime: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC),
			}},
			Properties: map[string]string{"ActiveState": "active"},
		},
	}
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"api_version":"v1","kind":"service","metadata":{"name":"sshd.service","labels":{"app":"sshd","tier":"system"},"annotations":{"owner":"daedalus","policy":"default"},"generation":7},"spec":{"desired":"active"},"status":{"observed_generation":7,"conditions":[{"type":"Ready","status":"True","reason":"AsExpected","message":"unit active","last_transition_time":"2026-09-13T00:00:00Z"}],"properties":{"ActiveState":"active"}}}`
	if string(b) != want {
		t.Fatalf("Object JSON 漂移:\n got %s\nwant %s", b, want)
	}

	var back Object
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(obj, back) {
		t.Fatalf("往返不等:\n got %#v\nwant %#v", back, obj)
	}
}

// TestObject_OmitEmpty 锁定零值形态:未填充的标签/条件/属性一律缺席,api_version
// 无版本化需求但仍恒出现(不加 omitempty,保持 core 侧线上契约逐字节不变),
// generation 与 observed_generation 作为计数器恒出现(零值也是有效信息)。
func TestObject_OmitEmpty(t *testing.T) {
	t.Parallel()
	obj := Resource{Kind: KindService, Name: "sshd", DesiredState: "active"}.Object()
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"api_version":"","kind":"service","metadata":{"name":"sshd","generation":0},"spec":{"desired_state":"active"},"status":{"observed_generation":0}}`
	if string(b) != want {
		t.Fatalf("声明投影形态漂移:\n got %s\nwant %s", b, want)
	}
}

// TestResource_Object_Projection 断言声明投影只搬 kind/name/desired_state,
// 不预先造 Labels/Annotations/Generation 的值(摆字段等用途反模式)。
func TestResource_Object_Projection(t *testing.T) {
	t.Parallel()
	obj := Resource{Kind: KindPackage, Name: "nginx", DesiredState: "latest"}.Object()
	if obj.Kind != KindPackage || obj.Metadata.Name != "nginx" {
		t.Fatalf("kind/name 投影错误: %#v", obj)
	}
	if obj.Metadata.Labels != nil || obj.Metadata.Annotations != nil || obj.Metadata.Generation != 0 {
		t.Fatalf("声明投影不得造 metadata 值: %#v", obj.Metadata)
	}
	var spec ResourceSpec
	if err := json.Unmarshal(obj.Spec, &spec); err != nil {
		t.Fatalf("spec 回解失败: %v", err)
	}
	if spec.DesiredState != "latest" {
		t.Fatalf("desired_state 未进 spec: %s", obj.Spec)
	}
}

// TestServiceState_Object_Projection 断言观测载荷投影无损:Properties 与
// Conditions 全部落 status,不丢键。
func TestServiceState_Object_Projection(t *testing.T) {
	t.Parallel()
	cond := Condition{Type: "Ready", Status: ConditionTrue, LastTransitionTime: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	st := ServiceState{
		Kind:         "service",
		Name:         "sshd.service",
		DesiredState: "active",
		Properties:   map[string]string{"ActiveState": "active", "SubState": "running"},
		Conditions:   []Condition{cond},
	}
	obj := st.Object()
	if obj.Kind != KindService || obj.Metadata.Name != "sshd.service" {
		t.Fatalf("定位维度投影错误: %#v", obj.Metadata)
	}
	if !reflect.DeepEqual(obj.Status.Properties, st.Properties) {
		t.Fatalf("Properties 丢失: %#v", obj.Status.Properties)
	}
	if !reflect.DeepEqual(obj.Status.Conditions, st.Conditions) {
		t.Fatalf("Conditions 丢失: %#v", obj.Status.Conditions)
	}
	// 返回值与源切片不得共享底层数组,否则消费方改条件会回写观测载荷。
	obj.Status.Conditions[0].Status = ConditionFalse
	if st.Conditions[0].Status != ConditionTrue {
		t.Fatal("Conditions 投影与源共享底层数组")
	}
	obj.Status.Properties["ActiveState"] = "failed"
	if st.Properties["ActiveState"] != "active" {
		t.Fatal("Properties 投影与源共享映射")
	}
}

// TestStatus_UpsertCondition 锁定条件写回语义:同 Status 只换 reason 不得刷新
// 转换时刻,Status 变化必须刷新,新类型追加即转换。
func TestStatus_UpsertCondition(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	var s Status

	if !s.UpsertCondition(Condition{Type: "Ready", Status: ConditionTrue, Reason: "Started", LastTransitionTime: t0}) {
		t.Fatal("新类型首次写入应判为转换")
	}
	if s.UpsertCondition(Condition{Type: "Ready", Status: ConditionTrue, Reason: "StillUp", LastTransitionTime: t1}) {
		t.Fatal("同 Status 的重复写回不得判为转换")
	}
	c, ok := s.GetCondition("Ready")
	if !ok || c.Reason != "StillUp" || !c.LastTransitionTime.Equal(t0) {
		t.Fatalf("同 Status 应更新 reason 并保留原转换时刻: %#v", c)
	}
	if !s.UpsertCondition(Condition{Type: "Ready", Status: ConditionFalse, Reason: "Stopped", LastTransitionTime: t1}) {
		t.Fatal("Status 变化应判为转换")
	}
	c, _ = s.GetCondition("Ready")
	if !c.LastTransitionTime.Equal(t1) {
		t.Fatalf("Status 变化必须刷新转换时刻: %#v", c)
	}
	if n := len(s.Conditions); n != 1 {
		t.Fatalf("同 Type 覆盖后条件数应为 1,得 %d", n)
	}
	s.UpsertCondition(Condition{Type: "Available", Status: ConditionUnknown, LastTransitionTime: t1})
	if n := len(s.Conditions); n != 2 {
		t.Fatalf("异 Type 应追加,条件数应为 2,得 %d", n)
	}
	if _, ok := s.GetCondition("Absent"); ok {
		t.Fatal("GetCondition 命中了不存在的类型")
	}
}

// TestMetadata_LabelSelectors 锁定标签读侧 API:缺键与值不符都拒绝,空选择器
// 恒真(等价"不筛选")。
func TestMetadata_LabelSelectors(t *testing.T) {
	t.Parallel()
	m := Metadata{Name: "sshd.service", Labels: map[string]string{"app": "sshd", "tier": "system"}}
	if v, ok := m.Label("app"); !ok || v != "sshd" {
		t.Fatalf("Label 读取失败: %q %v", v, ok)
	}
	if _, ok := m.Label("missing"); ok {
		t.Fatal("Label 命中了不存在的键")
	}
	if !m.MatchLabels(map[string]string{"tier": "system"}) {
		t.Fatal("子集选择器应命中")
	}
	if m.MatchLabels(map[string]string{"tier": "user"}) {
		t.Fatal("值不符的选择器不得命中")
	}
	if m.MatchLabels(map[string]string{"missing": "x"}) {
		t.Fatal("缺键的选择器不得命中")
	}
	if !m.MatchLabels(nil) {
		t.Fatal("空选择器应恒真")
	}
}

// TestServiceState_JSONBackwardCompat 断言旧落盘行(无 conditions 键)在新 schema 下
// 照常回解,state.jsonl 缓存零迁移。
func TestServiceState_JSONBackwardCompat(t *testing.T) {
	t.Parallel()
	const legacy = `{"kind":"service","name":"sshd.service","desired_state":"","properties":{"ActiveState":"inactive"}}`
	var st ServiceState
	if err := json.Unmarshal([]byte(legacy), &st); err != nil {
		t.Fatalf("旧行回解失败: %v", err)
	}
	if len(st.Conditions) != 0 || st.Properties["ActiveState"] != "inactive" {
		t.Fatalf("旧行回解结果错误: %#v", st)
	}
}

// TestMetadata_BumpGeneration 锁定 BumpGeneration 递增期望版本并返回新值;
// 零值、正数、大数三种 case 覆盖。
func TestMetadata_BumpGeneration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		init int64
		want int64
	}{
		{"零值递增", 0, 1},
		{"正数递增", 7, 8},
		{"大数递增", 1<<62 - 1, 1<<62},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := &Metadata{Name: "x", Generation: tc.init}
			got := m.BumpGeneration()
			if got != tc.want {
				t.Fatalf("返回值 = %d, want %d", got, tc.want)
			}
			if m.Generation != tc.want {
				t.Fatalf("Generation 字段未更新: got %d, want %d", m.Generation, tc.want)
			}
		})
	}
}

// BumpGeneration 不得触碰 ResourceVersion(后者由 set spec 后的版本调和方递增,
// BumpGeneration 是 tx apply 阶段的"我期望 v+1"信号)。
func TestMetadata_BumpGeneration_DoesNotTouchResourceVersion(t *testing.T) {
	t.Parallel()
	m := &Metadata{Name: "x", Generation: 5, ResourceVersion: "rv-7"}
	m.BumpGeneration()
	if m.ResourceVersion != "rv-7" {
		t.Fatalf("ResourceVersion 被改: got %q, want %q", m.ResourceVersion, "rv-7")
	}
}

// SetLabel 在 nil map 上必须惰性初始化,不得 panic。
func TestMetadata_SetLabel_NilMap(t *testing.T) {
	t.Parallel()
	m := &Metadata{Name: "x"} // Labels == nil
	m.SetLabel("app", "sshd")
	if m.Labels["app"] != "sshd" {
		t.Fatalf("SetLabel 未生效: %#v", m.Labels)
	}
}

func TestMetadata_SetLabel(t *testing.T) {
	t.Parallel()
	m := &Metadata{Name: "x", Labels: map[string]string{"old": "v"}}
	m.SetLabel("app", "sshd")
	if m.Labels["app"] != "sshd" || m.Labels["old"] != "v" {
		t.Fatalf("SetLabel 覆盖语义错误: %#v", m.Labels)
	}
}

func TestMetadata_SetLabel_EmptyKeyPanics(t *testing.T) {
	t.Parallel()
	m := &Metadata{Name: "x"}
	defer func() {
		if recover() == nil {
			t.Fatal("空 key 必须 panic")
		}
	}()
	m.SetLabel("", "v")
}

func TestMetadata_SetAnnotation_NilMap(t *testing.T) {
	t.Parallel()
	m := &Metadata{Name: "x"}
	m.SetAnnotation("owner", "ops")
	if m.Annotations["owner"] != "ops" {
		t.Fatalf("SetAnnotation 未生效: %#v", m.Annotations)
	}
}

func TestMetadata_HasLabel(t *testing.T) {
	t.Parallel()
	m := &Metadata{Name: "x", Labels: map[string]string{"app": "sshd"}}
	if !m.HasLabel("app") {
		t.Fatal("存在的 key 必须命中")
	}
	if m.HasLabel("missing") {
		t.Fatal("不存在的 key 不得命中")
	}
	// nil map 上不得 panic。
	var nilMap Metadata
	if nilMap.HasLabel("any") {
		t.Fatal("nil Labels 必须返回 false")
	}
}

// 空值 UID / ResourceVersion 在 JSON 里不出现(omitempty);既有零值形态字节不变。
func TestMetadata_UID_ResourceVersion_OmitEmpty(t *testing.T) {
	t.Parallel()
	m := Metadata{Name: "x"}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name":"x","generation":0}`
	if string(b) != want {
		t.Fatalf("零值形态漂移:\n got %s\nwant %s", b, want)
	}
}

// 非空 UID / ResourceVersion 在 JSON 出现且键名 = uid / resource_version,顺序在
// generation 之后(字段声明序)。
func TestMetadata_UID_ResourceVersion_RoundTrip(t *testing.T) {
	t.Parallel()
	m := Metadata{
		Name:            "sshd.service",
		Generation:      7,
		UID:             "abc-123",
		ResourceVersion: "rv-9",
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name":"sshd.service","generation":7,"uid":"abc-123","resource_version":"rv-9"}`
	if string(b) != want {
		t.Fatalf("序列化漂移:\n got %s\nwant %s", b, want)
	}
	var back Metadata
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m, back) {
		t.Fatalf("往返不等: got %#v want %#v", back, m)
	}
}

// FilterByLabels:子集匹配、空选择器恒真、顺序保持、空入参、空出参非 nil。
func TestFilterByLabels(t *testing.T) {
	t.Parallel()
	objs := []Object{
		{Kind: KindService, Metadata: Metadata{Name: "a", Labels: map[string]string{"app": "sshd", "tier": "system"}}},
		{Kind: KindService, Metadata: Metadata{Name: "b", Labels: map[string]string{"app": "nginx", "tier": "system"}}},
		{Kind: KindService, Metadata: Metadata{Name: "c", Labels: map[string]string{"app": "sshd", "tier": "user"}}},
	}

	t.Run("子集匹配", func(t *testing.T) {
		t.Parallel()
		got := FilterByLabels(objs, map[string]string{"app": "sshd"})
		if len(got) != 2 || got[0].Metadata.Name != "a" || got[1].Metadata.Name != "c" {
			t.Fatalf("子集匹配错误: %#v", got)
		}
	})

	t.Run("空选择器恒真", func(t *testing.T) {
		t.Parallel()
		got := FilterByLabels(objs, nil)
		if len(got) != 3 {
			t.Fatalf("空选择器应返回全部: got %d", len(got))
		}
	})

	// 空选择器必须返回副本,不得与原切片共享底层数组(Review Focus #2)。
	t.Run("空选择器返回副本", func(t *testing.T) {
		t.Parallel()
		got := FilterByLabels(objs, nil)
		got[0].Metadata.Name = "tampered"
		if objs[0].Metadata.Name == "tampered" {
			t.Fatal("空选择器返回了原切片别名")
		}
	})

	t.Run("空入参", func(t *testing.T) {
		t.Parallel()
		got := FilterByLabels(nil, map[string]string{"app": "x"})
		if got == nil {
			t.Fatal("空入参不得返回 nil 切片(消费方 range 安全)")
		}
		if len(got) != 0 {
			t.Fatalf("空入参应返回空切片: got %d", len(got))
		}
	})
}

// TestOwnerReference_RoundTrip 锁定 OwnerReference 字段顺序与 omitempty 语义:
// api_version / uid / controller / block_owner_deletion 都 omitempty;kind / name 必填且恒出。
func TestOwnerReference_RoundTrip(t *testing.T) {
	t.Parallel()
	obj := Object{
		Kind: KindService,
		// Spec 显式设置为 json.RawMessage("null") 以让 marshal+unmarshal 往返
		// DeepEqual 成立(nil json.RawMessage 会被 Unmarshal 为 []byte("null"),
		// 与 nil 不等 —— Go 标准库行为,非本测试可调控)。
		Spec: json.RawMessage("null"),
		Metadata: Metadata{
			Name: "child",
			OwnerReferences: []OwnerReference{{
				APIVersion:         "v1",
				Kind:               KindService,
				Name:               "parent",
				UID:                "parent-uid-1",
				Controller:         true,
				BlockOwnerDeletion: true,
			}},
		},
	}
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"api_version":"","kind":"service","metadata":{"name":"child","generation":0,"owner_references":[{"api_version":"v1","kind":"service","name":"parent","uid":"parent-uid-1","controller":true,"block_owner_deletion":true}]},"spec":null,"status":{"observed_generation":0}}`
	if string(b) != want {
		t.Fatalf("OwnerReference 序列化漂移:\n got %s\nwant %s", b, want)
	}
	var back Object
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(obj, back) {
		t.Fatalf("往返不等: got %#v want %#v", back, obj)
	}
}

// TestFinalizer_AddRemoveHas 锁定 finalizer 增删查语义:首次新增返回 true,重复返回
// false;Remove 已存在返回 true,不在返回 false;Has 仅查存在。
func TestFinalizer_AddRemoveHas(t *testing.T) {
	t.Parallel()
	m := &Metadata{Name: "x"}

	if !m.AddFinalizer("protect.example.com/cleanup") {
		t.Fatal("首次 AddFinalizer 应返回 true")
	}
	if m.AddFinalizer("protect.example.com/cleanup") {
		t.Fatal("重复 AddFinalizer 应返回 false")
	}
	if !m.HasFinalizer("protect.example.com/cleanup") {
		t.Fatal("已添加 finalizer 必须命中 HasFinalizer")
	}

	if !m.RemoveFinalizer("protect.example.com/cleanup") {
		t.Fatal("存在的 finalizer Remove 必须返回 true")
	}
	if m.RemoveFinalizer("protect.example.com/cleanup") {
		t.Fatal("不存在的 finalizer Remove 必须返回 false")
	}
	if m.HasFinalizer("protect.example.com/cleanup") {
		t.Fatal("移除后不得命中")
	}
}
