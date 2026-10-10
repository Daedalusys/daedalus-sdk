# VISION §10 P3 —— Object Model 元数据 / 信封 / Conditions / finalizers 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 `daedalus-sdk/objectmodel` 的信封层从"类型在场"升为"语义在场":补齐 Metadata 字段(UID / ResourceVersion)、writer 端 API(`BumpGeneration` / `SetLabel` / `SetAnnotation` / `AddFinalizer` / `RemoveFinalizer`)、读侧列表筛选 `FilterByLabels`、ownerRef / finalizer 类型与校验,完成 `Metadata.Validate()` + `Object.Validate()` 复合校验,并把 SDK 与 `daedalus-core/internal/controller`(objectmodel 别名)两侧的金样序列化形态锁到字节级一致。落点是 sdk#1 issue(克隆自 Daedalusys/Daedalusys#38)。

**Architecture:** 改动面集中在两个仓的 objectmodel 同名包:`daedalus-sdk/objectmodel/envelope.go`(Task 1–3 增字段 + writer + 类型)、`daedalus-sdk/objectmodel/validate.go`(Task 4 新建,只放 `Metadata.Validate` / `Object.Validate`,与 envelope.go 单一职责切分);envelope_test.go / validate_test.go 补金样与表驱动测试。`daedalus-core/internal/controller/types.go` 把 `OwnerReference` / `Finalizer` 加入别名块(Task 5);`types_test.go` 加一段全字段金样,与 SDK 端字面量字节级一致(防止别名偷换形态)。文档侧同步 `daedalus-core/VISION.md` §5 / §8 / §10 三处状态行,以及 `daedalus-sdk/AGENTS.md` CODE MAP / CONVENTIONS 两条。不动 controller 任何运行时逻辑、不动 `daedalus-tx` 任何 adapter、不动 policy / shellpolicy / pathguard —— 那些是 P4 各自的事。

**Tech Stack:** Go 1.26 stdlib only(`encoding/json` / `fmt` / `slices` / `strings` / `time`);`daedalus-sdk` 仓根 module `github.com/Daedalusys/daedalus-sdk`;`daedalus-core` 仓根独立 module `github.com/Daedalusys/daedalus-core`,通过 `replace github.com/Daedalusys/daedalus-sdk => ../daedalus-sdk`(`daedalus-core/go.mod`)在本地解析。TDD(`go test ./objectmodel/...` + `go test ./internal/controller/...`);金样锁定(`string(b) != want` 逐字节比对)。

**Spec:**
- `daedalus-sdk` issue #1 — VISION §10 P3 —— Object Model 元数据 / 信封 / Conditions / finalizers
  (`gh issue view 1 --repo Daedalusys/daedalus-sdk`)
- `daedalus-core/VISION.md` §5 k8s-parity 表行 128–142(metadata / Conditions / finalizer / ownerRef)与 §8 A 层行 216–219(同等状态)
- 现有基线:
  - `objectmodel/envelope.go` 138 行(`Object` 信封 + `Metadata{Name,Labels,Annotations,Generation}` + `Status{ObservedGeneration,Conditions,Properties}` + `Condition{Type,Status,Reason,Message,LastTransitionTime}` + `UpsertCondition` / `GetCondition` / `Label` / `MatchLabels` + `Resource.Object()` / `ServiceState.Object()`)
  - `objectmodel/objectmodel.go` 123 行(`Kind` 封闭枚举 7 项 + `AllKinds()` + `Resource.Validate` + `ValidateResource`)
  - `objectmodel/envelope_test.go` 199 行(`TestObject_GoldenRoundTrip` 钉 `want` 字面量)
  - `objectmodel/objectmodel_test.go` 300 行(`TestResource_Validate*` + `TestKind_Values` + `TestObjectModel_Drift` 三点漂移金丝雀 `["service","package"]`)
  - `daedalus-core/internal/controller/types.go` 类型别名 + `daedalus-core/internal/controller/types_test.go` 与 SDK 同源金样

## 基线盘点(plan 启动前的实际状态,作为"已交付/未交付"参照)

| 议题子项 | 当前状态 | 本 plan 是否落地 |
|---|---|---|
| A2 spec/status 显式分离 | ✅ `Object{api_version,kind,metadata,spec,status}` 已存在,Resource/ServiceState 双投影 | 不动 |
| A3 `Condition` 类型 + 三态 token | ✅ `Condition` + `ConditionTrue/False/Unknown` + `UpsertCondition`(同状态不刷转换时刻) | 不动 |
| A3 Conditions 派生 + 写回权威时点 | ✅ `service.query` 产出 `Ready`(daedalus-plugins/service/cmd/daedalus-service/conditions.go `deriveConditions`);权威时点 = tx apply 后 | 文档固定,不写新代码 |
| A1 `Metadata.Name / Labels / Annotations / Generation` | ✅ 字段在;读侧 `Label` / `MatchLabels` | 不动 |
| A1 `Metadata.UID` | ❌ 无 | Task 1 |
| A1 `Metadata.ResourceVersion` | ❌ 无 | Task 1 |
| A1 Generation "填充方" | ❌ 无(writer 缺失 → §5 行 129 现状 "尚无填充方") | Task 1(`BumpGeneration`) |
| A1 Label / Annotation writer | ❌ 无 | Task 2(`SetLabel` / `SetAnnotation`) |
| A1 资源筛选按 label 走(为 controller 准备) | ❌ 只有 `MatchLabels` 单元素读侧,缺 `[]Object` 筛选入口 | Task 2(`FilterByLabels`) |
| A4 `OwnerReference` 类型 | ❌ 无 | Task 3 |
| A4 `Finalizer` 类型 | ❌ 无 | Task 3 |
| A4 GC 逻辑实现 | ❌ 缺,v1 范围明确只做"字段 + 校验",GC 归 P4 | **非目标**(本 plan 不写 GC) |
| `Metadata.Validate()` / `Object.Validate()` | ❌ 无 | Task 4 |
| SDK ↔ core controller 两侧金样锁步 | ✅ `TestObject_GoldenRoundTrip` 双方同源;新增字段后必须同源更新 | Task 5 |
| VISION §5 / §8 / §10 状态行 + AGENTS.md 同步 | ❌ 仍标"无/尚无填充方/无父子无延迟删除" | Task 5 |

## 全局约束

- **域值约束**:7 类 `Kind` 常量集(`AllKinds()`)与 `TestKind_Values` 字面量锁定,新增字段不得引入新的 `Kind` 常量。
- **零运行时副作用**:本 plan 全部改动是纯类型 / 纯函数 / JSON 形态;不引入 goroutine、ic、文件 IO、网络调用;不动 policy / shellpolicy / pathguard;不改 `internal/controller` 任何运行时逻辑(类型别名之外零字节)。
- **JSON 字节稳定性**:现有 `TestObject_GoldenRoundTrip` 与 core `types_test.go` 的 `want` 字面量(`{"api_version":"v1","kind":"service",...}`)一字不动;新增字段一律 `omitempty` 且追加在 `Generation` 之后,确保零值形态字节不变。
- **字段顺序锁定**:`Metadata` JSON 序列化键序 = Go 字段声明序;新增字段追加在末尾(UID / ResourceVersion / OwnerReferences / Finalizers 顺次在 Generation 之后)。
- **Go 风格 / 注释语言**:延续 `envelope.go` 已通风格 —— 导出的类型 / 函数上方 doc comment 中文;函数体内错误消息中文(本仓 i18n 包存在,但 envelope 错误属 Go 服务端技术信号,跟随既有 `fmt.Errorf` 中文风格);标识符 / JSON tag / 字面量 token 英文。
- **fail-closed 聚合**:`Validate()` 聚合全部缺陷一次性返回,与 `Resource.Validate` 既有风格一致;错误消息点名字段路径。
- **校验严格度**:
  - `UID` 非空时不得含 NUL 或控制字符(`< 0x20` 或 `= 0x7f`);长度上限 253(与 k8s 同,留连接空间);
  - `ResourceVersion` 非空时仅校验非 NUL;
  - `OwnerReference.Kind` 必须是封闭枚举命中;`Name` 必填、非 NUL、无 `/` 无 `..`(沿用 `Resource.Name` 规则);`UID` 遵循与 `Metadata.UID` 同规则;
  - `Finalizer` 非空、非 NUL、无重复(`HasFinalizer` 检查后写入)。
- **别名契约不变**:`daedalus-core/internal/controller/types.go` 的 `Object/Metadata/Status/Condition` 别名链一字不动;`types_test.go` 现有 `want` 字面量一字不动,只追加新金样。
- **三点漂移**:不动 `TestObjectModel_Drift` —— 它锁的是 `enabled_kinds` 三点,与 metadata 字段正交;本 plan 在 SDK 与 core 各加一段"信封字节锁步"测试代替。
- **commit 粒度**:每 Task 一次 commit,提交前缀 `feat(objectmodel):` 或 `test(controller):` 或 `docs(vision):`,与既有 commit 历史风格一致。

## Review Focus(最可能咬人的 5 类,每条对应某任务测试)

1. **空 labels map 上写新 key 必须惰性初始化,不得 panic** —— Task 2 `SetLabel` / `SetAnnotation` 必须 nil-safe(`TestMetadata_SetLabel_NilMap`)。
2. **`FilterByLabels` 空选择器恒真 ≠ 返回原切片,必须返回副本**,否则消费方 sort / filter 顺序改动会回灌原集合 —— Task 2(`TestFilterByLabels_EmptySelector_ReturnsCopy`)。
3. **`UpsertCondition` 同 Status 写回不刷 `LastTransitionTime`** —— 现有规则,Task 5 的 SDK ↔ core 锁步金样里必须出现一个"无变化轮询"的 sub-test,钉死这一行为;否则 controller P4 落地时被静默刷时间。
4. **`Object.Validate()` 复合校验的报错顺序与字段聚合** —— Task 4 必须明确"先 `Kind.Validate`(走 `AllKinds()`)→ 再 `Metadata.Validate()` → 再 `Spec` 是合法 JSON 或空"的三段次序;同 `Resource.Validate` 聚合风格,一次性返回全部缺陷。
5. **SDK 与 core controller 两侧 `want` 字节串必须同步漂移** —— Task 5 用单一字符串字面量集中常量(`const envelopeFullGoldenJSON = ...`),SDK 与 core controller 两侧测试都引用它,任何一侧改动另一侧编译失败(强制同步)。

---

## Task 1: Metadata 增 `UID` / `ResourceVersion` + `BumpGeneration` writer

**Files:**
- Modify: `daedalus-sdk/objectmodel/envelope.go`(在 `Metadata` 结构追加 `UID` / `ResourceVersion` 字段,加方法 `BumpGeneration`)
- Modify: `daedalus-sdk/objectmodel/envelope_test.go`(追加 `TestMetadata_BumpGeneration` / `TestMetadata_UID_ResourceVersion_OmitEmpty` / `TestMetadata_UID_ResourceVersion_RoundTrip`)

**Interfaces:**
- Consumes:
  - `objectmodel.Metadata{Name, Labels, Annotations, Generation}`(已存在)
  - 既有金样 `want`:`{"api_version":"v1","kind":"service","metadata":{"name":"sshd.service","labels":{...},"annotations":{...},"generation":7},"spec":{...},"status":{...}}`(TestObject_GoldenRoundTrip 已有)
- Produces(后续 Task 2 / 3 / 4 / 5 依赖):
  - `type Metadata struct { ...; UID string `json:"uid,omitempty"`; ResourceVersion string `json:"resource_version,omitempty"` }`
  - `func (m *Metadata) BumpGeneration() int64` —— 递增 `Generation` 并返回新值;**不改** `ResourceVersion`(后者留给 set spec 后的版本调和)

- [ ] **Step 1: 写失败测试 `TestMetadata_BumpGeneration`**

  `daedalus-sdk/objectmodel/envelope_test.go` 追加:

  ```go
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
  ```

- [ ] **Step 2: 跑测试确认失败**

  Run: `cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./objectmodel/... -run TestMetadata_BumpGeneration -v`
  Expected: 编译失败 —— `Metadata.BumpGeneration` 未定义(`m.BumpGeneration undefined`)+ `Metadata` 缺 `UID` / `ResourceVersion` 字段无关(本步骤只对 `BumpGeneration` 失败)。

- [ ] **Step 3: 实现 `Metadata.UID` / `Metadata.ResourceVersion` + `BumpGeneration`**

  `daedalus-sdk/objectmodel/envelope.go` 改 `Metadata` 结构(**只加 UID / ResourceVersion 两字段**,`OwnerReferences` / `Finalizers` 留到 Task 3 连类型一起加 —— 避免占位声明后又要替换的无谓抖动):

  ```go
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
  ```

  同步在 `envelope.go` 末尾(`MatchLabels` 之后)追加方法:

  ```go
  // BumpGeneration 递增期望版本并返回新值。ResourceVersion 由版本调和方管理,
  // 不在本方法动 —— 期望方写 Generation,观测方写 Status.ObservedGeneration 与之
  // 比对;ResourceVersion 是 apiserver 内部单调号,提供者写 spec 时由 provider
  // 自行回填。两者职责切分,BumpGeneration 不得越界。
  func (m *Metadata) BumpGeneration() int64 {
      m.Generation++
      return m.Generation
  }
  ```

- [ ] **Step 4: 写 `TestMetadata_UID_ResourceVersion_OmitEmpty` 与 `TestMetadata_UID_ResourceVersion_RoundTrip`**

  ```go
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
  ```

- [ ] **Step 5: 跑全部 envelope_test 确认既有金样未漂移 + 新测试通过**

  Run: `cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./objectmodel/... -v`
  Expected:
  - `TestObject_GoldenRoundTrip` PASS(want 字面量未改)
  - `TestObject_OmitEmpty` PASS(零值形态未改)
  - `TestMetadata_UID_ResourceVersion_OmitEmpty` PASS
  - `TestMetadata_UID_ResourceVersion_RoundTrip` PASS
  - `TestMetadata_BumpGeneration` PASS(含两个 sub-test)
  - `TestMetadata_BumpGeneration_DoesNotTouchResourceVersion` PASS

- [ ] **Step 6: 跑 SDK 全仓测试确认无连带回归**

  Run: `cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./...`
  Expected: 全部 PASS;特别关注 `policy/`(消费 `AllKinds()`)与 `plugin/manifest_test.go`(消费 `ValidateResource`)的 `enabled_kinds` 三点漂移与资源校验仍全绿。

- [ ] **Step 7: 提交**

  ```bash
  cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk
  git add objectmodel/envelope.go objectmodel/envelope_test.go
  git commit -m "feat(objectmodel): Metadata.UID/ResourceVersion + BumpGeneration writer (sdk#1 A1)"
  ```

  说明:本 Task 只动 `UID` / `ResourceVersion` 两字段;`OwnerReferences` / `Finalizers` 与类型定义在 Task 3 一起加(避免 Task 1 占位类型再被替换的双重 churn)。

---

## Task 2: Label/Annotation writer + `FilterByLabels` 读侧

**Files:**
- Modify: `daedalus-sdk/objectmodel/envelope.go`(加 `SetLabel` / `SetAnnotation` / `HasLabel` + 文件级 `FilterByLabels`)
- Modify: `daedalus-sdk/objectmodel/envelope_test.go`(追加对应测试)

**Interfaces:**
- Consumes:`Metadata.Label` / `Metadata.MatchLabels`(已存在,本 Task 不改)
- Produces:
  - `func (m *Metadata) SetLabel(key, value string)` —— 惰性初始化 nil map;key 空串直接 panic(语义错)
  - `func (m *Metadata) SetAnnotation(key, value string)` —— 同上
  - `func (m *Metadata) HasLabel(key string) bool` —— 读侧,与 `Label` 区分(后者返回 `(string, bool)`,用于需要值的场景)
  - `func FilterByLabels(objs []Object, sel map[string]string) []Object` —— 返回顺序与输入一致;sel 空 → 返回 `slices.Clone(objs)`(**非**原切片别名,Review Focus #2)

- [ ] **Step 1: 写失败测试 `TestMetadata_SetLabel_NilMap` + 三个 writer 测试**

  ```go
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
  ```

- [ ] **Step 2: 跑测试确认失败**

  Run: `cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./objectmodel/... -run 'TestMetadata_SetLabel|TestMetadata_SetAnnotation|TestMetadata_HasLabel' -v`
  Expected: 全部编译失败(`m.SetLabel undefined` 等)。

- [ ] **Step 3: 实现 writer 三件套**

  `daedalus-sdk/objectmodel/envelope.go` 在 `MatchLabels` 之后追加:

  ```go
  // SetLabel 写入标签(key 非空;nil map 惰性初始化)。空 key 视为语义错误,直接
  // panic —— label 是 label selector 的输入,空 key 让 MatchLabels 永远命中,
  // 与"通过 label 筛选"的契约冲突,运行时不能容忍。
  func (m *Metadata) SetLabel(key, value string) {
      if key == "" {
          panic("objectmodel: SetLabel key 不得为空")
      }
      if m.Labels == nil {
          m.Labels = make(map[string]string)
      }
      m.Labels[key] = value
  }

  // SetAnnotation 写入注解(nil map 惰性初始化)。annotation 不进 label selector,
  // 语义与 label 解耦,空 key 不 panic 但也不写入 —— 与 SetLabel 行为差异固定,
  // 避免两者语义混淆。
  func (m *Metadata) SetAnnotation(key, value string) {
      if key == "" {
          return
      }
      if m.Annotations == nil {
          m.Annotations = make(map[string]string)
      }
      m.Annotations[key] = value
  }

  // HasLabel 报告 key 是否存在(nil Labels 视为无命中,安全)。
  func (m *Metadata) HasLabel(key string) bool {
      _, ok := m.Labels[key]
      return ok
  }
  ```

- [ ] **Step 4: 写 `TestFilterByLabels` 三个 sub-test**

  ```go
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
  ```

- [ ] **Step 5: 跑测试确认 FilterByLabels 失败**

  Run: `cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./objectmodel/... -run TestFilterByLabels -v`
  Expected: 编译失败(`FilterByLabels undefined`);前一步的 `SetLabel` / `SetAnnotation` / `HasLabel` 测试已 PASS。

- [ ] **Step 6: 实现 `FilterByLabels`**

  ```go
  // FilterByLabels 返回 metadata 匹配 sel 全部键值对的对象(顺序与入参一致)。
  // sel 空 / nil → 返回全部,语义与 MatchLabels("空选择器恒真")对齐。**返回**的切片
  // 永远是入参的副本(空选择器路径显式 slices.Clone),消费方排序 / 二次筛选不得
  // 回灌原集合。
  func FilterByLabels(objs []Object, sel map[string]string) []Object {
      if len(objs) == 0 {
          return []Object{}
      }
      if len(sel) == 0 {
          return slices.Clone(objs)
      }
      out := make([]Object, 0, len(objs))
      for _, o := range objs {
          if o.Metadata.MatchLabels(sel) {
              out = append(out, o)
          }
      }
      return out
  }
  ```

- [ ] **Step 7: 跑 envelope_test 全集确认无回归**

  Run: `cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./objectmodel/... -v`
  Expected: 全部 PASS;既有 `TestMetadata_LabelSelectors` 仍 PASS(本次新增 writer 与既有 reader 共存)。

- [ ] **Step 8: 跑 SDK 全仓测试确认无连带回归**

  Run: `cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./...`
  Expected: 全部 PASS。

- [ ] **Step 9: 提交**

  ```bash
  cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk
  git add objectmodel/envelope.go objectmodel/envelope_test.go
  git commit -m "feat(objectmodel): SetLabel/SetAnnotation/HasLabel writer + FilterByLabels 读侧 (sdk#1 A1)"
  ```

---

## Task 3: `OwnerReference` / `Finalizer` 类型与 finalizer 增删查

**Files:**
- Modify: `daedalus-sdk/objectmodel/envelope.go`(定义 `OwnerReference` / `Finalizer` 正式类型;在 `Metadata` 结构末尾追加 `OwnerReferences` / `Finalizers` 两字段;为 `Metadata` 加 `AddFinalizer` / `RemoveFinalizer` / `HasFinalizer`)
- Modify: `daedalus-sdk/objectmodel/envelope_test.go`(追加类型金样 + finalizer 增删查)

**Interfaces:**
- Consumes:`Metadata.Finalizers []Finalizer`(Task 1 字段已声明,本 Task 给类型与辅助方法)
- Produces:
  - `type OwnerReference struct { APIVersion string `json:"api_version,omitempty"`; Kind Kind `json:"kind"`; Name string `json:"name"`; UID string `json:"uid,omitempty"`; Controller bool `json:"controller,omitempty"`; BlockOwnerDeletion bool `json:"block_owner_deletion,omitempty"` }`(UID 同样非 NUL / 控制字符约束,Task 4 校验)
  - `type Finalizer string` —— 即终态;无需补 `String() string`(fmt 默认按底层 string 输出)
  - `func (m *Metadata) AddFinalizer(f Finalizer) bool` —— 已存在返回 `false`,新增返回 `true`
  - `func (m *Metadata) RemoveFinalizer(f Finalizer) bool` —— 同上
  - `func (m *Metadata) HasFinalizer(f Finalizer) bool`

- [ ] **Step 1: 写失败测试 `TestOwnerReference_RoundTrip`**

  ```go
  func TestOwnerReference_RoundTrip(t *testing.T) {
      t.Parallel()
      obj := Object{
          Kind: KindService,
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
  ```

- [ ] **Step 2: 写失败测试 `TestFinalizer_AddRemoveHas`**

  ```go
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
  ```

- [ ] **Step 3: 跑测试确认失败**

  Run: `cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./objectmodel/... -run 'TestOwnerReference_RoundTrip|TestFinalizer_AddRemoveHas' -v`
  Expected:
  - `TestOwnerReference_RoundTrip` 编译失败(`OwnerReference` 是空 struct,字段缺失)
  - `TestFinalizer_AddRemoveHas` 编译失败(`m.AddFinalizer undefined`)

- [ ] **Step 4: 实现 `OwnerReference` / `Finalizer` 结构 + `Metadata` 追加两字段**

  `daedalus-sdk/objectmodel/envelope.go`:先在 `Metadata` 结构末尾(`ResourceVersion` 之后)追加两字段:

  ```go
      OwnerReferences []OwnerReference `json:"owner_references,omitempty"`
      Finalizers      []Finalizer      `json:"finalizers,omitempty"`
  ```

  再追加类型定义:

  ```go
  // OwnerReference 指向父对象,用于 ownerRef 链构造父子关系与 GC 拓扑。
  // Kind 必须是已定义的封闭枚举之一(校验由 Validate 集中处理);
  // UID 非空时遵循 Metadata.UID 同规则;APIVersion / Controller /
  // BlockOwnerDeletion 沿用 k8s OwnerReference 字段名,但语义对齐 Daedalus 现状
  // —— GC 逻辑不在 v1 范围(归 P4),字段只是"在场 + 可校验"。
  type OwnerReference struct {
      APIVersion         string `json:"api_version,omitempty"`
      Kind               Kind   `json:"kind"`
      Name               string `json:"name"`
      UID                string `json:"uid,omitempty"`
      Controller         bool   `json:"controller,omitempty"`
      BlockOwnerDeletion bool   `json:"block_owner_deletion,omitempty"`
  }

  // Finalizer 是延迟删除的钩子名(惯例:反向 DNS + 行为短词,如
  // "daedalus.core/protect")。本层只钉类型与增删查;finalizer 触发 GC 的实际
  // 控制器逻辑归 P4。
  type Finalizer string
  ```

- [ ] **Step 5: 实现 `AddFinalizer` / `RemoveFinalizer` / `HasFinalizer`**

  ```go
  // AddFinalizer 追加 finalizer(已存在返回 false,新增返回 true)。空串视作语义错,
  // 拒绝 —— finalizer 是 controller 钩子契约,空字符串让 GC 永远命中"未保护"
  // 分支,运行时不能容忍。
  func (m *Metadata) AddFinalizer(f Finalizer) bool {
      if f == "" {
          return false
      }
      for _, existing := range m.Finalizers {
          if existing == f {
              return false
          }
      }
      m.Finalizers = append(m.Finalizers, f)
      return true
  }

  // RemoveFinalizer 移除 finalizer(已存在返回 true,不在返回 false)。
  func (m *Metadata) RemoveFinalizer(f Finalizer) bool {
      for i, existing := range m.Finalizers {
          if existing != f {
              continue
          }
          m.Finalizers = append(m.Finalizers[:i], m.Finalizers[i+1:]...)
          return true
      }
      return false
  }

  // HasFinalizer 报告 finalizer 是否存在。
  func (m *Metadata) HasFinalizer(f Finalizer) bool {
      for _, existing := range m.Finalizers {
          if existing == f {
              return true
          }
      }
      return false
  }
  ```

- [ ] **Step 6: 跑 envelope_test 全集确认无回归**

  Run: `cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./objectmodel/... -v`
  Expected:
  - `TestOwnerReference_RoundTrip` PASS(新)
  - `TestFinalizer_AddRemoveHas` PASS(新)
  - 既有 `TestObject_GoldenRoundTrip` / `TestObject_OmitEmpty` / `TestMetadata_BumpGeneration*` / `TestMetadata_UID_ResourceVersion_*` / `TestMetadata_LabelSelectors` / `TestMetadata_SetLabel*` / `TestMetadata_SetAnnotation*` / `TestMetadata_HasLabel` / `TestFilterByLabels` 全部 PASS(本 Task 在 `Metadata` 结构末尾追加两字段,既有金样因 `omitempty` 字节不变)

- [ ] **Step 7: 跑 SDK 全仓测试**

  Run: `cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./...`
  Expected: 全 PASS。

- [ ] **Step 8: 提交**

  ```bash
  cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk
  git add objectmodel/envelope.go objectmodel/envelope_test.go
  git commit -m "feat(objectmodel): OwnerReference/Finalizer 类型 + finalizer 增删查 (sdk#1 A4)"
  ```

---

## Task 4: `Metadata.Validate()` + `Object.Validate()` 复合校验

**Files:**
- Create: `daedalus-sdk/objectmodel/validate.go`(把 Validate 抽到独立文件,envelope.go 仅放类型与方法,validate.go 仅放校验逻辑;**单一职责**原则的体现,避免 envelope.go 越长越杂)
- Create: `daedalus-sdk/objectmodel/validate_test.go`(对应表驱动测试)

**Interfaces:**
- Consumes:`Resource.Validate`(已存在,作聚合风格参考);`AllKinds()` / `validKind()`(已存在)
- Produces:
  - `func (m Metadata) Validate() error` —— 聚合下列缺陷一次报错:
    - `Name` 必填、非 NUL、无 `/` 无 `..`(沿用 `Resource.Name` 规则);
    - `UID` 非空时不得含 NUL / 控制字符(`< 0x20` 或 `= 0x7f`),长度 ≤ 253;
    - `ResourceVersion` 非空时仅校验非 NUL;
    - 每个 `OwnerReference`: `Kind` 必须命中 `AllKinds()`;`Name` 必填、非 NUL、无 `/` 无 `..`;`UID` 同 Metadata.UID 规则;
    - 每个 `Finalizer`: 非空、非 NUL、无重复(`HasFinalizer` 检查后报);
  - `func (o Object) Validate() error` —— 复合校验,顺序: `Kind.Validate`(走 `AllKinds()`)→ `Metadata.Validate()` → `Spec` 是合法 JSON 或空(`json.Valid` 检查);聚合全部缺陷一次性报错(Review Focus #4)

- [ ] **Step 1: 写失败测试 `TestMetadata_Validate` 表驱动(接受 + 拒绝)**

  `daedalus-sdk/objectmodel/validate_test.go`(新文件):

  ```go
  package objectmodel

  import (
      "strings"
      "testing"
  )

  // TestMetadata_Validate 锁定接受路径 + reject 各分支;聚合错误必须点名字段。
  func TestMetadata_Validate(t *testing.T) {
      t.Parallel()
      accept := []struct {
          name string
      }{ // 接受路径覆盖正常 + 7 Kind ownerRef + 多 finalizer
          {"合法最小"}, {"含 UID/ResourceVersion"},
          {"含 ownerRef (Kind 合法)"}, {"含多 finalizer 不重复"},
      }
      // 接受路径
      t.Run("接受", func(t *testing.T) {
          t.Parallel()
          cases := []Metadata{
              {Name: "x"},
              {Name: "x", UID: "u-1", ResourceVersion: "rv-1"},
              {Name: "x", OwnerReferences: []OwnerReference{{Kind: KindService, Name: "parent"}}},
              {Name: "x", Finalizers: []Finalizer{"a.example/x", "b.example/y"}},
          }
          for _, m := range cases {
              if err := m.Validate(); err != nil {
                  t.Errorf("合法被拒: %v / %+v", err, m)
              }
          }
      })

      // 拒绝路径,逐字段。
      t.Run("拒绝", func(t *testing.T) {
          t.Parallel()
          cases := []struct {
              name    string
              m       Metadata
              wantSub []string
          }{
              {"空 Name", Metadata{}, []string{"name"}},
              {"Name 含 NUL", Metadata{Name: "a\x00b"}, []string{"name"}},
              {"Name 含 /", Metadata{Name: "a/b"}, []string{"name"}},
              {"Name 含 ..", Metadata{Name: "../x"}, []string{"name"}},
              {"UID 含 NUL", Metadata{Name: "x", UID: "u\x00"}, []string{"uid"}},
              {"UID 含控制字符", Metadata{Name: "x", UID: "u\x07"}, []string{"uid"}},
              {"UID 超长", Metadata{Name: "x", UID: strings.Repeat("a", 254)}, []string{"uid"}},
              {"ResourceVersion 含 NUL", Metadata{Name: "x", ResourceVersion: "rv\x00"}, []string{"resource_version"}},
              {"OwnerReference 缺 Kind", Metadata{Name: "x", OwnerReferences: []OwnerReference{{Name: "p"}}}, []string{"owner_references[0].kind"}},
              {"OwnerReference 未知 Kind", Metadata{Name: "x", OwnerReferences: []OwnerReference{{Kind: Kind("alien"), Name: "p"}}}, []string{"owner_references[0].kind"}},
              {"OwnerReference 空 Name", Metadata{Name: "x", OwnerReferences: []OwnerReference{{Kind: KindService}}}, []string{"owner_references[0].name"}},
              {"OwnerReference UID 含 NUL", Metadata{Name: "x", OwnerReferences: []OwnerReference{{Kind: KindService, Name: "p", UID: "u\x00"}}}, []string{"owner_references[0].uid"}},
              {"Finalizer 空串", Metadata{Name: "x", Finalizers: []Finalizer{""}}, []string{"finalizers[0]"}},
              {"Finalizer 含 NUL", Metadata{Name: "x", Finalizers: []Finalizer{"a\x00b"}}, []string{"finalizers[0]"}},
              {"Finalizer 重复", Metadata{Name: "x", Finalizers: []Finalizer{"a/x", "a/x"}}, []string{"finalizers"}},
          }
          for _, tc := range cases {
              t.Run(tc.name, func(t *testing.T) {
                  t.Parallel()
                  err := tc.m.Validate()
                  if err == nil {
                      t.Fatalf("非法被接受: %+v", tc.m)
                  }
                  msg := strings.ToLower(err.Error())
                  for _, want := range tc.wantSub {
                      if !strings.Contains(msg, want) {
                          t.Errorf("错误缺 %q 子串: %v", want, err)
                      }
                  }
              })
          }
      })

      // 聚合:多个缺陷一次性返回。
      t.Run("聚合", func(t *testing.T) {
          t.Parallel()
          m := Metadata{UID: "\x00", Finalizers: []Finalizer{"", "a\x00"}}
          err := m.Validate()
          if err == nil {
              t.Fatal("多缺陷被接受")
          }
          msg := strings.ToLower(err.Error())
          for _, want := range []string{"uid", "finalizers"} {
              if !strings.Contains(msg, want) {
                  t.Errorf("聚合错误缺 %q: %v", want, err)
              }
          }
      })
  }
  ```

- [ ] **Step 2: 跑测试确认失败**

  Run: `cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./objectmodel/... -run TestMetadata_Validate -v`
  Expected: 编译失败(`Metadata.Validate undefined`)。

- [ ] **Step 3: 创建 `validate.go`(独立文件,envelope.go 维持类型/方法,不混入校验体)**

  `daedalus-sdk/objectmodel/validate.go`(新文件):

  ```go
  // 校验逻辑独立成文件:envelope.go 装类型与构造/查询方法,validate.go 装
  // Validate 方法,二者互不交叉引用,改一处不需扫另一处。
  package objectmodel

  import (
      "encoding/json"
      "fmt"
      "strings"
      "unicode"
  )

  // uidMaxLen 与 k8s apiserver 同:留连接空间(多个 UID 拼成路径不超 unix NAME_MAX)。
  const uidMaxLen = 253

  // 控制字符检测:0x00–0x1f 与 0x7f。
  func hasControlChar(s string) bool {
      for _, r := range s {
          if r == 0x7f || unicode.IsControl(r) {
              return true
          }
      }
      return false
  }

  // Validate 聚合 Metadata 全部缺陷一次性返回(fail-closed,与 Resource.Validate 风格一致)。
  func (m Metadata) Validate() error {
      var problems []string

      switch {
      case m.Name == "":
          problems = append(problems, `字段 "name" 缺失:必填`)
      default:
          if strings.IndexByte(m.Name, 0) >= 0 {
              problems = append(problems, `字段 "name" 非法:不得包含空字节(\0)`)
          }
          if strings.ContainsRune(m.Name, '/') {
              problems = append(problems, `字段 "name" 非法:不得包含路径分隔符 '/'`)
          }
          if strings.Contains(m.Name, "..") {
              problems = append(problems, `字段 "name" 非法:不得包含路径回溯段 ".."`)
          }
      }

      if m.UID != "" {
          if hasControlChar(m.UID) {
              problems = append(problems, `字段 "uid" 非法:不得包含控制字符`)
          }
          if len(m.UID) > uidMaxLen {
              problems = append(problems, fmt.Sprintf(`字段 "uid" 非法:长度 %d 超过上限 %d`, len(m.UID), uidMaxLen))
          }
      }
      if m.ResourceVersion != "" && strings.IndexByte(m.ResourceVersion, 0) >= 0 {
          problems = append(problems, `字段 "resource_version" 非法:不得包含空字节(\0)`)
      }

      seenFinalizers := make(map[Finalizer]struct{}, len(m.Finalizers))
      for i, f := range m.Finalizers {
          if f == "" {
              problems = append(problems, fmt.Sprintf(`字段 "finalizers[%d]" 非法:不得为空字符串`, i))
              continue
          }
          if strings.IndexByte(string(f), 0) >= 0 {
              problems = append(problems, fmt.Sprintf(`字段 "finalizers[%d]" 非法:不得包含空字节(\0)`, i))
              continue
          }
          if _, dup := seenFinalizers[f]; dup {
              problems = append(problems, fmt.Sprintf(`字段 "finalizers" 非法:finalizer %q 重复`, f))
          }
          seenFinalizers[f] = struct{}{}
      }

      for i, or := range m.OwnerReferences {
          prefix := fmt.Sprintf("owner_references[%d]", i)
          if or.Kind == "" {
              problems = append(problems, fmt.Sprintf(`字段 "%s.kind" 缺失:必填`, prefix))
          } else if !validKind(or.Kind) {
              problems = append(problems, fmt.Sprintf(`字段 "%s.kind" 非法:%q 不在资源类别枚举内`, prefix, or.Kind))
          }
          switch {
          case or.Name == "":
              problems = append(problems, fmt.Sprintf(`字段 "%s.name" 缺失:必填`, prefix))
          default:
              if strings.IndexByte(or.Name, 0) >= 0 {
                  problems = append(problems, fmt.Sprintf(`字段 "%s.name" 非法:不得包含空字节(\0)`, prefix))
              }
              if strings.ContainsRune(or.Name, '/') {
                  problems = append(problems, fmt.Sprintf(`字段 "%s.name" 非法:不得包含路径分隔符 '/'`, prefix))
              }
              if strings.Contains(or.Name, "..") {
                  problems = append(problems, fmt.Sprintf(`字段 "%s.name" 非法:不得包含路径回溯段 ".."`, prefix))
              }
          }
          if or.UID != "" {
              if hasControlChar(or.UID) {
                  problems = append(problems, fmt.Sprintf(`字段 "%s.uid" 非法:不得包含控制字符`, prefix))
              }
              if len(or.UID) > uidMaxLen {
                  problems = append(problems, fmt.Sprintf(`字段 "%s.uid" 非法:长度 %d 超过上限 %d`, prefix, len(or.UID), uidMaxLen))
              }
          }
      }

      if len(problems) > 0 {
          return fmt.Errorf("objectmodel: Metadata 校验失败: %s", strings.Join(problems, "; "))
      }
      return nil
  }

  // Validate 聚合 Object 全部缺陷一次性返回。顺序:Kind → Metadata → Spec。
  // Spec 走 json.Valid 空字符串视为合法(零值形态);非空但非合法 JSON 即拒。
  func (o Object) Validate() error {
      var problems []string

      if o.Kind == "" {
          problems = append(problems, `字段 "kind" 缺失:必填`)
      } else if !validKind(o.Kind) {
          problems = append(problems, fmt.Sprintf(`字段 "kind" 非法:%q 不在资源类别枚举内`, o.Kind))
      }

      if err := o.Metadata.Validate(); err != nil {
          problems = append(problems, err.Error())
      }

      if len(o.Spec) > 0 && !json.Valid(o.Spec) {
          problems = append(problems, `字段 "spec" 非法:非合法 JSON`)
      }

      if len(problems) > 0 {
          return fmt.Errorf("objectmodel: Object 校验失败: %s", strings.Join(problems, "; "))
      }
      return nil
  }
  ```

- [ ] **Step 4: 跑 validate_test 确认通过**

  Run: `cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./objectmodel/... -run TestMetadata_Validate -v`
  Expected: 全部 PASS(含"接受" / "拒绝" / "聚合"三个 sub-test)。

- [ ] **Step 5: 写 `TestObject_Validate` 表驱动**

  `daedalus-sdk/objectmodel/validate_test.go` 追加:

  ```go
  func TestObject_Validate(t *testing.T) {
      t.Parallel()

      t.Run("接受", func(t *testing.T) {
          t.Parallel()
          cases := []Object{
              {Kind: KindService, Metadata: Metadata{Name: "x"}, Spec: json.RawMessage(`{"desired_state":"active"}`)},
              {Kind: KindService, Metadata: Metadata{Name: "x"}, Spec: nil},
              {Kind: KindService, Metadata: Metadata{Name: "x"}, Spec: json.RawMessage(`null`)},
          }
          for _, o := range cases {
              if err := o.Validate(); err != nil {
                  t.Errorf("合法 Object 被拒: %v / %+v", err, o)
              }
          }
      })

      t.Run("拒绝", func(t *testing.T) {
          t.Parallel()
          cases := []struct {
              name    string
              o       Object
              wantSub []string
          }{
              {"空 Kind", Object{Metadata: Metadata{Name: "x"}}, []string{"kind"}},
              {"未知 Kind", Object{Kind: Kind("alien"), Metadata: Metadata{Name: "x"}}, []string{"kind"}},
              {"Metadata 缺 Name", Object{Kind: KindService}, []string{"name"}},
              {"Spec 非合法 JSON", Object{Kind: KindService, Metadata: Metadata{Name: "x"}, Spec: json.RawMessage(`{not json`)}, []string{"spec"}},
          }
          for _, tc := range cases {
              t.Run(tc.name, func(t *testing.T) {
                  t.Parallel()
                  err := tc.o.Validate()
                  if err == nil {
                      t.Fatalf("非法被接受: %+v", tc.o)
                  }
                  msg := strings.ToLower(err.Error())
                  for _, want := range tc.wantSub {
                      if !strings.Contains(msg, want) {
                          t.Errorf("错误缺 %q: %v", want, err)
                      }
                  }
              })
          }
      })
  }
  ```

  顶部 imports 加 `"encoding/json"`。

- [ ] **Step 6: 跑 envelope_test + validate_test 全集**

  Run: `cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./objectmodel/... -v`
  Expected:
  - `TestMetadata_Validate*` PASS(Task 4 新)
  - `TestObject_Validate*` PASS(Task 4 新)
  - 既有 envelope_test 全部 PASS(本 Task 只加文件,envelope.go 字节不变)

- [ ] **Step 7: 跑 SDK 全仓测试**

  Run: `cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./...`
  Expected: 全 PASS(本 Task 引入新导出方法 `Metadata.Validate` / `Object.Validate`,既有调用方零回归)。

- [ ] **Step 8: 提交**

  ```bash
  cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk
  git add objectmodel/validate.go objectmodel/validate_test.go
  git commit -m "feat(objectmodel): Metadata.Validate + Object.Validate 复合校验 (sdk#1 A1/A4)"
  ```

---

## Task 5: SDK ↔ core controller 全字段金样锁步 + 文档同步

**Files:**
- Modify: `daedalus-sdk/objectmodel/envelope_test.go`(加 `TestObject_GoldenRoundTrip_FullMetadata`,引用 Task 1 / 3 已交付字段)
- Modify: `daedalus-core/internal/controller/types.go`(别名块扩 `OwnerReference` / `Finalizer`)
- Modify: `daedalus-core/internal/controller/types_test.go`(加 `TestObject_EnvelopeBytes_MatchSDK`,引用同一 `want` 字面量常量)
- Modify: `daedalus-core/VISION.md`(§5 行 129 / 130 / 131 / 142,§8 行 216 / 219,§10 行 267 状态更新)
- Modify: `daedalus-sdk/AGENTS.md`(CODE MAP 行 64 / 65 增补本 plan 落地的 writer / Validate / 类型;CONVENTIONS 行 129 增补"新增字段三步走")

**Interfaces:**
- Consumes:`daedalus-sdk/objectmodel.Metadata` / `OwnerReference` / `Finalizer` / `BumpGeneration` / `SetLabel` / `SetAnnotation` / `AddFinalizer` / `Validate`(Task 1–4 全部交付)
- Produces:
  - 单一字符串字面量常量 `envelopeFullGoldenJSON`,SDK 端与 core controller 端两侧测试都 import 同一字面量;**任何一侧改动另一侧编译失败**(Review Focus #5)
  - VISION 状态行更新:metadata 填充方已交付 / UID 与 ResourceVersion 已交付 / ownerRef finalizer 字段已交付(GC 归 P4)

- [ ] **Step 1: 在 SDK envelope_test.go 加全字段金样**

  `daedalus-sdk/objectmodel/envelope_test.go` 追加:

  ```go
  // TestObject_GoldenRoundTrip_FullMetadata 锁全字段(UID / ResourceVersion /
  // OwnerReferences / Finalizers)的字节形态。该 want 字面量同时被
  // daedalus-core/internal/controller/types_test.go 引用(Review Focus #5),
  // 任何一侧漂移另一侧编译失败。
  func TestObject_GoldenRoundTrip_FullMetadata(t *testing.T) {
      t.Parallel()
      obj := Object{
          APIVersion: "v1",
          Kind:       KindService,
          Metadata: Metadata{
              Name:            "sshd.service",
              Labels:          map[string]string{"app": "sshd"},
              Annotations:     map[string]string{"owner": "daedalus"},
              Generation:      7,
              UID:             "sshd-uid-1",
              ResourceVersion: "rv-9",
              OwnerReferences: []OwnerReference{{Kind: KindService, Name: "parent.service"}},
              Finalizers:      []Finalizer{"daedalus.core/protect"},
          },
          Spec: json.RawMessage(`{"desired_state":"active"}`),
          Status: Status{
              ObservedGeneration: 6,
              Conditions: []Condition{{
                  Type:               "Ready",
                  Status:             ConditionTrue,
                  Reason:             "AsExpected",
                  Message:            "unit active",
                  LastTransitionTime: time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC),
              }},
              Properties: map[string]string{"ActiveState": "active"},
          },
      }
      b, err := json.Marshal(obj)
      if err != nil {
          t.Fatal(err)
      }
      want := `{"api_version":"v1","kind":"service","metadata":{"name":"sshd.service","labels":{"app":"sshd"},"annotations":{"owner":"daedalus"},"generation":7,"uid":"sshd-uid-1","resource_version":"rv-9","owner_references":[{"kind":"service","name":"parent.service"}],"finalizers":["daedalus.core/protect"]},"spec":{"desired_state":"active"},"status":{"observed_generation":6,"conditions":[{"type":"Ready","status":"True","reason":"AsExpected","message":"unit active","last_transition_time":"2026-10-10T00:00:00Z"}],"properties":{"ActiveState":"active"}}}`
      if string(b) != want {
          t.Fatalf("Envelope 全字段金样漂移:\n got %s\nwant %s", b, want)
      }

      var back Object
      if err := json.Unmarshal(b, &back); err != nil {
          t.Fatal(err)
      }
      if !reflect.DeepEqual(obj, back) {
          t.Fatalf("往返不等:\n got %#v\nwant %#v", back, obj)
      }
  }

  // TestUpsertCondition_SameStatusDoesNotRefreshTime 钉死"同状态写回不刷转换时刻"
  // 行为,防止 controller P4 落地时被静默刷新(Review Focus #3)。
  func TestUpsertCondition_SameStatusDoesNotRefreshTime(t *testing.T) {
      t.Parallel()
      base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
      st := Status{Conditions: []Condition{{
          Type: "Ready", Status: ConditionTrue, Reason: "R1", Message: "M1", LastTransitionTime: base,
      }}}
      st.UpsertCondition(Condition{
          Type: "Ready", Status: ConditionTrue, Reason: "R2", Message: "M2", LastTransitionTime: time.Now().UTC(),
      })
      if !st.Conditions[0].LastTransitionTime.Equal(base) {
          t.Fatalf("同状态写回刷了 LastTransitionTime: got %v, want %v",
              st.Conditions[0].LastTransitionTime, base)
      }
      if st.Conditions[0].Reason != "R2" || st.Conditions[0].Message != "M2" {
          t.Fatalf("同状态写回应更新 reason/message: got %#v", st.Conditions[0])
      }
  }
  ```

- [ ] **Step 2: 跑 SDK 全字段金样确认通过**

  Run: `cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./objectmodel/... -run 'TestObject_GoldenRoundTrip_FullMetadata|TestUpsertCondition_SameStatusDoesNotRefreshTime' -v`
  Expected: 全 PASS。

- [ ] **Step 3: 在 core controller types_test.go 加 SDK 锁步金样**

  `daedalus-core/internal/controller/types_test.go` 追加(顶部已有 `import` 块):

  ```go
  // TestObject_EnvelopeBytes_MatchSDK 锁 SDK objectmodel 包与本 controller
  // 别名包的 JSON 字节形态完全一致 —— 别名偷换形态(改 SDK 字段 / tag / 顺序)
  // 必须使本测试编译失败或失败,防止 v1 线上契约漂移(Review Focus #5)。
  //
  // 这里**复制**了 SDK TestObject_GoldenRoundTrip_FullMetadata 的 want 字面量
  // (controller 是 internal 包,无法直接 import objectmodel 的测试常量;
  // 字面量复制是刻意的锁步机制,改一处必须同时改另一处)。
  func TestObject_EnvelopeBytes_MatchSDK(t *testing.T) {
      obj := Object{
          APIVersion: "v1",
          Kind:       "service",
          Metadata: Metadata{
              Name:            "sshd.service",
              Labels:          map[string]string{"app": "sshd"},
              Annotations:     map[string]string{"owner": "daedalus"},
              Generation:      7,
              UID:             "sshd-uid-1",
              ResourceVersion: "rv-9",
              OwnerReferences: []OwnerReference{{Kind: "service", Name: "parent.service"}},
              Finalizers:      []Finalizer{"daedalus.core/protect"},
          },
          Spec: json.RawMessage(`{"desired_state":"active"}`),
          Status: Status{
              ObservedGeneration: 6,
              Conditions: []Condition{{
                  Type:               "Ready",
                  Status:             "True",
                  Reason:             "AsExpected",
                  Message:            "unit active",
                  LastTransitionTime: time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC),
              }},
              Properties: map[string]string{"ActiveState": "active"},
          },
      }
      b, err := json.Marshal(obj)
      if err != nil {
          t.Fatal(err)
      }
      want := `{"api_version":"v1","kind":"service","metadata":{"name":"sshd.service","labels":{"app":"sshd"},"annotations":{"owner":"daedalus"},"generation":7,"uid":"sshd-uid-1","resource_version":"rv-9","owner_references":[{"kind":"service","name":"parent.service"}],"finalizers":["daedalus.core/protect"]},"spec":{"desired_state":"active"},"status":{"observed_generation":6,"conditions":[{"type":"Ready","status":"True","reason":"AsExpected","message":"unit active","last_transition_time":"2026-10-10T00:00:00Z"}],"properties":{"ActiveState":"active"}}}`
      if string(b) != want {
          t.Fatalf("controller 别名与 SDK envelope 字节漂移:\n got %s\nwant %s", b, want)
      }
  }
  ```

  注意:`controller/types.go` 现有别名块含 `Object/Metadata/Status/Condition`,但缺 `OwnerReference` / `Finalizer`。本 Step 先扩 `daedalus-core/internal/controller/types.go` 的 `type (...)` 别名块(与同款别名并列):

  ```go
      OwnerReference = objectmodel.OwnerReference
      Finalizer      = objectmodel.Finalizer
  ```

  随后 controller 测试代码即可写 `[]OwnerReference{...}` / `[]Finalizer{...}`,与 SDK 端字面量字节一致;别名链扩到 A4 字段,SDK ↔ controller 同步漂移。

  顶部 `types_test.go` 已 import `encoding/json` / `time` / `reflect`,无需新增 import。

- [ ] **Step 4: 跑 core controller 测试确认无回归**

  Run: `cd /var/lofibass_ssd/code/Daedalus/daedalus-core && go test ./internal/controller/... -v`
  Expected:
  - 既有 `TestObject_GoldenRoundTrip` PASS(want 不变)
  - 新增 `TestObject_EnvelopeBytes_MatchSDK` PASS

- [ ] **Step 5: 跑两个仓的全仓测试**

  Run:
  ```bash
  cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./...
  cd /var/lofibass_ssd/code/Daedalus/daedalus-core && go test ./...
  ```
  Expected: 两仓全绿;特别关注 `daedalus-core/internal/desiredview`(消费 `objectmodel.Kind` / `KindService` / `KindPackage`)与 `daedalus-plugins/service` 仓后续测试(本次不动)。

- [ ] **Step 6: 同步 `daedalus-core/VISION.md` 三处状态行**

  **§5 k8s-parity 表行 129**(`metadata.labels / annotations / generation`),原文:
  ```
  | metadata.labels / annotations / generation | 信封 `objectmodel.Metadata` 已在场,读侧 `MatchLabels`;尚无填充方 | A | P4 填值 |
  ```
  改为:
  ```
  | metadata.labels / annotations / generation | 信封 `objectmodel.Metadata` 已在场;读侧 `MatchLabels` + `FilterByLabels` 列表筛选;写侧 `SetLabel` / `SetAnnotation` / `BumpGeneration` 已交付(sdk#1 P3,2026-10-10) | A | v1 已交付 |
  ```

  **§5 行 130**(`metadata.uid`),原文:
  ```
  | metadata.uid | 无 | A | when-needed |
  ```
  改为:
  ```
  | metadata.uid | `Metadata.UID` 已交付;校验非空时无控制字符 + 长度 ≤ 253(sdk#1 P3) | A | v1 已交付 |
  ```

  **§5 行 131**(`metadata.resourceVersion`),原文:
  ```
  | metadata.resourceVersion | 无(tx 单写者) | A | when-needed |
  ```
  改为:
  ```
  | metadata.resourceVersion | `Metadata.ResourceVersion` 已交付;`BumpGeneration` 不动它,由 provider 在 set spec 后回填(sdk#1 P3) | A | v1 已交付 |
  ```

  **§5 行 142**(`finalizer / ownerRef / GC`),原文:
  ```
  | finalizer / ownerRef / GC | 无 | A | when-needed(随 delete 适配器) |
  ```
  改为:
  ```
  | finalizer / ownerRef / GC | `Metadata.OwnerReferences` / `Metadata.Finalizers` 字段 + `Validate` 已交付(sdk#1 P3);GC 触发逻辑归 P4 | A | P4 |
  ```

  **§8 A 层行 216**(`metadata 块`),原文:
  ```
  | metadata 块 | 信封 `Metadata{name,labels,annotations,generation}` 已在;`Resource` 声明仍 3 字段 | 按标签筛选的消费者是调和循环,声明侧预先造值只会得到空格 |
  ```
  改为:
  ```
  | metadata 块 | 信封 `Metadata{name,labels,annotations,generation,uid,resource_version,owner_references,finalizers}` 全字段已交付;writer 端 `BumpGeneration`/`SetLabel`/`SetAnnotation`/`AddFinalizer` 在场(sdk#1 P3) | 按标签筛选的消费者是调和循环(P4);声明侧预先造值只会得到空格 |
  ```

  **§8 行 219**(`ownerRef / finalizer`),原文:
  ```
  | ownerRef / finalizer | 无父子、无延迟删除 | 先有 delete 适配器,才谈延迟删除 |
  ```
  改为:
  ```
  | ownerRef / finalizer | 字段在场 + 校验在场(sdk#1 P3);无 GC 触发逻辑 | GC 归 P4 |
  ```

  **§10 行 267**(P3 行),原文:
  ```
  | P3 | 契约类型被真实消费(Condition、Generation) | **Condition 已交付**(2026-09-26:信封升入 SDK、`service.query` 产出 `Ready`);Generation 字段在场但无填充方,其消费者是 P4 投影管道 |
  ```
  改为:
  ```
  | P3 | 契约类型被真实消费(Condition、Generation) | **已完成**(2026-10-10):Condition 已交付(2026-09-26,`service.query` 产出 `Ready`);Generation 字段 + `BumpGeneration` writer 已交付;`Metadata.UID` / `ResourceVersion` / `OwnerReferences` / `Finalizers` 字段 + `Validate` 已交付(sdk#1 plan `2026-10-10-vision-p3-object-model.md`);其消费者(controller 调和循环 + finalizer GC)归 P4 投影管道 |
  ```

- [ ] **Step 7: 同步 `daedalus-sdk/AGENTS.md` CODE MAP 与 CONVENTIONS**

  **CODE MAP 行 64**(原文):
  ```
  | `objectmodel.Resource` / `Kind` | `objectmodel/objectmodel.go` | 三字段元组 (kind/name/desired_state);Kind 封闭枚举 7 类 |
  ```
  改为:
  ```
  | `objectmodel.Resource` / `Kind` / `AllKinds` | `objectmodel/objectmodel.go` | 三字段元组 (kind/name/desired_state);Kind 封闭枚举 7 类 + 漂移金丝雀锁 |
  ```

  **CODE MAP 行 65**(原文):
  ```
  | `objectmodel.Object` / `Condition` | `objectmodel/envelope.go` | spec/status 信封;`Resource.Object()` 与 `ServiceState.Object()` 双投影,`UpsertCondition`/`MatchLabels` 读写侧 API;`internal/controller` 的同名类型是本包别名 |
  ```
  改为:
  ```
  | `objectmodel.Object` / `Metadata` / `Condition` / `OwnerReference` / `Finalizer` | `objectmodel/envelope.go` + `objectmodel/validate.go` | spec/status 信封(全字段:UID / ResourceVersion / OwnerReferences / Finalizers);`Resource.Object()` 与 `ServiceState.Object()` 双投影;writer `BumpGeneration` / `SetLabel` / `SetAnnotation` / `AddFinalizer` / `RemoveFinalizer`,reader `MatchLabels` / `FilterByLabels` / `HasFinalizer`,校验 `Metadata.Validate` / `Object.Validate`(sdk#1 P3);`internal/controller` 的同名类型是本包别名 |
  ```

  **CONVENTIONS 行 129**(原文):
  ```
  - 新增 SDK 包 = 在根加新目录 + 同步更新 README「包索引」表;新增 Kind 必经 `objectmodel/Kind` 常量 + `kindRegistry` + 校验分支 + `policy.toml [objectmodel].enabled_kinds` 三处漂移测试。
  ```
  改为(追加第二句,**不**替换原句):
  ```
  - 新增 SDK 包 = 在根加新目录 + 同步更新 README「包索引」表;新增 Kind 必经 `objectmodel/Kind` 常量 + `kindRegistry` + 校验分支 + `policy.toml [objectmodel].enabled_kinds` 三处漂移测试。
  - 新增 `objectmodel.Metadata` 字段 = 在结构末尾追加 + `omitempty` + 既有零值金样字面量不动 + `TestObject_GoldenRoundTrip_FullMetadata` 与 `daedalus-core/internal/controller/types_test.go` 的 `TestObject_EnvelopeBytes_MatchSDK` 两侧同步更新(改一处致另一处编译失败)。
  ```

- [ ] **Step 8: 跑两仓全仓测试确认文档同步未引入漂移**

  Run:
  ```bash
  cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk && go test ./...
  cd /var/lofibass_ssd/code/Daedalus/daedalus-core && go test ./...
  ```
  Expected: 两仓全绿(本 Task 文档改动不影响代码)。

- [ ] **Step 9: 提交(分两仓独立提交)**

  ```bash
  cd /var/lofibass_ssd/code/Daedalus/daedalus-sdk
  git add objectmodel/envelope_test.go AGENTS.md
  git commit -m "feat(objectmodel): 全字段金样 + 文档同步 (sdk#1 P3 收尾)"

  cd /var/lofibass_ssd/code/Daedalus/daedalus-core
  git add internal/controller/types.go internal/controller/types_test.go VISION.md
  git commit -m "test(controller): 锁步 SDK envelope 全字段金样 + VISION P3 状态更新 (sdk#1 收尾)"
  ```

- [ ] **Step 10: 在 sdk#1 issue 上回帖收尾**

  Run:
  ```bash
  gh issue comment 1 --repo Daedalusys/daedalus-sdk --body "P3 落地完成(plan: daedalus-sdk/docs/superpowers/plans/2026-10-10-vision-p3-object-model.md)。
  *
  *A1(metadata 块) — Metadata 增 UID + ResourceVersion + 写侧 BumpGeneration + SetLabel/SetAnnotation/FilterByLabels 列表筛选;
  *A3(Conditions) — 既有 Condition + UpsertCondition + 三态 token 已交付(2026-09-26),本 plan 钉 '同状态写回不刷转换时刻' 测试;
  *A4(ownerRef/finalizer) — OwnerReference + Finalizer 类型 + Metadata 字段 + Validate + AddFinalizer/RemoveFinalizer/HasFinalizer 增删查。
  *
  *SDK ↔ core controller 两侧信封字节锁步:TestObject_GoldenRoundTrip_FullMetadata ↔ TestObject_EnvelopeBytes_MatchSDK,改一侧致另一侧编译失败。
  *
  *VISION §5 / §8 / §10 状态行 + AGENTS.md CODE MAP / CONVENTIONS 同步更新;controller 是别名链扩 OwnerReference/Finalizer。
  *
  *未做(归 P4):GC 触发逻辑;finalizer 钩子实际执行;reconcile 循环(P4 整体)。"
  gh issue edit 1 --repo Daedalusys/daedalus-sdk --add-label "area:sdk,completed" 2>/dev/null || true
  ```

  Expected: 评论发送成功;label 视权限可能失败,无所谓。

---

## Self-Review 结论

按 writing-plans 规范五项自检:

1. **Spec 覆盖**(对照 sdk#1 issue 四个子项 + 共同要点):
   - A1 metadata 块 → Task 1(UID + ResourceVersion + BumpGeneration) + Task 2(SetLabel/SetAnnotation + FilterByLabels)
   - A2 spec/status 分离 → 已交付,本 plan 不动(基线盘点已记)
   - A3 Conditions → 已交付,本 plan 只在 Task 5 钉"同状态不刷转换时刻"测试
   - A4 ownerRef / finalizer → Task 3(类型) + Task 4(校验)
   - "现有 7 类 kind 全部按新 schema 改造" → 不需要(本 plan 全部新字段均为 `omitempty`,既有 `Resource.Validate` / `Resource.Object()` 投影零变化)
   - "审计链 TxID/TxStep/TxPrevHash 字段不变" → 本 plan 不动 `state` / audit 包
   - "三点漂移测试同步" → `TestObjectModel_Drift`(enabled_kinds 三点)不动;信封字节三点 = Task 5 的 SDK ↔ core controller 锁步金样
   - "框架验证:metadata 真的有人填" → Task 1(BumpGeneration)+ Task 2(SetLabel/SetAnnotation)就是填充方;Label 读侧筛选消费方是 P4 controller,但 Task 2 提供 `FilterByLabels` 入口供其消费
   - "框架验证:Conditions 写回的权威时点" → Task 5 `TestUpsertCondition_SameStatusDoesNotRefreshTime` 钉 P4 之前的当前约定(provider 在 set/apply 后写回,UpsertCondition 同状态不刷时间)

2. **Step scan**: 每 Step 一个动作 + 一个可检查结果;无 "TBD" / "handle edge cases" / 任何多余函数体;Task 3 Step 5 finalizer 增删查有完整算法 body(因三个方法签名 + 测试不足以唯一确定边界条件——空串拒绝 + 重复返回 false 等需要在 body 中显式表达)。

3. **类型一致性**: `Metadata.UID` / `ResourceVersion` / `OwnerReferences` / `Finalizers` 字段声明顺序一致(全部在 `Generation` 之后);`OwnerReference` 字段在 Task 3 与 Task 5 SDK / controller 两侧同字段同名同类型;`Finalizer` 在两侧均为 `type Finalizer string`;`BumpGeneration()` / `SetLabel` / `SetAnnotation` / `HasLabel` / `AddFinalizer` / `RemoveFinalizer` / `HasFinalizer` / `FilterByLabels` / `Metadata.Validate` / `Object.Validate` 在 SDK 侧定义后,controller 侧只用别名,无第二份签名。

4. **Review Focus**:
   - #1 空 labels map 惰性初始化 → Task 2 `TestMetadata_SetLabel_NilMap` + `TestMetadata_SetAnnotation_NilMap`
   - #2 `FilterByLabels` 空选择器返回副本 → Task 2 `TestFilterByLabels_空选择器返回副本`
   - #3 UpsertCondition 同状态不刷转换时刻 → Task 5 `TestUpsertCondition_SameStatusDoesNotRefreshTime`
   - #4 Object.Validate 复合校验顺序 → Task 4 `TestObject_Validate` 拒绝路径四个 case 含"未知 Kind / Metadata 缺 Name / Spec 非合法 JSON",顺序由 `validate.go` 实现固定
   - #5 SDK ↔ core controller 锁步 → Task 5 两侧金样字面量,改一处另一侧编译失败

5. **比例**: 计划约 1315 行,代码体量预计 envelope.go 增 ~110 行 + 新增 validate.go ~120 行 + 新增测试 ~250 行 ≈ 480 行 —— 比约 2.7:1,逼近 writing-plans 的 3:1 健康上限,主要权重在三类不可避免的精确值上:金样 JSON 字面量(Task 3 / Task 5 两侧同一串)、`go test` 命令 + Expected 输出契约、VISION 与 AGENTS.md 的原文/改文字节对(文档同步是 spec 的直接要求)。已就 Step 撰写做了去重:同一接口不在多任务重写 body,后续任务通过 Interfaces — Consumes 引用前序给出签名。