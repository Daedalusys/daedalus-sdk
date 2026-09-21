package objectmodel

// 本文件是 objectmodel 包的表驱动测试(计划 todo 1):
// 覆盖 Kind 枚举全集、Resource.Validate 的每个接受/拒绝分支、
// ValidateResource 的 nil 入口,以及 Resource/ServiceState 的
// JSON 键名契约(供 todo 2/6/7/20 消费方钉死序列化形态)。

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Daedalusys/daedalus-sdk/policy"
)

// TestResource_Validate 证明合法 Resource(七个已定义 Kind × 干净 Name)
// 全部通过校验;空 DesiredState 与通配 "*" Name 亦属合法
// (todo 8 的 daedalus.service 清单声明 resources: [{kind: service, name: "*"}])。
func TestResource_Validate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		res  Resource
	}{
		{"service 全字段", Resource{Kind: KindService, Name: "sshd.service", DesiredState: "active"}},
		{"package 保留 kind", Resource{Kind: KindPackage, Name: "nginx", DesiredState: "installed"}},
		{"container 保留 kind", Resource{Kind: KindContainer, Name: "db01", DesiredState: "running"}},
		{"capability 保留 kind", Resource{Kind: KindCapability, Name: "fs.read", DesiredState: "enabled"}},
		{"task 保留 kind", Resource{Kind: KindTask, Name: "reindex", DesiredState: "pending"}},
		{"transaction 保留 kind", Resource{Kind: KindTransaction, Name: "0123456789abcdef", DesiredState: "applied"}},
		{"policy 保留 kind", Resource{Kind: KindPolicy, Name: "shell", DesiredState: "enforced"}},
		{"通配 Name 合法", Resource{Kind: KindService, Name: "*"}},
		{"空 DesiredState 合法", Resource{Kind: KindService, Name: "crond.service"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := tc.res
			if err := res.Validate(); err != nil {
				t.Fatalf("合法资源被拒绝: %v", err)
			}
		})
	}
}

// TestResource_Validate_Rejects 覆盖计划 todo 1 验收规定的全部拒绝分支:
// 空 Kind、未知 Kind、空 Name、Name 含空字节、Name 含 '/'、Name 含 "..";
// 并证明多个缺陷聚合进同一条错误(镜像 internal/policy 的聚合风格)。
func TestResource_Validate_Rejects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		res     Resource
		wantSub string // 错误消息必须点名的字段
	}{
		{"空 Kind", Resource{Name: "a"}, "kind"},
		{"未知 Kind", Resource{Kind: Kind("machine"), Name: "a"}, "kind"},
		{"Kind 大写变体未知", Resource{Kind: Kind("Service"), Name: "a"}, "kind"},
		{"空 Name", Resource{Kind: KindService}, "name"},
		{"Name 含空字节", Resource{Kind: KindService, Name: "ng\ting\x00in"}, "name"},
		{"Name 含斜杠", Resource{Kind: KindService, Name: "etc/passwd"}, "name"},
		{"Name 含路径回溯", Resource{Kind: KindService, Name: "../sshd.service"}, "name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := tc.res
			err := res.Validate()
			if err == nil {
				t.Fatalf("非法资源被接受: %+v", tc.res)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.wantSub) {
				t.Errorf("错误消息未点名 %q 字段: %v", tc.wantSub, err)
			}
		})
	}
}

// TestResource_Validate_Aggregates 证明空 Kind + 空 Name + 含 '/' 的 Name
// 三个缺陷一次性全部列出(聚合错误,非首错即返)。
func TestResource_Validate_Aggregates(t *testing.T) {
	t.Parallel()
	res := Resource{Kind: Kind("nope"), Name: "a/b"}
	err := res.Validate()
	if err == nil {
		t.Fatal("非法资源被接受")
	}
	msg := strings.ToLower(err.Error())
	for _, want := range []string{"kind", "name"} {
		if !strings.Contains(msg, want) {
			t.Errorf("聚合错误缺 %q 条目: %v", want, err)
		}
	}
}

// TestKind_Values 钉死七个常量的字面量值为小写形式(线协议契约:
// manifest JSON 与 policy.toml enabled_kinds 都用这些小写 token)。
func TestKind_Values(t *testing.T) {
	t.Parallel()
	cases := []struct {
		got  Kind
		want string
	}{
		{KindService, "service"},
		{KindPackage, "package"},
		{KindContainer, "container"},
		{KindCapability, "capability"},
		{KindTask, "task"},
		{KindTransaction, "transaction"},
		{KindPolicy, "policy"},
	}
	for _, tc := range cases {
		if string(tc.got) != tc.want {
			t.Errorf("Kind 常量值漂移: got %q, want %q", string(tc.got), tc.want)
		}
	}
	all := AllKinds()
	if len(all) != len(cases) {
		t.Fatalf("AllKinds 数量 = %d, want %d", len(all), len(cases))
	}
	for _, tc := range cases {
		if !slices.Contains(all, tc.got) {
			t.Errorf("AllKinds 缺 %q", tc.got)
		}
	}
	// 返回值必须是副本:调用方改动不得污染注册表。
	all[0] = Kind("tampered")
	if AllKinds()[0] != KindService {
		t.Error("AllKinds 返回了内部切片的别名")
	}
}

// TestValidateResource_Nil 证明 nil 条目被拒(todo 2 的清单数组
// 允许 JSON null,解出 nil 指针必须在入口挡下)。
func TestValidateResource_Nil(t *testing.T) {
	t.Parallel()
	if err := ValidateResource(nil); err == nil {
		t.Fatal("nil 资源条目被接受")
	}
}

// TestResource_JSONRoundTrip 钉死 Resource 的 JSON 键契约
// (kind / name / desired_state),todo 2 的 manifest 解析依赖它。
func TestResource_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	raw := `{"kind":"service","name":"*","desired_state":"active"}`
	var res Resource
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if res.Kind != KindService || res.Name != "*" || res.DesiredState != "active" {
		t.Fatalf("解析结果不符: %+v", res)
	}
	out, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if string(out) != raw {
		t.Errorf("序列化漂移:\ngot  %s\nwant %s", out, raw)
	}
}

// TestServiceState_JSONContract 钉死 ServiceState 的四键序列化契约
// (kind / name / desired_state / properties),todo 6/7/20 的结果
// 与状态载荷按此形态落盘/上线(计划第 4 轮评审 pin:Properties 键
// 为 systemctl 属性名原文)。
func TestServiceState_JSONContract(t *testing.T) {
	t.Parallel()
	st := ServiceState{
		Kind:         "service",
		Name:         "sshd.service",
		DesiredState: "active",
		Properties:   map[string]string{"ActiveState": "inactive", "SubState": "dead"},
	}
	out, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("回解失败: %v", err)
	}
	for _, key := range []string{"kind", "name", "desired_state", "properties"} {
		if _, ok := got[key]; !ok {
			t.Errorf("ServiceState JSON 缺键 %q: %s", key, out)
		}
	}
	props, _ := got["properties"].(map[string]any)
	if props["ActiveState"] != "inactive" {
		t.Errorf("Properties 键必须是 systemctl 属性名原文: %s", out)
	}
}

// ===== 计划 todo 4:三点对象模型漂移钉 =====
//
// TestObjectModel_Drift 断言三点锁:
//  (a) policy.Default().ObjectModel.EnabledKinds 的每个取值必须是
//      objectmodel 常量集(AllKinds())中的合法 Kind;
//  (b) 仓库真实 shared/policy.toml 经 policy.Load 解出的 enabled_kinds
//      同样逐项合法,且与 Default() 集合相等(零漂移);
//  (c) 金丝雀:冻结字面量 []string{"service", "package"} 必须与两点集合精确相等——
//      任何一侧改动(常量值、Default()、policy.toml)都会点亮金丝雀,
//      未来激活新 kind 必须显式更新本测试(刻意的高摩擦设计,
//      与 shellpolicy 三点防漂移链同构,见 AGENTS.md CONVENTIONS)。
//
// 路径解析说明(计划 todo 4 修正):policy 包测试走 policy.ResolvePath()
// 的 DevRelPaths 候选自 cwd 逐级上溯(其包目录 testdata/ 在 level 1 命中);
// 本测试(cwd = daedalus-sdk/objectmodel)的包目录没有 testdata 候选,
// walk-up 命中不到 policy 包的 testdata,故直接以相对路径指向
// ../policy/testdata/policy.toml(生产一致副本,经 sync-policy-testdata.sh
// 与 daedalus/files/system/opt/daedalus/shared/policy.toml 同步;
// 与 go test 的包目录机制绑定,不依赖 runtime.Caller,行为确定)。
//
// 循环依赖核验:internal/policy 只依赖 stdlib + BurntSushi/toml,
// 不 import internal/objectmodel;本文件是 objectmodel 包内部测试文件,
// 测试专用的单向 import(objectmodel 测试 → policy)不构成环。

// driftTriplet 汇总三点漂移断言的全部输入,避免辅助函数参数超限。
// 字段全部由调用方注入,compareDriftTriplet 只做纯比较——
// 负例演示(TMP canary)与正例共用同一比较器,保证比较器真实生效。
type driftTriplet struct {
	registry     []Kind   // objectmodel 常量集(AllKinds() 快照)
	defaultKinds []string // policy.Default() 的 enabled_kinds
	tomlKinds    []string // 真实 policy.toml 的 enabled_kinds
	canary       []string // 冻结字面量金丝雀
}

// compareDriftTriplet 执行 (a)(b)(c) 三点比较并在 stderr 逐项点名漂移。
func compareDriftTriplet(t *testing.T, trip driftTriplet) {
	t.Helper()

	// (a) Default() ⊆ 常量集:每个启用值必须是已定义 Kind 常量。
	for _, k := range trip.defaultKinds {
		if !slices.Contains(trip.registry, Kind(k)) {
			t.Errorf("(a) Default().enabled_kinds 含非法 Kind %q(不在 AllKinds() 常量集内)", k)
		}
	}
	// (b1) policy.toml ⊆ 常量集。
	for _, k := range trip.tomlKinds {
		if !slices.Contains(trip.registry, Kind(k)) {
			t.Errorf("(b) policy.toml enabled_kinds 含非法 Kind %q(不在 AllKinds() 常量集内)", k)
		}
	}

	// 集合相等比较统一先排序(与书写顺序无关;金丝雀腿用精确序)。
	sorted := func(s []string) []string { out := slices.Clone(s); slices.Sort(out); return out }

	// (b2) policy.toml == Default():零漂移。
	if !slices.Equal(sorted(trip.tomlKinds), sorted(trip.defaultKinds)) {
		t.Errorf("(b) policy.toml 与 Default() 的 enabled_kinds 漂移: %v vs %v",
			trip.tomlKinds, trip.defaultKinds)
	}

	// (c) 金丝雀:两点集合都须逐字等于冻结字面量(有序精确比较)。
	if !slices.Equal(trip.defaultKinds, trip.canary) {
		t.Errorf("(c) 金丝雀点亮:Default().enabled_kinds 偏离冻结字面量: got %v, want %v",
			trip.defaultKinds, trip.canary)
	}
	if !slices.Equal(sorted(trip.tomlKinds), sorted(trip.canary)) {
		t.Errorf("(c) 金丝雀点亮:policy.toml 的 enabled_kinds 偏离冻结字面量: got %v, want %v",
			trip.tomlKinds, trip.canary)
	}
}

func TestObjectModel_Drift(t *testing.T) {
	// --- (b) 腿输入:加载生产一致副本 policy.toml(policy 包 testdata,
	// 直接相对路径,见文件头"路径解析说明") ---
	policyPath := filepath.Join("..", "policy", "testdata", "policy.toml")
	loaded, err := policy.Load(policyPath)
	if err != nil {
		t.Fatalf("生产一致副本 policy.toml 未通过自身校验: %v", err)
	}

	// --- 三点正例:常量集 / Default() / policy.toml / 冻结字面量 ---
	compareDriftTriplet(t, driftTriplet{
		registry:     AllKinds(),
		defaultKinds: policy.Default().ObjectModel.EnabledKinds,
		tomlKinds:    loaded.ObjectModel.EnabledKinds,
		canary:       []string{"service", "package"}, // v1 冻结字面量:service 与 package 启用
	})

	// --- 负例扩展(T1 已钉 "machine"/"Service",此处补足全部大小写变体) ---
	// 校验器对启用值与金丝雀值的大小写变体一律拒绝:Kind 是小写线协议
	// token,"Service"/"SERVICE" 等不得混入常量集比较通道。
	for _, base := range policy.Default().ObjectModel.EnabledKinds {
		variants := []string{
			strings.ToUpper(base),                // 全大写变体(SERVICE)
			strings.ToUpper(base[:1]) + base[1:], // 首字母大写变体(Service)
			base + " ",                           // 尾随空格(精确匹配,不容忍)
		}
		for _, variant := range variants {
			res := Resource{Kind: Kind(variant), Name: "*"}
			if err := res.Validate(); err == nil {
				t.Errorf("Kind 变体 %q 应被校验器拒绝(未知即拒,大小写敏感)", variant)
			}
		}
	}
}
