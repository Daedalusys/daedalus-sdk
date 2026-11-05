package objectmodel

// 本文件是 Plan 的线上契约金样与跨仓词表交叉核对:
//   - TestPlan_JSONShape_Full 把 Plan 的全部 JSON 键名/键序/取值逐字节冻结;
//   - 两个 *_Vocabulary_MatchesProtoEnum 测试证明本仓的字符串词表与
//     proto/agent/v1 的枚举同源(枚举名去掉前缀转小写即本仓 token)。
//
// protobuf 依赖只出现在本 _test.go:objectmodel 的生产代码零 proto 依赖,
// 生产代码只 import stdlib(见 Global Constraint)。

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/Daedalusys/daedalus-sdk/proto/agent/v1"
)

// planGoldenJSON 是 Plan 的线上契约冻结串:键名 snake_case、键序 = 字段
// 声明序。intents[].kind 与 machines[].kind 同名不同域——前者是资源类别
// (service/package),后者是节点形态(agent/atomic),两处取值不重叠。
const planGoldenJSON = `{"id":"0123456789abcdef","intents":[{"kind":"service","target":"nginx","spec":{"desired_state":"active"},"expected_diff":"reload nginx","risk_class":"low"},{"kind":"package","target":"kernel-core","spec":{"version":"6.11"},"expected_diff":"+ kernel-core","risk_class":"high"}],"machines":[{"machine_id":"ubuntu-24.04-a","kind":"agent","support_level":"supported"},{"machine_id":"ubuntu-24.04-b","kind":"agent","support_level":"supported"},{"machine_id":"debian-12-a","kind":"agent","support_level":"experimental"}],"batching":{"strategy":"count","size":2},"blast_radius":{"count":3,"kind_breakdown":{"package":2,"service":1},"max_downtime_ns":30000000000,"max_risk":"high"},"status":"dirty"}`

// TestPlan_JSONShape_Full 逐字节冻结 Plan 的 JSON 形态。控制面与 agent
// 双侧按字面键解析,一次"顺手改名"(risk_class→riskClass)即静默破坏线上协议,
// 故此处不做结构断言而做整串比对。
func TestPlan_JSONShape_Full(t *testing.T) {
	plan := Plan{
		ID: "0123456789abcdef",
		Intents: []Intent{
			{
				Kind:         KindService,
				Target:       "nginx",
				Spec:         json.RawMessage(`{"desired_state":"active"}`),
				ExpectedDiff: "reload nginx",
				RiskClass:    RiskClassLow,
			},
			{
				Kind:         KindPackage,
				Target:       "kernel-core",
				Spec:         json.RawMessage(`{"version":"6.11"}`),
				ExpectedDiff: "+ kernel-core",
				RiskClass:    RiskClassHigh,
			},
		},
		Machines: []Machine{
			{MachineID: "ubuntu-24.04-a", Kind: MachineKindAgent, SupportLevel: SupportLevelSupported},
			{MachineID: "ubuntu-24.04-b", Kind: MachineKindAgent, SupportLevel: SupportLevelSupported},
			{MachineID: "debian-12-a", Kind: MachineKindAgent, SupportLevel: SupportLevelExperimental},
		},
		Batching: Batching{Strategy: BatchingCount, Size: 2},
		BlastRadius: BlastRadius{
			Count:         3,
			KindBreakdown: map[string]int{"service": 1, "package": 2},
			MaxDowntime:   30 * time.Second,
			MaxRisk:       RiskClassHigh,
		},
		Status: PlanStatusDirty,
	}

	b, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if string(b) != planGoldenJSON {
		t.Fatalf("Plan JSON 漂移:\n got %s\nwant %s", b, planGoldenJSON)
	}
}

// protoEnumTokens 把 proto 枚举的取值名逐个去掉前缀并转小写,排序后返回。
// 本仓的字符串词表必须是它的子集(去掉 unspecified),否则两侧不同源。
func protoEnumTokens(prefix string, names map[int32]string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, strings.ToLower(strings.TrimPrefix(name, prefix)))
	}
	slices.Sort(out)
	return out
}

// TestRiskClass_Vocabulary_MatchesProtoEnum 钉住本仓字符串词表与
// proto/agent/v1 的枚举同源:枚举 String() 去掉 RISK_CLASS_ 前缀并
// 转小写后,必须恰好是 {"low","high","unspecified"}。
// 依赖只出现在 _test.go——objectmodel 的生产代码不 import protobuf。
func TestRiskClass_Vocabulary_MatchesProtoEnum(t *testing.T) {
	derived := protoEnumTokens("RISK_CLASS_", agentv1.RiskClass_name)
	want := []string{"high", "low", "unspecified"}
	if !slices.Equal(derived, want) {
		t.Fatalf("proto RiskClass 词表漂移: got %v, want %v", derived, want)
	}

	// 本仓词表 = proto 词表去掉 unspecified(空值即"未指定",线上无此 token)。
	local := []string{string(RiskClassLow), string(RiskClassHigh)}
	slices.Sort(local)
	fromProto := slices.DeleteFunc(slices.Clone(derived), func(s string) bool {
		return s == "unspecified"
	})
	if !slices.Equal(local, fromProto) {
		t.Fatalf("RiskClass 常量集与 proto 词表不同源: got %v, want %v", local, fromProto)
	}
}

// TestApplyIntentResult_Vocabulary_MatchesProtoEnum 钉住控制面分桶用的
// 五词(success / refused_snapshot_capability_none / refused_policy /
// transient_failure / persistent_failure)与 proto/agent/v1 的
// APPLY_INTENT_RESULT_* 枚举同源。spec §4.3 的三桶 = success / transient /
// persistent,另两枚是拒因(reason 而非桶)。
func TestApplyIntentResult_Vocabulary_MatchesProtoEnum(t *testing.T) {
	derived := protoEnumTokens("APPLY_INTENT_RESULT_", agentv1.ApplyIntentResult_name)

	wantAll := []string{
		"persistent_failure",
		"refused_policy",
		"refused_snapshot_capability_none",
		"success",
		"transient_failure",
		"unspecified",
	}
	if !slices.Equal(derived, wantAll) {
		t.Fatalf("proto ApplyIntentResult 词表漂移: got %v, want %v", derived, wantAll)
	}

	// 控制面分桶要用的五词:去掉 unspecified 后的全集。
	bucket := slices.DeleteFunc(slices.Clone(derived), func(s string) bool {
		return s == "unspecified"
	})
	wantBucket := []string{
		"persistent_failure",
		"refused_policy",
		"refused_snapshot_capability_none",
		"success",
		"transient_failure",
	}
	if !slices.Equal(bucket, wantBucket) {
		t.Fatalf("分桶五词与 proto 词表不同源: got %v, want %v", bucket, wantBucket)
	}
}
