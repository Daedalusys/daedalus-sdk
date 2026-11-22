package pending

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// 这两个金样是线上形状的参照:键名与 core / plugins 已发的记录逐字相同,
// 改键名等于让历史待办与批准全部读不出来。
const validPendingJSON = `{
	"id": "p-517e2253edd4d4a9",
	"kind": "service",
	"name": "web.service",
	"desired_state": "restarted",
	"argv": ["systemctl", "--user", "restart", "web.service"],
	"scope": "systemd:user:restart:web.service",
	"reason": "用户要求重启",
	"created_at": "2026-11-22T10:00:00Z",
	"expires_at": "2026-11-22T10:15:00Z"
}`

const validApprovalJSON = `{
	"id": "p-517e2253edd4d4a9",
	"argv_sha256": "013995b36a7a6e5a76e5c9f28a81bd0d25ee4409664d349d3af44a339e4c7100",
	"requested_by_uid": 1000,
	"requested_by": "alice",
	"approved_by": "root",
	"approved_at": "2026-11-22T10:05:00Z"
}`

// mutateJSON 在合法金样上做一处改动,保持其余字段合法 ——
// 每个用例只让一条规则失效,失败原因才唯一。
func mutateJSON(t *testing.T, base string, mutate func(map[string]any)) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(base), &m); err != nil {
		t.Fatalf("金样不是合法 JSON: %v", err)
	}
	mutate(m)
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("改坏后的金样无法序列化: %v", err)
	}
	return string(data)
}

func TestParsePending_AcceptsValid(t *testing.T) {
	p, err := ParsePending([]byte(validPendingJSON))
	if err != nil {
		t.Fatalf("合法待办被拒: %v", err)
	}
	want := Pending{
		ID:           "p-517e2253edd4d4a9",
		Kind:         "service",
		Name:         "web.service",
		DesiredState: "restarted",
		Argv:         []string{"systemctl", "--user", "restart", "web.service"},
		Scope:        "systemd:user:restart:web.service",
		Reason:       "用户要求重启",
		CreatedAt:    time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC),
		ExpiresAt:    time.Date(2026, 11, 22, 10, 15, 0, 0, time.UTC),
	}
	assertPendingEqual(t, want, *p)
}

// 严格解析是收紧密不透风的门:待办目录任何本地用户可写,放过一条就等于
// 给伪造留一条缝。每条规则一个用例,删掉任何一条都会让对应的缝重新打开。
func TestParsePending_Strict(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		raw    string // 非空时直接用,用于结构性坏 JSON
	}{
		{"未知字段", func(m map[string]any) { m["executor_uid"] = 1000 }, ""},
		{"JSON 之后有残余内容", nil, validPendingJSON + ` {}`},
		{"缺 id", func(m map[string]any) { delete(m, "id") }, ""},
		{"缺 kind", func(m map[string]any) { delete(m, "kind") }, ""},
		{"缺 name", func(m map[string]any) { delete(m, "name") }, ""},
		{"缺 desired_state", func(m map[string]any) { delete(m, "desired_state") }, ""},
		{"缺 scope", func(m map[string]any) { delete(m, "scope") }, ""},
		{"缺 created_at", func(m map[string]any) { delete(m, "created_at") }, ""},
		{"缺 expires_at", func(m map[string]any) { delete(m, "expires_at") }, ""},
		{"argv 为空", func(m map[string]any) { m["argv"] = []any{} }, ""},
		{"argv 缺字段", func(m map[string]any) { delete(m, "argv") }, ""},
		{"argv[0] 为空", func(m map[string]any) { m["argv"] = []any{"", "restart"} }, ""},
		{"argv 元素含 NUL", func(m map[string]any) {
			m["argv"] = []any{"systemctl", "restart\x00web.service"}
		}, ""},
		{"created_at 不可解析", func(m map[string]any) { m["created_at"] = "昨天上午" }, ""},
		{"expires_at 不可解析", func(m map[string]any) { m["expires_at"] = "2026-11-22 10:15" }, ""},
		{"expires_at 等于 created_at", func(m map[string]any) {
			m["expires_at"] = m["created_at"]
		}, ""},
		{"expires_at 早于 created_at", func(m map[string]any) {
			m["expires_at"] = "2026-11-22T09:59:00Z"
		}, ""},
		{"scope 不可解析", func(m map[string]any) { m["scope"] = "not-a-scope" }, ""},
		{"scope 词表外运行时", func(m map[string]any) { m["scope"] = "k8s:restart:web" }, ""},
		{"id 形状非法", func(m map[string]any) { m["id"] = "517e2253" }, ""},
		{"id 带路径分隔符", func(m map[string]any) { m["id"] = "p-a/b" }, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.raw
			if raw == "" {
				raw = mutateJSON(t, validPendingJSON, tc.mutate)
			}
			if p, err := ParsePending([]byte(raw)); err == nil {
				t.Fatalf("应被拒却解析成功: %+v\n输入: %s", p, raw)
			}
		})
	}
}

func TestParseApproval_AcceptsValid(t *testing.T) {
	a, err := ParseApproval([]byte(validApprovalJSON))
	if err != nil {
		t.Fatalf("合法批准被拒: %v", err)
	}
	if a.RequestedByUID == nil {
		t.Fatal("requested_by_uid 应解析成非 nil 指针")
	}
	wantUID := uint32(1000)
	want := Approval{
		ID:             "p-517e2253edd4d4a9",
		ArgvSHA256:     "013995b36a7a6e5a76e5c9f28a81bd0d25ee4409664d349d3af44a339e4c7100",
		RequestedByUID: &wantUID,
		RequestedBy:    "alice",
		ApprovedBy:     "root",
		ApprovedAt:     time.Date(2026, 11, 22, 10, 5, 0, 0, time.UTC),
	}
	assertApprovalEqual(t, want, *a)
}

// root 自己是请求者(uid 0)必须与「字段缺失」区分开:
// 用 0 兼任「未指定」会让「批给 root」和「没写是谁」长得一样,而两者判定相反。
func TestParseApproval_RootRequesterIsNotMissing(t *testing.T) {
	raw := mutateJSON(t, validApprovalJSON, func(m map[string]any) {
		m["requested_by_uid"] = 0
		m["requested_by"] = "root"
	})
	a, err := ParseApproval([]byte(raw))
	if err != nil {
		t.Fatalf("requested_by_uid=0 应可解析: %v", err)
	}
	if a.RequestedByUID == nil || *a.RequestedByUID != 0 {
		t.Fatalf("requested_by_uid 应解析成指向 0 的指针, 实得 %v", a.RequestedByUID)
	}
}

func TestParseApproval_Strict(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		raw    string
	}{
		{"未知字段", func(m map[string]any) { m["scope"] = "systemd:user:restart:web.service" }, ""},
		{"JSON 之后有残余内容", nil, validApprovalJSON + ` []`},
		{"缺 id", func(m map[string]any) { delete(m, "id") }, ""},
		{"缺 argv_sha256", func(m map[string]any) { delete(m, "argv_sha256") }, ""},
		{"缺 approved_by", func(m map[string]any) { delete(m, "approved_by") }, ""},
		{"缺 approved_at", func(m map[string]any) { delete(m, "approved_at") }, ""},
		{"approved_at 不可解析", func(m map[string]any) { m["approved_at"] = "刚刚" }, ""},
		{"argv_sha256 大写", func(m map[string]any) {
			m["argv_sha256"] = strings.ToUpper(m["argv_sha256"].(string))
		}, ""},
		{"argv_sha256 过短", func(m map[string]any) { m["argv_sha256"] = "0139" }, ""},
		{"argv_sha256 非十六进制", func(m map[string]any) {
			m["argv_sha256"] = "013995b36a7a6e5a76e5c9f28a81bd0d25ee4409664d349d3af44a339e4c710g"
		}, ""},
		{"id 形状非法", func(m map[string]any) { m["id"] = "../p-517e2253edd4d4a9" }, ""},
		// 缺失 ≠ root:这两个用例覆盖「半填的归属」——只删 uid 与两个都删。
		{"requested_by 有值而 requested_by_uid 缺失", func(m map[string]any) {
			delete(m, "requested_by_uid")
		}, ""},
		{"requested_by_uid 与 requested_by 都缺失", func(m map[string]any) {
			delete(m, "requested_by_uid")
			delete(m, "requested_by")
		}, ""},
		{"requested_by_uid 为 null", func(m map[string]any) { m["requested_by_uid"] = nil }, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.raw
			if raw == "" {
				raw = mutateJSON(t, validApprovalJSON, tc.mutate)
			}
			if a, err := ParseApproval([]byte(raw)); err == nil {
				t.Fatalf("应被拒却解析成功: %+v\n输入: %s", a, raw)
			}
		})
	}
}

// 往返:线上是 RFC3339 字符串,进程内是 time.Time;输出恒 UTC,
// 所以同一时刻用不同时区构造也应读回同一个瞬间。
func TestRoundTrip_Pending(t *testing.T) {
	orig := Pending{
		ID:           "p-517e2253edd4d4a9",
		Kind:         "service",
		Name:         "web.service",
		DesiredState: "restarted",
		Argv:         []string{"systemctl", "--user", "restart", "web.service"},
		Scope:        "systemd:user:restart:web.service",
		Reason:       "用户要求重启",
		CreatedAt:    time.Date(2026, 11, 22, 18, 0, 0, 0, time.FixedZone("CST", 8*3600)),
		ExpiresAt:    time.Date(2026, 11, 22, 18, 15, 0, 0, time.FixedZone("CST", 8*3600)),
	}

	data, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("序列化待办失败: %v", err)
	}
	if !strings.Contains(string(data), `"created_at":"2026-11-22T10:00:00Z"`) {
		t.Errorf("created_at 应输出成 UTC RFC3339: %s", data)
	}

	got, err := ParsePending(data)
	if err != nil {
		t.Fatalf("读回自己写的待办失败: %v", err)
	}
	assertPendingEqual(t, orig, *got)
}

func TestRoundTrip_Approval(t *testing.T) {
	uid := uint32(1000)
	orig := Approval{
		ID:             "p-517e2253edd4d4a9",
		ArgvSHA256:     "013995b36a7a6e5a76e5c9f28a81bd0d25ee4409664d349d3af44a339e4c7100",
		RequestedByUID: &uid,
		RequestedBy:    "alice",
		ApprovedBy:     "root",
		ApprovedAt:     time.Date(2026, 11, 22, 18, 5, 0, 0, time.FixedZone("CST", 8*3600)),
	}

	data, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("序列化批准失败: %v", err)
	}
	if !strings.Contains(string(data), `"approved_at":"2026-11-22T10:05:00Z"`) {
		t.Errorf("approved_at 应输出成 UTC RFC3339: %s", data)
	}

	got, err := ParseApproval(data)
	if err != nil {
		t.Fatalf("读回自己写的批准失败: %v", err)
	}
	assertApprovalEqual(t, orig, *got)
}

// 键名是跨仓契约:两个仓的读侧都按这些名字取值,多一个、少一个都算漂移。
func TestMarshalJSON_KeyNames(t *testing.T) {
	t.Run("待办九键", func(t *testing.T) {
		data, err := Pending{}.MarshalJSON()
		if err != nil {
			t.Fatalf("序列化空待办失败: %v", err)
		}
		assertKeys(t, data, []string{
			"argv", "created_at", "desired_state", "expires_at",
			"id", "kind", "name", "reason", "scope",
		})
	})

	t.Run("批准六键", func(t *testing.T) {
		uid := uint32(1000)
		data, err := Approval{RequestedByUID: &uid, RequestedBy: "alice"}.MarshalJSON()
		if err != nil {
			t.Fatalf("序列化批准失败: %v", err)
		}
		assertKeys(t, data, []string{
			"approved_at", "approved_by", "argv_sha256", "id",
			"requested_by", "requested_by_uid",
		})
	})

	// requested_by 只作展示,没有值时省略该键;其余键恒在。
	t.Run("批准无展示名省略 requested_by", func(t *testing.T) {
		uid := uint32(0)
		data, err := Approval{RequestedByUID: &uid}.MarshalJSON()
		if err != nil {
			t.Fatalf("序列化批准失败: %v", err)
		}
		assertKeys(t, data, []string{
			"approved_at", "approved_by", "argv_sha256", "id", "requested_by_uid",
		})
	})
}

func assertKeys(t *testing.T, data []byte, want []string) {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("输出不是 JSON 对象: %v (%s)", err, data)
	}
	got := make([]string, 0, len(m))
	for k := range m {
		got = append(got, k)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("JSON 键集合 = %v, want %v (%s)", got, want, data)
	}
}

func assertPendingEqual(t *testing.T, want, got Pending) {
	t.Helper()
	if want.ID != got.ID || want.Kind != got.Kind || want.Name != got.Name ||
		want.DesiredState != got.DesiredState || want.Scope != got.Scope || want.Reason != got.Reason {
		t.Errorf("待办字段不一致:\n want %+v\n  got %+v", want, got)
	}
	if !reflect.DeepEqual(want.Argv, got.Argv) {
		t.Errorf("argv = %v, want %v", got.Argv, want.Argv)
	}
	// 时间只比较格式化后的 UTC 串:同一瞬间的时区表示不同不算差异。
	if formatTime(want.CreatedAt) != formatTime(got.CreatedAt) {
		t.Errorf("created_at = %s, want %s", formatTime(got.CreatedAt), formatTime(want.CreatedAt))
	}
	if formatTime(want.ExpiresAt) != formatTime(got.ExpiresAt) {
		t.Errorf("expires_at = %s, want %s", formatTime(got.ExpiresAt), formatTime(want.ExpiresAt))
	}
}

func assertApprovalEqual(t *testing.T, want, got Approval) {
	t.Helper()
	if want.ID != got.ID || want.ArgvSHA256 != got.ArgvSHA256 ||
		want.RequestedBy != got.RequestedBy || want.ApprovedBy != got.ApprovedBy {
		t.Errorf("批准字段不一致:\n want %+v\n  got %+v", want, got)
	}
	if (want.RequestedByUID == nil) != (got.RequestedByUID == nil) {
		t.Fatalf("requested_by_uid 指针有无不一致: want %v, got %v", want.RequestedByUID, got.RequestedByUID)
	}
	if want.RequestedByUID != nil && *want.RequestedByUID != *got.RequestedByUID {
		t.Errorf("requested_by_uid = %d, want %d", *got.RequestedByUID, *want.RequestedByUID)
	}
	if formatTime(want.ApprovedAt) != formatTime(got.ApprovedAt) {
		t.Errorf("approved_at = %s, want %s", formatTime(got.ApprovedAt), formatTime(want.ApprovedAt))
	}
}
