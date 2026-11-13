package jsonl_test

// jsonl_test.go —— 钉 JSONL 文件后端的行为面:往返、TTL 过期即不存在、
// 墓碑删除、列举的前缀与 scope 过滤、检索不可用哨兵、scope 越权与非法键、
// 跨进程重启后的持久性。

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Daedalusys/daedalus-sdk/memoryprovider"
	"github.com/Daedalusys/daedalus-sdk/memoryprovider/jsonl"
)

// clock 是注入的写入时钟:TTL 的计时起点归实现私有,测试要能推进时间。
type clock struct{ t time.Time }

func (c *clock) Now() time.Time          { return c.t }
func (c *clock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func newProvider(t *testing.T) (*jsonl.Provider, *clock, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "memory.jsonl")
	c := &clock{t: time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)}
	p, err := jsonl.New(path, jsonl.Options{Now: c.Now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p, c, path
}

func userEntry(key, value string, ttl time.Duration) memoryprovider.Entry {
	return memoryprovider.Entry{
		Key:   key,
		Value: json.RawMessage(value),
		Scope: memoryprovider.ScopeUser,
		TTL:   ttl,
	}
}

func TestSetGetRoundTrip(t *testing.T) {
	p, _, _ := newProvider(t)
	ctx := context.Background()
	want := userEntry("pref/key", `{"a":1}`, 0)
	if err := p.Set(ctx, want); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := p.Get(ctx, memoryprovider.ScopeUser, "pref/key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Key != want.Key || string(got.Value) != string(want.Value) {
		t.Fatalf("往返不一致: got=%+v want=%+v", got, want)
	}
	if got.Scope != memoryprovider.ScopeUser {
		t.Fatalf("scope 丢失: got=%q", got.Scope)
	}
}

func TestGetMissingKeyReturnsErrKeyNotFound(t *testing.T) {
	p, _, _ := newProvider(t)
	_, err := p.Get(context.Background(), memoryprovider.ScopeUser, "nope")
	if !errors.Is(err, memoryprovider.ErrKeyNotFound) {
		t.Fatalf("期望 ErrKeyNotFound,得到 %v", err)
	}
}

func TestTTLExpiryReadsAsNotFound(t *testing.T) {
	p, c, _ := newProvider(t)
	ctx := context.Background()
	if err := p.Set(ctx, userEntry("k", `1`, time.Minute)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	c.Advance(59 * time.Second)
	if _, err := p.Get(ctx, memoryprovider.ScopeUser, "k"); err != nil {
		t.Fatalf("TTL 未到期就不该读不到: %v", err)
	}
	c.Advance(time.Second)
	if _, err := p.Get(ctx, memoryprovider.ScopeUser, "k"); !errors.Is(err, memoryprovider.ErrKeyNotFound) {
		t.Fatalf("过期后应回 ErrKeyNotFound,得到 %v", err)
	}
}

func TestDeleteRemovesAndPersistsTombstone(t *testing.T) {
	p, c, path := newProvider(t)
	ctx := context.Background()
	if err := p.Set(ctx, userEntry("k", `1`, 0)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := p.Delete(ctx, memoryprovider.ScopeUser, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := p.Get(ctx, memoryprovider.ScopeUser, "k"); !errors.Is(err, memoryprovider.ErrKeyNotFound) {
		t.Fatalf("删除后应回 ErrKeyNotFound,得到 %v", err)
	}
	// 重开一次:删除必须已经落到文件里(墓碑),不能只在内存里生效。
	p2, err := jsonl.New(path, jsonl.Options{Now: c.Now})
	if err != nil {
		t.Fatalf("重开 New: %v", err)
	}
	if _, err := p2.Get(ctx, memoryprovider.ScopeUser, "k"); !errors.Is(err, memoryprovider.ErrKeyNotFound) {
		t.Fatalf("重开后仍应读不到,得到 %v", err)
	}
}

func TestDeleteMissingKeyReturnsErrKeyNotFound(t *testing.T) {
	p, _, _ := newProvider(t)
	err := p.Delete(context.Background(), memoryprovider.ScopeUser, "ghost")
	if !errors.Is(err, memoryprovider.ErrKeyNotFound) {
		t.Fatalf("期望 ErrKeyNotFound,得到 %v", err)
	}
}

func TestListReturnsKeysWithPrefixOnly(t *testing.T) {
	p, c, _ := newProvider(t)
	ctx := context.Background()
	for _, k := range []string{"a/1", "a/2", "b/1", "expired"} {
		if err := p.Set(ctx, userEntry(k, `1`, 0)); err != nil {
			t.Fatalf("Set %s: %v", k, err)
		}
	}
	if err := p.Set(ctx, userEntry("a/gone", `1`, time.Minute)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	c.Advance(2 * time.Minute)

	keys, err := p.List(ctx, memoryprovider.ScopeUser, "a/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"a/1", "a/2"}
	if len(keys) != len(want) {
		t.Fatalf("List 前缀过滤不对: got=%v want=%v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("List 结果不对: got=%v want=%v", keys, want)
		}
	}
}

func TestSearchAlwaysReportsUnavailable(t *testing.T) {
	p, _, _ := newProvider(t)
	_, err := p.Search(context.Background(), "anything", 10)
	if !errors.Is(err, memoryprovider.ErrSearchUnavailable) {
		t.Fatalf("期望 ErrSearchUnavailable,得到 %v", err)
	}
}

func TestNonUserScopeIsDenied(t *testing.T) {
	p, _, _ := newProvider(t)
	ctx := context.Background()
	err := p.Set(ctx, userEntry("k", `1`, 0))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	bad := userEntry("sys", `1`, 0)
	bad.Scope = memoryprovider.ScopeSystem
	if err := p.Set(ctx, bad); !errors.Is(err, memoryprovider.ErrScopeDenied) {
		t.Fatalf("system scope 写入应回 ErrScopeDenied,得到 %v", err)
	}
	if _, err := p.Get(ctx, memoryprovider.Scope("weird"), "k"); !errors.Is(err, memoryprovider.ErrScopeDenied) {
		t.Fatalf("非法 scope 应回 ErrScopeDenied,得到 %v", err)
	}
}

func TestInvalidKeyIsRejected(t *testing.T) {
	p, _, _ := newProvider(t)
	ctx := context.Background()
	for _, k := range []string{"", "has space", "tab\there"} {
		if err := p.Set(ctx, userEntry(k, `1`, 0)); !errors.Is(err, jsonl.ErrInvalidKey) {
			t.Fatalf("键 %q 应被拒,得到 %v", k, err)
		}
	}
}

func TestSecretReferenceValueRoundTrips(t *testing.T) {
	p, _, _ := newProvider(t)
	ctx := context.Background()
	raw := `{"ref":"secret://kv/daedalus/api-key"}`
	if err := p.Set(ctx, userEntry("k", raw, 0)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := p.Get(ctx, memoryprovider.ScopeUser, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got.Value) != raw {
		t.Fatalf("secret:// 引用被改动: got=%s want=%s", got.Value, raw)
	}
}

func TestEntriesSurviveReopen(t *testing.T) {
	p, c, path := newProvider(t)
	ctx := context.Background()
	if err := p.Set(ctx, userEntry("keep", `{"v":2}`, 0)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	p2, err := jsonl.New(path, jsonl.Options{Now: c.Now})
	if err != nil {
		t.Fatalf("重开 New: %v", err)
	}
	got, err := p2.Get(ctx, memoryprovider.ScopeUser, "keep")
	if err != nil {
		t.Fatalf("重开后 Get: %v", err)
	}
	if string(got.Value) != `{"v":2}` {
		t.Fatalf("重开后值不对: %s", got.Value)
	}
}

func TestFileIsJSONLines(t *testing.T) {
	p, _, path := newProvider(t)
	ctx := context.Background()
	// 三条里带一条值内嵌换行与引号的:这才能区分「一行一条」与「整个文件一个 JSON」。
	entries := []memoryprovider.Entry{
		userEntry("k1", `1`, 0),
		userEntry("k2", `{"text":"a\nb \"q\""}`, 0),
		userEntry("k3", `{"n":[1,2]}`, 0),
	}
	for _, e := range entries {
		if err := p.Set(ctx, e); err != nil {
			t.Fatalf("Set %s: %v", e.Key, err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitLines(string(raw))
	if len(lines) != len(entries) {
		t.Fatalf("应恰好 %d 行(一行一条),实际 %d 行", len(entries), len(lines))
	}
	for i, ln := range lines {
		var rec map[string]json.RawMessage
		if err := json.Unmarshal([]byte(ln), &rec); err != nil {
			t.Fatalf("第 %d 行不是独立 JSON: %v (行=%q)", i+1, err, ln)
		}
		for _, f := range []string{"key", "value", "scope", "set_at"} {
			if _, ok := rec[f]; !ok {
				t.Fatalf("第 %d 行缺字段 %q: %v", i+1, f, rec)
			}
		}
		var key string
		if err := json.Unmarshal(rec["key"], &key); err != nil {
			t.Fatal(err)
		}
		if key != entries[i].Key {
			t.Fatalf("第 %d 行应是 %s,实际 %s", i+1, entries[i].Key, key)
		}
	}
}

func firstLine(s string) string {
	for i, r := range s {
		if r == '\n' {
			return s[:i]
		}
	}
	return s
}

// ---- 修复 pass:损坏尾部容忍 / 压缩 / 空值 / 契约断言 / Close ----

func TestNewToleratesTruncatedTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.jsonl")
	good := `{"key":"a","value":1,"scope":"user","set_at":"2026-11-13T00:00:00Z"}`
	// 半截写:进程在写完前被杀,尾行没有闭合。
	if err := os.WriteFile(path, []byte(good+"\n"+`{"key":"b","val`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := jsonl.New(path, jsonl.Options{})
	if err != nil {
		t.Fatalf("尾部半截写不该让 store 打不开: %v", err)
	}
	if _, err := p.Get(context.Background(), memoryprovider.ScopeUser, "a"); err != nil {
		t.Fatalf("完好记录应可读: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(splitLines(string(raw))); n != 1 {
		t.Fatalf("重开时应把半截尾行清掉,实际剩 %d 行: %q", n, string(raw))
	}
}

func TestNewRejectsCorruptionInMiddle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.jsonl")
	body := `{"key":"a","scope":"user"}` + "\n" + `not json` + "\n" + `{"key":"c","scope":"user"}` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := jsonl.New(path, jsonl.Options{}); err == nil {
		t.Fatal("中间行损坏必须 fail-closed,不能静默跳过")
	}
}

func TestNewCompactsTombstonesAndExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.jsonl")
	c := &clock{t: time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)}
	p, err := jsonl.New(path, jsonl.Options{Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, k := range []string{"keep", "del", "ttl"} {
		if err := p.Set(ctx, userEntry(k, `1`, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Delete(ctx, memoryprovider.ScopeUser, "del"); err != nil {
		t.Fatal(err)
	}
	if err := p.Set(ctx, userEntry("ttl", `1`, time.Minute)); err != nil {
		t.Fatal(err)
	}
	c.Advance(2 * time.Minute)

	p2, err := jsonl.New(path, jsonl.Options{Now: c.Now})
	if err != nil {
		t.Fatalf("重开: %v", err)
	}
	keys, err := p2.List(ctx, memoryprovider.ScopeUser, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "keep" {
		t.Fatalf("压缩后应只剩 keep,得到 %v", keys)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(splitLines(string(raw))); n != 1 {
		t.Fatalf("文件应被压缩成 1 行(墓碑与过期行折叠),实际 %d 行", n)
	}
}

func TestEmptyValueIsRejected(t *testing.T) {
	p, _, _ := newProvider(t)
	err := p.Set(context.Background(), memoryprovider.Entry{Key: "empty", Value: json.RawMessage{}, Scope: memoryprovider.ScopeUser})
	if !errors.Is(err, jsonl.ErrInvalidValue) {
		t.Fatalf("空值不是合法 JSON,应在写入口被拒,得到 %v", err)
	}
}

func TestNullValueRoundTrips(t *testing.T) {
	p, c, path := newProvider(t)
	ctx := context.Background()
	if err := p.Set(ctx, memoryprovider.Entry{Key: "nil", Value: json.RawMessage("null"), Scope: memoryprovider.ScopeUser}); err != nil {
		t.Fatal(err)
	}
	p2, err := jsonl.New(path, jsonl.Options{Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	got, err := p2.Get(ctx, memoryprovider.ScopeUser, "nil")
	if err != nil {
		t.Fatalf("null 值条目必须还在: %v", err)
	}
	if string(got.Value) != "null" {
		t.Fatalf("null 往返后应仍是 null,得到 %q", got.Value)
	}
}

func TestProviderSatisfiesContract(t *testing.T) {
	p, _, _ := newProvider(t)
	var _ memoryprovider.Provider = p
}

func TestCloseSyncsAndIsIdempotent(t *testing.T) {
	p, _, path := newProvider(t)
	ctx := context.Background()
	if err := p.Set(ctx, userEntry("k", `1`, 0)); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("重复 Close 不该报错: %v", err)
	}
	p2, err := jsonl.New(path, jsonl.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p2.Get(ctx, memoryprovider.ScopeUser, "k"); err != nil {
		t.Fatalf("Close 后数据应已落盘: %v", err)
	}
}

func splitLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if ln != "" {
			out = append(out, ln)
		}
	}
	return out
}
