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
	if err := p.Set(ctx, userEntry("k", `1`, 0)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(firstLine(string(raw))), &rec); err != nil {
		t.Fatalf("每行必须是独立 JSON: %v (行=%q)", err, firstLine(string(raw)))
	}
	if rec["key"] != "k" {
		t.Fatalf("记录里没有 key 字段: %v", rec)
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
