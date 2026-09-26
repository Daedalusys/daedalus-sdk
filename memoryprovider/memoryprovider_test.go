package memoryprovider

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Daedalusys/daedalus-sdk/slot"
)

// memoryprovider_test.go —— 钉 scope 枚举、Entry 序列化形状与
// Provider 接口形状(fake 后端:map + 独立写入时钟,过期即不存在)。

// stored 携带 provider 内部写入时间:contract 的 Entry 只有 TTL 时长,
// 计时起点归实现私有(演示"过期即 ErrKeyNotFound"语义,不外泄到形状)。
type stored struct {
	entry Entry
	setAt time.Time
}

type fakeMemory struct {
	entries map[Scope]map[string]stored
	now     func() time.Time
}

func (f *fakeMemory) Swappability() slot.Level { return slot.LevelRestart }

func (f *fakeMemory) live(s stored) bool {
	return s.entry.TTL == 0 || f.now().Before(s.setAt.Add(s.entry.TTL))
}

func (f *fakeMemory) Get(_ context.Context, scope Scope, key string) (Entry, error) {
	if !scope.Valid() {
		return Entry{}, ErrScopeDenied
	}
	s, ok := f.entries[scope][key]
	if !ok || !f.live(s) {
		return Entry{}, ErrKeyNotFound
	}
	return s.entry, nil
}

func (f *fakeMemory) Set(_ context.Context, e Entry) error {
	if e.Key == "" {
		return errors.New("memoryprovider: key 为空")
	}
	if !e.Scope.Valid() {
		return ErrScopeDenied
	}
	if f.entries[e.Scope] == nil {
		f.entries[e.Scope] = map[string]stored{}
	}
	f.entries[e.Scope][e.Key] = stored{entry: e, setAt: f.now()}
	return nil
}

func (f *fakeMemory) Delete(ctx context.Context, scope Scope, key string) error {
	if _, err := f.Get(ctx, scope, key); err != nil {
		return err
	}
	delete(f.entries[scope], key)
	return nil
}

func (f *fakeMemory) List(_ context.Context, scope Scope, prefix string) ([]string, error) {
	if !scope.Valid() {
		return nil, ErrScopeDenied
	}
	var keys []string
	for k, s := range f.entries[scope] {
		if f.live(s) && strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys, nil
}

func (f *fakeMemory) Search(context.Context, string, int) ([]Entry, error) {
	return nil, ErrSearchUnavailable
}

var _ Provider = (*fakeMemory)(nil)

func TestScopeEnum(t *testing.T) {
	for _, s := range []Scope{ScopeUser, ScopeSystem} {
		if !s.Valid() {
			t.Errorf("全集内 scope 被拒: %q", s)
		}
	}
	for _, bad := range []Scope{"", "User", "global"} {
		if bad.Valid() {
			t.Errorf("表外 scope 应被拒: %q", bad)
		}
	}
}

func TestEntryJSONShape(t *testing.T) {
	raw, err := json.Marshal(Entry{
		Key: "pref/editor", Value: json.RawMessage(`{"vim":true}`), Scope: ScopeUser,
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["ttl_ns"]; ok {
		t.Errorf("TTL=0 应省略键: %v", m)
	}
	for _, want := range []string{"key", "value", "scope"} {
		if _, ok := m[want]; !ok {
			t.Errorf("Entry 缺键 %q: %v", want, m)
		}
	}
}

func TestFakeRoundTripAndTTL(t *testing.T) {
	now := time.Unix(1767225600, 0).UTC()
	f := &fakeMemory{entries: map[Scope]map[string]stored{}, now: func() time.Time { return now }}
	ctx := context.Background()

	e := Entry{Key: "fact/os", Value: json.RawMessage(`"AlmaLinux"`), Scope: ScopeUser, TTL: time.Hour}
	if err := f.Set(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := f.Set(ctx, Entry{Key: "pref/lang", Value: json.RawMessage(`"zh"`), Scope: ScopeSystem}); err != nil {
		t.Fatal(err)
	}
	if got, err := f.Get(ctx, ScopeUser, "fact/os"); err != nil || string(got.Value) != `"AlmaLinux"` {
		t.Fatalf("读取失败: %+v %v", got, err)
	}
	keys, err := f.List(ctx, ScopeUser, "")
	if err != nil || !slices.Equal(keys, []string{"fact/os"}) {
		t.Fatalf("List 只见本 scope: %v %v", keys, err)
	}
	if all, err := f.List(ctx, ScopeSystem, ""); err != nil || !slices.Equal(all, []string{"pref/lang"}) {
		t.Fatalf("system scope 列表异常: %v %v", all, err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := f.Get(ctx, ScopeUser, "fact/os"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("过期应视作不存在: %v", err)
	}
	if live, err := f.List(ctx, ScopeUser, ""); err != nil || len(live) != 0 {
		t.Fatalf("List 不得回过期键: %v %v", live, err)
	}
	if _, err := f.Search(ctx, "os", 5); !errors.Is(err, ErrSearchUnavailable) {
		t.Fatalf("Search 缺席必须回专用哨兵而非空集: %v", err)
	}
}
