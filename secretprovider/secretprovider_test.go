package secretprovider

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Daedalusys/daedalus-sdk/slot"
)

// secretprovider_test.go —— 钉 Ref 形状门、Secret 脱敏红线与
// Provider 接口形状(内存 fake 静态实现,零真实后端)。

// fakeProvider 同时充当接口形状的编译期钉子。
type fakeProvider struct{ refs map[Ref]string }

func (f *fakeProvider) Scheme() string           { return "fake" }
func (f *fakeProvider) Swappability() slot.Level { return slot.LevelRestart }
func (f *fakeProvider) Collections(context.Context) ([]string, error) {
	return []string{"default"}, nil
}
func (f *fakeProvider) List(_ context.Context, _, prefix string) ([]Ref, error) {
	var out []Ref
	for r := range f.refs {
		if strings.HasPrefix(string(r), "secret://fake/"+prefix) {
			out = append(out, r)
		}
	}
	slices.Sort(out)
	return out, nil
}
func (f *fakeProvider) Get(_ context.Context, ref Ref) (Secret, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	if ref.Scheme() != f.Scheme() {
		return nil, ErrSchemeMismatch
	}
	v, ok := f.refs[ref]
	if !ok {
		return nil, ErrNotFound
	}
	return Secret(v), nil
}
func (f *fakeProvider) Set(_ context.Context, ref Ref, value Secret) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if ref.Scheme() != f.Scheme() {
		return ErrSchemeMismatch
	}
	f.refs[ref] = string(value)
	return nil
}
func (f *fakeProvider) Delete(_ context.Context, ref Ref) error {
	if _, ok := f.refs[ref]; !ok {
		return ErrNotFound
	}
	delete(f.refs, ref)
	return nil
}

var _ Provider = (*fakeProvider)(nil)

func TestRefValidate(t *testing.T) {
	for _, ok := range []Ref{
		"secret://kwallet/agents/copilot/api_key",
		"secret://credstore/daedalus_token",
		"secret://a/-b_c/x",
	} {
		if err := ok.Validate(); err != nil {
			t.Errorf("合法引用被拒 %q: %v", ok, err)
		}
	}
	for _, bad := range []Ref{
		"", "kwallet/x", "secret://", "secret:///x", "secret://Uppercase/x",
		"secret://1digit/x", "secret://kwallet/", "secret://kwallet/a b",
		"secret://kwallet/a\x00b", "secret://kwallet/a\nb", "http://x/y",
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("非法引用被放行: %q", bad)
		} else if !strings.Contains(err.Error(), "非法") {
			t.Errorf("错误应指向形状门: %v", err)
		}
	}
}

func TestRefScheme(t *testing.T) {
	if got := Ref("secret://credstore/daedalus_token").Scheme(); got != "credstore" {
		t.Errorf("Scheme 解析错: %q", got)
	}
}

func TestSecretRedaction(t *testing.T) {
	s := Secret("hunter2")
	if strings.Contains(s.String(), "hunter2") || strings.Contains(s.GoString(), "hunter2") {
		t.Fatal("String/GoString 泄露明文")
	}
	if _, err := json.Marshal(map[string]any{"leak": s}); err == nil {
		t.Fatal("MarshalJSON 必须拒绝明文序列化(框架级红线)")
	}
	// 整包文档也不得因引用携带 Secret 而可序列化。
	if _, err := json.Marshal(struct{ S Secret }{s}); err == nil {
		t.Fatal("结构体字段序列化同样必须被拒")
	}
	s.Zeroize()
	if !slices.Equal([]byte(s), make([]byte, len(s))) {
		t.Fatalf("Zeroize 未清零: %v", s)
	}
}

func TestFakeProviderRoundTrip(t *testing.T) {
	ctx := context.Background()
	p := &fakeProvider{refs: map[Ref]string{"secret://fake/token": "v1"}}

	// 形状合法但 scheme 段不是本 provider:ErrSchemeMismatch(读写皆拒)。
	if _, err := p.Get(ctx, "secret://kwallet/token"); !errors.Is(err, ErrSchemeMismatch) {
		t.Fatalf("跨 scheme 读取应回 ErrSchemeMismatch: %v", err)
	}
	if err := p.Set(ctx, "secret://kwallet/token", Secret("x")); !errors.Is(err, ErrSchemeMismatch) {
		t.Fatalf("跨 scheme 写入应回 ErrSchemeMismatch: %v", err)
	}
	if _, err := p.Get(ctx, "secret://fake/absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("缺失引用应回 ErrNotFound: %v", err)
	}
	if _, err := p.Get(ctx, "secret://fake/a b"); !errors.Is(err, ErrRefInvalid) {
		t.Fatalf("非法形状应先行被拒: %v", err)
	}

	s, err := p.Get(ctx, "secret://fake/token")
	if err != nil || string(s) != "v1" {
		t.Fatalf("既有引用读取失败: %q %v", s, err)
	}
	if err := p.Set(ctx, "secret://fake/new", Secret("nv")); err != nil {
		t.Fatal(err)
	}
	if s, err := p.Get(ctx, "secret://fake/new"); err != nil || string(s) != "nv" {
		t.Fatalf("往返失败: %q %v", s, err)
	}
	if err := p.Delete(ctx, "secret://fake/new"); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(ctx, "secret://fake/new"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("二次删除应回 ErrNotFound: %v", err)
	}
}
