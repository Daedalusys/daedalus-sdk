// 校验层测试:Metadata.Validate + Object.Validate 的接受 / 拒绝 / 聚合语义,
// 与 envelope_test 同仓 objectmodel 包内。
package objectmodel

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestMetadata_Validate 锁定接受路径 + reject 各分支;聚合错误必须点名字段。
func TestMetadata_Validate(t *testing.T) {
	t.Parallel()

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

// TestObject_Validate 锁定 Object 三段式 (Kind → Metadata → Spec) 复合语义。
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
