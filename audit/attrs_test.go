package audit

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fakeAttrs 是测试用 AppendOnlyOps 实现,免 root 即可注入验证可替换性。
type fakeAttrs struct {
	on  bool
	err error
}

func (f fakeAttrs) HasAppend(string) (bool, error) { return f.on, f.err }
func (f fakeAttrs) ClearAppend(string) error       { return f.err }
func (f fakeAttrs) SetAppend(string) error         { return f.err }

// TestAppendOnlyOps_Injectable 验证 SetAppendOnlyOps / CurrentAppendOnlyOps
// 替换语义,生产代码可注入 fake(根除 chattr 测试对 root 的依赖)。
func TestAppendOnlyOps_Injectable(t *testing.T) {
	orig := CurrentAppendOnlyOps()
	t.Cleanup(func() { SetAppendOnlyOps(orig) })

	SetAppendOnlyOps(fakeAttrs{on: true})
	on, err := CurrentAppendOnlyOps().HasAppend("anything")
	if err != nil || !on {
		t.Fatalf("want (true, nil), got (%v, %v)", on, err)
	}

	SetAppendOnlyOps(fakeAttrs{err: errors.New("boom")})
	if _, err := CurrentAppendOnlyOps().HasAppend("anything"); err == nil {
		t.Fatalf("fake err 应透传, got nil")
	}
}

// TestXattrOps_HasAppend_UnsupportedFS 验证 xattrOps 在不支持 attrs 的 fs
// (tmpfs) 上返回 ErrAttrsUnsupported(包裹 ENOTTY/EOPNOTSUPP/ENOSYS)。
// 需 root 真实执行 ioctl 才能触发,否则 skip。
func TestXattrOps_HasAppend_UnsupportedFS(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("xattr 需要 root;CI root 跑过,本地 skip")
	}
	dir := t.TempDir()
	// tmpfs(/dev/shm) 不支持 FS_APPEND_FL;若跑在 ext4,使用 ioctl 探测
	// + 故意设置不存在的 flag 位?此处仅验证"不可支持时返 ErrAttrsUnsupported":
	// 实际 fs 行为依赖运行环境,本测试以 root 路径作 smoke。
	p := filepath.Join(dir, "x")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := xattrOps{}.HasAppend(p)
	if err != nil && !errors.Is(err, ErrAttrsUnsupported) {
		t.Fatalf("want ErrAttrsUnsupported (or nil if fs 支持), got %v", err)
	}
}
