package audit

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// noopAttrs 取代 chattr;免 root 即可完成"轮转 + 复原"路径。
type noopAttrs struct{}

func (noopAttrs) HasAppend(string) (bool, error) { return false, nil }
func (noopAttrs) ClearAppend(string) error       { return nil }
func (noopAttrs) SetAppend(string) error         { return nil }

func withFakeAttrs(t *testing.T) {
	t.Helper()
	orig := CurrentAppendOnlyOps()
	SetAppendOnlyOps(noopAttrs{})
	t.Cleanup(func() { SetAppendOnlyOps(orig) })
}

// TestRotate_RealAppendOnlyInode 走**完整 Rotate 路径**且**不换 attrs 实现**,
// 让默认的 xattrOps 在真 +a inode 上跑一遍。
//
// 上面所有 Rotate 用例都注入 noopAttrs,FS_IOC_SETFLAGS 因此从未被触达 ——
// 这正是"清 append-only 必失败"能潜伏到真机日志长大后才暴露的原因。
// 非 root 或 fs 不支持 FS_APPEND_FL 时 skip。
func TestRotate_RealAppendOnlyInode(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("FS_APPEND_FL 需要 CAP_LINUX_IMMUTABLE(root);non-root 环境 skip")
	}
	ops := CurrentAppendOnlyOps()
	probe := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(probe, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := ops.SetAppend(probe); err != nil {
		if isAttrsUnsupported(err) {
			t.Skipf("当前 fs 不支持 FS_APPEND_FL: %v", err)
		}
		t.Fatalf("探针 SetAppend 失败: %v", err)
	}
	_ = ops.ClearAppend(probe)

	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	ar := filepath.Join(dir, "archive")
	// 真 +a 文件不可 unlink,t.TempDir 的清理会 EPERM;先清属性再让它删。
	// 本 cleanup 注册在 t.TempDir 之后 → LIFO 下先执行。
	t.Cleanup(func() {
		_ = ops.ClearAppend(p)
		entries, _ := os.ReadDir(ar)
		for _, e := range entries {
			_ = ops.ClearAppend(filepath.Join(ar, e.Name()))
		}
	})
	for i := 0; i < 3; i++ {
		if _, err := LogAudit(Entry{Tool: "t", LogPath: p}); err != nil {
			t.Fatal(err)
		}
	}
	if err := ops.SetAppend(p); err != nil {
		t.Fatalf("轮转前置 SetAppend 失败: %v", err)
	}

	rotated, err := Rotate(RotateOptions{LogPath: p, ArchiveDir: ar, Force: true})
	if err != nil || !rotated {
		t.Fatalf("真 +a inode 上轮转失败(清 append-only 那一步): rotated=%v err=%v", rotated, err)
	}

	// 归档段真的产出了,不是"中止后什么都没做"。
	entries, err := os.ReadDir(ar)
	if err != nil {
		t.Fatal(err)
	}
	var gzName string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl.gz") {
			gzName = e.Name()
		}
	}
	if gzName == "" {
		t.Fatalf("归档目录里没有 .jsonl.gz,实得 %v", entries)
	}
	// 新建的活跃文件重新带上 +a(轮转末尾的"尽力恢复"须真的成功)。
	has, herr := ops.HasAppend(p)
	if herr != nil {
		t.Fatalf("轮转后 HasAppend 失败: %v", herr)
	}
	if !has {
		t.Fatalf("轮转后活跃文件未恢复 append-only")
	}
}

func TestRotate_SkipsWhenBelowThreshold(t *testing.T) {
	withFakeAttrs(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	if _, err := LogAudit(Entry{Tool: "t", LogPath: p}); err != nil {
		t.Fatal(err)
	}
	rotated, err := Rotate(RotateOptions{LogPath: p, ArchiveDir: filepath.Join(dir, "archive"), MaxSizeMB: 1000})
	if err != nil || rotated {
		t.Fatalf("want (false, nil), got (%v, %v)", rotated, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "archive")); !os.IsNotExist(err) {
		t.Fatal("未轮转时不该建 archive dir")
	}
}

func TestRotate_BasicFlow_ArchiveAndTailAndChain(t *testing.T) {
	withFakeAttrs(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	ar := filepath.Join(dir, "archive")
	var prev string
	for i := 0; i < 3; i++ {
		rec, err := LogAudit(Entry{Tool: "t", LogPath: p})
		if err != nil {
			t.Fatal(err)
		}
		prev = rec.EntryHash
	}
	rotated, err := Rotate(RotateOptions{LogPath: p, ArchiveDir: ar, Force: true})
	if err != nil || !rotated {
		t.Fatalf("rotate: %v %v", rotated, err)
	}
	entries, _ := os.ReadDir(ar)
	if len(entries) != 1 {
		t.Fatalf("want 1 archive, got %d", len(entries))
	}
	if !strings.HasSuffix(entries[0].Name(), ".jsonl.gz") {
		t.Fatalf("应为 .jsonl.gz, got %s", entries[0].Name())
	}
	// 解压校验
	gz, _ := os.Open(filepath.Join(ar, entries[0].Name()))
	defer gz.Close()
	zr, _ := gzip.NewReader(gz)
	defer zr.Close()
	var gotLines []string
	buf := make([]byte, 64*1024)
	for {
		n, _ := zr.Read(buf)
		if n == 0 {
			break
		}
		gotLines = append(gotLines, string(buf[:n]))
	}
	if strings.Count(strings.Join(gotLines, ""), "\n") != 3 {
		t.Fatalf("归档段应含 3 条记录, got %q", gotLines)
	}
	// .tail 存在并等于 prev
	tail, _ := os.ReadFile(TailPath(p))
	if strings.SplitN(strings.TrimSpace(string(tail)), "\n", 2)[0] != prev {
		t.Fatalf("tail 内容错: %s", tail)
	}
	// 再写一条:链续
	rec, _ := LogAudit(Entry{Tool: "t", LogPath: p})
	if rec.PrevHash != prev {
		t.Fatalf("链应续接: prev=%s want %s", rec.PrevHash, prev)
	}
	// VerifyChain 跨段
	n2, err := VerifyChain(p, ar)
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 4 {
		t.Fatalf("want 4 verified, got %d", n2)
	}
}

func TestPrune_WritesLedgerAndKeepsChain(t *testing.T) {
	withFakeAttrs(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	ar := filepath.Join(dir, "archive")
	for i := 0; i < 2; i++ {
		LogAudit(Entry{Tool: "t", LogPath: p})
	}
	manualRotateForTest(t, p, ar, "audit.jsonl.20260101T000000.000000Z")
	for i := 0; i < 2; i++ {
		LogAudit(Entry{Tool: "t", LogPath: p})
	}
	manualRotateForTest(t, p, ar, "audit.jsonl.20260102T000000.000000Z")
	LogAudit(Entry{Tool: "t", LogPath: p})

	// 全部 prune(Now 远在 1/1 之后,RetainDays=0)
	pruned, err := Prune(PruneOptions{ArchiveDir: ar, RetainDays: 30, Now: time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 2 {
		t.Fatalf("want 2 pruned, got %d", pruned)
	}
	entries, _ := os.ReadDir(ar)
	var gzs int
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl.gz") {
			gzs++
		}
	}
	if gzs != 0 {
		t.Fatalf("应全删, 剩余 gz=%d", gzs)
	}
	// ledger 1 行
	lb, err := os.ReadFile(filepath.Join(ar, "pruned.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(lb), "\n") < 1 {
		t.Fatalf("ledger 应至少 1 行: %q", lb)
	}
	// VerifyChain 通过
	n, err := VerifyChain(p, ar)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 (active only), got %d", n)
	}
}

// TestReconcileArchive_CompressesOrphanJSONL:Rotate 崩溃留下的未压缩 .jsonl
// (无 .gz 同伴)应被 reconcile 压成 .gz 并删除原件。
func TestReconcileArchive_CompressesOrphanJSONL(t *testing.T) {
	dir := t.TempDir()
	ar := filepath.Join(dir, "archive")
	if err := os.MkdirAll(ar, 0o750); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(ar, "audit.jsonl.20260101T000000.000000Z.jsonl")
	if err := os.WriteFile(plain, []byte(recordLine("2026-01-01T00:00:00+00:00", hashN(0), hashN(1))), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := reconcileArchive(ar); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(plain); !os.IsNotExist(err) {
		t.Fatalf("未压缩原件应被删除, err=%v", err)
	}
	if _, err := os.Stat(plain + ".gz"); err != nil {
		t.Fatalf(".gz 应存在: %v", err)
	}
}
