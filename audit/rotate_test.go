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
	if strings.TrimSpace(string(tail)) != prev {
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
