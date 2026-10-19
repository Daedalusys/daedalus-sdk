package audit

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// manualRotateForTest 是测试期"手动模拟一次轮转"辅助:读活跃文件末条 entry_hash,
// 写 .tail,rename 活跃到 archive/<name>.jsonl,新建空活跃文件。返回末哈希。
// 未压缩(留给 T6 验证 gz 路径;VerifyChain 既吃 .jsonl 也吃 .jsonl.gz)。
func manualRotateForTest(t *testing.T, active, archiveDir, name string) string {
	t.Helper()
	f, err := os.Open(active)
	if err != nil {
		t.Fatal(err)
	}
	h := lastEntryHash(f)
	_ = f.Close()
	if h == "" {
		t.Fatal("活跃文件无有效记录,无法轮转")
	}
	if err := os.MkdirAll(archiveDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(TailPath(active), []byte(h+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(active, filepath.Join(archiveDir, name+".jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	return h
}

// scanSegmentFile 读一段 .jsonl(无链校验),返回首 prev / 末 entry_hash / 末非 tx / 条数。
func scanSegmentFile(t *testing.T, path string) (firstPrev, last, lastNonTx string, entries int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		v, perr := ParseValue(line)
		if perr != nil || !v.IsObject() {
			continue
		}
		ph, ok1 := v.LookupString("prev_hash")
		eh, ok2 := v.LookupString("entry_hash")
		if !ok1 || !ok2 {
			continue
		}
		if entries == 0 {
			firstPrev = ph
		}
		last = eh
		if _, isTx := v.LookupString("tx_id"); !isTx {
			lastNonTx = eh
		}
		entries++
	}
	return
}

// TestVerifyChain_NoLedger_TwoArchivesPlusActive 跨两段归档 + 活跃,无 ledger,
// 起点为创世,期望整链计数正确(6)。
func TestVerifyChain_NoLedger_TwoArchivesPlusActive(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	archiveDir := filepath.Join(dir, "archive")

	// 段 A:3 条
	for i := 0; i < 3; i++ {
		if _, err := LogAudit(Entry{Tool: "t", LogPath: active}); err != nil {
			t.Fatal(err)
		}
	}
	manualRotateForTest(t, active, archiveDir, "audit.jsonl.20260101T000000.000000Z")

	// 段 B:2 条
	for i := 0; i < 2; i++ {
		if _, err := LogAudit(Entry{Tool: "t", LogPath: active}); err != nil {
			t.Fatal(err)
		}
	}
	manualRotateForTest(t, active, archiveDir, "audit.jsonl.20260102T000000.000000Z")

	// 活跃:1 条
	if _, err := LogAudit(Entry{Tool: "t", LogPath: active}); err != nil {
		t.Fatal(err)
	}

	n, err := VerifyChain(active, archiveDir)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if n != 6 {
		t.Fatalf("want 6, got %d", n)
	}
}

// TestVerifyChain_WithPrunedLedger_PassesAfterMiddleArchiveDeleted 删最老段,
// 用 prune ledger 锚定链骨,VerifyChain 仍通过并算准记录数。
func TestVerifyChain_WithPrunedLedger_PassesAfterMiddleArchiveDeleted(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	archiveDir := filepath.Join(dir, "archive")

	for i := 0; i < 3; i++ {
		if _, err := LogAudit(Entry{Tool: "t", LogPath: active}); err != nil {
			t.Fatal(err)
		}
	}
	segA := filepath.Join(archiveDir, "audit.jsonl.20260101T000000.000000Z.jsonl")
	manualRotateForTest(t, active, archiveDir, "audit.jsonl.20260101T000000.000000Z")
	for i := 0; i < 2; i++ {
		if _, err := LogAudit(Entry{Tool: "t", LogPath: active}); err != nil {
			t.Fatal(err)
		}
	}
	manualRotateForTest(t, active, archiveDir, "audit.jsonl.20260102T000000.000000Z")
	if _, err := LogAudit(Entry{Tool: "t", LogPath: active}); err != nil {
		t.Fatal(err)
	}

	// 读段 A 的骨头,然后删除。
	firstPrevA, lastA, lastNonTxA, entriesA := scanSegmentFile(t, segA)
	if firstPrevA != GenesisHash {
		t.Fatalf("段 A 首 prev 应为 Genesis, got %s", firstPrevA)
	}
	if err := os.Remove(segA); err != nil {
		t.Fatal(err)
	}
	// 构造 ledger:记录被删前缀的段骨 + 锚点(AnchorPrev = 段 A 末 = 段 B 首 prev)。
	rec := PruneRecord{
		Pruned: []PrunedSegment{{
			File:          filepath.Base(segA),
			FirstPrevHash: firstPrevA,
			LastEntryHash: lastA,
			LastNonTxHash: lastNonTxA,
			Entries:       entriesA,
		}},
		AnchorPrev:    lastA,
		LastNonTxHash: lastNonTxA,
		InheritedTx:   nil,
		At:            "2026-01-03T00:00:00+00:00",
	}
	ledger, err := encodePruneRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archiveDir, "pruned.jsonl"), ledger, 0o640); err != nil {
		t.Fatal(err)
	}

	n, err := VerifyChain(active, archiveDir)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	// 段 A(3)被 ledger 骨架承担,段 B(2) + 活跃(1) 实算 = 3。
	if n != 3 {
		t.Fatalf("want 3 (实算), got %d", n)
	}
}

// TestVerifyChain_NoArchiveNoLedger_EqualsVerify 退化路径:无归档无 ledger → 走单文件 Verify。
func TestVerifyChain_NoArchiveNoLedger_EqualsVerify(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	for i := 0; i < 3; i++ {
		if _, err := LogAudit(Entry{Tool: "t", LogPath: active}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := VerifyChain(active, filepath.Join(dir, "archive"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("want 3, got %d", n)
	}
}

// TestVerifyChain_MiddleArchiveDeleted_NoLedger_Errors 删中间段、无 ledger → 链断裂。
func TestVerifyChain_MiddleArchiveDeleted_NoLedger_Errors(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	archiveDir := filepath.Join(dir, "archive")
	for i := 0; i < 2; i++ {
		LogAudit(Entry{Tool: "t", LogPath: active})
	}
	manualRotateForTest(t, active, archiveDir, "audit.jsonl.20260101T000000.000000Z")
	for i := 0; i < 2; i++ {
		LogAudit(Entry{Tool: "t", LogPath: active})
	}
	manualRotateForTest(t, active, archiveDir, "audit.jsonl.20260102T000000.000000Z")
	LogAudit(Entry{Tool: "t", LogPath: active})
	// 删中间段
	entries, _ := os.ReadDir(archiveDir)
	for _, e := range entries {
		if e.Name() == "audit.jsonl.20260101T000000.000000Z.jsonl" {
			os.Remove(filepath.Join(archiveDir, e.Name()))
		}
	}
	_, err := VerifyChain(active, archiveDir)
	if err == nil {
		t.Fatal("删中间段无 ledger 应报链断裂, got nil")
	}
}

// TestVerifyChain_HeadArchiveDeleted_NoLedger_Errors 删最老段、无 ledger → 起点非创世即断。
func TestVerifyChain_HeadArchiveDeleted_NoLedger_Errors(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	archiveDir := filepath.Join(dir, "archive")
	for i := 0; i < 2; i++ {
		LogAudit(Entry{Tool: "t", LogPath: active})
	}
	manualRotateForTest(t, active, archiveDir, "audit.jsonl.20260101T000000.000000Z")
	for i := 0; i < 2; i++ {
		LogAudit(Entry{Tool: "t", LogPath: active})
	}
	manualRotateForTest(t, active, archiveDir, "audit.jsonl.20260102T000000.000000Z")
	// 删最老段
	os.Remove(filepath.Join(archiveDir, "audit.jsonl.20260101T000000.000000Z.jsonl"))
	_, err := VerifyChain(active, archiveDir)
	if err == nil {
		t.Fatal("删最老段无 ledger 应报起点非创世, got nil")
	}
}

// TestVerifyChain_LedgerTampered_Errors 篡改 ledger AnchorPrev → seedFromPrune 拒。
func TestVerifyChain_LedgerTampered_Errors(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	archiveDir := filepath.Join(dir, "archive")
	for i := 0; i < 2; i++ {
		LogAudit(Entry{Tool: "t", LogPath: active})
	}
	segA := filepath.Join(archiveDir, "audit.jsonl.20260101T000000.000000Z.jsonl")
	manualRotateForTest(t, active, archiveDir, "audit.jsonl.20260101T000000.000000Z")
	firstPrevA, lastA, lastNonTxA, entriesA := scanSegmentFile(t, segA)
	os.Remove(segA)
	// AnchorPrev 故意写成错误值
	rec := PruneRecord{
		Pruned:        []PrunedSegment{{File: filepath.Base(segA), FirstPrevHash: firstPrevA, LastEntryHash: lastA, LastNonTxHash: lastNonTxA, Entries: entriesA}},
		AnchorPrev:    "deadbeef" + lastA[8:],
		LastNonTxHash: lastNonTxA,
		At:            "2026-01-03T00:00:00+00:00",
	}
	b, _ := encodePruneRecord(rec)
	os.WriteFile(filepath.Join(archiveDir, "pruned.jsonl"), b, 0o640)
	_, err := VerifyChain(active, archiveDir)
	if err == nil {
		t.Fatal("ledger anchor 不符末段 last_entry 应报断链, got nil")
	}
}
