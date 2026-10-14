package audit

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// recordLine 用真实 Record.Line() 造一行合法审计 JSON(无链约束,只验证迭代顺序)。
func recordLine(ts, prev, hash string) string {
	return (&Record{
		Timestamp: ts, Identity: "i", Tool: "t", Args: NewObject(),
		PolicyVersion: "1.0", Outcome: "success", PrevHash: prev, EntryHash: hash,
	}).Line() + "\n"
}

func hashN(n int) string { return fmt.Sprintf("%064d", n) }

func writeArchiveGz(t *testing.T, dir, base, content string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, base))
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err := zw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func collectOpenLog(t *testing.T, r LogReader) []string {
	t.Helper()
	var got []string
	for {
		rec, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		got = append(got, rec.EntryHash)
	}
	return got
}

func setupThreeSegments(t *testing.T) (logPath, archiveDir string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "audit.jsonl")
	archiveDir = filepath.Join(dir, "archive")
	if err := os.MkdirAll(archiveDir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeArchiveGz(t, archiveDir, "audit.jsonl.20260101T000000.000000Z.jsonl.gz",
		recordLine("2026-01-01T00:00:00+00:00", hashN(0), hashN(1)))
	writeArchiveGz(t, archiveDir, "audit.jsonl.20260102T000000.000000Z.jsonl.gz",
		recordLine("2026-01-02T00:00:00+00:00", hashN(1), hashN(2)))
	if err := os.WriteFile(logPath, []byte(recordLine("2026-01-03T00:00:00+00:00", hashN(2), hashN(3))), 0o640); err != nil {
		t.Fatal(err)
	}
	return logPath, archiveDir
}

// TestOpenLog_OldestFirst_IteratesAcrossArchives:归档(旧→新)+ 活跃在最末。
func TestOpenLog_OldestFirst_IteratesAcrossArchives(t *testing.T) {
	logPath, _ := setupThreeSegments(t)
	r, err := OpenLog(logPath, OldestFirst)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got := collectOpenLog(t, r)
	want := []string{hashN(1), hashN(2), hashN(3)}
	if len(got) != len(want) {
		t.Fatalf("got %d records %v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("顺序错: got[%d]=%s want %s (全部 %v)", i, got[i], want[i], got)
		}
	}
}

// TestOpenLog_NewestFirst_ActiveFirst:活跃最前,归档(新→旧)在后,供 tx 扫描短路。
func TestOpenLog_NewestFirst_ActiveFirst(t *testing.T) {
	logPath, _ := setupThreeSegments(t)
	r, err := OpenLog(logPath, NewestFirst)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got := collectOpenLog(t, r)
	want := []string{hashN(3), hashN(2), hashN(1)}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("顺序错: got[%d]=%s want %s (全部 %v)", i, got[i], want[i], got)
		}
	}
}

// TestOpenLog_NoArchiveDir 只迭代活跃文件(archive 目录不存在)。
func TestOpenLog_NoArchiveDir(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(recordLine("2026-01-03T00:00:00+00:00", hashN(2), hashN(3))), 0o640); err != nil {
		t.Fatal(err)
	}
	r, err := OpenLog(logPath, OldestFirst)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := collectOpenLog(t, r); len(got) != 1 || got[0] != hashN(3) {
		t.Fatalf("got %v, want [%s]", got, hashN(3))
	}
}
