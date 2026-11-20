// 条子用量日志的测试:追加排他、折叠计数、损坏行 fail-closed。
package grant_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Daedalusys/daedalus-sdk/dirs"
	"github.com/Daedalusys/daedalus-sdk/grant"
)

// usagePath 在临时目录里给出用量日志路径(不经 env,直接测文件语义)。
func usagePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "grant-usage.jsonl")
}

// readUsageLines 读回日志行,顺带校验每行都是合法 JSON 且带 grant_id / used_at。
func readUsageLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("打开用量日志失败: %v", err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			t.Fatalf("用量日志出现空行(交错或半行写入)")
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("用量日志行不是合法 JSON: %q (%v)", string(line), err)
		}
		if _, ok := rec["grant_id"].(string); !ok {
			t.Fatalf("用量日志行缺 grant_id: %q", string(line))
		}
		if _, ok := rec["used_at"].(string); !ok {
			t.Fatalf("用量日志行缺 used_at: %q", string(line))
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("读用量日志失败: %v", err)
	}
	return out
}

func TestUsageLogPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAEDALUS_TX_DIR", dir)
	got, err := grant.UsageLogPath()
	if err != nil {
		t.Fatalf("UsageLogPath 失败: %v", err)
	}
	want := filepath.Join(dir, "grant-usage.jsonl")
	if got != want {
		t.Fatalf("UsageLogPath = %q, 期望 %q", got, want)
	}
}

func TestUsageLogPathRejectsRelativeEnv(t *testing.T) {
	t.Setenv("DAEDALUS_TX_DIR", "relative/tx")
	_, err := grant.UsageLogPath()
	if !errors.Is(err, dirs.ErrEnvNotAbsolute) {
		t.Fatalf("期望 ErrEnvNotAbsolute,实际: %v", err)
	}
}

func TestRecordUseAndUsedCounts(t *testing.T) {
	path := usagePath(t)
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if err := grant.RecordUse(path, "g-1", now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("RecordUse(g-1) 失败: %v", err)
		}
	}
	if err := grant.RecordUse(path, "g-2", now); err != nil {
		t.Fatalf("RecordUse(g-2) 失败: %v", err)
	}

	counts, err := grant.UsedCounts(path)
	if err != nil {
		t.Fatalf("UsedCounts 失败: %v", err)
	}
	if counts["g-1"] != 3 || counts["g-2"] != 1 || len(counts) != 2 {
		t.Fatalf("计数 = %v, 期望 g-1:3 g-2:1", counts)
	}

	lines := readUsageLines(t, path)
	if len(lines) != 4 {
		t.Fatalf("日志行数 = %d, 期望 4", len(lines))
	}
}

func TestRecordUseWritesUTC(t *testing.T) {
	path := usagePath(t)
	loc := time.FixedZone("CST", 8*3600)
	now := time.Date(2026, 11, 20, 18, 0, 0, 0, loc)
	if err := grant.RecordUse(path, "g-1", now); err != nil {
		t.Fatalf("RecordUse 失败: %v", err)
	}
	lines := readUsageLines(t, path)
	raw, ok := lines[0]["used_at"].(string)
	if !ok {
		t.Fatalf("used_at 不是字符串: %v", lines[0]["used_at"])
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t.Fatalf("used_at 不是 RFC3339: %q (%v)", raw, err)
	}
	if !parsed.UTC().Equal(now.UTC()) {
		t.Fatalf("used_at = %s, 期望与 %s 同一时刻", parsed, now)
	}
	if _, offset := parsed.Zone(); offset != 0 {
		t.Fatalf("used_at 未归一到 UTC(偏移 %d)", offset)
	}
}

func TestUsedCountsMissingFileIsEmpty(t *testing.T) {
	counts, err := grant.UsedCounts(filepath.Join(t.TempDir(), "absent.jsonl"))
	if err != nil {
		t.Fatalf("文件不存在应返回空表与 nil,实际: %v", err)
	}
	if counts == nil {
		t.Fatalf("空表不应为 nil map")
	}
	if len(counts) != 0 {
		t.Fatalf("计数 = %v, 期望空表", counts)
	}
}

func TestRecordUseRejectsEmptyGrantID(t *testing.T) {
	path := usagePath(t)
	if err := grant.RecordUse(path, "", time.Now()); err == nil {
		t.Fatalf("空条子 id 应被拒绝")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("拒绝时不应创建日志文件")
	}
}

func TestUsedCountsRejectsCorruptLine(t *testing.T) {
	path := usagePath(t)
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	if err := grant.RecordUse(path, "g-1", now); err != nil {
		t.Fatalf("RecordUse 失败: %v", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		t.Fatalf("打开日志失败: %v", err)
	}
	if _, err := f.WriteString("half-written-no-newline"); err != nil {
		t.Fatalf("写坏行失败: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	if _, err := grant.UsedCounts(path); err == nil {
		t.Fatalf("坏行必须报错,否则会静默少计次数(等于放宽用量上限)")
	}
}

func TestRecordUseWaitsForExclusiveLock(t *testing.T) {
	// 记账必须拿排他锁:否则并发写会交错出半行,折叠计数就不可信了。
	path := usagePath(t)
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	if err := grant.RecordUse(path, "g-seed", now); err != nil {
		t.Fatalf("RecordUse 失败: %v", err)
	}
	holder, err := os.OpenFile(path, os.O_RDWR, 0o640)
	if err != nil {
		t.Fatalf("打开日志失败: %v", err)
	}
	defer holder.Close()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatalf("加锁失败: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- grant.RecordUse(path, "g-1", now) }()
	select {
	case err := <-done:
		t.Fatalf("持锁期间 RecordUse 不该完成(实际: %v)", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatalf("解锁失败: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("释放锁后 RecordUse 失败: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("释放锁后 RecordUse 仍未完成")
	}
}

func TestRecordUseIsExclusive(t *testing.T) {
	path := usagePath(t)
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := grant.RecordUse(path, "g-1", now.Add(time.Duration(i)*time.Millisecond)); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("并发 RecordUse 失败: %v", err)
	}

	counts, err := grant.UsedCounts(path)
	if err != nil {
		t.Fatalf("UsedCounts 失败: %v", err)
	}
	if counts["g-1"] != workers {
		t.Fatalf("计数 = %d, 期望 %d", counts["g-1"], workers)
	}
	lines := readUsageLines(t, path)
	if len(lines) != workers {
		t.Fatalf("日志行数 = %d, 期望 %d", len(lines), workers)
	}
}
