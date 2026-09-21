package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goldenFile = "testdata/golden.jsonl"

// sha256Hex 独立参考实现(仅测试断言用)。
func sha256Hex(t *testing.T, payload string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// readGolden 返回金样文件的非空行列表。
func readGolden(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", goldenFile, err)
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// TestGolden_ReplayEachEntryHash 逐条重放金样向量:
// Go ComputeEntryHash(timestamp, identity, tool, args_str, outcome, prev_hash)
// 必须与文件内 entry_hash 逐字节相等; 同时断言整行重序列化字节一致。
func TestGolden_ReplayEachEntryHash(t *testing.T) {
	lines := readGolden(t)
	if len(lines) < 10 {
		t.Fatalf("金样至少 10 条, 实得 %d", len(lines))
	}
	for i, line := range lines {
		v, err := ParseValue(line)
		if err != nil {
			t.Fatalf("第 %d 行解析失败: %v", i+1, err)
		}
		ts, _ := v.LookupString("timestamp")
		id, _ := v.LookupString("identity")
		tool, _ := v.LookupString("tool")
		outcome, _ := v.LookupString("outcome")
		prev, _ := v.LookupString("prev_hash")
		wantHash, _ := v.LookupString("entry_hash")
		args, ok := v.Lookup("args")
		if !ok {
			t.Fatalf("第 %d 行缺 args", i+1)
		}
		got := ComputeEntryHash(ts, id, tool, args.ArgsString(), outcome, prev)
		if got != wantHash {
			t.Fatalf("第 %d 行 entry_hash 不符:\n  python=%s\n  go    =%s\n  args_str=%s",
				i+1, wantHash, got, args.ArgsString())
		}
		// 整行(默认分隔符 sort_keys)必须与 Python 原文逐字节一致 → 证明序列化器兼容。
		if re := encodeValue(v, modeLine).String(); re != line {
			t.Fatalf("第 %d 行重序列化不符:\n  文件=%s\n  Go  =%s", i+1, line, re)
		}
	}
}

// TestGolden_HashChainContinuity 断言 prev_hash 递推 + 创世 "0"*64。
func TestGolden_HashChainContinuity(t *testing.T) {
	lines := readGolden(t)
	prev := GenesisHash
	for i, line := range lines {
		v, err := ParseValue(line)
		if err != nil {
			t.Fatal(err)
		}
		gotPrev, _ := v.LookupString("prev_hash")
		entryHash, _ := v.LookupString("entry_hash")
		if gotPrev != prev {
			t.Fatalf("第 %d 行链断裂: prev_hash=%s 期望=%s", i+1, gotPrev, prev)
		}
		prev = entryHash
	}
}

// TestVerify_GoldenFile 端到端: Verify 对金样全链通过且条数正确。
func TestVerify_GoldenFile(t *testing.T) {
	n, err := Verify(goldenFile)
	if err != nil {
		t.Fatalf("Verify(golden) 失败: %v", err)
	}
	if want := len(readGolden(t)); n != want {
		t.Fatalf("Verify 报告 %d 条, 期望 %d", n, want)
	}
}

// TestVerify_DetectsTamperAndChainBreak 篡改字段与剪断链接均须报错。
func TestVerify_DetectsTamperAndChainBreak(t *testing.T) {
	t.Run("篡改第2行outcome", func(t *testing.T) {
		p := copyGoldenToTemp(t)
		data, _ := os.ReadFile(p)
		lines := strings.Split(string(data), "\n")
		lines[1] = strings.Replace(lines[1], `"outcome": "success"`, `"outcome": "denied"`, 1)
		if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(p); err == nil || !strings.Contains(err.Error(), "第 2 行") {
			t.Fatalf("应报第 2 行哈希不符, 实得 %v", err)
		}
	})
	t.Run("删除首行致链断裂", func(t *testing.T) {
		p := copyGoldenToTemp(t)
		data, _ := os.ReadFile(p)
		rest := strings.SplitN(string(data), "\n", 2)[1]
		if err := os.WriteFile(p, []byte(rest), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(p); err == nil || !strings.Contains(err.Error(), "链断裂") {
			t.Fatalf("应报链断裂, 实得 %v", err)
		}
	})
}

func copyGoldenToTemp(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "seeded.jsonl")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestGolden_HashComparisonTable 打印 Python 产出 entry_hash 与 Go 重算值的
// 逐条对照表(至少覆盖 3 条, 含 CJK 行), 作为证据链的可视化对照。
func TestGolden_HashComparisonTable(t *testing.T) {
	for i, line := range readGolden(t) {
		v, err := ParseValue(line)
		if err != nil {
			t.Fatal(err)
		}
		ts, _ := v.LookupString("timestamp")
		id, _ := v.LookupString("identity")
		tool, _ := v.LookupString("tool")
		outcome, _ := v.LookupString("outcome")
		prev, _ := v.LookupString("prev_hash")
		pyHash, _ := v.LookupString("entry_hash")
		args, _ := v.Lookup("args")
		goHash := ComputeEntryHash(ts, id, tool, args.ArgsString(), outcome, prev)
		t.Logf("#%-2d tool=%-14s identity=%-10s\n    python: %s\n    go    : %s\n    match : %v",
			i+1, tool, id, pyHash, goHash, pyHash == goHash)
		if pyHash != goHash {
			t.Fatalf("第 %d 行两侧哈希不一致", i+1)
		}
	}
}
