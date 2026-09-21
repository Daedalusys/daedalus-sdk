package audit

// logaudit_test.go —— 写入侧: Go LogAudit 产出经真实 Python 重放的反向验证、
// flock 并发链完整性、get_last_entry_hash 尾行回溯边界。

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestLogAudit_PythonReplayReverseVerification 反向验证(核心门禁):
// 用 Go LogAudit 写 3 条(含 CJK、嵌套、原始字符串 args), 再由**真实 Python**
// 内联重算哈希 + 校验链 + 校验行格式, 全部断言一致。
func TestLogAudit_PythonReplayReverseVerification(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("环境缺少 python3, 跳过反向验证")
	}
	logPath := filepath.Join(t.TempDir(), "go-written.jsonl")

	for _, e := range []Entry{
		{Identity: "cli", Tool: "fs.read_file",
			Args: mustParse(t, `{"文件": "测试", "路径": "/home/用户/x.txt"}`)},
		{Identity: "mcp-client", Tool: "shell_exec",
			Args:    mustParse(t, `{"cmd": "df", "flags": ["-h", "--output=人机"], "n": 3}`),
			Outcome: "denied"},
		{Identity: "cli", Tool: "raw_tool", Args: NewString("不是 JSON { 原文"),
			PolicyVersion: "9.9"},
	} {
		rec, err := LogAudit(Entry{
			Identity:      e.Identity,
			Tool:          e.Tool,
			Args:          e.Args,
			Outcome:       e.Outcome,
			PolicyVersion: e.PolicyVersion,
			LogPath:       logPath,
		})
		if err != nil {
			t.Fatalf("LogAudit(%s) 失败: %v", e.Tool, err)
		}
		if rec.PrevHash == "" || rec.EntryHash == "" {
			t.Fatal("记录哈希字段为空")
		}
	}

	out, err := exec.Command(py, "-c", pythonReplayScript, logPath).CombinedOutput()
	t.Logf("python3 反向验证输出:\n%s", out)
	if err != nil {
		t.Fatalf("Python 重放 Go 产出失败: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PYTHON REPLAY OK 3") {
		t.Fatalf("Python 重放未见成功标记, 输出: %s", out)
	}
}

func mustParse(t *testing.T, s string) *Value {
	t.Helper()
	v, err := ParseValue(s)
	if err != nil {
		t.Fatalf("测试夹具 JSON 非法: %v", err)
	}
	return v
}

// TestLogAudit_ConcurrentFlockKeepsChainIntact flock 竞态: 20 路并发 LogAudit
// 全部串行化(排他锁), 链必须完整(任一写入方中途持锁读尾行)。
func TestLogAudit_ConcurrentFlockKeepsChainIntact(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "concurrent.jsonl")
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		argsFixture := mustParse(t, fmt.Sprintf(`{"i": %d}`, i))
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := LogAudit(Entry{
				Identity: fmt.Sprintf("agent-%d", i),
				Tool:     "concurrent",
				Args:     argsFixture,
				LogPath:  logPath,
			})
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("并发写入失败: %v", err)
	}
	got, err := Verify(logPath)
	if err != nil {
		t.Fatalf("并发后链校验失败: %v", err)
	}
	if got != n {
		t.Fatalf("链上 %d 条, 期望 %d", got, n)
	}
}

// TestLastEntryHash_EdgeCases 尾行回溯语义与 get_last_entry_hash 对齐。
func TestLastEntryHash_EdgeCases(t *testing.T) {
	t.Run("空文件创世", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "empty.jsonl")
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if got := lastEntryHash(f); got != GenesisHash {
			t.Fatalf("空文件 prev_hash = %s", got)
		}
	})
	t.Run("尾行非法JSON回退上一有效行", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "mixed.jsonl")
		content := `{"entry_hash": "abc"}

GARBAGE NOT JSON

`
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(p, os.O_RDWR, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if got := lastEntryHash(f); got != "abc" {
			t.Fatalf("回退结果 = %q, 期望 abc", got)
		}
	})
	t.Run("无entry_hash键创世", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "nohash.jsonl")
		if err := os.WriteFile(p, []byte(`{"foo": "bar"}`+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(p, os.O_RDWR, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if got := lastEntryHash(f); got != GenesisHash {
			t.Fatalf("无 entry_hash 文件 prev = %s, 期望创世", got)
		}
	})
}

// pythonReplayScript 与 tests/test_mcp_integration.py:344-346 同源公式:
// 对 Go 写出的每一行做哈希重算、链递推、行规范形与时间戳形制检查。
const pythonReplayScript = `
import json, hashlib, re, sys

GEN = "0" * 64
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?\+00:00$")

with open(sys.argv[1], "r", encoding="utf-8") as f:
    raw_lines = [l for l in f.read().splitlines() if l.strip()]

prev = GEN
for i, raw in enumerate(raw_lines, 1):
    r = json.loads(raw)
    # 1) 行规范形: 整行必须等于 json.dumps(record, sort_keys=True) 原文
    assert raw == json.dumps(r, sort_keys=True), f"line {i}: 行字节不一致"
    # 2) 时间戳形制(Python isoformat 两种分支)
    assert TS.match(r["timestamp"]), f"line {i}: 时间戳形制异常 {r['timestamp']}"
    # 3) 哈希重算(与 audit-log.py:30-37 同式)
    args = r["args"]
    args_str = args if isinstance(args, str) else json.dumps(args, sort_keys=True, separators=(",", ":"))
    payload = f"{r['timestamp']}{r['identity']}{r['tool']}{args_str}{r['outcome']}{r['prev_hash']}"
    h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    assert h == r["entry_hash"], f"line {i}: entry_hash 不一致"
    assert r["prev_hash"] == prev, f"line {i}: 链断裂"
    prev = h

print("PYTHON REPLAY OK", len(raw_lines))
`
