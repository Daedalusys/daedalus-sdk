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

// pythonReplayScript 与 Python 集成测试同源公式:
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
    # 3) 哈希重算(与 audit-log.py 同式)
    args = r["args"]
    args_str = args if isinstance(args, str) else json.dumps(args, sort_keys=True, separators=(",", ":"))
    payload = f"{r['timestamp']}{r['identity']}{r['tool']}{args_str}{r['outcome']}{r['prev_hash']}"
    h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    assert h == r["entry_hash"], f"line {i}: entry_hash 不一致"
    assert r["prev_hash"] == prev, f"line {i}: 链断裂"
    prev = h

print("PYTHON REPLAY OK", len(raw_lines))
`

// === 轮转适配(2026-10-14 audit-state-rotation) ===

// TestLogAudit_FirstAppendAfterRotationSeedsFromTail 验证:轮转后活跃文件为空时,
// 首条 append 的 prev_hash 取 <logPath>.tail(上一段尾哈希),而非 GenesisHash,
// 保证链跨段连续。
func TestLogAudit_FirstAppendAfterRotationSeedsFromTail(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	// 模拟"轮转后":活跃文件存在但为空,旁有 .tail 写好上一段尾哈希。
	if f, err := os.Create(p); err != nil {
		t.Fatal(err)
	} else if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	const prevTail = "1111111111111111111111111111111111111111111111111111111111111111"
	if err := os.WriteFile(p+".tail", []byte(prevTail+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	rec, err := LogAudit(Entry{Tool: "x", LogPath: p})
	if err != nil {
		t.Fatal(err)
	}
	if rec.PrevHash != prevTail {
		t.Fatalf("空文件首条应从 .tail 播种: prev=%s want %s", rec.PrevHash, prevTail)
	}
	if rec.EntryHash == "" || rec.PrevHash == GenesisHash {
		t.Fatalf("不应退回 GenesisHash")
	}
}

// TestLogAudit_CreatesFileMode0640 验证轮转窗口内新建的审计文件恒 0640,
// 不因 O_CREATE 回落成 0644。
func TestLogAudit_CreatesFileMode0640(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	if _, err := LogAudit(Entry{Tool: "x", LogPath: p}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o640 {
		t.Fatalf("新建审计文件权限 = %o, want 640", got)
	}
}

// TestLogAudit_RejectsSymlink 验证 O_NOFOLLOW:活跃路径是符号链接时拒绝打开,
// 防止"符号链接换址"把审计写到别处。
func TestLogAudit_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.jsonl")
	if err := os.WriteFile(target, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "audit.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LogAudit(Entry{Tool: "x", LogPath: link}); err == nil {
		t.Fatal("符号链接应被 O_NOFOLLOW 拒绝, got nil")
	}
}

// TestLogAudit_TxBeginAfterRotation_SeedsFromArchiveLastNonTx:轮转后活跃为空时,
// 新 tx begin 的 tx_prev_hash 应取归档最后一条非 tx 记录的哈希(而非 GenesisHash)。
func TestLogAudit_TxBeginAfterRotation_SeedsFromArchiveLastNonTx(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	ar := filepath.Join(dir, "archive")
	// 写一条非 tx
	if _, err := LogAudit(Entry{Tool: "shell", LogPath: p}); err != nil {
		t.Fatal(err)
	}
	// 强制轮转(用 Rotate 真实路径,产物 .tail 含段末信息)
	if _, err := Rotate(RotateOptions{LogPath: p, ArchiveDir: ar, Force: true}); err != nil {
		t.Fatal(err)
	}
	// 新活跃为空;再写一条 tx begin
	rec, err := LogAudit(Entry{
		Tool: "daedalus_tx_begin", LogPath: p, TxID: "abcdef01", TxStep: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.TxPrevHash == GenesisHash {
		t.Fatalf("tx begin 在轮转后首条应从归档最后非 tx 种子,非 Genesis")
	}
	// 必须是归档最后一条记录的 entry_hash(=归档唯一的非 tx 记录)
	if rec.TxPrevHash == "" {
		t.Fatal("tx_prev_hash 不应为空")
	}
	// 整链应过
	if _, err := VerifyChain(p, ar); err != nil {
		t.Fatalf("跨归档+tx begin 后整链应过, got %v", err)
	}
}
