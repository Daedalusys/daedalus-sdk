package audit

// txchain_test.go —— todo 13 双链校验(test-first 钉桩):
//   - 干净 5 事务 × 2-3 步 begin/apply/rollback + 交错非 tx(propose/status/host/shell)日志 → Verify 全过;
//   - 篡改类 (a) tx_id 文本 / (b) in-tx args: 裸改(不重链) → 全局链以"哈希不符"捕获; 自洽重链后
//     (全局链完整、旧单链遍历全绿) → 具名 tx 链断裂捕获 —— 双链各自独立咬合;
//   - 篡改类 (c) tx_begin 创世 tx_prev_hash 改写为他条有效哈希(自洽重链) → 具名 tx 链;
//   - 承重证明: 相邻两事务步记录 tx_prev_hash 互换 + 全局重链 → singleChainOld(升级前算法)
//     整文件通过, 双链 Verify 必报具名 tx 断裂(证明新断言承重、非同义反复);
//   - 金样非 tx 逐字节语义不变由既有 TestVerify_GoldenFile 守护, 此处不重复;
//   - CLI 端到端夹具导出见 TestAudit_Verify_TxChain_CLI(go run ./cmd/daedalus-audit verify 断言退出码)。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 事务 ID 常量(十六进制形态, 与 todo 15 的 tx-id 形状一致; D/E 仅夹具使用故内联)。
const (
	txA        = "aaaa1111bbbb2222"
	txB        = "bbbb2222cccc3333"
	txC        = "cccc3333dddd4444"
	txTampered = "ffff9999eeee8888"
)

// txChainFix 按 todo 15 盖章规则构建夹具的镜像追踪器:
// begin 创世 = 最近非 tx 条目 entry_hash(初始创世 64 零), 步记录 tx_prev = 同事务上一条 entry_hash。
// Verify 读侧必须与此写侧算法互为逆运算 → 干净日志恒过。
type txChainFix struct {
	t       *testing.T
	path    string
	lastNon string            // 写侧镜像的 lastNonTxHash
	inTx    map[string]string // txID -> 该事务最近一条 entry_hash
	next    map[string]int    // txID -> 下一条记录的 tx_step
	recs    []*Record         // 按落盘行序记录(下标 = 行号-1)
}

func newChainFix(t *testing.T, path string) *txChainFix {
	return &txChainFix{t: t, path: path, lastNon: GenesisHash, inTx: map[string]string{}, next: map[string]int{}}
}

func (c *txChainFix) log(e Entry) *Record {
	c.t.Helper()
	e.LogPath = c.path
	rec, err := LogAudit(e)
	if err != nil {
		c.t.Fatalf("LogAudit(%s) 失败: %v", e.Tool, err)
	}
	if e.TxID == "" {
		c.lastNon = rec.EntryHash
	} else {
		c.inTx[e.TxID] = rec.EntryHash
		c.next[e.TxID] = e.TxStep + 1
	}
	c.recs = append(c.recs, rec)
	return rec
}

// nonTx 追加一条非 tx 条目(propose/status/host/shell 类, TxID 恒空)。
func (c *txChainFix) nonTx(identity, tool, args string) {
	c.log(Entry{Identity: identity, Tool: tool, Args: mustParse(c.t, args)})
}

// begin 追加 tx_begin(step 0, 创世 = 当前 lastNonTxHash), 返回落盘记录。
func (c *txChainFix) begin(txID, args string) *Record {
	return c.log(Entry{Identity: "daedalus-tx", Tool: "tx_begin", Args: mustParse(c.t, args),
		TxID: txID, TxStep: 0, TxPrevHash: c.lastNon})
}

// step 追加事务内后续步(apply/rollback, TxStep 逐事务递增)。
func (c *txChainFix) step(txID, tool, args string) *Record {
	return c.log(Entry{Identity: "daedalus-tx", Tool: tool, Args: mustParse(c.t, args),
		TxID: txID, TxStep: c.next[txID], TxPrevHash: c.inTx[txID]})
}

// buildMainFixture 主夹具布局(1 基行号钉死, 篡改测试按行号定位):
//
//	 1 propose(非tx)  2 A.begin  3 A.apply  4 A.rollback  5 status(非tx)
//	 6 B.begin  7 C.begin(与 B 共享同一创世 h5, 钉"两 begin 可共一创世")
//	 8 B.apply  9 C.apply 10 C.rollback 11 host_list(非tx)
//	12 D.begin 13 D.apply 14 shell_exec(非tx) 15 E.begin 16 E.apply 17 E.rollback
func buildMainFixture(t *testing.T, path string) *txChainFix {
	t.Helper()
	c := newChainFix(t, path)
	c.nonTx("copilot", "propose", `{"cmd": "df -h"}`)
	c.begin(txA, `{"adapter": "service.set"}`)
	c.step(txA, "tx_apply", `{"op": "apply", "seq": 1}`)
	c.step(txA, "tx_rollback", `{"op": "rollback", "seq": 2}`)
	c.nonTx("daedalus-tx", "daedalus_tx_status", fmt.Sprintf(`{"tx_id": %q}`, txA))
	c.begin(txB, `{"adapter": "service.set", "unit": "nginx"}`)
	c.begin(txC, `{"adapter": "service.set", "unit": "redis"}`)
	c.step(txB, "tx_apply", `{"op": "apply", "seq": 1}`)
	c.step(txC, "tx_apply", `{"op": "apply", "seq": 1}`)
	c.step(txC, "tx_rollback", `{"op": "rollback", "seq": 2}`)
	c.nonTx("daedalus-host", "host_list", `{}`)
	c.begin("dddd4444eeee5555", `{"adapter": "service.set", "unit": "sshd"}`)
	c.step("dddd4444eeee5555", "tx_apply", `{"op": "apply", "seq": 1}`)
	c.nonTx("cli", "shell_exec", `{"cmd": "free"}`)
	c.begin("eeee5555ffff6666", `{"adapter": "service.set", "unit": "cron"}`)
	c.step("eeee5555ffff6666", "tx_apply", `{"op": "apply", "seq": 1}`)
	c.step("eeee5555ffff6666", "tx_rollback", `{"op": "rollback", "seq": 2}`)
	return c
}

// buildSwapFixture 互换承重证明专用小夹具(共 5 行):
// 1 propose(非tx) / 2 A.begin / 3 B.begin / 4 A.apply / 5 B.apply。
// A/B 两个 begin 共享创世 h1(合法), 4/5 的 tx_prev 分别指向 h2/h3 → 可互换。
func buildSwapFixture(t *testing.T, path string) *txChainFix {
	t.Helper()
	c := newChainFix(t, path)
	c.nonTx("cli", "propose", `{"cmd": "df"}`)
	c.begin(txA, `{"unit": "a"}`)
	c.begin(txB, `{"unit": "b"}`)
	c.step(txA, "tx_apply", `{"seq": 1}`)
	c.step(txB, "tx_apply", `{"seq": 1}`)
	return c
}

// swapTamper 对 buildSwapFixture 产物执行"互换两事务步的 tx_prev_hash + 自洽重链":
// 行 4 指向 B 的 begin 哈希、行 5 指向 A 的, 载荷/entry_hash/全局 prev 全部重算自洽。
// 夹具 args 不同 → 两 begin 哈希必然不同 → 互换有区分度(断言兜底)。
func swapTamper(t *testing.T, c *txChainFix) {
	hA, hB := c.recs[1].EntryHash, c.recs[2].EntryHash // 第 2/3 行两个 begin 的哈希
	if hA == hB {
		t.Fatal("夹具失效: 两 begin 哈希相同, 互换无区分度")
	}
	rewrite(t, c.path, 4, func(no int, r Record) Record {
		if no == 4 {
			r.TxPrevHash = hB
		} else {
			r.TxPrevHash = hA
		}
		return r
	})
}

// logLines 返回去空行后的日志行(本文件夹具均无空行, 下标+1 即落盘行号)。
func logLines(data []byte) []string {
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// rewrite 自 from 行起做"自洽篡改 + 全局重链": mk 改写目标行载荷, 其后每一行的
// prev_hash 挂到上一行新 entry_hash、entry_hash 按载荷重算(tx 字段原样保留 →
// 同事务交叉引用被篡改点甩脱)。产出的日志对**旧单链**完全合法(哈希自洽 +
// 全局 prev_hash 递推成立), 只有双链的 tx_prev 断言能识破。
func rewrite(t *testing.T, path string, from int, mk func(lineNo int, r Record) Record) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := logLines(data)
	prev := GenesisHash
	out := make([]string, 0, len(lines))
	for i, line := range lines {
		no := i + 1
		rec, ok := recordFromValue(mustParse(t, line))
		if !ok {
			t.Fatalf("重写第 %d 行: recordFromValue 拒绝", no)
		}
		if no >= from {
			rec = mk(no, rec)
			rec.PrevHash = prev
			rec.EntryHash = ComputeEntryHashRecord(rec)
		}
		out = append(out, rec.Line())
		prev = rec.EntryHash
	}
	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// singleChainOld 复刻 todo 13 之前的旧单链遍历: 全局 prev_hash 递推 + entry_hash
// 重算(todo 12 的 tx 载荷派发保留), 但**绝不**断言 tx_prev_hash。用于承重证明:
// 自洽篡改日志旧链全绿、新双链必须报具名 tx 断裂 —— 断言在 Verify 之前先行执行,
// 若旧链都过不了则"漏网"前提不成立, 测试当场红。
func singleChainOld(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	prev := GenesisHash
	for i, line := range logLines(data) {
		rec, ok := recordFromValue(mustParse(t, line))
		if !ok || rec.PrevHash != prev || ComputeEntryHashRecord(rec) != rec.EntryHash {
			t.Fatalf("旧链本应全绿: 第 %d 行", i+1)
		}
		prev = rec.EntryHash
	}
}

// namedBreakMsg 具名诊断钉桩: "第 N 行 tx <id> step <n> 链断裂"。
func namedBreakMsg(lineNo int, txID string, step int) string {
	return fmt.Sprintf("第 %d 行 tx %s step %d 链断裂", lineNo, txID, step)
}

// evilArgsRewrite 改写主夹具第 3 行(A.apply)的 args —— args 篡改类共用。
func evilArgsRewrite(t *testing.T) func(no int, r Record, c *txChainFix) Record {
	return func(no int, r Record, _ *txChainFix) Record {
		if no == 3 {
			r.Args = mustParse(t, `{"op": "evi!", "seq": 1}`)
		}
		return r
	}
}

// relinkFn 篡改改写器: 按行号改写记录(未命中的行原样返回)。
type relinkFn = func(no int, r Record, c *txChainFix) Record

// relinkCase 自洽重链篡改类: 从 from 行起重链, mk 改写目标行, want 为具名诊断。
type relinkCase struct {
	name string
	from int
	mk   relinkFn
	want string
}

// expectTxBreak 旧链必须先整绿(承重前提, 防同义反复)→ 双链 Verify 报具名 tx 断裂。
func expectTxBreak(t *testing.T, p, want string) {
	singleChainOld(t, p)
	if _, err := Verify(p); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("双链应报 %q, 实得 %v", want, err)
	}
}

// relinkAndExpectTxBreak 自洽重链后断言具名 tx 断裂。日志留在 c.path, 供 CLI 端到端复用。
func relinkAndExpectTxBreak(t *testing.T, c *txChainFix, tc relinkCase) {
	rewrite(t, c.path, tc.from, func(no int, r Record) Record { return tc.mk(no, r, c) })
	expectTxBreak(t, c.path, tc.want)
}

// replaceInLine 对文件第 lineNo 行做字符串替换(裸篡改, 不重链 → 哈希必失配)。
func replaceInLine(t *testing.T, path string, lineNo int, old, new string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	got := strings.Replace(lines[lineNo-1], old, new, 1)
	if got == lines[lineNo-1] {
		t.Fatalf("第 %d 行未含 %q, 篡改未生效", lineNo, old)
	}
	lines[lineNo-1] = got
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAudit_Verify_TxChain(t *testing.T) {
	t.Run("干净5事务日志全过", func(t *testing.T) {
		c := buildMainFixture(t, filepath.Join(t.TempDir(), "chain.jsonl"))
		if n, err := Verify(c.path); err != nil || n != 17 {
			t.Fatalf("干净夹具应通过 17 条, 实得 n=%d err=%v", n, err)
		}
	})

	// 裸篡改(不改 entry_hash): tx_id 与 args 都参与哈希载荷 → 全局链以"哈希不符"捕获。
	for _, tc := range []struct{ name, old, nw string }{
		{"tx_id", fmt.Sprintf(`"tx_id": %q`, txA), fmt.Sprintf(`"tx_id": %q`, txTampered)},
		{"in-tx_args", `"op": "apply"`, `"op": "evi!"`},
	} {
		t.Run("篡改"+tc.name+"_全局链以哈希不符捕获", func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "chain.jsonl")
			buildMainFixture(t, p)
			replaceInLine(t, p, 3, tc.old, tc.nw)
			if _, err := Verify(p); err == nil || !strings.Contains(err.Error(), "第 3 行哈希不符") {
				t.Fatalf("裸改 %s 应致第 3 行哈希不符(全局链), 实得 %v", tc.name, err)
			}
		})
	}

	// 自洽重链(全局链完整, 旧链全绿)后, 双链必须各自报具名 tx 链断裂:
	//  tx_id 改写 → 新 id 首见, 创世断言比对 lastNonTxHash(h1), 记录值 h2 失配;
	//  args 改写 → 同事务下一步(第 4 行 rollback)仍引用被篡改前的 A.apply 哈希;
	//  begin 创世改写为第 2 行(A.begin)有效哈希 → C.begin 首见创世断言失配(期望 h5)。
	for _, tc := range []relinkCase{
		{"tx_id", 3, func(no int, r Record, _ *txChainFix) Record {
			if no == 3 {
				r.TxID = txTampered
			}
			return r
		}, namedBreakMsg(3, txTampered, 1)},
		{"in-tx_args", 3, evilArgsRewrite(t), namedBreakMsg(4, txA, 2)},
		{"begin创世有效错值", 7, func(no int, r Record, c *txChainFix) Record {
			if no == 7 {
				r.TxPrevHash = c.recs[1].EntryHash
			}
			return r
		}, namedBreakMsg(7, txC, 0)},
	} {
		t.Run("篡改"+tc.name+"_自洽重链后具名tx链捕获", func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "chain.jsonl")
			relinkAndExpectTxBreak(t, buildMainFixture(t, p), tc)
		})
	}

	t.Run("互换tx_prev_hash_旧链漏网新链必获", func(t *testing.T) {
		c := buildSwapFixture(t, filepath.Join(t.TempDir(), "swap.jsonl"))
		swapTamper(t, c) // 旧单链整文件通过 —— 唯有双链 tx 断言能识破(新断言承重)
		expectTxBreak(t, c.path, namedBreakMsg(4, txA, 1))
	})
}

// TestAudit_Verify_TxChain_CLI 仅在 DAEDALUS_TX_FIXTURE=<目录> 时导出三夹具
// (干净 17 行主日志 / 互换篡改 / 自洽重链 args 篡改), 由 bash 以真实 CLI 断言
// 退出码 0/1 与具名诊断; 常规 go test 下跳过, 不进 CI 关键路径。
func TestAudit_Verify_TxChain_CLI(t *testing.T) {
	dir := os.Getenv("DAEDALUS_TX_FIXTURE")
	if dir == "" {
		t.Skip("未设置 DAEDALUS_TX_FIXTURE, 跳过 CLI 夹具导出")
	}
	buildMainFixture(t, filepath.Join(dir, "clean.jsonl"))
	swapTamper(t, buildSwapFixture(t, filepath.Join(dir, "swap.jsonl")))
	relinkAndExpectTxBreak(t, buildMainFixture(t, filepath.Join(dir, "args.jsonl")),
		relinkCase{from: 3, mk: evilArgsRewrite(t), want: namedBreakMsg(4, txA, 2)})
}
