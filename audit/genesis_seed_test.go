package audit

// genesis_seed_test.go —— todo 15 授权的唯一 internal/audit 外科手术: LogAudit
// 在持有同一把 flock 时, 对 "TxID 非空且 TxPrevHash 为空" 的事务创世条目
// (tx_begin)自动播种 tx_prev_hash = 回溯到的最近一条**非 tx**记录 entry_hash
// (无则 64 零创世)。播种发生在哈希计算之前 → tx 载荷扩展与落盘键都吃到播种值。
// 显式传入 TxPrevHash 的一律原样尊重(apply/rollback 步链由 CLI 自己串)。
//
// 反造假纪律: 本测试同时钉 "无界回溯"(5 条 in-tx 尾段之后仍有 begin, 播种值
// 必须越过它们命中更早的非 tx 原始记录)与 "verify 整链接受"。

import (
	"path/filepath"
	"strings"
	"testing"
)

// sha256Hex 独立参考实现专用(与 tx_test.go 共享的 helper 若已存在则复用)。
// 这里不重复定义 —— sha256Hex 已在 tx_test.go 声明, 本文件直接用。

// TestAudit_TxGenesisSeedInLogAudit 钉死 LogAudit 播种:
//   - 非 tx 原始记录 → 5 条连续 in-tx(tx-A)→ 另起一个 begin(tx-B):
//     tx-A 的 begin(step0, 空 prev)播种 = 原始非 tx 记录哈希;
//     tx-B 的 begin(step0, 空 prev)播种 = **同一条原始非 tx 记录哈希**
//     (越过 tx-A 的 5 条 in-tx 尾段 —— 无界回溯证明, 且两 begin 可共享同一创世);
//   - verify() 接受整条混合日志。
func TestAudit_TxGenesisSeedInLogAudit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "seed.jsonl")

	// 1) 原始非 tx 记录: 后续所有 begin 的创世都应指向它。
	orig, err := LogAudit(Entry{Identity: "cli", Tool: "shell_exec",
		Args: mustParse(t, `{"cmd": "df -h"}`), LogPath: p})
	if err != nil {
		t.Fatal(err)
	}

	// 2) tx-A begin(step 0, 空 TxPrevHash)→ 播种应 = orig.EntryHash。
	aBegin, err := LogAudit(Entry{Identity: "daedalus-tx", Tool: "daedalus_tx_begin",
		Args: mustParse(t, `{"adapter": "noop"}`), TxID: "a1b2c3d4e5f60718",
		TxStep: 0, LogPath: p})
	if err != nil {
		t.Fatal(err)
	}
	if aBegin.TxPrevHash != orig.EntryHash {
		t.Fatalf("tx-A begin 播种 = %s, 期望原始非 tx 哈希 %s", aBegin.TxPrevHash, orig.EntryHash)
	}

	// 3) tx-A 四条 in-tx 步(step 1..4, 显式串链)—— 尾挂 in-tx 段, 供下一 begin 越过。
	prev := aBegin.EntryHash
	for step := 1; step <= 4; step++ {
		rec, err := LogAudit(Entry{Identity: "daedalus-tx", Tool: "daedalus_tx_apply",
			Args: mustParse(t, `{"op": "apply", "seq": 1}`), TxID: "a1b2c3d4e5f60718",
			TxStep: step, TxPrevHash: prev, LogPath: p})
		if err != nil {
			t.Fatal(err)
		}
		prev = rec.EntryHash
	}

	// 4) 另起 tx-B begin(step 0, 空 TxPrevHash): 播种必须越过 tx-A 的 5 条 in-tx
	//    记录, 命中更早的那条原始非 tx 记录 —— 证明无界回扫(旧 2 行窗口在此必失败)。
	bBegin, err := LogAudit(Entry{Identity: "daedalus-tx", Tool: "daedalus_tx_begin",
		Args: mustParse(t, `{"adapter": "noop"}`), TxID: "beefcafe00112233",
		TxStep: 0, LogPath: p})
	if err != nil {
		t.Fatal(err)
	}
	if bBegin.TxPrevHash != orig.EntryHash {
		t.Fatalf("tx-B begin 播种 = %s, 期望越过 5 条 in-tx 后仍指向原始非 tx 哈希 %s",
			bBegin.TxPrevHash, orig.EntryHash)
	}

	// 5) 整条日志(1 非 tx + 5 in-tx-A + 1 in-tx-B = 7 条)双链校验必须通过。
	if n, err := Verify(p); err != nil || n != 7 {
		t.Fatalf("Verify = (n=%d, err=%v), 期望 7 条全过", n, err)
	}
	// 播种键确实落盘(而非仅内存态): 最后一条 begin 行的 tx_prev_hash == 原始哈希。
	v, err := ParseValue(bBegin.Line())
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := v.LookupString("tx_prev_hash"); s != orig.EntryHash {
		t.Fatalf("落盘 tx_prev_hash = %s, 期望 %s", s, orig.EntryHash)
	}
}

// TestAudit_TxExplicitPrevHashHonored 钉死 "显式 prev 原样尊重": begin 若自带
// 一个非空的(哪怕是他条有效哈希的)TxPrevHash, LogAudit 绝不覆盖它。
func TestAudit_TxExplicitPrevHashHonored(t *testing.T) {
	p := filepath.Join(t.TempDir(), "explicit.jsonl")
	if _, err := LogAudit(Entry{Identity: "cli", Tool: "x", Args: mustParse(t, `{}`), LogPath: p}); err != nil {
		t.Fatal(err)
	}
	manual := strings.Repeat("f", 64)
	rec, err := LogAudit(Entry{Identity: "daedalus-tx", Tool: "daedalus_tx_begin",
		Args: mustParse(t, `{}`), TxID: "1234abcd5678ef90", TxStep: 0,
		TxPrevHash: manual, LogPath: p})
	if err != nil {
		t.Fatal(err)
	}
	if rec.TxPrevHash != manual {
		t.Fatalf("显式 TxPrevHash 被覆盖: got %s want %s", rec.TxPrevHash, manual)
	}
}
