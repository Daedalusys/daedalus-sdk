package audit

// lastnontxrecord_test.go —— todo 12 无界回溯钉桩: 尾部挂任意长 in-tx 段时,
// lastNonTxRecord 必须持续扩块命中其前最近一条非 tx 记录(旧 2 行窗口的
// lastEntryHash 在该夹具下只能见到尾部 tx 行 → 本测试是 round-1 误规格的防回归)。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLastNonTxRecord_UnboundedWalkPastLongTxTail(t *testing.T) {
	// 无界回溯钉桩: 尾部挂 **5 条连续 in-tx 记录**(每条 args ~1200 字节, 合计 >4096,
	// 跨越多个回溯块)——旧 lastEntryHash 的 2 行窗口只能见尾部两行 tx, 必返回创世;
	// lastNonTxRecord 必须持续扩块直至命中其前那条非 tx 记录。
	p := filepath.Join(t.TempDir(), "mixed.jsonl")
	big := strings.Repeat("x", 1200)
	if _, err := LogAudit(Entry{Identity: "cli", Tool: "early", Args: mustParse(t, `{}`), LogPath: p}); err != nil {
		t.Fatal(err)
	}
	want, err := LogAudit(Entry{Identity: "cli", Tool: "lastNonTx",
		Args: mustParse(t, `{"k": "v"}`), Outcome: "denied", LogPath: p})
	if err != nil {
		t.Fatal(err)
	}
	for step := 0; step <= 4; step++ {
		if _, err := LogAudit(Entry{Identity: "daedalus-tx", Tool: "tx_apply",
			Args: mustParse(t, `{"blob": "`+big+`"}`), TxID: "cafe0000cafe0001",
			TxStep: step, TxPrevHash: strings.Repeat("a", 64), LogPath: p}); err != nil {
			t.Fatal(err)
		}
	}
	// 前提自检: 5 条 tx 尾行合计必须超过单个回溯块, 否则本测试钉不住"无界"。
	txTail := 5 * (1200 + 100)
	if txTail <= tailChunkSize {
		t.Fatal("夹具尾部 tx 段未超过 tailChunkSize, 无法证明无界回溯")
	}

	f, err := os.OpenFile(p, os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, ok, err := lastNonTxRecord(f)
	if err != nil {
		t.Fatalf("lastNonTxRecord 报错: %v", err)
	}
	if !ok {
		t.Fatal("lastNonTxRecord 未找到非 tx 记录(回溯被尾部 tx 段耗尽 → 无界性失效)")
	}
	if got.EntryHash != want.EntryHash || got.Tool != "lastNonTx" || got.Outcome != "denied" {
		t.Fatalf("回溯返回错记录: tool=%s outcome=%s hash=%s, 期望 lastNonTx/denied/%s",
			got.Tool, got.Outcome, got.EntryHash, want.EntryHash)
	}
}

func TestLastNonTxRecord_ExhaustsToGenesisFalse(t *testing.T) {
	// BOE 且全程无 tx 记录: 空文件与"纯 tx 文件"都必须返回 (零值, false, nil),
	// 由调用方(daedalus-tx begin)替换 64 零创世。
	t.Run("空文件", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "empty.jsonl")
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if rec, ok, err := lastNonTxRecord(f); err != nil || ok || rec != (Record{}) {
			t.Fatalf("空文件 = (%+v, %v, %v), 期望 (零值, false, nil)", rec, ok, err)
		}
	})
	t.Run("全tx日志", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "alltx.jsonl")
		for step := 0; step < 3; step++ {
			if _, err := LogAudit(Entry{Identity: "daedalus-tx", Tool: "tx_apply",
				Args: mustParse(t, `{}`), TxID: "beef0000beef0002", TxStep: step,
				TxPrevHash: strings.Repeat("b", 64), LogPath: p}); err != nil {
				t.Fatal(err)
			}
		}
		f, err := os.OpenFile(p, os.O_RDWR, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, ok, err := lastNonTxRecord(f); err != nil || ok {
			t.Fatalf("纯 tx 日志 = (ok=%v, err=%v), 期望 (false, nil)", ok, err)
		}
	})
}
