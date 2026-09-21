package audit

// tx_test.go —— todo 12 条件 tx 扩展(test-first 钉桩):
//   - ComputeEntryHashRecord/payloadFor 的非 tx 逐字节恒等 + in-tx 载荷扩展参与哈希;
//   - toValue 条件发射: 金样每一行经**新 toValue 路径**重序列化仍逐字节相等;
//   - LogAudit 写侧派发 + 篡改 tx_id 破坏全局 Verify;
//   - lastNonTxRecord 无界回溯(尾部 ≥5 条连续 in-tx 记录, 远超旧 2 行窗口);
//   - NewInt64 / setIfNonEmpty 单元测试。

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// basePayload 独立参考拼接(与 ComputeEntryHash 的 6 段序一致), 测试断言专用。
func basePayload(r Record) string {
	return r.Timestamp + r.Identity + r.Tool + r.Args.ArgsString() + r.Outcome + r.PrevHash
}

func TestAudit_TxComputeEntryHashRecordNonTxParity(t *testing.T) {
	// 非 tx 记录(TxID == ""): payloadFor 必须恰为 6 段基串,
	// ComputeEntryHashRecord 与 6 参路径、独立 sha256Hex 三方逐字节一致。
	rec := Record{
		Timestamp: "2026-08-28T01:47:02.676956+00:00", Identity: "cli",
		Tool: "fs.read_file", Args: mustParse(t, `{"路径": "/home/x"}`),
		PolicyVersion: "1.0", Outcome: "success", PrevHash: GenesisHash,
	}
	if got := string(payloadFor(rec)); got != basePayload(rec) {
		t.Fatalf("非 tx payloadFor 偏离 6 段基串:\n got=%q\nwant=%q", got, basePayload(rec))
	}
	want := ComputeEntryHash(rec.Timestamp, rec.Identity, rec.Tool,
		rec.Args.ArgsString(), rec.Outcome, rec.PrevHash)
	if got := ComputeEntryHashRecord(rec); got != want {
		t.Fatalf("非 tx ComputeEntryHashRecord = %s, 6 参路径 = %s", got, want)
	}
	if got := ComputeEntryHashRecord(rec); got != sha256Hex(t, basePayload(rec)) {
		t.Fatalf("非 tx ComputeEntryHashRecord 与独立参考哈希不一致")
	}
}

func TestAudit_TxComputeEntryHashRecordPayloadExtension(t *testing.T) {
	// in-tx 记录: 载荷在 6 段之后追加 tx_id + strconv.Itoa(tx_step) + tx_prev_hash,
	// 三个字段各自都必须参与哈希(改任一 → 摘要变), 否则篡改检测形同虚设。
	rec := Record{
		Timestamp: "2026-08-28T01:47:02.676956+00:00", Identity: "daedalus-tx",
		Tool: "tx_begin", Args: mustParse(t, `{"adapter": "service.set"}`),
		PolicyVersion: "1.0", Outcome: "success", PrevHash: GenesisHash,
	}
	nonTx := ComputeEntryHashRecord(rec)

	tx := rec
	tx.TxID = "0123456789abcdef"
	tx.TxStep = 0
	tx.TxPrevHash = GenesisHash

	want := sha256Hex(t, basePayload(tx)+"0123456789abcdef"+strconv.Itoa(0)+GenesisHash)
	if got := ComputeEntryHashRecord(tx); got != want {
		t.Fatalf("in-tx(step0) 摘要 = %s, 独立扩展拼接 = %s", got, want)
	}
	if got := ComputeEntryHashRecord(tx); got == nonTx {
		t.Fatal("in-tx 摘要与非 tx 等价记录相同 → tx 字段未参与哈希(载荷扩展失效)")
	}
	// step 参与哈希: step 0 与 step 1 必须产生不同摘要。
	step1 := tx
	step1.TxStep = 1
	if ComputeEntryHashRecord(step1) == ComputeEntryHashRecord(tx) {
		t.Fatal("tx_step 未参与哈希: step0 与 step1 摘要相同")
	}
	// tx_prev_hash 参与哈希。
	otherPrev := tx
	otherPrev.TxPrevHash = strings.Repeat("f", 64)
	if ComputeEntryHashRecord(otherPrev) == ComputeEntryHashRecord(tx) {
		t.Fatal("tx_prev_hash 未参与哈希")
	}
	// strconv.Itoa 负数形态钉桩(仅保证确定性, 不代表业务语义)。
	neg := tx
	neg.TxStep = -1
	if got, wantN := ComputeEntryHashRecord(neg), sha256Hex(t, basePayload(neg)+"0123456789abcdef-1"+GenesisHash); got != wantN {
		t.Fatalf("负 step 载荷扩展异常: %s vs %s", got, wantN)
	}
}

func TestAudit_TxGoldenToValueByteEquality(t *testing.T) {
	// 金样字节防护门(新 toValue 路径): 每一行解析 → recordFromValue 重建 Record →
	// rec.Line()(经 setIfNonEmpty 条件发射)必须与原文件行**逐字节相等**。
	lines := readGolden(t)
	for i, line := range lines {
		v, err := ParseValue(line)
		if err != nil {
			t.Fatalf("第 %d 行解析失败: %v", i+1, err)
		}
		rec, ok := recordFromValue(v)
		if !ok {
			t.Fatalf("第 %d 行 recordFromValue 拒绝(完整金样行必须可重建)", i+1)
		}
		if rec.TxID != "" {
			t.Fatalf("第 %d 行金样不应含 TxID", i+1)
		}
		if got := rec.Line(); got != line {
			t.Fatalf("第 %d 行经新 toValue 路径重序列化不符:\n  文件=%s\n  Go  =%s", i+1, line, got)
		}
	}
}

func TestAudit_TxLogAuditWritesConditionalKeysAndExtendedHash(t *testing.T) {
	// 写侧派发: 同字段内容, in-tx 条目落盘带 tx_id/tx_step/tx_prev_hash 三键、
	// entry_hash = 独立参考实现的扩展载荷哈希; 非 tx 条目(另一文件)零新键。
	logTx := filepath.Join(t.TempDir(), "tx.jsonl")
	logNoTx := filepath.Join(t.TempDir(), "notx.jsonl")

	args := mustParse(t, `{"tx_id_arg": 1}`)
	txRec, err := LogAudit(Entry{
		Identity: "daedalus-tx", Tool: "tx_begin", Args: args,
		TxID: "deadbeefdeadbeef", TxStep: 0, TxPrevHash: GenesisHash,
		LogPath: logTx,
	})
	if err != nil {
		t.Fatalf("LogAudit(in-tx) 失败: %v", err)
	}
	// step 0 必须落盘(与 tx_id 空串抑制规则不同, NewInt64(0) 是 kindNumber)。
	v, err := ParseValue(strings.TrimSuffix(txRec.Line(), "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(v.members) != 11 {
		t.Fatalf("in-tx 行应含 8+3=11 键, 实得 %d: %s", len(v.members), txRec.Line())
	}
	stepVal, ok := v.Lookup("tx_step")
	if !ok || stepVal.kind != kindNumber || stepVal.text != "0" {
		t.Fatalf("tx_step 应为无引号整数 0, 实得 %+v (ok=%v)", stepVal, ok)
	}
	want := sha256Hex(t, basePayload(*txRec)+"deadbeefdeadbeef"+"0"+GenesisHash)
	if txRec.EntryHash != want {
		t.Fatalf("in-tx entry_hash = %s, 独立扩展载荷 = %s", txRec.EntryHash, want)
	}

	noTxRec, err := LogAudit(Entry{
		Identity: "daedalus-tx", Tool: "tx_begin", Args: args, LogPath: logNoTx,
	})
	if err != nil {
		t.Fatalf("LogAudit(非 tx) 失败: %v", err)
	}
	v2, _ := ParseValue(noTxRec.Line())
	if len(v2.members) != 8 {
		t.Fatalf("非 tx 行必须保持 8 键(条件发射失效, 泄漏 tx 键): %s", noTxRec.Line())
	}
	if noTxRec.EntryHash == txRec.EntryHash {
		t.Fatal("in-tx 与非 tx 同内容条目 entry_hash 相同 → tx 字段未参与写侧哈希")
	}
}

func TestAudit_TxTamperTxIDBreaksGlobalVerify(t *testing.T) {
	// 篡改钉桩: Verify 的 :66 哈希派发使 tx_id 参与重算 → 改掉 tx_id 必断全局校验。
	p := filepath.Join(t.TempDir(), "tamper.jsonl")
	first, err := LogAudit(Entry{Identity: "cli", Tool: "shell_exec",
		Args: mustParse(t, `{"cmd": "df"}`), LogPath: p})
	if err != nil {
		t.Fatal(err)
	}
	// 盖章规则(todo 13 双链定版): tx_begin 创世 = 最近非 tx 条目 entry_hash,
	// 而非 64 零 —— 本夹具首条非 tx 在前, 创世快照须指向 first.EntryHash。
	if _, err := LogAudit(Entry{Identity: "daedalus-tx", Tool: "tx_apply",
		Args: mustParse(t, `{"step": 1}`), TxID: "aaaa1111bbbb2222", TxStep: 1,
		TxPrevHash: first.EntryHash, LogPath: p}); err != nil {
		t.Fatal(err)
	}
	if n, err := Verify(p); err != nil || n != 2 {
		t.Fatalf("未篡改时 Verify 应通过 2 条, 实得 n=%d err=%v", n, err)
	}

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	tampered := strings.Replace(lines[1], `"tx_id": "aaaa1111bbbb2222"`, `"tx_id": "ffff9999eeee8888"`, 1)
	if tampered == lines[1] {
		t.Fatal("夹具行未含预期 tx_id, 篡改未生效")
	}
	lines[1] = tampered
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(p); err == nil || !strings.Contains(err.Error(), "哈希不符") {
		t.Fatalf("篡改 tx_id 应致全局 Verify 报哈希不符, 实得 %v", err)
	}
}

func TestValue_NewInt64(t *testing.T) {
	// kindNumber + 规范化十进制文本(与 scan.go 解析路径的整数形态字节一致)。
	for n, want := range map[int64]string{42: "42", -7: "-7", 0: "0", 1 << 40: "1099511627776"} {
		v := NewInt64(n)
		if v.kind != kindNumber || v.text != want {
			t.Fatalf("NewInt64(%d) = (kind=%v, text=%q), 期望 (kindNumber, %q)", n, v.kind, v.text, want)
		}
	}
	// 上线形态: 无引号整数(Python json.dumps int 一致)。
	obj := NewObject()
	obj.set("n", NewInt64(0))
	if got := obj.ArgsString(); got != `{"n":0}` {
		t.Fatalf("NewInt64 序列化 = %q, 期望 {\"n\":0}", got)
	}
	// 与解析器往返一致。
	parsed, err := ParseValue("12345")
	if err != nil {
		t.Fatal(err)
	}
	if p, q := parsed.ArgsString(), NewInt64(12345).ArgsString(); p != q {
		t.Fatalf("NewInt64 与解析路径文本不一致: %q vs %q", p, q)
	}
}

func TestValue_SetIfNonEmpty(t *testing.T) {
	v := NewObject()
	v.setIfNonEmpty("nil_key", nil)                             // val==nil → no-op
	v.setIfNonEmpty("empty_str", NewString(""))                 // 空串 kindString → no-op
	v.setIfNonEmpty("ok_str", NewString("deadbeef"))            // 非空 → 写入
	v.setIfNonEmpty("zero_int", NewInt64(0))                    // kindNumber → 恒写入(无空值可抑制)
	v.setIfNonEmpty("non_str", &Value{kind: kindBool, b: true}) // 非字符串 kind → 恒写入
	if len(v.members) != 3 {
		t.Fatalf("no-op 规则失效, 键数 = %d, 期望 3(两个抑制键未消失): %+v", len(v.members), v.members)
	}
	// 原位更新语义与 set 一致(不追加重复键)。
	v.setIfNonEmpty("ok_str", NewString("cafe"))
	if len(v.members) != 3 {
		t.Fatalf("setIfNonEmpty 原位更新追加了重复键, 键数 = %d", len(v.members))
	}
	if s, _ := v.LookupString("ok_str"); s != "cafe" {
		t.Fatalf("原位更新失败, ok_str = %q", s)
	}
}
