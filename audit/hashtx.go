package audit

// hashtx.go —— todo 12 条件 tx 载荷扩展: Record ↔ 哈希载荷 / 记录回读解析。
// ComputeEntryHash 的 6 参签名与拼接字节**严禁改动**(金样锚点), 本文件只做
// 其记录形态超集: 基段 6 拼接逐字节复用, tx 段仅在 TxID 非空时条件追加。

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// payloadFor 组装 r 的哈希载荷字节。
//
// 基段 = timestamp+identity+tool+args_str+outcome+prev_hash(与 ComputeEntryHash
// 完全一致的 6 段拼接); 仅当 TxID 非空时追加 tx_id + strconv.Itoa(tx_step) +
// tx_prev_hash 三段。非 tx 记录的返回值与 6 参路径的入参拼接逐字节相同 →
// 创世金样的哈希不受本扩展影响(发射端判据与 toValue 的 setIfNonEmpty 同源)。
func payloadFor(r Record) []byte {
	payload := r.Timestamp + r.Identity + r.Tool + r.Args.ArgsString() + r.Outcome + r.PrevHash
	if r.TxID != "" {
		payload += r.TxID + strconv.Itoa(r.TxStep) + r.TxPrevHash
	}
	return []byte(payload)
}

// ComputeEntryHashRecord 是 ComputeEntryHash 的记录形态超集:
// entry_hash = SHA-256(payloadFor(r)) 小写十六进制。
// 非 tx 记录(TxID == "")必须与 6 参路径产生同一摘要(由 tx_test.go 钉桩)。
func ComputeEntryHashRecord(r Record) string {
	sum := sha256.Sum256(payloadFor(r))
	return hex.EncodeToString(sum[:])
}

// recordFromValue 把解析好的对象值还原为完整 Record(含条件 tx 键);
// 必需字段缺失/类型错、或 in-tx 行的 tx_step 非整数 → ok=false(视为损坏)。
//
// 供 lastNonTxRecord 回溯、Verify 的 in-tx 哈希派发与金样字节防护测试共用;
// tx_prev_hash 缺失按空串还原(与 setIfNonEmpty 对空串的抑制互为镜像)。
func recordFromValue(v *Value) (Record, bool) {
	if v == nil || !v.IsObject() {
		return Record{}, false
	}
	ts, ok1 := v.LookupString("timestamp")
	id, ok2 := v.LookupString("identity")
	tool, ok3 := v.LookupString("tool")
	args, ok4 := v.Lookup("args")
	pv, ok5 := v.LookupString("policy_version")
	oc, ok6 := v.LookupString("outcome")
	ph, ok7 := v.LookupString("prev_hash")
	eh, ok8 := v.LookupString("entry_hash")
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7 && ok8) {
		return Record{}, false
	}
	rec := Record{
		Timestamp: ts, Identity: id, Tool: tool, Args: args,
		PolicyVersion: pv, Outcome: oc, PrevHash: ph, EntryHash: eh,
	}
	if txid, ok := v.LookupString("tx_id"); ok && txid != "" {
		rec.TxID = txid
		sv, ok := v.Lookup("tx_step")
		if !ok || sv == nil || sv.kind != kindNumber {
			return Record{}, false
		}
		n, err := strconv.ParseInt(sv.text, 10, 64)
		if err != nil {
			return Record{}, false
		}
		rec.TxStep = int(n)
		rec.TxPrevHash, _ = v.LookupString("tx_prev_hash")
	}
	return rec, true
}
