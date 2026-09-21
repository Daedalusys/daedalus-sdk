package audit

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// requiredFields 是一条合法记录必须包含且必须为字符串的字段
// (args 单独处理: 任意 JSON 类型均合法)。
var requiredFields = []string{
	"timestamp", "identity", "tool", "policy_version",
	"outcome", "prev_hash", "entry_hash",
}

// Verify 全链重算校验 logPath 的哈希链, 是证据边界的完整性证明入口。
//
// 语义(比追加路径 get_last_entry_hash 更严格, 这是证据层的应有姿态):
//  1. 逐行: 跳过空行; 任一非空行不可解析/缺字段/字段类型错 → 报损坏;
//  2. 首条有效记录的 prev_hash 必须为 GenesisHash;
//  3. 每条记录的 prev_hash 必须等于上一条的 entry_hash(全局链连续性);
//  4. 每条记录的 entry_hash 必须等于按 §4.3 载荷重算的哈希(防篡改);
//  5. 双链(todo 13): in-tx 记录另走逐事务链。每个 TxID 的首条记录(tx_begin,
//     step 0)的 tx_prev_hash 必须等于**最近一条非 tx 记录**的 entry_hash
//     (lastNonTxHash 快照, 初始为创世; 两 begin 可共享同一创世); 同事务后续
//     记录的 tx_prev_hash 必须等于该事务上一条 in-tx 记录的 entry_hash。
//     纯非 tx 日志退化为 1-4, 与升级前逐字节同语义(金样不变)。
//
// 断链诊断具名到链: "第 N 行链断裂" = 全局 prev_hash 链(沿用既有文案, 非 tx
// 日志语义零改动); "第 N 行 tx <id> step <n> 链断裂" = 事务链。
//
// 返回校验通过的记录条数; 任一环节失败返回带行号的 error。
func Verify(logPath string) (int, error) {
	f, err := os.Open(logPath)
	if err != nil {
		return 0, fmt.Errorf("audit: 打开日志失败: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // 审计行可能含长 args, 上限 4MiB

	// 双链遍历器(todo 13 钉桩, 单趟): lastGlobalHash 即既有 prev 递推;
	// lastNonTxHash 在每条 TxID 为空的记录通过后刷新; inTx/seen 按事务记
	// 最近 in-tx entry_hash 与是否已见(首见即 begin, 走创世断言)。
	prev := GenesisHash
	lastNonTxHash := GenesisHash
	inTx := make(map[string]string)
	seen := make(map[string]bool)
	count := 0
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		v, perr := ParseValue(line)
		if perr != nil {
			return count, fmt.Errorf("audit: 第 %d 行损坏: 非法 JSON", lineNo)
		}
		if !v.IsObject() {
			return count, fmt.Errorf("audit: 第 %d 行损坏: 记录不是 JSON 对象", lineNo)
		}
		fields := make(map[string]string, len(requiredFields))
		for _, name := range requiredFields {
			s, ok := v.LookupString(name)
			if !ok {
				return count, fmt.Errorf("audit: 第 %d 行损坏: 字段 %s 缺失或非字符串", lineNo, name)
			}
			fields[name] = s
		}
		args, ok := v.Lookup("args")
		if !ok {
			return count, fmt.Errorf("audit: 第 %d 行损坏: 字段 args 缺失", lineNo)
		}
		if fields["prev_hash"] != prev {
			return count, fmt.Errorf(
				"audit: 第 %d 行链断裂: prev_hash=%s, 期望 %s", lineNo, fields["prev_hash"], prev)
		}
		// 哈希派发(todo 12) + 记录形态回读: 非 tx 行走原 6 参常量路径(金样逐字节不变);
		// in-tx 行走记录形态, 使 tx_id/tx_step/tx_prev_hash 参与重算(篡改可见),
		// 并复用还原出的 rec 做下方事务链断言。
		var rec Record
		isTx := false
		var recomputed string
		if txID, ok := v.LookupString("tx_id"); ok && txID != "" {
			r, ok := recordFromValue(v)
			if !ok {
				return count, fmt.Errorf("audit: 第 %d 行损坏: in-tx 记录字段不完整或 tx_step 非整数", lineNo)
			}
			rec, isTx = r, true
			recomputed = ComputeEntryHashRecord(r)
		} else {
			recomputed = ComputeEntryHash(
				fields["timestamp"], fields["identity"], fields["tool"],
				args.ArgsString(), fields["outcome"], fields["prev_hash"])
		}
		if recomputed != fields["entry_hash"] {
			return count, fmt.Errorf(
				"audit: 第 %d 行哈希不符: entry_hash=%s, 重算=%s", lineNo, fields["entry_hash"], recomputed)
		}
		// 事务链断言(todo 13): 先判链, 全部通过后统一刷新三个遍历器。
		// 首见 TxID → 创世断言比对 lastNonTxHash 快照(= 严格先于本行的最近非 tx
		// 条目 entry_hash; 确定性强于回溯读, 无需调 lastNonTxRecord); 否则比对
		// 同事务上一条 entry_hash。tx_prev_hash 缺失按空串参与比较(recordFromValue
		// 与 setIfNonEmpty 的镜像语义), 空串对任何有效快照必然失配 → 缺键即断链。
		if isTx {
			wantTx := lastNonTxHash
			if seen[rec.TxID] {
				wantTx = inTx[rec.TxID]
			}
			if rec.TxPrevHash != wantTx {
				return count, fmt.Errorf(
					"audit: 第 %d 行 tx %s step %d 链断裂: tx_prev_hash=%s, 期望 %s",
					lineNo, rec.TxID, rec.TxStep, rec.TxPrevHash, wantTx)
			}
		}
		if isTx {
			inTx[rec.TxID] = fields["entry_hash"]
			seen[rec.TxID] = true
		} else {
			lastNonTxHash = fields["entry_hash"]
		}
		prev = fields["entry_hash"]
		count++
	}
	if err := sc.Err(); err != nil {
		return count, fmt.Errorf("audit: 读取日志失败: %w", err)
	}
	return count, nil
}
