package audit

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// requiredFields 是一条合法记录必须包含且必须为字符串的字段
// (args 单独处理: 任意 JSON 类型均合法)。
var requiredFields = []string{
	"timestamp", "identity", "tool", "policy_version",
	"outcome", "prev_hash", "entry_hash",
}

// segSeg 是一个段(单文件或归档段)的统计与边界哈希。
type segSeg struct {
	FirstPrev string // 首条记录的 prev_hash(空段为 "")
	Last      string // 末条记录的 entry_hash(空段为 "")
	LastNonTx string // 末条非 tx 记录的 entry_hash(无则 "")
	Entries   int
}

// verifier 是跨段共享的单趟哈希链状态机。prev / lastNonTxHash / inTx / seen
// 四个遍历器在段间延续,使"活跃文件 + 归档段"能作为一个连续链 replay。
type verifier struct {
	prev          string
	lastNonTxHash string
	inTx          map[string]string
	seen          map[string]bool
	count         int
}

// newVerifier 返回创世态(prev = lastNonTxHash = GenesisHash)。
func newVerifier() *verifier {
	return &verifier{
		prev:          GenesisHash,
		lastNonTxHash: GenesisHash,
		inTx:          map[string]string{},
		seen:          map[string]bool{},
	}
}

// feed 读整个 r(一个段),逐行校验并推进 v 的状态,返回本段统计。
//
// 语义(比追加路径 get_last_entry_hash 更严格,这是证据层的应有姿态):
//  1. 逐行:跳过空行;任一非空行不可解析/缺字段/字段类型错 → 报损坏;
//  2. 每条记录的 prev_hash 必须等于 v.prev(跨段延续);
//  3. 每条记录的 entry_hash 必须等于按 payloadFor 载荷重算的哈希(防篡改);
//  4. 双链:in-tx 记录另走逐事务链;首见的 tx 的 tx_prev_hash 必须等于
//     v.lastNonTxHash 快照,同事务后续记录必须等于该事务上一条 entry_hash。
//
// 行号是段内 1-based(单文件 Verify 下即文件行号);跨段调用方负责在错误里
// 补段名。空段(无有效行)返回零值 segSeg。
func (v *verifier) feed(r io.Reader) (segSeg, error) {
	var seg segSeg
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // 审计行可能含长 args, 上限 4MiB
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		val, perr := ParseValue(line)
		if perr != nil {
			return seg, fmt.Errorf("audit: 第 %d 行损坏: 非法 JSON", lineNo)
		}
		if !val.IsObject() {
			return seg, fmt.Errorf("audit: 第 %d 行损坏: 记录不是 JSON 对象", lineNo)
		}
		fields := make(map[string]string, len(requiredFields))
		for _, name := range requiredFields {
			s, ok := val.LookupString(name)
			if !ok {
				return seg, fmt.Errorf("audit: 第 %d 行损坏: 字段 %s 缺失或非字符串", lineNo, name)
			}
			fields[name] = s
		}
		args, ok := val.Lookup("args")
		if !ok {
			return seg, fmt.Errorf("audit: 第 %d 行损坏: 字段 args 缺失", lineNo)
		}
		if fields["prev_hash"] != v.prev {
			return seg, fmt.Errorf(
				"audit: 第 %d 行链断裂: prev_hash=%s, 期望 %s", lineNo, fields["prev_hash"], v.prev)
		}
		// 哈希派发 + 记录形态回读: 非 tx 行走原 6 参常量路径(金样逐字节不变);
		// in-tx 行走记录形态, 使 tx_id/tx_step/tx_prev_hash 参与重算(篡改可见)。
		var rec Record
		isTx := false
		var recomputed string
		if txID, ok := val.LookupString("tx_id"); ok && txID != "" {
			r, ok := recordFromValue(val)
			if !ok {
				return seg, fmt.Errorf("audit: 第 %d 行损坏: in-tx 记录字段不完整或 tx_step 非整数", lineNo)
			}
			rec, isTx = r, true
			recomputed = ComputeEntryHashRecord(r)
		} else {
			recomputed = ComputeEntryHash(
				fields["timestamp"], fields["identity"], fields["tool"],
				args.ArgsString(), fields["outcome"], fields["prev_hash"])
		}
		if recomputed != fields["entry_hash"] {
			return seg, fmt.Errorf(
				"audit: 第 %d 行哈希不符: entry_hash=%s, 重算=%s", lineNo, fields["entry_hash"], recomputed)
		}
		// 事务链断言: 先判链, 全部通过后再统一刷新四个遍历器。
		if isTx {
			wantTx := v.lastNonTxHash
			if v.seen[rec.TxID] {
				wantTx = v.inTx[rec.TxID]
			}
			if rec.TxPrevHash != wantTx {
				return seg, fmt.Errorf(
					"audit: 第 %d 行 tx %s step %d 链断裂: tx_prev_hash=%s, 期望 %s",
					lineNo, rec.TxID, rec.TxStep, rec.TxPrevHash, wantTx)
			}
		}
		if seg.Entries == 0 {
			seg.FirstPrev = fields["prev_hash"]
		}
		seg.Last = fields["entry_hash"]
		if isTx {
			v.inTx[rec.TxID] = fields["entry_hash"]
			v.seen[rec.TxID] = true
		} else {
			v.lastNonTxHash = fields["entry_hash"]
			seg.LastNonTx = fields["entry_hash"]
		}
		v.prev = fields["entry_hash"]
		v.count++
		seg.Entries++
	}
	if err := sc.Err(); err != nil {
		return seg, fmt.Errorf("audit: 读取日志失败: %w", err)
	}
	return seg, nil
}

// Verify 全链重算校验 logPath 的哈希链, 是证据边界的完整性证明入口。
// 单文件语义: 首条有效记录的 prev_hash 必须为 GenesisHash。
// 返回校验通过的记录条数; 任一环节失败返回带行号的 error。
func Verify(logPath string) (int, error) {
	f, err := os.Open(logPath)
	if err != nil {
		return 0, fmt.Errorf("audit: 打开日志失败: %w", err)
	}
	defer f.Close()
	v := newVerifier()
	if _, err := v.feed(f); err != nil {
		return v.count, err
	}
	return v.count, nil
}
