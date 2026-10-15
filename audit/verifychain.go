package audit

// verifychain.go —— 跨"活跃文件 + 归档段 + 已清理前缀账本"的整链校验。
//
// 归档段自描述(每段首条 prev_hash = 上段尾 entry_hash),故保留中的段按内容链
// 天然可 replay。保留期删除的最老前缀,其链骨写进 <archive>/pruned.jsonl;
// VerifyChain 先用账本把 verifier 的 prev / lastNonTxHash / inTx / seen 播种到
// "第一个保留段的期望起点",再 replay 保留段与活跃文件。
//
// 威胁边界:保留窗口外的段被合法删除后,其哈希只能取自账本,不可再算——
// 能检测窗口内任意段的删改重排;检测不了窗口外前缀删除(保留策略的固有代价)。

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// PrunedSegment 是被清理掉的一个归档段的链骨。
type PrunedSegment struct {
	File          string `json:"file"`
	FirstPrevHash string `json:"first_prev_hash"`
	LastEntryHash string `json:"last_entry_hash"`
	LastNonTxHash string `json:"last_non_tx_hash"`
	Entries       int    `json:"entries"`
}

// InheritedTx 是"在被删前缀里出现、且在第一个保留段里也出现"的事务,
// 记录其在前缀内的最后一条 in-tx entry_hash,供 verifier 播种 inTx/seen。
type InheritedTx struct {
	ID   string `json:"id"`
	Hash string `json:"hash"`
}

// PruneRecord 是 pruned.jsonl 的一行(一次保留清理操作)。
type PruneRecord struct {
	Pruned        []PrunedSegment `json:"pruned"`
	AnchorPrev    string          `json:"anchor_prev_hash"` // = 被删前缀末段 last_entry_hash = 第一个保留段首条期望 prev
	LastNonTxHash string          `json:"last_non_tx_hash"` // = 被删前缀末段的 last_non_tx_hash
	InheritedTx   []InheritedTx   `json:"inherited_tx"`
	At            string          `json:"at"`
}

// readPruneLedger 读 <dir>/pruned.jsonl(不存在 → nil, nil)。坏行 → 报错(证据层不宽容)。
func readPruneLedger(dir string) ([]PruneRecord, error) {
	path := filepath.Join(dir, "pruned.jsonl")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: 打开 prune 账本失败: %w", err)
	}
	defer f.Close()
	var out []PruneRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxLogLineBytes)
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec PruneRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("audit: prune 账本第 %d 行损坏: %w", lineNo, err)
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("audit: 读取 prune 账本失败: %w", err)
	}
	return out, nil
}

// seedFromPrune 用一条 prune 记录把 v 的状态推进到"第一个保留段的期望起点"。
// 校验账本内部自洽:首段 first_prev == v.prev(承接上一轮),段间首尾相接。
func (v *verifier) seedFromPrune(rec PruneRecord) error {
	if len(rec.Pruned) == 0 {
		return errors.New("audit: prune 账本记录为空(无 pruned 段)")
	}
	if rec.Pruned[0].FirstPrevHash != v.prev {
		return fmt.Errorf("audit: prune 账本断链: %s first_prev=%s, 期望 %s",
			rec.Pruned[0].File, rec.Pruned[0].FirstPrevHash, v.prev)
	}
	for i := 1; i < len(rec.Pruned); i++ {
		if rec.Pruned[i].FirstPrevHash != rec.Pruned[i-1].LastEntryHash {
			return fmt.Errorf("audit: prune 账本段间断链: %s", rec.Pruned[i].File)
		}
	}
	if rec.Pruned[len(rec.Pruned)-1].LastEntryHash != rec.AnchorPrev {
		return fmt.Errorf("audit: prune 账本 anchor 不符: 末段 last=%s, anchor=%s",
			rec.Pruned[len(rec.Pruned)-1].LastEntryHash, rec.AnchorPrev)
	}
	v.prev = rec.AnchorPrev
	v.lastNonTxHash = rec.LastNonTxHash
	for _, it := range rec.InheritedTx {
		v.inTx[it.ID] = it.Hash
		v.seen[it.ID] = true
	}
	return nil
}

// VerifyChain 校验"活跃文件 + archiveDir 下所有保留段 + prune 账本"的整链。
// 无账本且无归档段 → 与 Verify(activePath) 等价(单文件、创世锚点)。
func VerifyChain(activePath, archiveDir string) (int, error) {
	if archiveDir == "" {
		archiveDir = filepath.Join(filepath.Dir(activePath), "archive")
	}
	ledger, err := readPruneLedger(archiveDir)
	if err != nil {
		return 0, err
	}
	segs, err := listArchiveSegments(archiveDir, filepath.Base(activePath))
	if err != nil {
		return 0, err
	}
	if len(ledger) == 0 && len(segs) == 0 {
		return Verify(activePath)
	}

	v := newVerifier()
	for _, rec := range ledger {
		if err := v.seedFromPrune(rec); err != nil {
			return v.count, err
		}
	}
	for _, p := range segs {
		rc, err := openSegment(p)
		if err != nil {
			return v.count, err
		}
		_, ferr := v.feed(rc)
		_ = rc.Close()
		if ferr != nil {
			return v.count, fmt.Errorf("audit: 段 %s: %w", filepath.Base(p), ferr)
		}
	}
	f, err := os.Open(activePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// 活跃文件可缺失(刚轮转、尚无新写);已 replay 的保留段即全部证据。
			return v.count, nil
		}
		return v.count, fmt.Errorf("audit: 打开日志失败: %w", err)
	}
	defer f.Close()
	if _, err := v.feed(f); err != nil {
		return v.count, err
	}
	return v.count, nil
}

// 保证 io 被使用(openSegment 返回 io.ReadCloser)。
var _ io.Reader = (*os.File)(nil)

// encodePruneRecord 把一条记录序列化为单行 JSON(末尾加 \n),供保留清理或
// 测试写 pruned.jsonl 用。
func encodePruneRecord(rec PruneRecord) ([]byte, error) {
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
