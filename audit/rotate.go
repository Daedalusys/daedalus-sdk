package audit

// rotate.go —— audit.jsonl 轮转(§4.1):先落 .tail,再 rename,再压缩归档。
//
// 崩溃安全的关键次序:新段尾哈希必须先于"活跃文件变空"落盘,否则空文件首条
// 会从陈旧来源播种、链即断。全部关键步骤在活跃文件的 flock(LOCK_EX)内完成;
// gzip 与 reconcile 在锁外做。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// RotateOptions 是 Rotate 的输入。
type RotateOptions struct {
	LogPath    string
	ArchiveDir string
	MaxSizeMB  int64
	Force      bool
	Attrs      AppendOnlyOps // nil → CurrentAppendOnlyOps()
	Now        time.Time     // 零值 → time.Now().UTC()
}

// Rotate 走"size 达阈值 → 轮转"路径:
//  1. 未达阈值且非 Force → (false, nil),不建归档目录;
//  2. flock(LOCK_EX) 活跃文件;
//  3. 扫末信息(末 entry_hash / 末非 tx / 末时间戳);
//  4. 原子写 <logPath>.tail(必须在文件变空之前);
//  5. 清 attrs(不支持 → 跳过;失败 → 中止,不碰数据);
//  6. rename 活跃 → archive/<ts>.jsonl;
//  7. 新建空活跃 0640 + 设 attrs(尽力);
//  8. 解锁;
//  9. reconcile 归档(gzip 未压缩项 + 去除重复)。
//
// 返回是否真的轮转。
func Rotate(opts RotateOptions) (bool, error) {
	if opts.Attrs == nil {
		opts.Attrs = CurrentAppendOnlyOps()
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.ArchiveDir == "" {
		opts.ArchiveDir = filepath.Join(filepath.Dir(opts.LogPath), "archive")
	}

	fi, err := os.Stat(opts.LogPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("audit: 轮转 stat 活跃文件失败: %w", err)
	}
	if !opts.Force && opts.MaxSizeMB > 0 {
		if fi.Size() < opts.MaxSizeMB*1024*1024 {
			// 未达阈值:只做回收(reconcile),不轮转。
			return false, reconcileArchive(opts.ArchiveDir)
		}
	}

	// 打开并持锁。
	f, err := os.OpenFile(opts.LogPath, os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW, 0o640)
	if err != nil {
		return false, fmt.Errorf("audit: 轮转打开活跃文件失败: %w", err)
	}
	// 二重释放防护:defer 闭包拍下变量指针;手动 close 后 f = nil,
	// defer 跳过(否则会在 fd 被后续 open 复用时关错文件)。
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return false, fmt.Errorf("audit: 轮转 flock 失败: %w", err)
	}
	defer func() {
		if f != nil {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		}
	}()

	seg, err := scanSegmentFileHandle(f)
	if err != nil {
		return false, err
	}
	if seg.Entries == 0 {
		// 空活跃文件:无需轮转,只回收。
		return false, reconcileArchive(opts.ArchiveDir)
	}

	// 4. 先落尾(活跃文件变空之前)。两行:全局链尾 + 最后非 tx(供 tx begin 播种)。
	if err := writeFileAtomic(TailPath(opts.LogPath), []byte(seg.Last+"\n"+seg.LastNonTx+"\n")); err != nil {
		return false, fmt.Errorf("audit: 写 .tail 失败: %w", err)
	}

	if err := os.MkdirAll(opts.ArchiveDir, 0o750); err != nil {
		return false, fmt.Errorf("audit: 建归档目录失败: %w", err)
	}

	// 5. 清 attrs(仅当确实置了)。
	if has, herr := opts.Attrs.HasAppend(opts.LogPath); herr == nil && has {
		if cerr := opts.Attrs.ClearAppend(opts.LogPath); cerr != nil {
			return false, fmt.Errorf("audit: 清除 append-only 失败(中止轮转): %w", cerr)
		}
	} else if herr != nil && !isAttrsUnsupported(herr) {
		return false, fmt.Errorf("audit: 探测 append-only 失败(中止轮转): %w", herr)
	}

	// 6. rename 到归档(未压缩,先用最终名)。
	name := archiveSegmentName(seg.LastTimestamp, opts.Now)
	dest := filepath.Join(opts.ArchiveDir, name+".jsonl")
	dest = uniquePath(dest)
	if err := os.Rename(opts.LogPath, dest); err != nil {
		return false, fmt.Errorf("audit: rename 活跃文件到归档失败: %w", err)
	}
	if err := syncDir(opts.ArchiveDir); err != nil {
		return false, fmt.Errorf("audit: fsync 归档目录失败: %w", err)
	}

	// 7. 新建空活跃 + 尽力恢复 attrs。
	nf, err := os.OpenFile(opts.LogPath, os.O_RDWR|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW, 0o640)
	if err != nil {
		return false, fmt.Errorf("audit: 新建活跃文件失败: %w", err)
	}
	_ = nf.Close()
	if err := opts.Attrs.SetAppend(opts.LogPath); err != nil && !isAttrsUnsupported(err) {
		// 尽力而为:已完成的轮转不回滚,仅让调用方可见(由 CLI 记 stderr)。
		fmt.Fprintf(os.Stderr, "audit: 警告: 恢复 append-only 失败: %v\n", err)
	}

	// 主动释放:defer 闭包看见 f=nil 跳过,避免后续 reconcileArchive 的 open
	// 复用本 fd 后被误关。
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
	f = nil

	// 9. 压缩归档(锁外亦可,此处仍在锁内但不再触碰活跃文件)。
	return true, reconcileArchive(opts.ArchiveDir)
}

// PruneOptions 是 Prune 的输入。
type PruneOptions struct {
	ArchiveDir string
	RetainDays int64
	Now        time.Time
}

// Prune 按 rotated_at(取文件名时间戳)删除早于 now-retainDays 的最老前缀段,
// 并把其链骨写入 <archive>/pruned.jsonl(append-only),使 VerifyChain 仍可锚定。
// 返回删除的段数。
func Prune(opts PruneOptions) (int, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.RetainDays <= 0 {
		return 0, nil
	}
	segs, err := listArchiveSegments(opts.ArchiveDir)
	if err != nil {
		return 0, err
	}
	cutoff := opts.Now.Add(-time.Duration(opts.RetainDays) * 24 * time.Hour)

	// 选出最老的、超过保留期的连续前缀。
	var pruneFiles []string
	for _, p := range segs {
		if _, ok := segmentTime(p); !ok {
			break // 时间戳解析失败:保守停止
		}
		ts, _ := segmentTime(p)
		if ts.After(cutoff) {
			break
		}
		pruneFiles = append(pruneFiles, p)
	}
	if len(pruneFiles) == 0 {
		return 0, nil
	}

	// 累积被删前缀的骨头与 tx 尾。
	var pruned []PrunedSegment
	prefixTx := map[string]string{}
	for _, p := range pruneFiles {
		sc, err := scanSegment(p)
		if err != nil {
			return 0, err
		}
		pruned = append(pruned, sc.bones(filepath.Base(p)))
		for id, h := range sc.TxLast {
			prefixTx[id] = h
		}
	}

	// 找第一个保留段,算 inherited_tx(前缀 ∩ 保留段)。
	inherited := []InheritedTx{}
	for _, p := range segs {
		if containsString(pruneFiles, p) {
			continue
		}
		sc, err := scanSegment(p)
		if err != nil {
			return 0, err
		}
		for id := range sc.TxLast {
			if h, ok := prefixTx[id]; ok {
				inherited = append(inherited, InheritedTx{ID: id, Hash: h})
			}
		}
		break
	}

	lastPruned := pruned[len(pruned)-1]
	rec := PruneRecord{
		Pruned:        pruned,
		AnchorPrev:    lastPruned.LastEntryHash,
		LastNonTxHash: lastPruned.LastNonTxHash,
		InheritedTx:   inherited,
		At:            opts.Now.UTC().Format(time.RFC3339Nano),
	}
	line, err := encodePruneRecord(rec)
	if err != nil {
		return 0, err
	}
	ledger := filepath.Join(opts.ArchiveDir, "pruned.jsonl")
	lf, err := os.OpenFile(ledger, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return 0, fmt.Errorf("audit: 打开 prune 账本失败: %w", err)
	}
	if _, err := lf.Write(line); err != nil {
		_ = lf.Close()
		return 0, fmt.Errorf("audit: 写 prune 账本失败: %w", err)
	}
	if err := lf.Sync(); err != nil {
		_ = lf.Close()
		return 0, fmt.Errorf("audit: fsync prune 账本失败: %w", err)
	}
	_ = lf.Close()

	for _, p := range pruneFiles {
		if err := os.Remove(p); err != nil {
			return len(pruneFiles), fmt.Errorf("audit: 删除归档段 %s 失败: %w", p, err)
		}
	}
	return len(pruneFiles), nil
}

func isAttrsUnsupported(err error) bool {
	return err != nil && strings.Contains(err.Error(), ErrAttrsUnsupported.Error())
}
