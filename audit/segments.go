package audit

// segments.go —— Rotate/Prune 用的段扫描 / 命名 / 原子写工具。
//
// 段文件命名:`audit.jsonl.<YYYYMMDDTHHMMSS.ffffffZ>.jsonl[.gz]`,时间戳取自
// 段最后一条记录的 timestamp(RFC3339Nano)。本文件负责"从路径解析出时间戳"
// 与"为新段挑一个唯一名"。

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// segScan 是一个段的扫描结果。TxLast 是"末次出现的 entry_hash per txID" 映射,
// 供 Prune 算 inherited_tx 用。
type segScan struct {
	FirstPrev     string
	Last          string
	LastNonTx     string
	Entries       int
	LastTimestamp string
	TxLast        map[string]string
}

// bones 返回 ledger 用 PrunedSegment 视图。
func (s segScan) bones(name string) PrunedSegment {
	return PrunedSegment{
		File:          name,
		FirstPrevHash: s.FirstPrev,
		LastEntryHash: s.Last,
		LastNonTxHash: s.LastNonTx,
		Entries:       s.Entries,
	}
}

// scanSegment 正向扫描一段文件(可读)。无链校验,只取元数据。
func scanSegment(path string) (segScan, error) {
	f, err := os.Open(path)
	if err != nil {
		return segScan{}, fmt.Errorf("audit: 打开段 %s 失败: %w", path, err)
	}
	defer f.Close()
	return scanSegmentFileHandle(f)
}

// scanSegmentFileHandle 从 fd 起点正向扫描。Rotate 拿到 flock 后的 fd 后调用。
func scanSegmentFileHandle(f *os.File) (segScan, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return segScan{}, err
	}
	var s segScan
	s.TxLast = map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		v, perr := ParseValue(line)
		if perr != nil || !v.IsObject() {
			continue
		}
		ph, ok1 := v.LookupString("prev_hash")
		eh, ok2 := v.LookupString("entry_hash")
		ts, _ := v.LookupString("timestamp")
		if !ok1 || !ok2 {
			continue
		}
		if s.Entries == 0 {
			s.FirstPrev = ph
		}
		s.Last = eh
		s.LastTimestamp = ts
		if txID, ok := v.LookupString("tx_id"); ok && txID != "" {
			s.TxLast[txID] = eh
		} else {
			s.LastNonTx = eh
		}
		s.Entries++
	}
	if err := sc.Err(); err != nil {
		return s, err
	}
	return s, nil
}

// archiveSegmentName 从段最后一条 timestamp 构造段名;若时间戳缺失/非法,落 opts.Now。
// 格式:YYYYMMDDTHHMMSS.ffffffZ。
func archiveSegmentName(lastTS string, fallback time.Time) string {
	if lastTS != "" {
		if t, err := time.Parse(time.RFC3339Nano, lastTS); err == nil {
			return t.UTC().Format("20060102T150405.000000Z")
		}
	}
	return fallback.UTC().Format("20060102T150405.000000Z")
}

// segmentTime 从段路径解析时间戳;失败返 false。
// 名形如 `audit.jsonl.20260101T000000.000000Z.jsonl[.gz]`。
func segmentTime(p string) (time.Time, bool) {
	name := filepath.Base(p)
	for _, suf := range []string{".jsonl.gz", ".jsonl"} {
		if strings.HasSuffix(name, suf) {
			name = strings.TrimSuffix(name, suf)
			break
		}
	}
	idx := strings.LastIndex(name, ".jsonl.")
	if idx < 0 {
		return time.Time{}, false
	}
	ts := name[idx+len(".jsonl."):]
	t, err := time.Parse("20060102T150405.000000Z", ts)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// uniquePath 若 p 已存在,加 -NN 后缀找首个未占用。
func uniquePath(p string) string {
	if _, err := os.Stat(p); err != nil {
		return p
	}
	ext := filepath.Ext(p)
	base := strings.TrimSuffix(p, ext)
	for n := 1; n < 1000; n++ {
		cand := base + "-" + strconv.Itoa(n) + ext
		if _, err := os.Stat(cand); err != nil {
			return cand
		}
	}
	return p
}

// reconcileArchive 把 archive 中未压缩的 .jsonl 压成 .jsonl.gz,删未压缩原件;
// 同名 .jsonl + .jsonl.gz 并存时以 .gz 为准(启动期自愈)。
func reconcileArchive(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		base := e.Name() // 形如 audit.jsonl.<ts>.jsonl
		gzPath := filepath.Join(dir, base+".gz")
		plain := filepath.Join(dir, base)
		// 已有 .gz 同伴 → 删未压缩
		if _, err := os.Stat(gzPath); err == nil {
			_ = os.Remove(plain)
			continue
		}
		// 压。
		if err := gzipFile(plain, gzPath); err != nil {
			return err
		}
		if err := os.Remove(plain); err != nil {
			return err
		}
	}
	return syncDir(dir)
}

// gzipFile 把 plainPath 压缩到 gzPath(原子:temp + rename)。
func gzipFile(plainPath, gzPath string) error {
	tmp := gzPath + ".tmp"
	src, err := os.Open(plainPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(dst)
	if _, err := io.Copy(zw, src); err != nil {
		_ = zw.Close()
		_ = dst.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := zw.Close(); err != nil {
		_ = dst.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := dst.Sync(); err != nil {
		_ = dst.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, gzPath)
}

// writeFileAtomic 写文件:temp+fsync+rename+fsync 父目录。
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

// syncDir fsync 目录(对创建/rename 的元数据落盘至关重要)。
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
