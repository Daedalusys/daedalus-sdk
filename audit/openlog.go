package audit

// openlog.go —— 跨"活跃文件 + archive 目录"的只读迭代器。
//
// 轮转把旧段 rename 进 <dir(logPath)>/archive/ 并(异步)gzip。读侧消费者
// (daedalus-tx 的 scanTxTail、daedalus-trace 的回放、VerifyChain)必须能透明
// 跨段读取,否则轮转一上线就读不到历史。
//
// 段定序约定:归档文件名形如 `audit.jsonl.<UTC时间戳>.jsonl[.gz]`。OpenLog 仅
// 按文件名字典序排列(时间戳零填充 → 与写入序一致);VerifyChain 走内容链定序
// (见 verifychain.go),两者互不依赖。

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LogOrder 决定 OpenLog 的遍历方向。
type LogOrder int

const (
	// OldestFirst:最老归档段 → 最新归档段 → 活跃文件。回放/校验用。
	OldestFirst LogOrder = iota
	// NewestFirst:活跃文件 → 最新归档段 → 最老归档段。事务链尾查找用(短路最新段)。
	NewestFirst
)

// LogReader 是跨段记录迭代器。Next 返回下一条记录;流尽返回 io.EOF。
// 遇到不可解析的非空行返回(非 EOF)错误但游标已前进,宽容调用方可 continue。
type LogReader interface {
	Next() (Record, error)
	Close() error
}

// maxLogLineBytes 与 Verify 同参:审计行可能含长 args,单行上限 4 MiB。
const maxLogLineBytes = 4 * 1024 * 1024

// OpenLog 返回 logPath 的记录迭代器,自动纳入 <dir(logPath)>/archive/ 下的归档段。
// archive 目录不存在/为空时只迭代活跃文件。
func OpenLog(logPath string, order LogOrder) (LogReader, error) {
	segs, err := listArchiveSegments(filepath.Join(filepath.Dir(logPath), "archive"))
	if err != nil {
		return nil, err
	}
	var paths []string
	switch order {
	case OldestFirst:
		paths = append(paths, segs...)
		paths = append(paths, logPath)
	default: // NewestFirst
		paths = append(paths, logPath)
		for i := len(segs) - 1; i >= 0; i-- {
			paths = append(paths, segs[i])
		}
	}
	return &multiReader{paths: paths}, nil
}

// listArchiveSegments 列出归档段,按 base 名升序;同段 .jsonl 与 .jsonl.gz 并存时
// 取 .gz(压缩完成的版本)。目录不存在 → (nil, nil)。
func listArchiveSegments(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: 读取归档目录 %s 失败: %w", dir, err)
	}
	byBase := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// 只收归档段名 `audit.jsonl.<ts>.jsonl[.gz]`;排除 pruned.jsonl 等
		// 非段文件(其不含 `.jsonl.` 中缀)。
		if !strings.Contains(name, ".jsonl.") {
			continue
		}
		var base string
		switch {
		case strings.HasSuffix(name, ".jsonl.gz"):
			base = strings.TrimSuffix(name, ".gz")
		case strings.HasSuffix(name, ".jsonl"):
			base = name
		default:
			continue
		}
		// 同一 base:优先 .gz;已存 .gz 时不回退 .jsonl。
		if prev, ok := byBase[base]; ok && strings.HasSuffix(prev, ".gz") {
			continue
		}
		byBase[base] = filepath.Join(dir, name)
	}
	bases := make([]string, 0, len(byBase))
	for b := range byBase {
		bases = append(bases, b)
	}
	sort.Strings(bases)
	out := make([]string, 0, len(bases))
	for _, b := range bases {
		out = append(out, byBase[b])
	}
	return out, nil
}

// openSegment 打开一个归档段(自动识别 .gz),返回可读流。
func openSegment(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("audit: 打开段 %s 失败: %w", path, err)
	}
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("audit: 解压段 %s 失败: %w", path, err)
		}
		return &gzSegment{f: f, gz: gz}, nil
	}
	return f, nil
}

type gzSegment struct {
	f  *os.File
	gz *gzip.Reader
}

func (g *gzSegment) Read(p []byte) (int, error) { return g.gz.Read(p) }
func (g *gzSegment) Close() error {
	_ = g.gz.Close()
	return g.f.Close()
}

// multiReader 顺序读 paths 里的段;每段一个 bufio.Scanner。
type multiReader struct {
	paths   []string
	idx     int
	curPath string
	cur     io.ReadCloser
	sc      *bufio.Scanner
}

func (m *multiReader) Next() (Record, error) {
	for {
		if m.sc == nil {
			if m.idx >= len(m.paths) {
				return Record{}, io.EOF
			}
			p := m.paths[m.idx]
			m.idx++
			rc, err := openSegment(p)
			if err != nil {
				return Record{}, err
			}
			m.closeCur()
			m.cur, m.curPath = rc, p
			m.sc = bufio.NewScanner(rc)
			m.sc.Buffer(make([]byte, 0, 64*1024), maxLogLineBytes)
		}
		if !m.sc.Scan() {
			err := m.sc.Err()
			m.closeCur()
			m.sc = nil
			if err != nil {
				return Record{}, fmt.Errorf("audit: 读段 %s 失败: %w", m.curPath, err)
			}
			continue
		}
		line := strings.TrimSpace(m.sc.Text())
		if line == "" {
			continue
		}
		v, perr := ParseValue(line)
		if perr != nil || !v.IsObject() {
			return Record{}, fmt.Errorf("audit: 段 %s 损坏: 非法 JSON 行", m.curPath)
		}
		rec, ok := recordFromValue(v)
		if !ok {
			return Record{}, fmt.Errorf("audit: 段 %s 损坏: 记录字段不完整", m.curPath)
		}
		return rec, nil
	}
}

func (m *multiReader) closeCur() {
	if m.cur != nil {
		_ = m.cur.Close()
		m.cur = nil
	}
}

func (m *multiReader) Close() error {
	m.closeCur()
	m.sc = nil
	return nil
}
