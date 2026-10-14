// Package state 实现机器状态记忆:state.jsonl 追加式(append-only)观测缓存。
//
// 职责与审计链分离:audit = 证据层(哈希链、防篡改、每步留痕);state = 派生
// 缓存(容错读取,损坏/丢失只意味缓存重建,不构成证据缺口)。解析路径唯一委托
// dirs.StateFile() 不复制;v1 已知限制见 dirs 包文档。并发协议与
// audit.LogAudit 同源:O_APPEND → flock(LOCK_EX) → 追加写 → Sync → LOCK_UN
// (defer LIFO 先解锁后关闭),锁在文件自身 fd 上,保证单行完整追加、无交错丢失。
package state

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/Daedalusys/daedalus-sdk/dirs"
)

// 阈值解析优先序:SetMaxSizeBytes(显式)> env DAEDALUS_STATE_MAX_SIZE_MB(MB)
// > 默认 64 MiB。SetMaxSizeBytes(0) 复位到 env/默认(测试用)。
const (
	EnvMaxSizeMB        = "DAEDALUS_STATE_MAX_SIZE_MB"
	defaultMaxSizeBytes = 64 * 1024 * 1024
)

var (
	maxSizeBytes int64 = defaultMaxSizeBytes
	maxSizeSet   bool
)

// SetMaxSizeBytes 显式设置轮转上限(字节);n<=0 复位到 env/默认。
// 并发不安全,启动期或测试调用。
func SetMaxSizeBytes(n int64) {
	if n <= 0 {
		maxSizeSet = false
		return
	}
	maxSizeBytes = n
	maxSizeSet = true
}

// MaxSizeBytes 返回当前生效阈值(字节)。
func MaxSizeBytes() int64 {
	if maxSizeSet {
		return maxSizeBytes
	}
	if v := os.Getenv(EnvMaxSizeMB); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n * 1024 * 1024
		}
	}
	return defaultMaxSizeBytes
}

// prevGenPath 返回活跃文件旁边的上一代路径(<active>.1)。
func prevGenPath(active string) string { return active + ".1" }

// StateEntry 是一条状态观测记录,对应 state.jsonl 的一行 JSON。
// ObservedAt 由调用方填充(如 service.query 的观测时刻);
// Payload 是 provider 自己的序列化载荷(如 objectmodel.ServiceState),
// 本包不理解也不校验其内容——载荷 schema 属提供方。
type StateEntry struct {
	Kind       string          `json:"kind"`
	Name       string          `json:"name"`
	ObservedAt time.Time       `json:"observed_at"` // 落盘恒 UTC RFC3339Nano
	Payload    json.RawMessage `json:"payload"`
}

// DefaultPath 解析 state.jsonl 落位:完全委托 dirs.StateFile()
// (DAEDALUS_STATE_PATH env 覆盖 → /var/lib/daedalus/state.jsonl →
// $HOME/.local/share/daedalus/state.jsonl → 显式错误,绝不静默回落)。
func DefaultPath() (string, error) {
	return dirs.StateFile()
}

// Log 追加一条状态观测:compact JSON + 行尾换行,单行一次写入;ObservedAt 恒转
// UTC(RFC3339Nano),载荷不做 HTML 转义、以 RawMessage 紧凑落盘。
func Log(entry StateEntry) error {
	path, err := DefaultPath()
	if err != nil {
		return fmt.Errorf("state: 解析状态文件路径失败: %w", err)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	entry.ObservedAt = entry.ObservedAt.UTC()
	if err := enc.Encode(entry); err != nil {
		return fmt.Errorf("state: 序列化条目失败: %w", err)
	}

	// 目录不存在则尽力创建,失败静默(留给下面的 open 报错)。
	if dir := filepath.Dir(path); dir != "" {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			_ = os.MkdirAll(dir, 0o755)
		}
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("state: 打开状态文件失败: %w", err)
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("state: flock(LOCK_EX) 失败: %w", err)
	}
	// defer 为 LIFO:本行注册晚于上面的 Close → 退出时先 LOCK_UN 再 Close,
	// 与 audit.LogAudit 的"写完后解锁、随函数退出关闭文件"顺序一致。
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()

	// O_APPEND 下写恒追加,内核保证偏移原子;单行一次 Write,无需防御性 Seek。
	if _, err := f.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("state: 写入状态行失败: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("state: flush 失败: %w", err)
	}
	// 缓存轮转:超阈值后 rename 活跃到 .1 并重建空活跃。发生在同一把 EX 锁
	// 窗口内;flock 持在旧 inode,rename 不影响;readers 拿 SH 锁(见 Read)被
	// 本次 EX 阻塞,期间 .1 不会变动,快照一致。
	if lim := MaxSizeBytes(); lim > 0 {
		if fi, serr := f.Stat(); serr == nil && fi.Size() > lim {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
			if rerr := rotateStateFile(path); rerr != nil {
				return fmt.Errorf("state: 轮转失败: %w", rerr)
			}
		}
	}
	return nil
}

// rotateStateFile:rename active → active.1,新建空 active 0640。覆盖旧 .1。
func rotateStateFile(path string) error {
	if err := os.Rename(path, prevGenPath(path)); err != nil {
		return err
	}
	nf, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	return nf.Close()
}

// Read 顺序解析全量观测(跨"上一代 .1 + 活跃"),仅返回 ObservedAt >= since
// 的条目。容错读取器(state 是缓存而非证据):文件不存在 → (nil, nil);坏行
// 静默跳过;仅真实 I/O 失败才返回 error。
//
// 锁协议:先开活跃 + LOCK_SH(与 Log 的 LOCK_EX 互斥),期间轮转被阻塞,
// 再依次读 .1(老)与活跃(新),构成同一次轮转前后的一致快照;避免"读了旧 .1
// 又读了新空活跃"的"写过的读不到"空窗。
func Read(since time.Time) ([]StateEntry, error) {
	path, err := DefaultPath()
	if err != nil {
		return nil, fmt.Errorf("state: 解析状态文件路径失败: %w", err)
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		// 活跃缺失(新启动 / 刚轮转窗口):退化只读 .1。
		if pf, perr := os.Open(prevGenPath(path)); perr == nil {
			out := scanEntries(pf, since)
			_ = pf.Close()
			return out, nil
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("state: 打开状态文件失败: %w", err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		return nil, fmt.Errorf("state: flock(LOCK_SH) 失败: %w", err)
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()

	var out []StateEntry
	if pf, perr := os.Open(prevGenPath(path)); perr == nil {
		out = append(out, scanEntries(pf, since)...)
		_ = pf.Close()
	}
	out = append(out, scanEntries(f, since)...)
	return out, nil
}

// scanEntries 顺序解析 r,按 ObservedAt 过滤(零值不过滤);坏行静默跳过。
func scanEntries(r io.Reader, since time.Time) []StateEntry {
	var out []StateEntry
	br := bufio.NewReader(r)
	for {
		line, readErr := br.ReadBytes('\n')
		if len(line) > 0 {
			var e StateEntry
			if json.Unmarshal(bytes.TrimSpace(line), &e) == nil {
				if since.IsZero() || !e.ObservedAt.Before(since) {
					out = append(out, e)
				}
			}
		}
		if readErr != nil {
			break
		}
	}
	return out
}

// LatestByKind 返回指定类别每个资源名的最新一条观测。文件是 append-only,
// "后写即新",同一 Name 的最后出现行即最新观测;输出按 (kind, name) 排序保证确定性。
func LatestByKind(kind string) ([]StateEntry, error) {
	entries, err := Read(time.Time{})
	if err != nil {
		return nil, err
	}
	latest := make(map[string]StateEntry)
	for _, e := range entries {
		if e.Kind == kind {
			latest[e.Name] = e
		}
	}
	out := make([]StateEntry, 0, len(latest))
	for _, e := range latest {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}
