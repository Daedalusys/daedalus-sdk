// Package state 实现 C4 机器状态记忆:state.jsonl 追加式(append-only)观测缓存。
//
// 职责与审计链分离:audit = 证据层(哈希链、防篡改、每步留痕);state = 派生
// 缓存(容错读取,损坏/丢失只意味缓存重建,不构成证据缺口)。解析路径唯一委托
// dirs.StateFile() 不复制;v1 KNOWN LIMITATION 见 dirs 包文档。并发协议与
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
	"syscall"
	"time"

	"github.com/Daedalusys/daedalus-sdk/dirs"
)

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

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
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
	return nil
}

// Read 顺序解析全量观测,仅返回 ObservedAt >= since 的条目(since 为零值表示
// "全要")。容错读取器(state 是缓存而非证据,姿态与审计验证器刻意相反):文件
// 不存在 → (nil, nil);坏行静默跳过;仅真实 I/O 失败才返回 error。
func Read(since time.Time) ([]StateEntry, error) {
	path, err := DefaultPath()
	if err != nil {
		return nil, fmt.Errorf("state: 解析状态文件路径失败: %w", err)
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("state: 打开状态文件失败: %w", err)
	}
	defer f.Close()

	var out []StateEntry
	r := bufio.NewReader(f)
	for {
		line, readErr := r.ReadBytes('\n')
		if len(line) > 0 {
			var e StateEntry
			// TrimSpace 容忍 \r\n 与尾随空白;解析失败即坏行,跳过。
			if json.Unmarshal(bytes.TrimSpace(line), &e) == nil {
				if since.IsZero() || !e.ObservedAt.Before(since) {
					out = append(out, e)
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break // 末行可无换行,已在上面处理
			}
			return nil, fmt.Errorf("state: 读取状态文件失败: %w", readErr)
		}
	}
	return out, nil
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
