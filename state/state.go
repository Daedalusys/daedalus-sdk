// Package state 实现 C4 机器状态记忆:state.jsonl 追加式(append-only)观测缓存。
//
// 职责与审计链分离(计划 aios-object-model-alignment todo 19):
//   - audit = 证据层——哈希链、防篡改、每步留痕;
//   - state = 派生缓存——"系统曾观测到什么",允许容错读取,无哈希链,
//     损坏/丢失只意味着缓存重建,不构成证据缺口。
//
// 解析路径唯一委托给 internal/dirs.StateFile()(env→系统→$HOME 链),
// 本包绝不复制解析逻辑。v1 KNOWN LIMITATION(按上下文隔离,DynamicUser
// 命名空间可见性)见 dirs 包文档;此处不重复。
//
// 并发协议与 audit.LogAudit 同源:打开(O_RDWR|O_CREATE|O_APPEND)→
// flock(LOCK_EX)→ 追加写 → Sync → LOCK_UN(defer LIFO 保证先解锁后关闭)。
// 锁加在文件自身 fd 上,与任何其他经本包/同 flock 语义的写入方互斥,
// 保证单行完整追加、无交错丢失。
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
	Kind       string          `json:"kind"`        // 资源类别(如 "service")
	Name       string          `json:"name"`        // 资源名(如 "sshd.service")
	ObservedAt time.Time       `json:"observed_at"` // 观测时刻(落盘恒 UTC RFC3339Nano)
	Payload    json.RawMessage `json:"payload"`     // 提供方序列化载荷,原样嵌入
}

// DefaultPath 解析 state.jsonl 落位:完全委托 dirs.StateFile()
// (DAEDALUS_STATE_PATH env 覆盖 → /var/lib/daedalus/state.jsonl →
// $HOME/.local/share/daedalus/state.jsonl → 显式错误,绝不静默回落)。
func DefaultPath() (string, error) {
	return dirs.StateFile()
}

// Log 追加一条状态观测:compact JSON + 行尾换行,单行一次写入。
//
// 时间戳归一:ObservedAt 先转 UTC 再走 time.Time 原生序列化
// (RFC3339Nano;整秒省略小数段是 Go 内建行为),与调用方传入的时区无关。
// 载荷不做 HTML 转义(SetEscapeHTML(false)),RawMessage 以紧凑形态落盘。
func Log(entry StateEntry) error {
	path, err := DefaultPath()
	if err != nil {
		return fmt.Errorf("state: 解析状态文件路径失败: %w", err)
	}

	// 单行序列化:json.Encoder.Encode 产出 compact JSON 且自带尾随 \n,
	// 恰为 JSONL 一行;关闭 HTML 转义以保载荷字节自洽。
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	entry.ObservedAt = entry.ObservedAt.UTC()
	if err := enc.Encode(entry); err != nil {
		return fmt.Errorf("state: 序列化条目失败: %w", err)
	}

	// 镜像 audit.go:目录不存在则尽力创建,失败静默(留给 open 报错)。
	if dir := filepath.Dir(path); dir != "" {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			_ = os.MkdirAll(dir, 0o755)
		}
	}

	// 镜像 audit.go 的写入+flock 协议(逐步骤对应)。
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

// Read 顺序解析全量观测,仅返回 ObservedAt >= since 的条目;
// since 为零值时间表示"全要"。
//
// 容错读取器(与审计验证器的严格姿态刻意相反:state 是缓存,不是证据):
//   - 文件不存在 → (nil, nil):无观测是正常态(新镜像/新 demo),非错误;
//   - 坏行(非法 JSON、截断行、非对象行)→ 静默跳过,绝不因单行损坏而报错;
//   - 仅真实的打开/读 I/O 失败(权限、设备错误等)才返回 error。
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

// LatestByKind 返回指定类别每个资源名(Name)的最新一条观测。
//
// 语义依据:文件是 append-only,"后写即新",同一 Name 的**最后出现行**
// 即最新观测(newest-wins)。输出按 (kind, name) 字典序排序保证确定性。
// 过滤/容错姿态同 Read。
func LatestByKind(kind string) ([]StateEntry, error) {
	entries, err := Read(time.Time{})
	if err != nil {
		return nil, err
	}
	latest := make(map[string]StateEntry)
	for _, e := range entries {
		if e.Kind == kind {
			latest[e.Name] = e // 顺序扫描,后来者覆盖前者
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
