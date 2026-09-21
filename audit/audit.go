package audit

// allow: SIZE_OK —— 计划 todo 12 零裁量钉桩 lastNonTxRecord 必须住在本文件,
// 且 LogAudit 哈希派发与 Record/Entry 的 tx 字段是同一条件扩展的三块拼图;
// 可独立搬运的 payloadFor/ComputeEntryHashRecord/recordFromValue 已外迁 hashtx.go。

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// 哈希链与默认值常量, 与 audit-log.py:16-18 逐一对应。
const (
	// GenesisHash 是创世 prev_hash(空文件/无有效尾行时使用), Python GENESIS_HASH = "0"*64。
	GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
	// DefaultPolicyVersion 对应 Python POLICY_VERSION = "1.0"。
	DefaultPolicyVersion = "1.0"
	// EnvLogPath 对应 Python AUDIT_LOG_PATH 的环境变量覆盖。
	EnvLogPath = "DAEDALUS_AUDIT_LOG_PATH"
	// systemLogPath 对应 Python 的 /var/log/daedalus/audit.jsonl 默认值。
	systemLogPath = "/var/log/daedalus/audit.jsonl"
	// tailChunkSize 对应 Python get_last_entry_hash 的 buffer_size = 4096。
	tailChunkSize = 4096
)

// DefaultLogPath 复刻 audit-log.py:16: 环境变量优先, 否则系统默认路径。
// (argparse 的 --log-path 默认值即该常量, 显式旗标仍可覆盖环境变量。)
func DefaultLogPath() string {
	if v := os.Getenv(EnvLogPath); v != "" {
		return v
	}
	return systemLogPath
}

// ComputeEntryHash 计算审计条目哈希, 等价 audit-log.py:21-37 的 compute_entry_hash。
//
// args 参数传**已规范化**的 args_str(由 Value.ArgsString 产出, 语义等价 Python 端
// 接收 args 后内部的 json.dumps 规范化); 载荷拼接顺序严禁改动:
//
//	payload = timestamp + identity + tool + args_str + outcome + prev_hash
//	entry_hash = SHA-256(payload.encode("utf-8")).hexdigest()   # 小写十六进制
func ComputeEntryHash(timestamp, identity, tool, args, outcome, prevHash string) string {
	payload := timestamp + identity + tool + args + outcome + prevHash
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// Record 是一条完整审计记录, 字段与 audit-log.py:133-142 的 record dict 一致;
// tx 三元组为 todo 12 的可选扩展: 仅当 TxID 非空时落盘(tx_id/tx_step/tx_prev_hash)
// 且参与哈希载荷(见 payloadFor), 非 tx 记录与金样逐字节兼容。
type Record struct {
	Timestamp     string
	Identity      string
	Tool          string
	Args          *Value
	PolicyVersion string
	Outcome       string
	PrevHash      string
	EntryHash     string
	TxID          string // 事务 ID; "" 表示非 tx 条目(发射与哈希判据均以此为准)
	TxStep        int    // 事务内步序号(begin=0, apply/rollback 递增)
	TxPrevHash    string // 同事务前一步的 entry_hash(创世 = 最近非 tx 条目的哈希)
}

// toValue 按 Python dict 插入序组装记录对象(stdout 依赖该字段序)。
//
// 前 8 键恒用 set() 落盘(金样逐字节锚点); tx 三元组**仅当 TxID 非空**时经
// setIfNonEmpty 条件追加。非 tx 记录由此保证零新键 → 磁盘行与既有金样完全一致。
func (r *Record) toValue() *Value {
	v := NewObject()
	v.set("timestamp", NewString(r.Timestamp))
	v.set("identity", NewString(r.Identity))
	v.set("tool", NewString(r.Tool))
	v.set("args", r.Args)
	v.set("policy_version", NewString(r.PolicyVersion))
	v.set("outcome", NewString(r.Outcome))
	v.set("prev_hash", NewString(r.PrevHash))
	v.set("entry_hash", NewString(r.EntryHash))
	if r.TxID != "" {
		v.setIfNonEmpty("tx_id", NewString(r.TxID))
		v.setIfNonEmpty("tx_step", NewInt64(int64(r.TxStep)))
		v.setIfNonEmpty("tx_prev_hash", NewString(r.TxPrevHash))
	}
	return v
}

// Line 返回日志文件中的一行(不含换行符), 等价 json.dumps(record, sort_keys=True)。
func (r *Record) Line() string {
	return encodeValue(r.toValue(), modeLine).String()
}

// IndentJSON 返回 CLI stdout 的格式化记录, 等价 json.dumps(record, indent=2):
// 不排序(保持字段插入序), 嵌套 args 保持输入文档键序。
func (r *Record) IndentJSON() string {
	return encodeValue(r.toValue(), modeStdout).String()
}

// Entry 是 LogAudit 的输入(参数 >3 个的字段聚合为类型化值对象)。
type Entry struct {
	Identity      string // 调用者 ID(默认由 CLI 填 "cli")
	Tool          string // 工具名, 必填
	Args          *Value // nil 视为 {} (audit-log.py:106-107)
	Outcome       string // "" 视为 "success"
	PolicyVersion string // "" 视为 DefaultPolicyVersion
	LogPath       string // "" 视为 DefaultLogPath()
	TxID          string // 事务 ID; 非空即触发发射与哈希的条件扩展(todo 12)
	TxStep        int    // 事务内步序号(仅 TxID 非空时有意义; begin=0)
	TxPrevHash    string // 同事务前一步 entry_hash(仅 TxID 非空时落盘并参与哈希)
}

// LogAudit 追加一条哈希链审计条目, 等价 audit-log.py:85-150 的 log_audit。
//
// 并发协议: 打开(a+ 等价 O_RDWR|O_CREATE|O_APPEND) → flock(LOCK_EX) →
// 读尾行 prev_hash → 写行 → flush → LOCK_UN(由 defer 在 Close 前释放)。
// 锁加在**日志文件本身**的 fd 上, 与 Python fcntl.flock(f.fileno(), LOCK_EX) 同语义,
// 与外部 Python 写入方互斥, 保证链计算无竞态。
func LogAudit(e Entry) (*Record, error) {
	if e.Args == nil {
		e.Args = NewObject()
	}
	if e.Outcome == "" {
		e.Outcome = "success"
	}
	if e.PolicyVersion == "" {
		e.PolicyVersion = DefaultPolicyVersion
	}
	if e.LogPath == "" {
		e.LogPath = DefaultLogPath()
	}

	// audit-log.py:109-114: 目录不存在则尽力创建, 失败静默忽略(留给 open 报错)。
	if dir := filepath.Dir(e.LogPath); dir != "" {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			_ = os.MkdirAll(dir, 0o755)
		}
	}

	f, err := os.OpenFile(e.LogPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("audit: 打开日志文件失败: %w", err)
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("audit: flock(LOCK_EX) 失败: %w", err)
	}
	// defer 为 LIFO: 本行注册晚于上面的 Close → 退出时先 LOCK_UN 再 Close,
	// 与 Python try/finally 中"写完后 LOCK_UN、随 with 块关闭文件"顺序一致。
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()

	prevHash := lastEntryHash(f)

	// 事务创世播种(todo 15): 条目带 TxID 却未显式携带 tx_prev_hash 时, 在**同一把
	// LOCK_EX 之下**复用 lastNonTxRecord 从刚回溯过的日志尾部取最近一条非 tx 记录的
	// entry_hash 作为播种值(回溯至 BOE 仍无 → 64 零 GenesisHash)。播种发生在哈希计算
	// **之前**, 使 tx 载荷扩展(payloadFor)与落盘键(tx_prev_hash)都吃到播种后的值,
	// 与 Verify 前向遍历维护的 lastNonTxHash 快照判据同源(确定、无竞态)。
	// 显式传入 TxPrevHash 的(apply/rollback 事务内步链)一律原样尊重, 绝不覆盖。
	// 门控条件是 `TxID != ""`, 故非 tx 条目根本不进入本分支 → 金样字节兼容零回归。
	if e.TxID != "" && e.TxPrevHash == "" {
		rec, found, err := lastNonTxRecord(f)
		if err != nil {
			return nil, err
		}
		if found {
			e.TxPrevHash = rec.EntryHash
		} else {
			e.TxPrevHash = GenesisHash
		}
	}

	timestamp := FormatTimestamp(time.Now())
	// 哈希派发(todo 12 钉桩): TxID 非空走记录形态(含 tx 载荷扩展),
	// 否则沿用 6 参常量路径 → 非 tx 条目哈希与旧实现逐字节相同。
	argsStr := e.Args.ArgsString()
	var entryHash string
	if e.TxID != "" {
		entryHash = ComputeEntryHashRecord(Record{
			Timestamp: timestamp, Identity: e.Identity, Tool: e.Tool,
			Args: e.Args, Outcome: e.Outcome, PrevHash: prevHash,
			TxID: e.TxID, TxStep: e.TxStep, TxPrevHash: e.TxPrevHash,
		})
	} else {
		entryHash = ComputeEntryHash(timestamp, e.Identity, e.Tool, argsStr, e.Outcome, prevHash)
	}

	rec := &Record{
		Timestamp:     timestamp,
		Identity:      e.Identity,
		Tool:          e.Tool,
		Args:          e.Args,
		PolicyVersion: e.PolicyVersion,
		Outcome:       e.Outcome,
		PrevHash:      prevHash,
		EntryHash:     entryHash,
		TxID:          e.TxID,
		TxStep:        e.TxStep,
		TxPrevHash:    e.TxPrevHash,
	}

	// a+ 模式下写恒追加; 与 Python f.seek(0, SEEK_END) 等效的防御性定位。
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return nil, fmt.Errorf("audit: 定位文件末尾失败: %w", err)
	}
	if _, err := f.WriteString(rec.Line() + "\n"); err != nil {
		return nil, fmt.Errorf("audit: 写入日志行失败: %w", err)
	}
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("audit: flush 失败: %w", err)
	}
	return rec, nil
}

// FormatTimestamp 复刻 datetime.datetime.now(datetime.timezone.utc).isoformat()。
//
// 输出 "YYYY-MM-DDTHH:MM:SS.ffffff+00:00"; **微秒为 0 时 Python 省略整个小数秒段**
// (audit-log.py:122 的隐性契约, 断链高发点, 单独成函数便于测试该怪癖)。
// 纳秒按 Python 习惯向零截断为微秒, 不做四舍五入。
func FormatTimestamp(t time.Time) string {
	t = t.UTC()
	base := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		base += fmt.Sprintf(".%06d", us)
	}
	return base + "+00:00"
}

// lastEntryHash 镜像 audit-log.py:40-82 的 get_last_entry_hash(f):
// 自文件末尾按 4096 字节块回溯, 收集"最后一个换行边界块"内的行,
// 倒序找第一条非空且可解析为对象、含 entry_hash 的行; 找不到返回 GenesisHash。
//
// 回溯算法逐行复刻(含"块首行被截断则解析失败跳过"的 Python 同源行为),
// 保证两侧对畸形/超大尾行的 prev_hash 判定完全一致。
func lastEntryHash(f *os.File) string {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil || size == 0 {
		return GenesisHash
	}

	offset := size
	var lines []string
	residual := ""

	for offset > 0 && len(lines) < 2 {
		readSize := int64(tailChunkSize)
		if readSize > offset {
			readSize = offset
		}
		offset -= readSize
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return GenesisHash
		}
		chunk := make([]byte, readSize)
		n, err := io.ReadFull(f, chunk)
		if err != nil && n == 0 {
			return GenesisHash
		}
		chunkCombined := string(chunk[:n]) + residual
		if split := pySplitLines(chunkCombined); len(split) > 1 {
			lines = split
			break
		}
		residual = chunkCombined
	}
	if len(lines) == 0 && residual != "" {
		lines = []string{residual}
	}

	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		v, err := ParseValue(line)
		if err != nil {
			continue
		}
		if !v.IsObject() {
			continue
		}
		// Python: return str(data["entry_hash"]) —— 仅字符串 kind 与哈希链实态一致,
		// 其余类型视为损坏并继续向更早行回溯。
		if eh, ok := v.LookupString("entry_hash"); ok {
			return eh
		}
	}
	return GenesisHash
}

// lastNonTxRecord 自文件末尾**无界**回溯最近一条完整解析且 TxID 为空(非 tx)的记录。
//
// 与 lastEntryHash 的关系与差异(todo 12 关键设计):
//   - lastEntryHash 收集到"最后一个换行边界块"(≤2 行窗口)即停, 尾部若挂任意长的
//     in-tx 段会直接返回该段的哈希或创世值 —— 无法回答"最后一条非 tx 条目是谁";
//   - 本函数持续按 tailChunkSize 块向 BOE 扩窗, 行边界规则与"块首行截断则本轮跳过、
//     下一轮补全后再扫"的容忍行为与 lastEntryHash 同源(pySplitLines), 但扫描无界:
//     已定界且扫过的行计数(done)避免重复解析; 解析失败/损坏/非对象/in-tx 行一律跳过。
//
// 返回 (记录, true, nil) 命中; (零值, false, nil) 表示回溯至 BOE 仍无非 tx 记录
// (含空文件), 由调用方(daedalus-tx begin)替换为 64 零创世哈希; I/O 失败返回 error。
//
// 副作用: 结束时会把 f 的读指针定位在命中行所在偏移之前; 调用方(LogAudit)本就
// 在写前显式 Seek(0, io.SeekEnd), 不依赖此状态。
func lastNonTxRecord(f *os.File) (Record, bool, error) {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return Record{}, false, fmt.Errorf("audit: 定位文件末尾失败: %w", err)
	}
	if size == 0 {
		return Record{}, false, nil
	}

	offset := size
	var buf []byte // 已读入的尾部文本 [offset, size)
	seen := 0      // buf 内末尾已扫描过的完整行数(扩块只增头部, 尾部分行稳定)

	for {
		readSize := int64(tailChunkSize)
		if readSize > offset {
			readSize = offset
		}
		next := offset - readSize
		if _, err := f.Seek(next, io.SeekStart); err != nil {
			return Record{}, false, fmt.Errorf("audit: 回溯定位失败: %w", err)
		}
		chunk := make([]byte, readSize)
		n, err := io.ReadFull(f, chunk)
		if n == 0 {
			if err == nil {
				err = io.ErrNoProgress
			}
			return Record{}, false, fmt.Errorf("audit: 回溯读取失败: %w", err)
		}
		buf = append(chunk[:n:n], buf...)
		lines := pySplitLines(string(buf))
		// 本轮新行 = 头部新增(含上一轮截断留待补全的 lines[0]); 末尾 seen 行跳过。
		// next > 0 时头部第一行仍可能被块界截断 → 本轮不扫, 留待补全(容忍规则与
		// lastEntryHash 的截断跳行同源, 但扩窗无界、可越过任意长 in-tx 尾段)。
		lower := 0
		if next > 0 {
			lower = 1
		}
		for i := len(lines) - seen - 1; i >= lower; i-- {
			line := strings.TrimSpace(lines[i])
			if line == "" {
				continue
			}
			v, perr := ParseValue(line)
			if perr != nil || !v.IsObject() {
				continue
			}
			rec, ok := recordFromValue(v)
			if !ok || rec.TxID != "" {
				continue // 损坏行容忍跳过 / in-tx 行: 继续向更早回溯
			}
			return rec, true, nil
		}
		seen = len(lines) - lower
		if next == 0 {
			break // 已扫至 BOE, 全程无非 tx 记录
		}
		offset = next
	}
	return Record{}, false, nil
}

// pySplitLines 近似 Python str.splitlines: 以 \n / \r\n / \r 断行且不产出尾部空行。
func pySplitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '\n' && s[i] != '\r' {
			continue
		}
		out = append(out, s[start:i])
		if s[i] == '\r' && i+1 < len(s) && s[i+1] == '\n' {
			i++
		}
		start = i + 1
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
