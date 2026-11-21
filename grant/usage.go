// 条子用量日志:append-only 记账,消费侧按条子 id 折叠计数。
//
// 服务对条子目录只读,单次性只能靠这里的记账;所以写入必须排他
// (O_APPEND → flock(LOCK_EX) → 整行一次写 → Sync),否则并发下会丢计或交错;
// 读侧同样加共享锁,避免读到半行。
package grant

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Daedalusys/daedalus-sdk/dirs"
)

// UsageFilePrefix / UsageFileSuffix 是用量日志的文件名形态(位于 dirs.TxRoot() 之下)。
// 账本**按执行者分文件**:全节点一份时,第一个创建者拥有那个文件,第二个用户
// 打不开它 ⇒ 记账失败 ⇒ fail-closed ⇒ 他的第二档永远不可用。分文件后谁也动不了
// 别人的账,顺带把「借别人的条子」也堵上(记账要写进条子属主的账本)。
const (
	UsageFilePrefix = "usage-"
	UsageFileSuffix = ".jsonl"
)

// UsageRecord 是一次用量记账:哪张条子、什么时候用的。
// 本结构即日志行格式:字段改名 = 破坏下游读取方,新增字段才能向后兼容。
type UsageRecord struct {
	GrantID string    `json:"grant_id"`
	UsedAt  time.Time `json:"used_at"`
}

// UsageFileNameFor 拼出某个执行者的用量账本文件名。
// 单独暴露是为了让调用方(消费侧、CLI、测试)不必各拼一份字符串:拼法漂移会让
// 「写进 A 的账本、读 B 的账本」这类错误静默发生。
func UsageFileNameFor(uid uint32) string {
	return fmt.Sprintf("%s%d%s", UsageFilePrefix, uid, UsageFileSuffix)
}

// UsageLogPathFor 解析某个执行者的用量日志路径:tx 根目录 + usage-<uid>.jsonl。
// uid 是执行者的 uid(不是签发者的):账本归记账的人所有。
func UsageLogPathFor(uid uint32) (string, error) {
	root, err := dirs.TxRoot()
	if err != nil {
		return "", fmt.Errorf("grant: 解析用量日志根目录失败: %w", err)
	}
	return filepath.Join(root, UsageFileNameFor(uid)), nil
}

// RecordUse 追加一条用量记账:整行一次写入 + flock 排他,保证并发下不交错、不丢计。
// 记账失败必须让调用方 fail-closed 拒绝执行(先做后记等于条子可以无限用)。
func RecordUse(path, grantID string, now time.Time) error {
	if path == "" {
		return fmt.Errorf("grant: 用量日志路径为空")
	}
	if grantID == "" {
		return fmt.Errorf("grant: 用量记账的条子 id 为空")
	}
	line, err := json.Marshal(UsageRecord{GrantID: grantID, UsedAt: now.UTC()})
	if err != nil {
		return fmt.Errorf("grant: 序列化用量记账失败: %w", err)
	}
	line = append(line, '\n')

	// 父目录由 dirs.TxRoot() 解析时创建;这里只管写,不再重复一份建目录逻辑,
	// 免得两个包各持一套权限口径。
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("grant: 打开用量日志失败: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("grant: flock(LOCK_EX) 失败: %w", err)
	}
	// defer 后注册先执行:先解锁再关文件。
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()

	// O_APPEND 下写恒追加,内核保证偏移原子;整行一次 Write,不必防御性 Seek。
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("grant: 写入用量记账失败: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("grant: flush 用量记账失败: %w", err)
	}
	return nil
}

// UsedCounts 折叠计数:按条子 id 统计已用次数。文件不存在 ⇒ 空表;
// 坏行 ⇒ 报错(fail-closed:静默跳过坏行等于少计次数,等于悄悄放宽用量上限)。
func UsedCounts(path string) (map[string]int, error) {
	counts := make(map[string]int)
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return counts, nil
	}
	if err != nil {
		return nil, fmt.Errorf("grant: 打开用量日志失败: %w", err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		return nil, fmt.Errorf("grant: flock(LOCK_SH) 失败: %w", err)
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var rec UsageRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("grant: 用量日志存在损坏行: %w", err)
		}
		if rec.GrantID == "" {
			return nil, fmt.Errorf("grant: 用量日志存在无条子 id 的行")
		}
		counts[rec.GrantID]++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("grant: 读用量日志失败: %w", err)
	}
	return counts, nil
}
