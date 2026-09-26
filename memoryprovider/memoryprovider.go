// Package memoryprovider 钉 MemoryProvider slot 的第一批 contract
// (daedalus-sdk#2,消费者议题 #29 持久记忆)。
//
// 职责边界(契约缝·零运行时,同 secretprovider 姿势):
//   - 只有接口、条目形状、scope 枚举与哨兵错误,没有任何实现/注册表;
//     provider 接线归消费方 cmd/daemon 构造期。
//   - 语义单一事实源见仓内 docs/provider-slot.md §3。
//
// 与 state.jsonl 的分工:state 是**观测缓存**(系统真实发生的事,追加式),
// memory 是**声明性知识**(偏好/事实/决策,可改可删),二者语义正交,
// 本包不迁 state 消费者。
//
// 跨 slot 铁律:记忆值里不得存 secret 明文,只允许 `secret://` 引用
// (#29);写侧替换/读侧解析归装配层,本包以 json.RawMessage 承载值,
// 不承诺也无法在类型层强制——文档化 + 评审门。
package memoryprovider

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Daedalusys/daedalus-sdk/slot"
)

// 哨兵错误:实现包装底层细节必须用 %w 保留哨兵,消费者以 errors.Is 判别。
var (
	// ErrKeyNotFound 表示键不存在或已过期(过期即当作不存在,不做墓碑)。
	ErrKeyNotFound = errors.New("memoryprovider: 记忆键不存在")
	// ErrScopeDenied 表示调用方对该 scope 无治理许可
	// (policy `[memory]` 段的裁决由消费侧翻译成此哨兵)。
	ErrScopeDenied = errors.New("memoryprovider: scope 越权")
	// ErrSearchUnavailable 表示语义检索未启用——这不是空结果,
	// 消费者必须把它与"搜到了但没命中"区分开。
	ErrSearchUnavailable = errors.New("memoryprovider: 检索后端不可用")
)

// Scope 是记忆的治理域,封闭枚举(#29 scope=user|system)。
type Scope string

const (
	ScopeUser   Scope = "user"
	ScopeSystem Scope = "system"
)

// Valid 判定 scope 是否在全集内。
func (s Scope) Valid() bool {
	switch s {
	case ScopeUser, ScopeSystem:
		return true
	default:
		return false
	}
}

// Entry 是一条记忆。Value 用 json.RawMessage 承载结构化值(避免自由
// 文本夹带);TTL=0 表示永久,过期条目读到即 ErrKeyNotFound,清理由
// provider 执行。
type Entry struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
	Scope Scope           `json:"scope"`
	TTL   time.Duration   `json:"ttl_ns,omitempty"`
}

// Provider 是 MemoryProvider slot 的稳定 contract,方法与 #29 工具面
// 对应(get/set/delete/list/search)。实现者义务:
//   - Key 非空且不含空白(扁平命名空间,形状由 provider 统一收口);
//   - Search 未启用必须回 ErrSearchUnavailable,禁止静默返回空集;
//   - 值中不得内嵌 secret 明文(跨 slot 铁律,见包注释)。
type Provider interface {
	// Swappability 声明替换上限;builtin 文件后端钉 L1,L3 单独裁决。
	Swappability() slot.Level
	// Get 按 scope+key 取一条(#29 memory_get)。
	Get(ctx context.Context, scope Scope, key string) (Entry, error)
	// Set 写入一条(#29 memory_set;confirm_token 归工具面,不在此层)。
	Set(ctx context.Context, e Entry) error
	// Delete 删除一条(#29 memory_delete)。
	Delete(ctx context.Context, scope Scope, key string) error
	// List 按 scope + 前缀列键(#29 memory_list;只回键,不回值)。
	List(ctx context.Context, scope Scope, prefix string) ([]string, error)
	// Search 语义检索(#29 memory_search;嵌入未启用 → ErrSearchUnavailable)。
	Search(ctx context.Context, query string, limit int) ([]Entry, error)
}
