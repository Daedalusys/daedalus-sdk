// Package slot 是 Provider/Slot 架构(daedalus-sdk#2)的共享词汇:
// 只定义可拔插分级枚举,不含注册表/分发器/装配逻辑——Core 持有接口,
// provider 接线发生在消费方 cmd/daemon 的构造期(镜像即完整清单)。
//
// 语义单一事实源见 docs/provider-slot.md;本包与工具风险分级
// (L0/L1/L2 风险档)是两套正交词汇,token 形状虽同为 Ln,含义不得互引。
package slot

// Level 是 provider 自行声明的 swappability 上限,采用 issue #42 原生
// Ln token,逐字节冻结。
type Level string

// 分级全集(语义详见 docs/provider-slot.md §1):
//   - L0: build-time selectable,构建期选择,镜像即完整清单;
//   - L1: restart-time replaceable,重启替换实现(如 KWallet → Vault);
//   - L2: runtime load/unload,运行时装卸(如 UI / MCP / Skill 插件);
//   - L3: state-preserving hot swap,状态迁移后热切换(MemoryProvider 远期)。
const (
	LevelBuild   Level = "L0"
	LevelRestart Level = "L1"
	LevelRuntime Level = "L2"
	LevelHotSwap Level = "L3"
)

// Valid 判定 token 是否在分级全集内(provider 声明的接入门)。
func (l Level) Valid() bool {
	switch l {
	case LevelBuild, LevelRestart, LevelRuntime, LevelHotSwap:
		return true
	default:
		return false
	}
}
