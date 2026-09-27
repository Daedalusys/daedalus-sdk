# Architecture

## Overview

daedalus-sdk 是 Daedalus 的公开 contract 仓,对应四层结构中的 SDK 层。
仓内 16 个顶级 Go 包承载对象模型、安全策略、哈希链审计、JSONL 状态缓存与
Provider/Slot 契约,是 `daedalus-core` 与 `daedalus-plugins` 共享的类型与规则层。
本仓没有 `main.go`,不产二进制、不产镜像,只产 Go 包:消费方经 `go.mod` 的
`replace` 指令引用,三仓平级 clone 时由 `../daedalus-core/go.work` 解析优先。
这些包原先位于 core 的 `internal/`,迁出后成为公开面,任何模块都能 import,
Go 编译器的"同模块限可见"防护随之失效。安全边界因此从编译期转移到消费方进程
的 systemd 沙箱,详见下方「Security Surface」段。

## Package Index

| Package | Purpose | Consumers |
|---------|---------|-----------|
| `objectmodel` | Resource model types (Kind, Resource, Object, Condition),对象模型 schema 单一事实源 | core, plugins |
| `policy` | Policy engine (policy.toml loading, validation),严格加载与 fail-closed 默认值 | core |
| `audit` | SHA-256 hash chain audit logging,与 Python 参考实现字节级兼容 | core |
| `state` | JSONL state cache (append-only, latest-value),观测态派生缓存 | core |
| `plugin` | Plugin manifest parsing and validation,Pack/Extract/Verify 与 zip-slip 防线 | core, plugins |
| `pathguard` | Filesystem path sandboxing (symlink resolution, deny-list),前缀边界 + realpath | plugins (fs, shell, blueprint) |
| `shellpolicy` | Shell command policy (allow/deny patterns),15 命令 / 4 bin 目录权威实现 | plugins (shell) |
| `pkgquery` | Package manager abstraction (DNF),rpm 优先、dnf repoquery 兜底 | plugins (pkg) |
| `sysinfo` | System information collection,os-release / cpuinfo / meminfo / 网络只读探测 | plugins (sysinfo) |
| `dirs` | XDG directory resolution,state/tx 根路径统一解析链 | plugins |
| `blueprint` | Blueprint type definitions,schema 校验 + 渲染 + confirm_token | plugins (blueprint) |
| `i18n` | Internationalization (P1 - not yet implemented),locale 文件与 `t(key, ...args)` | core, plugins |
| `version` | Semantic versioning,版本常量与构建信息 | core |
| `slot` | Provider/Slot vocabulary (Swappability levels),共享 Level 枚举 | core |
| `secretprovider` | SecretProvider contract (`secret://` references),引用不持明文 | core |
| `memoryprovider` | MemoryProvider contract (cross-session memory),scope 封闭枚举 + TTL | core |

另有 3 个 Provider/Slot 占位目录(`modelprovider/`、`agentprovider/`、
`transportprovider/`),形态是空目录 + README,尚无 Go 代码,见下文
「Contract Status」。

## Package Dependency

仓内依赖极少且全部单向,装配与接线由消费方完成,SDK 不提供运行时组合逻辑:

| Package | SDK 内部依赖 | 依赖原因 |
|---------|--------------|----------|
| `state` | `dirs` | 落盘路径委托 `dirs.StateFile()` 解析 |
| `shellpolicy` | `policy` | 消费 policy 结构体,常量参与三点漂移链 |
| `plugin` | `objectmodel` | manifest 校验引用 `Kind` 与 spec/status 信封 |
| `secretprovider` | `slot` | 用 `slot.Level` 声明自身 Swappability |
| `memoryprovider` | `slot` | 同上 |

其余包(`audit`、`policy`、`pathguard`、`objectmodel`、`dirs`、`slot`、
`blueprint`、`sysinfo`、`pkgquery`、`version`、`i18n`)在仓内互不依赖,
只依赖标准库与第三方库。分层方向可概括为:

```
objectmodel  ──>  plugin            dirs  ──>  state
policy       ──>  shellpolicy       slot  ──>  secretprovider / memoryprovider
```

箭头表示"被依赖方在左"。新增依赖必须保持单向,规则层(`policy` /
`objectmodel` / `slot`)不得反过来 import 使用它们的包。

## Security Surface

SDK 只定义规则,不强制规则。运行时强制归消费方进程的 systemd drop-in
(`DynamicUser=yes` / `ProtectSystem=strict` / landlock + seccomp)。

### Object Model

- `Kind`: closed enum(封闭枚举)七类:`service`、`package`、`container`、
  `capability`、`task`、`transaction`、`policy`;`kindRegistry` 是唯一注册表,
  新增 Kind 必须同步 `policy.toml` 的 `[objectmodel].enabled_kinds`。
- `Resource`: 三字段元组 `{kind, name, desired_state}`。`kind` 必须命中枚举,
  `name` 拒绝空字节、`/` 与 `..`。
- `Object`: spec/status 信封 `{api_version, kind, metadata, spec, status}`;
  `Resource.Object()` 与 `ServiceState.Object()` 提供双投影。
- `Condition`: three-state(`True` / `False` / `Unknown`)带时间戳,经
  `UpsertCondition` 写入 status,`MatchLabels` 做读侧匹配。
- `ServiceState`: 服务观测态容器(`kind`/`name`/`properties`/`conditions`),
  `Properties` 键保留 systemctl 属性名原文,与 `state.jsonl` 共用 payload 形状;
  core 侧 `internal/controller` 的同名类型是本包别名。
- 新增 Kind 是三处联动:`objectmodel` 常量 + `kindRegistry` + 校验分支,
  外加 `policy.toml` 的 `enabled_kinds`,漂移测试钉死三侧一致。

### Policy System

- `policy.toml`: fail-closed。文件缺失或损坏一律拒绝启动;回退到
  `policy.Default()` 需要 `DAEDALUS_POLICY_MODE=development` 显式开启。
- 加载入口只有 `policy.Load`(严格)与 `policy.LoadOrDefault`(显式回退),
  解析后经 `validate()` 逐节检查,每个策略节的空列表都判为损坏。
- `enabled_kinds`: 当前白名单是 `service` 与 `package`,空列表视为损坏策略。
- `secret_sources`: `["kwallet", "credstore"]`,secret 引用解析的准入白名单。
- Three-way drift tests: `policy.toml` ↔ `policy.Default()` ↔
  `shellpolicy`/`pathguard` 常量三点互相钉死,任何一侧改动不同步,
  `policy` 包的漂移测试即失败。

### Audit System

- SHA-256 hash chain,genesis 为 64 个 `0`;序列化与 Python 参考实现字节级一致,
  `testdata/golden.jsonl` 金样重放守住格式漂移。
- 每条记录的哈希覆盖前一条,任一行被改写、删除或重排都会让 `Verify` 失败;
  `Scan` 提供只解析不校验的遍历能力。
- Begin / apply / rollback 各自创建 audit entry,携带 `TxID` + `TxStep`
  串成事务内链;交易记录与普通记录共用同一 `Record` 编码。
- Go 侧唯一合规写入口是 `audit.LogAudit`;非 Go 写入方经 core 仓
  `daedalus-audit` CLI 桥接,SDK 之外禁止另立第二套写入实现。
- `syscall.Flock` 文件锁保护并发追加,`LOCK_UN` 在 `Close` 之前经 defer LIFO 释放。

## Provider/Slot Model

核心约束一句话:*Core only knows stable interfaces, not implementations.*
接线发生在消费方 cmd/daemon 构造期,SDK 只有接口、形状门、值类型与哨兵错误,
没有注册表、分发器或 provider 实现(契约缝 · 零运行时)。

### Swappability Levels

| Level | 语义 | 典型例 |
|-------|------|--------|
| `L0` | build-time selectable,构建期选择,镜像即完整清单 | 当前全部 Go 能力服务器 |
| `L1` | restart-time replaceable,重启即可换实现 | KWallet → Vault |
| `L2` | runtime load/unload,运行时装卸 | UI / MCP / Skill 插件 |
| `L3` | state-preserving hot swap,状态迁移后热切换 | MemoryProvider 远期 |

每个 provider 在 contract 里自己声明可达级别(`Swappability()`),平台承诺
永不超越该声明,默认不承诺任何热切换。注意 `slot.Level` 与工具风险分级
(L0/L1/L2 风险档)是两套正交词汇,含义不得互引。

### Contract Status

- SecretProvider: contract pinned (`Scheme`, `Collections`, `List`, `Get`, `Set`, `Delete`)
- MemoryProvider: contract pinned (`Get`, `Set`, `Delete`, `List`, `Search`)
- ModelProvider: problem domain only (not yet pinned),提示词缓存与模型适配
- AgentProvider: problem domain only (not yet pinned),上层智能体接入形态
- TransportProvider: problem domain only (not yet pinned),MCP stdio/HTTP/A2A 通道

已钉的两个 contract 语义事实源是 `docs/provider-slot.md`;后三个仍是占位目录,
等各自 issue 落地再填实。

### Security Guarantees

- `Secret` 类型的 `String` / `GoString` 恒脱敏,`MarshalJSON` 直接报错:
  明文在类型层就进不了审计行、日志行与任何 JSON 序列化路径。
- `Get` 返回的 `Secret` 用毕必须 `Zeroize()`;错误字符串不得内嵌值内容,
  实现包装底层错误时用 `%w` 保留哨兵。
- audit entry 只允许含 `secret://` 引用,永远不含值。
- 跨 slot 铁律:记忆值里不得存 secret 明文,只允许 `secret://` 引用,
  读侧渲染时才经 SecretProvider 解析。
- `secret_sources` 两席分工:kwallet 归用户态后端,credstore 归服务态
  (systemd LoadCredential 管线),两条路径共用同一 `Ref` 词汇表,不互相复制实现。
- 特权 provider 的实现永远走 System Extension(image-built、签名、有特权),
  User Extension 不得申请特权 slot 接线;双层 extension 模型见 `docs/provider-slot.md`。

## State Cache

- Append-only JSONL format: `state.jsonl` 每行一个
  `StateEntry{kind, name, observed_at, payload}`,时间戳恒 UTC RFC3339Nano。
- Latest-value semantics: 同 `(kind, name)` 的新记录覆盖旧记录,读取端取最新值。
- Per-context isolation: 各上下文独立落位,路径由 `dirs.StateFile()` 解析
  (`DAEDALUS_STATE_PATH` 覆盖 → `/var/lib/daedalus/state.jsonl` →
  `$HOME/.local/share/daedalus/state.jsonl`,解析失败即报错,绝不静默回落)。
- NOT a memory store: 它是派生观测缓存,与审计链分离;跨会话记忆归
  `memoryprovider`,两者语义正交,互不替代。

## Directory Structure

- `objectmodel/` - Resource model types
- `policy/` - Policy engine
- `audit/` - Hash chain audit
- `state/` - JSONL state cache
- `plugin/` - Plugin manifest
- `pathguard/` - Path sandboxing
- `shellpolicy/` - Shell policy
- `pkgquery/` - Package abstraction
- `sysinfo/` - System info
- `dirs/` - XDG dirs
- `blueprint/` - Blueprint types
- `slot/` - Provider vocabulary
- `secretprovider/` - Secret contract
- `memoryprovider/` - Memory contract
- `docs/` - Design documents

## Reference

- See `docs/provider-slot.md` for Provider/Slot contract details
- See `../daedalus-core/VISION.md` for system-wide architecture
- See `../daedalus-core/AGENTS.md` for operational details
