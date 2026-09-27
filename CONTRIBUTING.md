# Contributing to daedalus-sdk

本文档是**SDK 仓特有的贡献指南**。通用贡献规范（代码风格、注释语言、测试要求、commit convention、PR 流程）见 [`../daedalus-core/CONTRIBUTING.md`](../daedalus-core/CONTRIBUTING.md)。

## 本仓特有约束

### 公开 Contract 仓

SDK 是**公开 contract 仓**：包是顶级包，可被外部模块 import。失去 Go 编译器"同模块限可见"防护后，安全边界从"编译器强制"转移到"运行时沙箱强制"（由下游消费方的 systemd 沙箱守住）。

**不要**在 SDK 包内做运行时防护——那是 core 仓 systemd drop-in 的职责。SDK 只定义规则，不强制规则。

### Package Layout

```
daedalus-sdk/
├── audit/              # 哈希链审计库
├── policy/             # policy.toml 严格加载
├── pathguard/          # fs 路径校验
├── shellpolicy/        # 15 命令 / 4 bin 目录 / 路径规则
├── pkgquery/           # dnf/rpm 只读查询
├── sysinfo/            # os-release / cpuinfo / meminfo / 网络探测
├── plugin/             # manifest schema + Pack/Extract/Verify
├── objectmodel/        # 对象模型 schema 单一事实源
├── i18n/               # 翻译基础设施
├── blueprint/          # 蓝图 schema 校验 + 渲染
├── version/            # 版本常量
├── state/              # state.jsonl 追加式观测缓存
├── dirs/               # 根路径统一解析链
├── slot/               # Provider/Slot 共享词汇（swappability Level）
├── secretprovider/     # SecretProvider contract
├── memoryprovider/     # MemoryProvider contract
├── modelprovider/      # 占位（不写 Go 代码）
├── agentprovider/      # 占位（不写 Go 代码）
├── transportprovider/  # 占位（不写 Go 代码）
└── docs/               # 设计文档
```

### 新增 Package

1. 在根加新目录
2. 同步更新 README「包索引」表
3. 新增 Kind 必经 `objectmodel/Kind` 常量 + `kindRegistry` + 校验分支 + `policy.toml [objectmodel].enabled_kinds` 三处漂移测试

### 新增 Kind（三步走）

1. `objectmodel/`: 添加 `Kind` 常量 + `kindRegistry` 登记 + 校验分支
2. `policy.toml`: `[objectmodel].enabled_kinds` 放行
3. 漂移测试：三点防漂移链（`policy.toml ↔ policy.Default() ↔ shellpolicy/pathguard 常量`）钉死

## 三点防漂移链（重要）

`policy.toml` ↔ `policy.Default()` ↔ `shellpolicy` / `pathguard` 常量

任何一处修改**必须同步更新**另外两处，跑 `policy` 包的 drift 测试钉死。漂移测试失败 = 拒构建。

```bash
go test ./policy/...   # 三点漂移检查
```

## 金样向量

`audit/testdata/golden.jsonl` 是哈希链字节级参考。新增序列化模式必须重放，微秒 == 0 的 isoformat 怪癖必须保留。

```bash
go test -run TestGolden ./audit/...
```

## Provider/Slot 契约

`slot/` `secretprovider/` `memoryprovider/` 是**契约缝·零运行时**：只有接口、形状门、值类型与哨兵错误，零实现零注册表。

- **不要**在 `secretprovider/` / `memoryprovider/` 写 provider 实现、注册表或装配逻辑
- **不要**在 `modelprovider/` / `agentprovider/` / `transportprovider/` 写 Go 代码（占位目录，等各自 issue 落地）
- 实现与接线归消费方 `cmd/daemon` 构造期

## 反模式（本仓）

| 禁止行为 | 原因 |
|----------|------|
| 手搓哈希链格式或绕过本包直写审计文件 | Go 侧唯一合规写入口是 `audit.LogAudit` |
| 修改 shellpolicy / pathguard / policy 常量不联动 `policy.Default()` | 三点防漂移测试会拒 |
| 让 SDK 包绕过 policy 加载流程 | 必须经 `policy.Load` / `policy.LoadOrDefault` |
| 在 Provider/Slot 占位目录写 Go 代码 | 空目录 + README 是合法形态 |
| 在 SDK 包内做运行时防护 | 那是 core 仓 systemd drop-in 的职责 |
| 暴露 `internal/` 防护 | 已迁出的包就是公开面 |

## Architecture References

- [`../daedalus-core/ARCHITECTURE.md`](../daedalus-core/ARCHITECTURE.md) — 系统架构总览
- [`../daedalus-core/VISION.md`](../daedalus-core/VISION.md) — 系统愿景与设计
- [`../daedalus-core/AGENTS.md`](../daedalus-core/AGENTS.md) — AI 操作知识库
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — SDK 架构说明
- [`docs/provider-slot.md`](docs/provider-slot.md) — Provider/Slot contract 详情
