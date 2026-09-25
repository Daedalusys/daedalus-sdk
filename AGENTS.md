# daedalus-sdk — Knowledge Base

**Generated:** 2026-09-21
**Repo:** `github.com/Daedalusys/daedalus-sdk` (Go module, single root)
**Siblings:** `../daedalus-core/` (Daedalusys, runtime + image), `../daedalus-plugins/` (6 capability plugins)

## OVERVIEW
Daedalus SDK 仓根 = 四层结构中的 **SDK 层**(决策 23/24 + 25)。
11 个安全核心包(从 `daedalus-core/internal/` 迁出)+ 5 个 Provider/Slot 占位目录 +
2 个编排器裁决迁入包(`state/` `dirs/`)。**公开 contract 仓**:包是顶级包,可被外部模块 import;
失去 Go 编译器"同模块限可见"防护,威胁模型见下段。

## STRUCTURE
```
daedalus-sdk/                          # module github.com/Daedalusys/daedalus-sdk
├── audit/         # 哈希链审计库 (Python 金样字节级兼容)
├── policy/        # policy.toml 严格加载 (ErrNotFound 哨兵 / Default / ALLOW_COMMANDS REPLACE)
├── pathguard/     # fs 路径校验 (ALLOWED_DIRS 前缀边界 / 空字节 / realpath)
├── shellpolicy/   # 15 命令 / 4 bin 目录 / 路径规则权威实现
├── pkgquery/      # dnf/rpm 只读查询 (rpm 优先 / dnf repoquery 兜底)
├── sysinfo/       # os-release / cpuinfo / meminfo / 网络只读探测
├── plugin/        # manifest schema + Pack/Extract/Verify/VerifyDir (zip-slip 九道防线)
├── objectmodel/   # 对象模型 schema 单一事实源 (Kind 封闭枚举 7 类 + spec/status 信封)
├── i18n/          # locale 文件 + t(key, ...args) 翻译基础设施
├── blueprint/     # 蓝图 schema 校验 + 渲染 (jsonschema-go 预编译)
├── version/       # 版本常量与构建信息
├── state/         # state.jsonl 追加式观测缓存 (todo 6 迁入)
├── dirs/          # state/tx 根路径统一解析链 (todo 6 迁入)
├── secretprovider/  ← Provider/Slot 占位 (#33 KWallet + #34 systemd-creds)
├── memoryprovider/  ← Provider/Slot 占位 (#29 持久记忆)
├── modelprovider/   ← Provider/Slot 占位 (#31 prompt cache)
├── agentprovider/   ← Provider/Slot 占位 (未来 agent)
└── transportprovider/  ← Provider/Slot 占位 (MCP stdio/HTTP/A2A)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| 哈希链审计实现 / 金样向量 | `audit/` | Python 金样字节级兼容;`testdata/golden.jsonl` 重放 |
| 策略加载与默认值 | `policy/` | 三点防漂移链:policy.toml ↔ `policy.Default()` ↔ shellpolicy/pathguard 常量 |
| fs 路径白名单边界 | `pathguard/` | 防 `/home` 匹配 `/home2` (前缀边界 + realpath) |
| Shell 白名单与 argv 规则 | `shellpolicy/` | 15 命令 / 4 bin 目录;`RegisterBlueprintsPostCheckSource` 钩子 |
| 插件 manifest + zip 打包 | `plugin/` | schema 校验 + zip-slip 九道防线 + checksums 注入 |
| 对象模型类型 + Kind 注册 | `objectmodel/` | `Kind` 封闭枚举 + `kindRegistry`;新增 Kind 三步走 |
| 蓝图 schema + 渲染 | `blueprint/` | jsonschema-go 预编译 + confirm_token(15 分钟过期) |
| 观测态追加缓存 | `state/` | `state.jsonl` 行形 `StateEntry`;派生缓存,与审计链分离 |
| 根路径解析链 | `dirs/` | state/tx 根路径统一解析 (DynamicUser 命名空间隔离) |

## CODE MAP

| Symbol / Component | Location | Role |
|--------------------|----------|------|
| `audit.Hashtx` / `audit.Append` | `audit/hashtx.go` | sha256 链 + syscall.Flock (LOCK_UN before Close via defer LIFO) |
| `audit.Verify` / `audit.Scan` | `audit/verify.go` `audit/scan.go` | 哈希链验证 / 扫描 |
| `policy.Load` / `policy.Default` | `policy/load.go` | 严格加载 / 缺失 fallback (drift-tested 一致) |
| `shellpolicy.AllowCommands` | `shellpolicy/allow.go` | 15 命令权威实现;CLEAN_ENV + 30s + rc 126/124 |
| `pathguard.Validate` | `pathguard/validate.go` | ALLOWED_DIRS 前缀 + realpath 防逃逸 |
| `plugin.Manifest` / `plugin.Pack` | `plugin/manifest.go` `plugin/pack.go` | 规范化自摘要 + 逐条目 sha256 + zip-slip 防线 |
| `objectmodel.Resource` / `Kind` | `objectmodel/objectmodel.go` | 三字段元组 (kind/name/desired_state);Kind 封闭枚举 7 类 |
| `objectmodel.Object` / `Condition` | `objectmodel/envelope.go` | spec/status 信封;`Resource.Object()` 与 `ServiceState.Object()` 双投影,`UpsertCondition`/`MatchLabels` 读写侧 API;`internal/controller` 的同名类型是本包别名 |
| `blueprint.Registry` / `blueprint.ConfirmToken` | `blueprint/registry.go` `confirm_token.go` | 蓝图加载 + 一次性消费令牌 |
| `state.Append` / `state.StateEntry` | `state/state.go` | state.jsonl 追加;payload 序列化为 `objectmodel.ServiceState` |
| `dirs.State` / `dirs.Tx` | `dirs/dirs.go` | state/tx 根路径解析 |

## CONVENTIONS
- **注释语言(强制)**:本仓全部 `.go` 源文件、测试文件注释**必须中文**。标识符 / 字符串字面量 / API 协议字段(JSON 键 / HTTP 头 / 系统命令 / URL)保留英文。
- **金样向量**: `audit/testdata/golden.jsonl` 是哈希链字节级参考;新增序列化模式必须重放,微秒 == 0 的 isoformat 怪癖必须保留。
- **三点防漂移链**: `policy.toml ↔ policy.Default() ↔ shellpolicy/pathguard 常量` 任何一处修改必须同步更新另外两处,跑 `policy` 包的 drift 测试钉死。
- **Copilot 冻结副本**: `policy.ts`(在 Daedalusys `plugin/copilot/`)是 shellpolicy 的 TypeScript 冻结副本;改一侧必改另一侧,跨语言契约由 `tests/deno/shellpolicy_contract.test.ts`(在 Daedalusys 根)钉住。
- **跨仓 dev 桥**: `daedalus-sdk/go.work.example` (`use ( . )`) 是单仓 clone 的兜底;三仓平级 clone 时由 `../daedalus-core/go.work` 解析优先于各仓 `replace` 指令。
- **不产二进制 / 不产镜像**: 本仓只产 Go 包;无 `cmd/`、无 `bin/`、无 Dockerfile 链。打包/安装由 `daedalus-core` 的 `just plugin-pack` + 各插件仓完成。
- **禁止注释引用计划编号**: `todo N` / `决策 N` / `oracle review` / `round-N` 等进度信息写 commit message 或 `.omo/plans/`,不进源码注释。
- **注释只写 why,不写 what**: 代码可自解释处不加注释。
- **单文件注释密度软上限 ~15%**: 后续可接 CI 门禁。
- **跨仓/跨语言对齐注释不写精确行号**: `py:43-53` 这类行号会腐烂,只写行为语义。
- **文件头 ≤8 行**: 一句 what + 关键 invariant + 指回 README/AGENTS 的链接。

## Security surface / threat model

**威胁面增量(明确)**。`policy` / `shellpolicy` / `pathguard` / `audit` 等包从 `daedalus-core/internal/` 迁出后变为顶级包,公开可被 import。失去"同模块限可见"防护后:
- 可绕过 policy 加载流程直接构造 `policy.Default()`,或 import `shellpolicy`/`pathguard` 常量自行拼装"看起来合法"策略对象;
- 可 import `audit` 直接写审计文件,绕过 `daedalus-audit` CLI 哈希链入口;
- 可借 SDK 包探测策略形状,为后续攻击做准备。

**补偿控制(运行时侧,core 仓守)**。SDK 包本身不做运行时防护——防护在**消费方进程的 systemd 沙箱**上:`DynamicUser=yes` + `ProtectSystem=strict` / `ReadOnlyPaths=/opt/daedalus/shared/policy.toml` + `daedalus-*.service.d/landlock.conf` (seccomp 白名单 + `MemoryDenyWriteExecute=yes`)。审计写入一律经 `daedalus-audit` CLI,进程内**禁止**直接 import `audit` 写文件。

**trade-off 立场**: SDK 路线 = 公开 contract(否则 SDK 不可用)。issue #46 决定走 SDK 路线 = 接受此 trade-off。安全边界从"编译器强制"转移到"运行时沙箱强制",由下游使用方承担。

## ANTI-PATTERNS (THIS REPO)
- **NEVER** 直接 import `audit` 写文件 — 必经 `daedalus-audit` CLI (`--identity/--tool/--args/--outcome/--log-path`)。
- **NEVER** 修改 `shellpolicy` / `pathguard` / `policy` 常量而不联动 `policy.Default()` 与 policy.toml(三点防漂移测试会拒)。
- **NEVER** 让 SDK 包绕过 policy 加载流程 — 必须经 `policy.Load` / `policy.LoadOrDefault`。
- **NEVER** 让 SDK 包暴露 `internal/` 防护(已迁出的包就是公开面,不要再加 `internal/` 子目录)。
- **NEVER** 在 Provider/Slot 占位目录(`secretprovider/` 等 5 个)写 Go 代码 — 等 #42 落地时填实 contract;空目录 + README 是当前合法形态。
- **NEVER** 在 SDK 包内做运行时防护(防越界 / 防绕过)— 那是 core 仓 systemd drop-in 的职责;SDK 只定义规则,不强制规则。

## COMMANDS
```bash
# 全包测试 (含金样向量重放 + 三点漂移链)
cd daedalus-sdk && go test ./...

# 单包测试
go test ./audit/      # 金样向量
go test ./policy/     # 三点漂移
go test ./shellpolicy/
go test ./objectmodel/  # Kind 封闭枚举

# 单仓 clone (无兄弟仓): 启用 go.work
cp go.work.example go.work

# 三仓平级 clone (推荐): core 仓根 go.work 已桥,无需本仓 go.work
# 仓名必须为 daedalus-core / daedalus-sdk / daedalus-plugins (与 go.work 路径对应)

# Lint (与 core 仓共用同一份 .editorconfig / gofmt / golangci-lint)
gofmt -l . && go vet ./...

# 审计链重放
go test -run TestGolden ./audit/...
```

## NOTES
- 本仓与 `daedalus-core` (Daedalusys)、`daedalus-plugins` 经 `go.work` 平级桥接;**单仓发布,跨仓协作**。
- 新增 SDK 包 = 在根加新目录 + 同步更新 README「包索引」表;新增 Kind 必经 `objectmodel/Kind` 常量 + `kindRegistry` + 校验分支 + `policy.toml [objectmodel].enabled_kinds` 三处漂移测试。
- 5 个 Provider/Slot 占位(secretprovider/memoryprovider/modelprovider/agentprovider/transportprovider)等待 issue #42 落地时填实 contract;**目前请勿在这些目录写 Go 代码**。
- 测试布局: `*_test.go` 随包;`testdata/` 内是金样向量 / 配置文件。
- SDK 公开面**不豁免** `daedalus-core/AGENTS.md` 的 ANTI-PATTERNS 条款(中文注释 / 零 image 残留 / 审计链经 CLI 等)。
- 老仓 `Daedalusys/Daedalusys` 已于 2026-09-21 archived,历史 issue 保留可读;新 issue 一律开在本仓。