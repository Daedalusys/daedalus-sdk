# daedalus-sdk — Daedalus SDK 仓根

四层结构(决策 23/24 + 25)中的 **SDK 层**:11 个安全核心包 + 5 个 Provider/Slot 占位目录,
独立 Go 模块(`module github.com/Daedalusys/daedalus-sdk`),独立仓根。
SDK 包由 `daedalus-core/` 与 `daedalus-plugins/` 经 `replace` 指令本地引用
(见各仓 `go.mod`;3 仓平级 clone 后 `go.work` 优先)。

> 本仓是**公开 contract 仓**:包从 core 的 `internal/` 迁出后失去 Go 编译器
> "同模块限可见"防护,任何模块都可 import。威胁模型见下方
> 「Security surface / threat model」段——这是有意的 trade-off,不是疏漏。

## 包索引(11 个安全核心包)

| 包 | 职责 | 消费方 |
|----|------|--------|
| `audit/` | 哈希链审计库(genesis `0`*64、syscall.Flock、sha256 链、Python 金样字节级兼容) | `daedalus-core/cmd/daedalus-audit`、copilot `audit.ts`、宿主 |
| `policy/` | policy.toml 严格加载(ErrNotFound 哨兵 / LoadOrDefault / ALLOW_COMMANDS REPLACE) | 全部能力服务器、`76-daedalus-plugin-gen.sh` 构建期握手 |
| `pathguard/` | fs 路径校验(ALLOWED_DIRS 前缀边界、空字节、realpath) | `daedalus-plugins/fs` |
| `shellpolicy/` | 15 命令 / 4 bin 目录 / 路径规则权威实现(CLEAN_ENV、30s、rc 126/124) | `daedalus-plugins/shell`、copilot `policy.ts` 冻结副本(双向同步义务) |
| `pkgquery/` | dnf/rpm 只读查询(rpm 优先、dnf repoquery 兜底) | `daedalus-plugins/pkg` |
| `sysinfo/` | os-release / cpuinfo / meminfo / 网络只读探测 | `daedalus-plugins/sysinfo` |
| `plugin/` | manifest schema 校验 + Pack/Extract/Verify/VerifyDir(zip-slip 九道防线) | `daedalus-core/cmd/daedalus-{host,plugin-pack}` |
| `objectmodel/` | 对象模型 schema 单一事实源(Kind 封闭枚举 7 类 + Resource/ServiceState) | `daedalus-core/internal/controller`、`daedalus-plugins/{service,pkg}` manifest |
| `i18n/` | locale 文件与 `t(key, ...args)` 翻译基础设施 | copilot、Go 侧 MCP server(P1 接入) |
| `blueprint/` | 蓝图 schema 校验 + 渲染(jsonschema-go 预编译) | `daedalus-plugins/blueprint` |
| `version/` | 版本常量与构建信息 | 各二进制 |

**附加包(todo 6 编排器裁决迁入)**:`state/`(state.jsonl 追加式观测缓存)与
`dirs/`(state/tx 根路径统一解析链)因 Go internal 跨模块规则随 service 插件迁入本仓,
不在上述 11 包清单内,但同属 SDK 公开面。

## Provider/Slot 占位(5 个空目录)

以下目录是 #42 Provider/Slot 抽象的**占位**(issue #46 C3 拍板):空目录 + README,
仅声明 slot 名,不带 Go 代码、不暴露 import。等 #42 落地时填实 contract 与实现。

| 占位目录 | 指向的抽象 |
|----------|-----------|
| `secretprovider/` | #33 KWallet + #34 systemd-creds 抽象 |
| `memoryprovider/` | #29 持久记忆/知识图谱抽象 |
| `modelprovider/` | #31 提示词缓存 / 模型 provider 抽象 |
| `agentprovider/` | 未来 agent provider 抽象 |
| `transportprovider/` | MCP stdio/HTTP/A2A 抽象 |

## Security surface / threat model

> 本段由 review Oracle Issue 8 硬性要求写入:SDK 公开面增量必须文档化。

**威胁面增量**。`policy`、`shellpolicy`、`pathguard`、`audit` 等包从
`daedalus-core/internal/` 迁出后变为本仓**顶级包,公开可被 import**。
失去 Go 编译器的"同模块限可见"防护后,攻击者(或恶意第三方模块)可以:

- 绕过 policy 加载流程,直接构造 `policy.Default()` 实例,或 import `shellpolicy`/
  `pathguard` 常量自行拼装"看起来合法"的策略对象;
- import `audit` 包直接写审计文件,绕过 `daedalus-audit` CLI 的哈希链入口;
- 以 SDK 包为跳板探测策略形状,为后续攻击做准备。

**补偿控制(运行时侧,由 core 仓守住,不是 SDK 代码内补偿)**。SDK 包本身
不做运行时防护——防护在**消费方进程的 systemd 沙箱**上:

- `systemd DynamicUser=yes`:隔离进程命名空间,SDK 包运行在无特权动态用户下;
- `ProtectSystem=strict`(等价 `ReadOnlyPaths=/opt/daedalus/shared/policy.toml`):
  策略文件对运行时只读,进程无法改写自身策略;
- Landlock/seccomp drop-in(`daedalus-*.service.d/landlock.conf`):
  `SystemCallFilter=@system-service ~@privileged ~@resources ~@obsolete` +
  `MemoryDenyWriteExecute=yes` 等,限制 syscall 面。

**trade-off 立场(明确)**。SDK 路线 = **公开 contract,否则 SDK 不可用**:
SDK 存在的意义就是让插件作者与外部消费者扩展策略、复用安全原语,
这要求包可被公开 import;若保留 `internal/` 保护,SDK 就退化为 core 的内部库,
抽仓失去意义。本计划承认该威胁面增量而**无代码内 mitigation**——
issue #46 决定走 SDK 路线 = 接受此 trade-off。安全边界从"编译器强制"
转移到"运行时沙箱强制",由下游使用方承担。

**下游使用方清单(必须经 systemd drop-in 守住运行时)**。任何 import SDK 包的
进程,部署时必须满足:

1. `DynamicUser=yes`(或等价用户隔离);
2. `ProtectSystem=strict` / `ReadOnlyPaths=/opt/daedalus/shared/policy.toml`
   (策略文件只读);
3. `daedalus-*.service.d/landlock.conf` 全套(seccomp 白名单 +
   `MemoryDenyWriteExecute=yes` + 网络/地址族限制);
4. 审计写入一律经 `daedalus-audit` CLI,进程内**禁止**直接 import `audit` 写文件
   (AGENTS.md「ANTI-PATTERNS」条款,SDK 公开面不豁免)。

当前镜像内全部能力服务器(`daedalus-{fs,shell,pkg,sysinfo,service,blueprint}.service`)
与宿主均满足上述清单;新增消费方(如未来 controller runtime)必须照抄
`daedalus-*.service.d/` 模式,否则视为部署错误。

## 开发与测试

```bash
cd daedalus-sdk && go test ./...   # 全包测试(含金样向量重放)
```

- 包内注释一律中文(仓库根 CONVENTIONS)。
- 本仓不产二进制、不产镜像产物;打包/安装由 `daedalus-core` 的
  `just plugin-pack` 与 `daedalus-plugins/` 各插件仓完成。