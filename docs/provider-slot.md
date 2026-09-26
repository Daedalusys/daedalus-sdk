# Provider / Slot 架构 —— 第一批 contract(SecretProvider / MemoryProvider)

**状态**: 草案成文(daedalus-sdk#2,源自 Daedalusys/Daedalusys#42);
实现落点: `slot/`(共享词汇)+ `secretprovider/` + `memoryprovider/`。
本文只写 contract 语义与改造清单,接口形状以包内 Go 源码为唯一权威。

核心思想不变:

> Core only knows stable interfaces, not implementations.

Core 持有 slot(稳定 contract),实现以 provider 形式接入;接线发生在装配处
构造期(core/cmd 侧),本仓不提供注册表/分发器(见 §7 非目标)。

## 0. Slot 全景

| Slot | 包 | 状态 | 已知候选 | 声明上限 |
| --- | --- | --- | --- | --- |
| SecretProvider | `secretprovider/` | **contract 已钉** | KWallet / systemd-creds / Vault | L1 |
| MemoryProvider | `memoryprovider/` | **contract 已钉** | builtin / mem0 / memU / BML | L1(远期 L3) |
| ModelProvider | `modelprovider/`(占位) | 只定义问题域 | OpenAI 兼容 / Ollama / 统一网关 | 未裁决 |
| AgentProvider | `agentprovider/`(占位) | 只定义问题域 | Vivy / SYSTEM-V / Codex / OpenCode | 未裁决 |
| TransportProvider | `transportprovider/`(占位) | 只定义问题域 | MCP stdio / MCP HTTP / A2A | 未裁决 |

后三个 slot 的问题域一句话:ModelProvider = 云端推理适配与提示词缓存(#31
去向),不接管 reasoning;AgentProvider = 上层智能体接入形态,不建 Agent
Kernel;TransportProvider = capability 服务器与 copilot 的协议通道选择。
各自等真实消费者出现再钉 contract。

## 1. Swappability 分级(`slot.Level`)

每个 provider 在 contract 里**自己声明**可达级别(`Swappability()`),
平台承诺永不超过该声明;默认不承诺任何热切换。

| Level | 语义 | 典型例 |
| --- | --- | --- |
| `L0` | build-time selectable(镜像即完整清单,VISION 现状) | 当前全部 Go 能力服务器 |
| `L1` | restart-time replaceable(重启换实现) | KWallet → Vault |
| `L2` | runtime load/unload(运行时装卸) | UI / MCP / Skill 插件 |
| `L3` | state-preserving hot swap(状态迁移后热切换) | MemoryProvider 远期 |

注意:`slot.Level` 与工具风险分级(L0/L1/L2 风险档)是**两套正交词汇**,
各自在文档/类型名处显式限定,不得互引。

## 2. SecretProvider contract

引用模型:调用方(agent/copilot/蓝图渲染)只持引用 `secret://<scheme>/<path>`,
明文只在解析瞬间存在于 L0 调用栈。

接口(权威形状见 `secretprovider.Provider`):
`Scheme` / `Swappability` / `Collections` / `List` / `Get` / `Set` / `Delete`,
与 #33 五工具一一对应(`secrets_collections/list/get/set/delete`)。

错误语义(哨兵,`errors.Is` 判别;实现包装底层细节必须用 `%w` 保留哨兵):

| 哨兵 | 语义 |
| --- | --- |
| `ErrRefInvalid` | 引用形状非法(`Ref.Validate` 门) |
| `ErrSchemeMismatch` | provider 收到非本 scheme 的引用(拒读拒写) |
| `ErrNotFound` | 引用不存在(与"存在但无权"不可区分,防探测) |
| `ErrLocked` | 后端锁定/未解锁(如 KWallet collection 未解锁) |
| `ErrUnavailable` | 后端不可达;与 blueprint 渲染侧 `ErrSecretSourceUnavailable` 同一姿势:解析失败 ≠ 返回空串 |

框架级硬约束(不靠实现者自律):

1. `Secret` 类型的 `String/GoString` 恒脱敏,`MarshalJSON` **直接报错**——
   明文在类型层就进不了审计行、日志行与任何 JSON 序列化路径;
2. `Get` 返回的 `Secret` 用毕应 `Zeroize()`;错误字符串**不得内嵌**值内容
   (contract 义务,评审门);
3. `Set/Delete` 的调用记录(审计)只允许含引用,不含值。

与 systemd LoadCredential 的分工:**用户态**归本 slot(KWallet,#33);
**服务态**归 LoadCredential 管线(systemd-creds,#34)——credstore 引用
(`secret://credstore/<name>`)的 provider 实现读 `$CREDENTIALS_DIRECTORY` /
`/etc/credstore/`,两条路径经同一 `Ref` 词汇表互通,不互相复制实现。

## 3. MemoryProvider contract

跨会话持久记忆(#29):保存/检索用户偏好、事实、决策;受 policy 约束
(`[memory]` 段归消费者落地,本 contract 不预埋 policy 键)。

接口(权威形状见 `memoryprovider.Provider`):
`Swappability` / `Get` / `Set` / `Delete` / `List` / `Search`,与 #29 五工具
对应(`memory_get/set/delete/list/search`;`Search` 语义检索可缺席)。

- `Entry{Key, Value, Scope, TTL}`:值用 `json.RawMessage`(结构化,避免
  自由文本夹带);`Scope` 封闭枚举 `user` / `system`;`TTL=0` 永久,过期
  清理由 provider 执行(读到即已过期 → `ErrKeyNotFound`)。
- 错误语义:`ErrKeyNotFound`、`ErrScopeDenied`(scope 越权,由消费侧 policy
  裁决后回哨兵)、`ErrSearchUnavailable`(嵌入未启用,**不是**空结果)。
- 跨 slot 铁律:**记忆值里不得存 secret 明文**,只允许 `secret://` 引用;
  写侧由 copilot 记忆装配层先做值→引用替换,读侧渲染时才经
  SecretProvider 解析(#29「记忆里也不应存明文 secret」的框架级落点)。

swappability:builtin(JSONL/SQLite 文件后端)声明 L1;L3 需要状态迁移
协议,单独裁决,不在本 contract 承诺。

## 4. Core 直依赖 slot 化改造点清单(验收②)

现状核查:代码中**不存在** KWallet 直连与 builtin memory 子系统,以下为
全部相邻缝:

| # | 位置(core 仓) | 现状 | slot 化改造点 |
| --- | --- | --- | --- |
| 1 | `plugin/copilot/llm.ts`(key 解析链) | flag > env > `copilot.json` 明文 key,裸入 `Authorization` | 新增 `secret://` 引用形态:解析链末端接 SecretProvider.Get(仅 L0 栈),env/file 路径保留为无 provider 时的降级 |
| 2 | `files/system/usr/lib/systemd/system/daedalus-*.service.d/credentials.conf` ×7 | 静态 `LoadCredential=daedalus_token:/etc/credstore/daedalus_token` | 服务态即 credstore provider 的既有底座,**不改**;#34 `creds_*` 工具是其运维面封装 |
| 3 | `daedalus-env.service` + `/etc/credstore/` 占位 | root 属主空文件 bootstrap | 保持;Vault 等远端 backend 接入时替换其填充方,unit 侧无感 |
| 4 | `files/scripts/76-daedalus-plugin-gen.sh` | 构建期断言 LoadCredential 行存在 | 保持(它是 #2 的构建门,不是直依赖) |
| 5 | `files/system/opt/daedalus/shared/policy.toml` `secret_sources=["kwallet","credstore"]` | 声明在场 | 落 `[memory]` 同族治理时一并裁决 provider 选择键(与 §3 联动) |
| 6 | blueprint `secret://` 渲染 resolver | v1 恒 `ErrSecretSourceUnavailable`(预留位) | 改为按 `Ref` scheme 分发到已接线 provider;哨兵姿势不变,`policy.toml` secret_sources 白名单仍是准入门 |
| 7 | `state/state.go`(state.jsonl) | 追加式**观测缓存** | **不是**记忆,不迁;MemoryProvider 是新增独立根(`~/.local/share/daedalus/memory/`),二者语义正交 |
| 8 | copilot LLM history | 进程内数组,不落盘 | 不改造(无持久依赖可 slot 化) |

## 5. 双层 Extension 模型(VISION §11 演进提案)

化解 immutable OS(构建期内建)与插件生态(runtime 可装)的张力——
**分层,不是推翻**:

| 层 | 形态 | 落点 |
| --- | --- | --- |
| System Extensions | image-built / signed / privileged / immutable,参与 system capability 与 controller | `/opt/daedalus/plugins` |
| User Extensions | runtime installable / unprivileged / sandboxed / user-scoped,承载 MCP / Skill / Agent / UI | `~/.local/share/daedalus/plugins` |

规则:特权 provider(SecretProvider/MemoryProvider 实现)**永远**走
System Extension;User Extension 不得申请特权 slot 接线。provider 接线
发生在装配构造期,注册 ≠ 运行时安装,"镜像即完整清单"对特权面保持字面
成立。远期 Control Center panel/route/schema/action 按 extension 注册,
不预埋在本文。

## 6. 治理原则

- 每个 slot 的 contract 变更 = 本仓公开面增量,须同步更新 README 包索引、
  威胁面段与本文;三点漂移链(如 `[ownership]`、`[memory]` 落 policy.toml 时)
  由消费者侧测试联动。
- provider 实现选择归装配处(cmd/daemon),不进 SDK;SDK 只有接口与哨兵。
- 不为假想 provider 预留字段:`Provider` 接口的每一方法都对应已裁决工具面。

## 7. 非目标

- 不实现任何具体 provider 替换(§4 清单是改造点,不是本期工程)。
- 不把 L2/L3 设为默认承诺;每 slot 单独裁决。
- 不做 manifest slot 字段:`daedalus.plugin.json` schema 等真实消费者(特权
  provider 插件化)出现再扩,避免第二注册事实源。
- 不建 plugin marketplace / 应用商店;不接管 agent reasoning。
