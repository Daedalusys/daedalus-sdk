# MemoryProvider contract(已填实)

daedalus-sdk#2 钉死的第一批 slot contract 之一(原 Daedalusys/Daedalusys#42;
消费者议题 #29 持久记忆)。

## 形态
- `memoryprovider.go`:`Scope` 封闭枚举、`Entry{Key,Value,Scope,TTL}`、
  `Provider` 接口、哨兵错误;
- **契约缝·零运行时**:契约包本身无实现、无注册表;实现放子包,接线归消费方构造期;
- 语义单一事实源:仓内 `docs/provider-slot.md` §3
  (含跨 slot 铁律:记忆值只存 `secret://` 引用,不存明文)。

## builtin 实现
| 包 | swappability | 后端 | 边界 |
| --- | --- | --- | --- |
| `memoryprovider/jsonl` | `L1`(`slot.LevelRestart`) | 单个 JSONL 文件,追加写 + 墓碑删除,开库时压缩 | 见下 |

构造:`jsonl.New(path, jsonl.Options{Now: ...})`。`Options.Now` 只为测试注入时钟,生产留空。

### `memoryprovider/jsonl` 的能力边界

- **只服务 `ScopeUser`**:`system` scope 与非法 scope 一律 `ErrScopeDenied`。
  跨用户/系统共享不在本实现范围(issue #25 的 out 项)。契约里 `ErrScopeDenied`
  本应由消费侧把 policy 裁决翻译过来;本实现选择在**写入层**直接拒绝 `system`。
- **`Search` 恒 `ErrSearchUnavailable`**:本后端没有语义检索,空结果不等于没命中。
- **每文件单实例**:索引是 per-instance 的,同一路径开两个实例会各持一份旧索引
  (没有跨进程/跨实例锁)。
- **值的合法性在写入口把关**:不是合法 JSON 的值(含空值)直接 `ErrInvalidValue`
  —— 写进去半截 JSON,下次重放就成了一条读不出来的记录。
- **`Entry.TTL` 是写入时设定的原值**,不是剩余寿命;剩余寿命由 provider 内部按
  写入时刻判定,过期即读作 `ErrKeyNotFound`。
- **持久性边界**:写操作不 fsync。进程崩溃(含 SIGKILL)最多损坏最后一行,下次开库
  会把半截尾行折掉;机器掉电可能丢掉 page cache 里尚未回写的若干行。需要
  「返回 nil 即已落盘」的调用方请显式 `Close()`(它会 `Sync`)。
- **不检测 secret 明文**:契约明说类型层无法强制,靠评审门;本实现按字节存取,
  不假装能拦。

## 测试
- `memoryprovider_test.go`:钉 scope 枚举、Entry JSON 形状与 TTL 过期语义(fake 后端,零磁盘写入);
- `jsonl/jsonl_test.go`:钉 JSONL 后端的往返、TTL 过期即 `ErrKeyNotFound`、墓碑删除的持久性、
  列举的前缀过滤、`ErrSearchUnavailable`、scope 越权与非法键、跨重开持久性、
  **尾部半截写可开库而中间行损坏 fail-closed**、开库时压缩(墓碑/过期行折叠)、
  空值被拒与 `null` 往返、契约接口断言、`Close()` 落盘与幂等。
