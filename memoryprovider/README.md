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
| `memoryprovider/jsonl` | `L1`(`slot.LevelRestart`) | 单个 JSONL 文件,追加写 + 墓碑删除 | 只服务 `ScopeUser`;`Search` 恒 `ErrSearchUnavailable`;单进程(无跨进程锁) |

构造:`jsonl.New(path, jsonl.Options{Now: ...})`。`Options.Now` 只为测试注入时钟,生产留空。

`memoryprovider/jsonl` 按字节原样存取值 —— **不检测也不剥离** `secret://` 明文违例:
契约明说类型层无法强制,该铁律靠评审门(见包注释)。

## 测试
- `memoryprovider_test.go`:钉 scope 枚举、Entry JSON 形状与 TTL 过期语义(fake 后端,零磁盘写入);
- `jsonl/jsonl_test.go`:钉 JSONL 后端的往返、TTL 过期即 `ErrKeyNotFound`、墓碑删除的持久性、
  列举的前缀/scope 过滤、`ErrSearchUnavailable`、scope 越权与非法键、跨重开持久性。
