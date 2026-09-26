# MemoryProvider contract(已填实)

daedalus-sdk#2 钉死的第一批 slot contract 之一(原 Daedalusys/Daedalusys#42;
消费者议题 #29 持久记忆)。

## 形态
- `memoryprovider.go`:`Scope` 封闭枚举、`Entry{Key,Value,Scope,TTL}`、
  `Provider` 接口、哨兵错误;
- **契约缝·零运行时**:无实现、无注册表,builtin(mem0/memU/BML 等)接线
  归消费方构造期;
- 语义单一事实源:仓内 `docs/provider-slot.md` §3
  (含跨 slot 铁律:记忆值只存 `secret://` 引用,不存明文)。

## 测试
`memoryprovider_test.go` 钉 scope 枚举、Entry JSON 形状与 TTL 过期语义
(fake 后端,零磁盘写入)。
