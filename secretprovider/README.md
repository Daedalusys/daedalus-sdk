# SecretProvider contract(已填实)

daedalus-sdk#2 钉死的第一批 slot contract 之一(原 Daedalusys/Daedalusys#42;
消费者议题 #33 KWallet / #34 systemd-creds)。

## 形态
- `secretprovider.go`:`Ref` 形状门、`Secret` 脱敏值类型、`Provider` 接口、哨兵错误;
- **契约缝·零运行时**:无实现、无注册表,provider 接线归消费方 cmd/daemon 构造期;
- 语义单一事实源:仓内 `docs/provider-slot.md` §2。

## 测试
`secretprovider_test.go` 钉引用形状表、脱敏红线(String/GoString/MarshalJSON)
与接口形状(内存 fake 静态实现)。
