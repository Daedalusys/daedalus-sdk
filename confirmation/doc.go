// Package confirmation 是 Daedalus 单次有效确认令牌(confirm_token)的通用契约。
//
// 契约语义:签发(GenerateConfirmToken)与消费(VerifyConfirmToken)必须处于
// 同一进程会话;令牌与一个 subject(被授权的操作对象,如蓝图的 plan_id、磁盘
// 清理的 plan_id、文件整理的 plan_id)配对,校验通过即原子消费,单次有效。
//
// 本包从 blueprint 插件抽出时保持行为字节级一致(仅错误前缀由 "blueprint:"
// 改为 "confirmation:",planID 概念泛化为 subjectID),供 blueprint / disk-clean
// / organize 等所有"扫描/预览 → 显式确认 → 执行"形态的插件共用。blueprint 包
// 保留薄包装(confirm_token.go)做向后兼容。
package confirmation
