package blueprint

// confirm_token.go —— blueprint 包对 confirmation 通用契约的薄包装。
//
// 本文件保留 confirm_token 契约的 blueprint 端入口,确保既有调用方
// (daedalus-plugins/blueprint) 不需在抽取阶段做大规模迁移。实际状态由
// confirmation 包持有:本文件仅做类型别名 + 函数包装。
//
// 历史:confirm_token 契约原属 blueprint 包内,与 plan 概念深度耦合;
// 抽出到 confirmation 包后,plan 概念泛化为 subject(被授权的操作对象),
// 可被 disk-clean、organize 等其他"扫描/预览 → 显式确认 → 执行"形态插件复用。

import (
	"github.com/Daedalusys/daedalus-sdk/confirmation"
)

// ConfirmToken 是 confirmation.ConfirmToken 的类型别名,保留 blueprint 端既有
// 字段访问语义(SubjectID 即原 PlanID)。新代码应直接 import confirmation 包。
type ConfirmToken = confirmation.ConfirmToken

// GenerateConfirmToken 包装 confirmation.GenerateConfirmToken,接受 planID 参数
// 并透传为 subjectID。
func GenerateConfirmToken(planID string) confirmation.ConfirmToken {
	return confirmation.GenerateConfirmToken(planID)
}

// VerifyConfirmToken 包装 confirmation.VerifyConfirmToken。
func VerifyConfirmToken(planID string, tok ConfirmToken) error {
	return confirmation.VerifyConfirmToken(planID, tok)
}
