package blueprint

import (
	"testing"
	"time"
)

// TestConfirmToken_SingleUse 是守门测试(todo 6 桩):
// 确认令牌单次有效——Verify 成功一次即消费,第二次必须失败。
// 该契约是 framework "step 间依赖"扩展的早期落地(plan 决策 14)。
func TestConfirmToken_SingleUse(t *testing.T) {
	tok := GenerateConfirmToken("plan-1")

	// 第一次 Verify:配对且未消费 → 成功。
	if err := VerifyConfirmToken("plan-1", tok); err != nil {
		t.Fatalf("第一次 Verify 返回错误,期望成功: %v", err)
	}
	// 第二次 Verify:已消费 → 必须失败。
	if err := VerifyConfirmToken("plan-1", tok); err == nil {
		t.Fatal("第二次 Verify 返回 nil 错误,期望令牌已消费而失败")
	}
}

// TestConfirmToken_PlanIDMismatch 是守门测试(todo 6 桩):
// plan_id 与令牌携带的 PlanID 不匹配必须失败(配对校验)。
func TestConfirmToken_PlanIDMismatch(t *testing.T) {
	tok := GenerateConfirmToken("plan-1")

	if err := VerifyConfirmToken("plan-2", tok); err == nil {
		t.Fatal("VerifyConfirmToken 返回 nil 错误,期望 plan_id 不匹配而失败")
	}
}

// TestConfirmToken_Expired 验证过期令牌即使未消费也不可用。
func TestConfirmToken_Expired(t *testing.T) {
	tok := GenerateConfirmToken("plan-1")
	// 把过期时间改成过去(已过期),未消费状态。
	tok.Expires = time.Now().Add(-time.Minute).UnixMilli()

	if err := VerifyConfirmToken("plan-1", tok); err == nil {
		t.Fatal("VerifyConfirmToken 返回 nil 错误,期望过期令牌失败")
	}
}

// TestConfirmToken_Empty 验证空令牌被拒绝。
func TestConfirmToken_Empty(t *testing.T) {
	tok := ConfirmToken{Token: "", PlanID: "plan-1", Expires: time.Now().Add(time.Hour).UnixMilli()}
	if err := VerifyConfirmToken("plan-1", tok); err == nil {
		t.Fatal("VerifyConfirmToken 返回 nil 错误,期望空令牌失败")
	}
}

// TestConfirmToken_ExpiresZeroAllowed 验证 Expires==0(未设过期)的令牌按未过期处理。
//
// 这是契约的宽松分支:Expires 是可选字段,0 表示"不设过期"而非"已过期",
// 避免旧调用方构造的令牌被误判。已消费 / planID 不匹配等硬约束不受影响。
func TestConfirmToken_ExpiresZeroAllowed(t *testing.T) {
	tok := GenerateConfirmToken("plan-zero")
	tok.Expires = 0 // 显式清零,模拟未设过期。

	if err := VerifyConfirmToken("plan-zero", tok); err != nil {
		t.Fatalf("VerifyConfirmToken 返回错误,期望 Expires==0 视为未过期: %v", err)
	}
}
