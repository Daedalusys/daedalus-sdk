package blueprint

import (
	"testing"
	"time"
)

// TestConfirmToken_SingleUse 是守门测试:
// 确认令牌单次有效——Verify 成功一次即消费,第二次必须失败。
// 该契约是 framework "step 间依赖"扩展的早期落地。
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

// TestConfirmToken_PlanIDMismatch 是守门测试:
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

// TestConfirmToken_UnissuedRejected 是守门测试:
// 未经 GenerateConfirmToken 签发的令牌(凭空伪造的串,含 Expires==0
// "永不过期"形态)必须被拒——校验只认签发登记表,不采信自报字段。
func TestConfirmToken_UnissuedRejected(t *testing.T) {
	forged := ConfirmToken{Token: "deadbeef", PlanID: "x", Expires: 0}
	if err := VerifyConfirmToken("x", forged); err == nil {
		t.Fatal("伪造的未签发令牌通过了校验")
	}
}

// TestConfirmToken_SelfReportedCannotExtend 验证自报 Expires 不能放宽有效期:
// 签发记录内(未过期)的令牌,自报一个已过去的 Expires 必须判过期被拒;
// 自报 0 则回落到签发记录的过期时刻,不存在"不设过期"特权。
func TestConfirmToken_SelfReportedCannotExtend(t *testing.T) {
	tok := GenerateConfirmToken("plan-zero")

	early := tok
	early.Expires = time.Now().Add(-time.Minute).UnixMilli()
	if err := VerifyConfirmToken("plan-zero", early); err == nil {
		t.Fatal("自报已过期时刻的令牌通过了校验")
	}

	zero := tok
	zero.Expires = 0 // 自报 0 不是永不过期,也不是豁免:按签发记录判定。
	if err := VerifyConfirmToken("plan-zero", zero); err != nil {
		t.Fatalf("签发记录未过期的令牌应通过(自报 0 回落记录值): %v", err)
	}
}
