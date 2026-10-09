package confirmation

import (
	"strings"
	"testing"
	"time"
)

// TestToken_SingleUse 是守门测试:
// 确认令牌单次有效——Verify 成功一次即消费,第二次必须失败。
// 该契约是 framework "step 间依赖"扩展的早期落地。
func TestToken_SingleUse(t *testing.T) {
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

// TestToken_SubjectMismatch 是守门测试:
// subject 与令牌携带的 SubjectID 不匹配必须失败(配对校验)。
func TestToken_SubjectMismatch(t *testing.T) {
	tok := GenerateConfirmToken("plan-1")

	if err := VerifyConfirmToken("plan-2", tok); err == nil {
		t.Fatal("VerifyConfirmToken 返回 nil 错误,期望 subject 不匹配而失败")
	}
}

// TestToken_CrossSubject 是新增的跨 subject 互不可信测试:
// 不同 subject 签发的 token 必须严格不能跨域消费(plan-1 token 用 plan-2
// 校验、apply-1 token 用 remove-1 校验等所有"看起来形似实则不同"的误用
// 必须被拒)。
func TestToken_CrossSubject(t *testing.T) {
	cases := []struct{ name, got string }{
		{"plan", "plan-other"},
		{"apply", "remove"},
		{"scan", "plan"},
		{"organize-move", "disk-clean"},
	}
	for _, c := range cases {
		tok := GenerateConfirmToken(c.name)
		if err := VerifyConfirmToken(c.got, tok); err == nil {
			t.Errorf("跨 subject 误用未拒绝: %s token 用 %s 校验通过", c.name, c.got)
		}
	}
}

// TestToken_Expired 验证过期令牌即使未消费也不可用。
func TestToken_Expired(t *testing.T) {
	tok := GenerateConfirmToken("plan-1")
	// 把过期时间改成过去(已过期),未消费状态。
	tok.Expires = time.Now().Add(-time.Minute).UnixMilli()

	if err := VerifyConfirmToken("plan-1", tok); err == nil {
		t.Fatal("VerifyConfirmToken 返回 nil 错误,期望过期令牌失败")
	}
}

// TestToken_Empty 验证空令牌被拒绝。
func TestToken_Empty(t *testing.T) {
	tok := ConfirmToken{Token: "", SubjectID: "plan-1", Expires: time.Now().Add(time.Hour).UnixMilli()}
	if err := VerifyConfirmToken("plan-1", tok); err == nil {
		t.Fatal("VerifyConfirmToken 返回 nil 错误,期望空令牌失败")
	}
}

// TestToken_UnissuedRejected 是守门测试:
// 未经 GenerateConfirmToken 签发的令牌(凭空伪造的串,含 Expires==0
// "永不过期"形态)必须被拒——校验只认签发登记表,不采信自报字段。
func TestToken_UnissuedRejected(t *testing.T) {
	forged := ConfirmToken{Token: "deadbeef", SubjectID: "x", Expires: 0}
	if err := VerifyConfirmToken("x", forged); err == nil {
		t.Fatal("伪造的未签发令牌通过了校验")
	}
}

// TestToken_SelfReportedCannotExtend 验证自报 Expires 不能放宽有效期:
// 签发记录内(未过期)的令牌,自报一个已过去的 Expires 必须判过期被拒;
// 自报 0 则回落到签发记录的过期时刻,不存在"不设过期"特权。
func TestToken_SelfReportedCannotExtend(t *testing.T) {
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

// TestToken_ErrorPrefix 确认所有错误消息以 "confirmation: " 为前缀
// (而非 "blueprint: "),便于上游日志聚合与契约缝判定。
func TestToken_ErrorPrefix(t *testing.T) {
	const prefix = "confirmation: "

	// 空 token。
	if err := VerifyConfirmToken("x", ConfirmToken{Token: ""}); err == nil ||
		!strings.HasPrefix(err.Error(), prefix) {
		t.Errorf("空 token 错误前缀应为 %q,实得: %v", prefix, err)
	}

	// 未签发 token。
	if err := VerifyConfirmToken("x", ConfirmToken{Token: "deadbeef", SubjectID: "x"}); err == nil ||
		!strings.HasPrefix(err.Error(), prefix) {
		t.Errorf("未签发 token 错误前缀应为 %q,实得: %v", prefix, err)
	}

	// 过期 token。
	expired := GenerateConfirmToken("exp")
	expired.Expires = time.Now().Add(-time.Minute).UnixMilli()
	if err := VerifyConfirmToken("exp", expired); err == nil ||
		!strings.HasPrefix(err.Error(), prefix) {
		t.Errorf("过期 token 错误前缀应为 %q,实得: %v", prefix, err)
	}

	// subject 不匹配。
	wrong := GenerateConfirmToken("alpha")
	if err := VerifyConfirmToken("beta", wrong); err == nil ||
		!strings.HasPrefix(err.Error(), prefix) {
		t.Errorf("subject 不匹配错误前缀应为 %q,实得: %v", prefix, err)
	}
}
