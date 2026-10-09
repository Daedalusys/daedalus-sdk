package blueprint

import (
	"testing"
	"time"

	"github.com/Daedalusys/daedalus-sdk/confirmation"
)

// TestBlueprint_ConfirmTokenIsReExport 钉死 blueprint 薄包装与 confirmation 通用包
// 的字节级兼容:blueprint 端签发的 token 必须既能通过 blueprint 包装校验,也能
// 通过 confirmation 包校验(两者共享同一签发登记表),反之亦然。
//
// 该测试是抽取阶段(plan framework 缺口落地)的回归护栏:一旦有人把 blueprint
// 薄包装改为独立实现(而非透传),双向兼容立即失败。
func TestBlueprint_ConfirmTokenIsReExport(t *testing.T) {
	// blueprint 签发 → blueprint 校验(backward-compat 主路径)。
	tok := GenerateConfirmToken("plan-compat")
	if err := VerifyConfirmToken("plan-compat", tok); err != nil {
		t.Fatalf("blueprint 包装双向校验失败: %v", err)
	}

	// blueprint 签发 → confirmation 直接校验(同登记表,共享消费语义)。
	tok2 := GenerateConfirmToken("plan-shared")
	if err := confirmation.VerifyConfirmToken("plan-shared", tok2); err != nil {
		t.Fatalf("blueprint 签发 token 未通过 confirmation 校验: %v", err)
	}

	// confirmation 签发 → blueprint 包装校验。
	tok3 := confirmation.GenerateConfirmToken("plan-reverse")
	if err := VerifyConfirmToken("plan-reverse", tok3); err != nil {
		t.Fatalf("confirmation 签发 token 未通过 blueprint 包装校验: %v", err)
	}
}

// TestBlueprint_ConfirmTokenTypeAlias 确认 blueprint.ConfirmToken 与
// confirmation.ConfirmToken 是同一类型(别名,非独立结构)。
func TestBlueprint_ConfirmTokenTypeAlias(t *testing.T) {
	var a ConfirmToken = confirmation.ConfirmToken{
		Token:     "x",
		SubjectID: "s",
		Expires:   time.Now().Add(time.Hour).UnixMilli(),
	}
	// 类型别名下,两边字段必须完全互通(编译期即证明)。
	var b confirmation.ConfirmToken = a
	if b.SubjectID != "s" || b.Token != "x" {
		t.Fatalf("类型别名字段互通失败: %+v", b)
	}
}
