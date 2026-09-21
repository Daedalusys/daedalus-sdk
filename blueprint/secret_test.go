package blueprint

import (
	"errors"
	"testing"
)

// TestResolveSecret_FailClosed_NoPlaintext 是守门测试(todo 6 桩):
// 明文 secret(非 secret:// 前缀)必须被 ResolveSecret 直接拒绝。
//
// 这是本包"明文 secret 永不出现在 audit log"强约束的第一道防线:
// 任何工具实现(render/apply)在构建 audit args 前必须先经 ResolveSecret
// 校验,明文输入在此处即返回 error,绝不流入渲染结果或审计参数。
func TestResolveSecret_FailClosed_NoPlaintext(t *testing.T) {
	plaintexts := []string{
		"password=foo123",
		"value: secret",
		"secret",
		"secret://", // 前缀残缺(无 source/path),同样拒绝
	}
	for _, ref := range plaintexts {
		if _, err := ResolveSecret(ref); err == nil {
			t.Errorf("ResolveSecret(%q) 返回 nil 错误,期望拒绝明文/残缺引用", ref)
		}
	}
}

// TestResolveSecret_Happy 验证两种合法源(kwallet / credstore)的 happy path。
//
// v1 真值获取未接入,因此注入假实现验证引用校验 + 转发逻辑完整可测;
// 假实现返回确定值,断言 ResolveSecret 原样透传。
func TestResolveSecret_Happy(t *testing.T) {
	// 保存原函数缝,测试结束后恢复(避免污染其他测试)。
	origKwallet, origCredstore := resolveKwallet, resolveCredstore
	t.Cleanup(func() {
		resolveKwallet, resolveCredstore = origKwallet, origCredstore
	})

	resolveKwallet = func(path string) (string, error) {
		if path != "kde/nginx/htpasswd" {
			return "", errors.New("kwallet 假实现收到意外 path: " + path)
		}
		return "fake-kwallet-value", nil
	}
	resolveCredstore = func(name string) (string, error) {
		if name != "postgres_app" {
			return "", errors.New("credstore 假实现收到意外 name: " + name)
		}
		return "fake-credstore-value", nil
	}

	got, err := ResolveSecret("secret://kwallet/kde/nginx/htpasswd")
	if err != nil {
		t.Fatalf("ResolveSecret(kwallet) 返回错误,期望成功: %v", err)
	}
	if got != "fake-kwallet-value" {
		t.Errorf("kwallet 解析值 = %q,期望 %q", got, "fake-kwallet-value")
	}

	got, err = ResolveSecret("secret://credstore/postgres_app")
	if err != nil {
		t.Fatalf("ResolveSecret(credstore) 返回错误,期望成功: %v", err)
	}
	if got != "fake-credstore-value" {
		t.Errorf("credstore 解析值 = %q,期望 %q", got, "fake-credstore-value")
	}
}

// TestResolveSecret_UnknownSource 验证未知 source 被拒绝。
func TestResolveSecret_UnknownSource(t *testing.T) {
	if _, err := ResolveSecret("secret://vault/foo"); err == nil {
		t.Fatal("ResolveSecret 返回 nil 错误,期望未知 source 失败")
	}
}

// TestResolveSecret_DotDotPath 验证 path 含 ".." 被拒绝(目录穿越防线)。
func TestResolveSecret_DotDotPath(t *testing.T) {
	for _, ref := range []string{
		"secret://kwallet/../etc/shadow",
		"secret://credstore/foo/../../bar",
	} {
		if _, err := ResolveSecret(ref); err == nil {
			t.Errorf("ResolveSecret(%q) 返回 nil 错误,期望 path 含 '..' 失败", ref)
		}
	}
}

// TestResolveSecret_NULPath 验证 path 含空字节被拒绝。
func TestResolveSecret_NULPath(t *testing.T) {
	if _, err := ResolveSecret("secret://kwallet/foo\x00bar"); err == nil {
		t.Fatal("ResolveSecret 返回 nil 错误,期望 path 含空字节失败")
	}
}

// TestResolveSecret_EmptyString 验证空字符串被拒绝(明文检测分支)。
func TestResolveSecret_EmptyString(t *testing.T) {
	if _, err := ResolveSecret(""); err == nil {
		t.Fatal("ResolveSecret(\"\") 返回 nil 错误,期望拒绝空串")
	}
}

// TestResolveSecret_EmptyPath 验证 secret:// 后有 source 但无 path 被拒绝。
func TestResolveSecret_EmptyPath(t *testing.T) {
	for _, ref := range []string{
		"secret://kwallet/",
		"secret://credstore/",
	} {
		if _, err := ResolveSecret(ref); err == nil {
			t.Errorf("ResolveSecret(%q) 返回 nil 错误,期望空 path 失败", ref)
		}
	}
}

// TestResolveSecret_SourceUnavailable 验证 v1 占位行为:
// 合法引用但真值获取未接入时,返回 ErrSecretSourceUnavailable(fail-closed,
// 不静默降级为明文或空值)。
func TestResolveSecret_SourceUnavailable(t *testing.T) {
	// 不注入假实现,保持默认占位(恒返回 ErrSecretSourceUnavailable)。
	if _, err := ResolveSecret("secret://kwallet/kde/nginx/htpasswd"); !errors.Is(err, ErrSecretSourceUnavailable) {
		t.Errorf("kwallet 占位错误 = %v,期望 ErrSecretSourceUnavailable", err)
	}
	if _, err := ResolveSecret("secret://credstore/postgres_app"); !errors.Is(err, ErrSecretSourceUnavailable) {
		t.Errorf("credstore 占位错误 = %v,期望 ErrSecretSourceUnavailable", err)
	}
}
