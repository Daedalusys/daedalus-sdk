// Package blueprint 测试:类型、注册表、secret 引用解析与 confirm_token 契约。
//
// ## 安全强约束(框架层):明文 secret 永不出现在 audit log
//
// 本包与 daedalus.blueprint 插件共同承诺:任何 secret 真值(明文密码、
// token、密钥)绝不写入 audit log。该约束是框架层强约束,来源:
//
//   - issue #033(secrets):KWallet / LoadCredential 真值获取接入前,
//     params 只接受 secret:// 引用,明文直接拒;
//   - plan daedalus-blueprint-p1 §6 第 5 条:post_check 子进程 stdout/stderr
//     默认不进 audit(防 secret 泄漏),仅显式 opt-in 时经审计通道。
//
// ## 工具实现的强制路径
//
// 任何工具实现(render / apply)在构建 audit args 之前,必须先经
// ResolveSecret 完成 secret 引用校验:合法引用才允许解析真值;
// 明文(非 secret:// 前缀)在 ResolveSecret 即返回 error,绝不流入
// 渲染结果或 audit 参数。守门测试 TestResolveSecret_FailClosed_NoPlaintext
// 钉死该防线——若实现绕过 ResolveSecret 直接把明文塞进 audit args,
// 该测试保持通过但框架约束被违反,review 时以本注释为审查锚点。
package blueprint

import "testing"

// 测试用最小合法 manifest(仅填通过校验所需字段)。
func validManifest() *BlueprintManifest {
	return &BlueprintManifest{
		ID:             "nginx-vhost",
		DisplayName:    "Nginx VHost",
		Version:        "1.0.0",
		Description:    "为指定域名添加一个 nginx vhost",
		Category:       "web",
		OutputPathTmpl: "/etc/nginx/conf.d/{domain}.conf",
		ReloadService:  "nginx",
		RequiredTools:  []string{"nginx", "systemctl"},
	}
}

// TestBlueprint_New_Happy 验证从合法 manifest 构造 Blueprint 成功,
// 且 RequiredTools 与 manifest 底层数组不共享(独立拷贝,防外部修改)。
func TestBlueprint_New_Happy(t *testing.T) {
	m := validManifest()

	b, err := New(m)
	if err != nil {
		t.Fatalf("New 返回错误,期望 nil: %v", err)
	}
	if b.ID != "nginx-vhost" {
		t.Errorf("ID = %q,期望 %q", b.ID, "nginx-vhost")
	}
	if b.DisplayName != "Nginx VHost" {
		t.Errorf("DisplayName = %q,期望 %q", b.DisplayName, "Nginx VHost")
	}
	if b.Version != "1.0.0" {
		t.Errorf("Version = %q,期望 %q", b.Version, "1.0.0")
	}
	if b.Description != "为指定域名添加一个 nginx vhost" {
		t.Errorf("Description = %q,与输入不符", b.Description)
	}
	if b.Category != "web" {
		t.Errorf("Category = %q,期望 %q", b.Category, "web")
	}
	if b.OutputPathTmpl != "/etc/nginx/conf.d/{domain}.conf" {
		t.Errorf("OutputPathTmpl = %q,与输入不符", b.OutputPathTmpl)
	}
	if b.ReloadService != "nginx" {
		t.Errorf("ReloadService = %q,期望 %q", b.ReloadService, "nginx")
	}
	if len(b.RequiredTools) != 2 || b.RequiredTools[0] != "nginx" || b.RequiredTools[1] != "systemctl" {
		t.Fatalf("RequiredTools = %v,期望 [nginx systemctl]", b.RequiredTools)
	}

	// 修改 manifest 的 RequiredTools 不得影响已构造实例(独立拷贝)。
	m.RequiredTools[0] = "mutated"
	if b.RequiredTools[0] == "mutated" {
		t.Error("RequiredTools 与 manifest 共享底层数组,期望独立拷贝")
	}
}

// TestBlueprint_New_EmptyID 验证空 ID 被拒绝。
func TestBlueprint_New_EmptyID(t *testing.T) {
	m := validManifest()
	m.ID = ""

	if _, err := New(m); err == nil {
		t.Fatal("New 返回 nil 错误,期望因空 ID 失败")
	}
}

// TestBlueprint_New_EmptyVersion 验证空版本被拒绝。
func TestBlueprint_New_EmptyVersion(t *testing.T) {
	m := validManifest()
	m.Version = ""

	if _, err := New(m); err == nil {
		t.Fatal("New 返回 nil 错误,期望因空版本失败")
	}
}

// TestBlueprint_New_MissingRequiredTools 验证空工具列表被拒绝。
func TestBlueprint_New_MissingRequiredTools(t *testing.T) {
	m := validManifest()
	m.RequiredTools = nil

	if _, err := New(m); err == nil {
		t.Fatal("New 返回 nil 错误,期望因缺少必需工具失败")
	}
}

// TestBlueprint_New_NoPlaceholder 验证输出路径模板不含 {param} 占位符被拒绝。
func TestBlueprint_New_NoPlaceholder(t *testing.T) {
	m := validManifest()
	m.OutputPathTmpl = "/etc/nginx/conf.d/site.conf"

	if _, err := New(m); err == nil {
		t.Fatal("New 返回 nil 错误,期望因模板缺占位符失败")
	}
}

// TestBlueprint_New_EmptyPlaceholder 验证空占位符 "{}" 不视为有效占位符
// (无参数名可替换,拒绝构造)。
func TestBlueprint_New_EmptyPlaceholder(t *testing.T) {
	m := validManifest()
	m.OutputPathTmpl = "/etc/nginx/conf.d/{}.conf"

	if _, err := New(m); err == nil {
		t.Fatal("New 返回 nil 错误,期望因空占位符失败")
	}
}
