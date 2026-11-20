package autonomy_test

import (
	"testing"

	"github.com/Daedalusys/daedalus-sdk/autonomy"
)

func TestParseScope(t *testing.T) {
	s, err := autonomy.ParseScope("systemd:user:start:myapp.service")
	if err != nil {
		t.Fatalf("合法作用域解析失败: %v", err)
	}
	want := autonomy.Scope{Runtime: "systemd", Domain: "user", Action: "start", Target: "myapp.service"}
	if s != want {
		t.Fatalf("解析结果漂移: 得到 %+v,期望 %+v", s, want)
	}
	if got := s.String(); got != "systemd:user:start:myapp.service" {
		t.Fatalf("String 未按四段还原: %q", got)
	}

	// 非 systemd 运行时没有域段,按三段解析。
	p, err := autonomy.ParseScope("podman:restart:test-web")
	if err != nil {
		t.Fatalf("三段作用域解析失败: %v", err)
	}
	if p != (autonomy.Scope{Runtime: "podman", Action: "restart", Target: "test-web"}) {
		t.Fatalf("三段作用域解析结果漂移: %+v", p)
	}
	if got := p.String(); got != "podman:restart:test-web" {
		t.Fatalf("String 未按三段还原: %q", got)
	}
}

func TestParseScopeRejects(t *testing.T) {
	cases := []string{
		"systemd:start:x.service",   // systemd 缺域
		"systemd:user:frobnicate:x", // 动作不在词表
		"systemd:user:start",        // 段数不足
		"podman:user:start:x",       // podman 不带域
		"",                          // 空串
		"a::b",                      // 未知运行时 + 空段
		"systemd:admin:start:x",     // 未知域
		"podman:start:",             // 目标为空
		"unknown:start:x",           // 未知运行时
	}
	for _, in := range cases {
		if got, err := autonomy.ParseScope(in); err == nil {
			t.Errorf("ParseScope(%q) 竟然通过: %+v", in, got)
		}
	}
}

func TestScopeMatches(t *testing.T) {
	rule, err := autonomy.ParseScope("podman:restart:test-*")
	if err != nil {
		t.Fatalf("规则作用域解析失败: %v", err)
	}
	cases := []struct {
		target string
		want   bool
	}{
		{"test-web", true},
		{"test-web-2", true},
		{"prod-web", false},
	}
	for _, c := range cases {
		if got := rule.Matches(autonomy.Scope{Runtime: "podman", Action: "restart", Target: c.target}); got != c.want {
			t.Errorf("podman:restart:test-* 匹配 %q: 得到 %v,期望 %v", c.target, got, c.want)
		}
	}

	// 域不同即不匹配:systemd:user 的规则不得覆盖 systemd:system。
	userRule, err := autonomy.ParseScope("systemd:user:start:*")
	if err != nil {
		t.Fatalf("规则作用域解析失败: %v", err)
	}
	systemTarget, err := autonomy.ParseScope("systemd:system:start:nginx.service")
	if err != nil {
		t.Fatalf("目标作用域解析失败: %v", err)
	}
	if userRule.Matches(systemTarget) {
		t.Fatal("systemd:user 规则竟然匹配了 systemd:system 目标")
	}

	// 动作不支持通配,只有目标走 path.Match。
	startOnly, _ := autonomy.ParseScope("systemd:user:start:*")
	restartTarget, _ := autonomy.ParseScope("systemd:user:restart:myapp.service")
	if startOnly.Matches(restartTarget) {
		t.Fatal("start 规则竟然匹配了 restart 动作")
	}
}
