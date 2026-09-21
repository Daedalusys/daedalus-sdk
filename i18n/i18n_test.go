package i18n

import "testing"

// reset 把包级状态归零(同包白盒),让每个用例从干净状态开始。
// 调用方应先用 t.Setenv 固定 locale env 再调 reset(t.Setenv 自动
// 注册测后恢复)。
func reset() {
	currentMu.Lock()
	current = ""
	currentMu.Unlock()
	localesMu.Lock()
	locales = map[string]map[string]string{}
	localesMu.Unlock()
}

// TestDetect_LCAllCodeset LC_ALL 带 codeset 后缀时去后缀保留语言区。
func TestDetect_LCAllCodeset(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	t.Setenv("LANG", "")
	if got := Detect(); got != "zh_CN" {
		t.Fatalf("Detect() = %q, 期望 %q", got, "zh_CN")
	}
}

// TestDetect_LangOnly 仅 LANG 设置时生效。
func TestDetect_LangOnly(t *testing.T) {
	t.Setenv("LC_ALL", "")
	t.Setenv("LANG", "en_US.UTF-8")
	if got := Detect(); got != "en_US" {
		t.Fatalf("Detect() = %q, 期望 %q", got, "en_US")
	}
}

// TestDetect_Empty 全空 env 时兜底 en_US。
func TestDetect_Empty(t *testing.T) {
	t.Setenv("LC_ALL", "")
	t.Setenv("LANG", "")
	if got := Detect(); got != "en_US" {
		t.Fatalf("Detect() = %q, 期望 %q", got, "en_US")
	}
}

// TestDetect_LCAllWins LC_ALL 与 LANG 同时存在时 LC_ALL 优先(POSIX 标准)。
func TestDetect_LCAllWins(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	t.Setenv("LANG", "en_US.UTF-8")
	if got := Detect(); got != "zh_CN" {
		t.Fatalf("Detect() = %q, 期望 %q", got, "zh_CN")
	}
}

// TestDetect_Modifier 验证 @modifier 去除(zh_CN@pinyin → zh_CN)。
func TestDetect_Modifier(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN@pinyin")
	t.Setenv("LANG", "")
	if got := Detect(); got != "zh_CN" {
		t.Fatalf("Detect() = %q, 期望 %q", got, "zh_CN")
	}
}

// TestT_ExactHit 精确 locale 命中(zh_CN 文件含该 key)。
func TestT_ExactHit(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	t.Setenv("LANG", "")
	reset()
	Init()
	if got := T("test.key"); got != "测试值" {
		t.Fatalf("T(test.key) = %q, 期望 %q", got, "测试值")
	}
	if got := Locale(); got != "zh_CN" {
		t.Fatalf("Locale() = %q, 期望 %q", got, "zh_CN")
	}
}

// TestT_LanguageFallback locale 文件缺失时沿 fallback 链降级:
// fr_FR(无文件)→ fr(无文件)→ en_US 兜底命中。
func TestT_LanguageFallback(t *testing.T) {
	t.Setenv("LC_ALL", "fr_FR.UTF-8")
	t.Setenv("LANG", "")
	reset()
	Init()
	if got := Locale(); got != "fr_FR" {
		t.Fatalf("Locale() = %q, 期望 %q", got, "fr_FR")
	}
	if got := T("test.key"); got != "test value" {
		t.Fatalf("T(test.key) = %q, 期望 en_US 兜底 %q", got, "test value")
	}
}

// TestT_MissReturnsKey 未命中 key 返回 key 本身,永不 panic。
func TestT_MissReturnsKey(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	t.Setenv("LANG", "")
	reset()
	Init()
	if got := T("nonexistent.xyz"); got != "nonexistent.xyz" {
		t.Fatalf("T(nonexistent.xyz) = %q, 期望返 key 本身", got)
	}
}

// TestT_Placeholders 占位符 {0} {1} 按序号替换;缺参清空。
func TestT_Placeholders(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	t.Setenv("LANG", "")
	reset()
	Init()
	if got, want := T("test.placeholder", "a", "b"), "值=a 名=b"; got != want {
		t.Fatalf("T(test.placeholder, a, b) = %q, 期望 %q", got, want)
	}
	if got, want := T("test.placeholder"), "值= 名="; got != want {
		t.Fatalf("T(test.placeholder) 无参 = %q, 期望 %q", got, want)
	}
}

// TestT_LazyInit 未调 Init 直接 T():lazy 触发一次 Init,仍能命中。
func TestT_LazyInit(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	t.Setenv("LANG", "")
	reset()
	if got := T("test.key"); got != "测试值" {
		t.Fatalf("裸 T(test.key) = %q, 期望 lazy Init 后命中 %q", got, "测试值")
	}
}

// TestT_NilArg 参数为 nil 时占位符替换为空串(不 panic)。
func TestT_NilArg(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	t.Setenv("LANG", "")
	reset()
	Init()
	if got, want := T("test.placeholder", nil, "b"), "值= 名=b"; got != want {
		t.Fatalf("T(test.placeholder, nil, b) = %q, 期望 %q", got, want)
	}
}

// TestInit_Idempotent Init 多次调用幂等:locale 定死不随 env 变化。
func TestInit_Idempotent(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	t.Setenv("LANG", "")
	reset()
	Init()
	Init()
	if got := Locale(); got != "zh_CN" {
		t.Fatalf("Locale() = %q, 期望 %q", got, "zh_CN")
	}
}

// TestLocale_BeforeInit 未 Init 时 Locale() 等价 Detect()。
func TestLocale_BeforeInit(t *testing.T) {
	t.Setenv("LC_ALL", "")
	t.Setenv("LANG", "ja_JP.UTF-8")
	reset()
	if got := Locale(); got != "ja_JP" {
		t.Fatalf("Locale() 未 Init = %q, 期望 Detect() 结果 %q", got, "ja_JP")
	}
}
