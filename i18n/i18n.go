// Package i18n 提供 Go 侧本地化字符串查询,与 copilot 插件的 i18n.ts
// 行为对齐但实现完全独立(Go 无 import.meta.url,改用 //go:embed
// 把 locales/*.json 嵌入二进制)。
//
// 双端共享同一份扁平 JSON 格式({"key": "value"} 一层,无嵌套命名空间):
// TS 侧从 i18n/<locale>.json 读盘,Go 侧从嵌入 FS 读;P1a 阶段两侧 key
// 命名空间相互独立——Go 用 host.* 前缀(表格表头、错误文案),TS 用
// 现有扁平 key(confirm.prompt 等),互不重叠,漂移由
// scripts/plugin-i18n-sync.sh --check-cross 守门。
//
// locale 探测优先级:LC_ALL > LANG > en_US 兜底;
// 解析 POSIX 形式("zh_CN.UTF-8" → "zh_CN",下划线保留不转连字符)。
// fallback 链:精确("zh_CN")→ 语言级("zh")→ 兜底("en_US"),每级
// 缺文件自动降级。未命中 key 返回 key 字符串本身(永不 panic);
// 占位符 {0} {1} 按参数序号替换,缺参或越界用空串。
//
// Init 一次定死,不做热重载(P1a 决策);Init 未调用时 T() lazy 触发
// 一次 Init,防止裸调用返回裸 key。
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

//go:embed locales/*.json
var localesFS embed.FS

// defaultLocale 是 en_US 兜底 locale,与 TS 侧 i18n.ts 一致。
const defaultLocale = "en_US"

// placeholderRe 匹配 {0} {1} 等 printf 风格序号占位符。
var placeholderRe = regexp.MustCompile(`\{(\d+)\}`)

// locales 是已加载的翻译表:外层 locale,内层 key → 译文。
var (
	localesMu sync.RWMutex
	locales   = map[string]map[string]string{}
)

// Locale() 返回值的缓存;Init 后定死。
var (
	currentMu sync.RWMutex
	current   string
)

// Init 初始化包级 locale 状态:探测 env 并加载对应 locale json。
// 推荐在 main 启动时调一次。多次调用安全(幂等):已初始化直接返回。
func Init() {
	currentMu.Lock()
	defer currentMu.Unlock()
	if current != "" {
		return
	}
	loc := Detect()
	localesMu.Lock()
	locales[loc] = loadLocale(loc)
	localesMu.Unlock()
	current = loc
}

// Detect 探测当前 locale(仅计算不加载):LC_ALL > LANG > "en_US"。
// 解析 POSIX 形式:去 codeset 与 modifier("zh_CN.UTF-8" → "zh_CN",
// "zh_CN@pinyin" → "zh_CN"),下划线保留不转连字符(与 TS 侧一致)。
func Detect() string {
	raw := os.Getenv("LC_ALL")
	if raw == "" {
		raw = os.Getenv("LANG")
	}
	if raw == "" {
		return defaultLocale
	}
	base := strings.Split(raw, ".")[0]
	if i := strings.IndexByte(base, '@'); i >= 0 {
		base = base[:i]
	}
	base = strings.TrimSpace(base)
	if base == "" {
		return defaultLocale
	}
	return base
}

// Locale 返回 Init 后生效的 locale;未 Init 时返回 Detect() 结果。
func Locale() string {
	currentMu.RLock()
	defer currentMu.RUnlock()
	if current != "" {
		return current
	}
	return Detect()
}

// ResetForTest 仅测试使用:清空包级 locale 状态(current 与已加载表),
// 让下一个 Init/T 按当前 env 重新探测。生产代码绝不可调用。
func ResetForTest() {
	currentMu.Lock()
	current = ""
	currentMu.Unlock()
	localesMu.Lock()
	locales = map[string]map[string]string{}
	localesMu.Unlock()
}

// T 按当前 locale 查 key,替换 {N} 占位符。永远不 panic:
//   - 未命中 key → 返回 key 本身
//   - 缺参 / 越界 / 参数为 nil → 该占位符替换为空串
//   - Init 未调用 → lazy 触发一次 Init
//
// 查找顺序:当前 locale → 语言级(如 zh_CN → zh)→ en_US 兜底;均未命中
// 返 key 本身。
func T(key string, args ...any) string {
	currentMu.RLock()
	loc := current
	currentMu.RUnlock()
	if loc == "" {
		Init()
		currentMu.RLock()
		loc = current
		currentMu.RUnlock()
	}

	localesMu.RLock()
	msg, ok := lookup(loc, key)
	localesMu.RUnlock()
	if !ok {
		return key
	}
	return format(msg, args...)
}

// lookup 按 fallback 链在已加载的 locale 表中查 key,必要时按链加载文件。
// 调用方必须持有 localesMu 读锁或写锁。
func lookup(loc, key string) (string, bool) {
	for {
		dict, ok := locales[loc]
		if !ok {
			dict = loadLocale(loc)
			locales[loc] = dict
		}
		if v, ok := dict[key]; ok {
			return v, true
		}
		// fallback 链:精确 → 语言级("zh_CN" → "zh")→ "en_US" → 终止
		switch {
		case loc != defaultLocale && strings.Contains(loc, "_"):
			loc = loc[:strings.IndexByte(loc, '_')]
		case loc != defaultLocale:
			loc = defaultLocale
		default:
			return "", false
		}
	}
}

// loadLocale 从嵌入 FS 读 locales/<loc>.json 并解析为扁平 map;
// 文件缺失或 JSON 损坏按空表处理(调用方继续走 fallback 链)。
func loadLocale(loc string) map[string]string {
	empty := map[string]string{}
	data, err := localesFS.ReadFile("locales/" + loc + ".json")
	if err != nil {
		return empty
	}
	dict := map[string]string{}
	if err := json.Unmarshal(data, &dict); err != nil {
		return empty
	}
	return dict
}

// format 按序号替换 {N} 占位符:N 越界或参数为 nil 用空串。
// 与 TS 侧 t() 的 replace(/\{(\d+)\}/g, ...) 行为一致(无参时占位符
// 一律清空)。
func format(msg string, args ...any) string {
	return placeholderRe.ReplaceAllStringFunc(msg, func(m string) string {
		n, err := strconv.Atoi(m[1 : len(m)-1])
		if err != nil || n < 0 || n >= len(args) {
			return ""
		}
		v := args[n]
		if v == nil {
			return ""
		}
		return fmt.Sprint(v)
	})
}
