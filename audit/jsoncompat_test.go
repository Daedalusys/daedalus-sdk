package audit

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// ---- 以下期望值全部取自本机真实 CPython 3.9 json.dumps 输出(与金样同一环境),
// 属"规范示例"而非金样向量; 金样的字节级断言在 golden_test.go 中重放。 ----

func TestArgsString_MatchesPythonDumps(t *testing.T) {
	cases := []struct {
		name  string
		input string // --args 原始文本
		want  string // Python compute_entry_hash 使用的 args_str
	}{
		{"嵌套排序", `{"b": {"z":1,"a":[1,2]}, "A":"x"}`, `{"A":"x","b":{"a":[1,2],"z":1}}`},
		{"CJK", `{"文件": "测试", "路径": "/home/用户"}`,
			`{"\u6587\u4ef6":"\u6d4b\u8bd5","\u8def\u5f84":"/home/\u7528\u6237"}`},
		{"emoji代理对", `{"s": "😀"}`, `{"s":"\ud83d\ude00"}`},
		{"HTML不转义", `{"h": "<a>&b</a>"}`, `{"h":"<a>&b</a>"}`},
		{"引号反斜杠斜杠", `{"p": "a\"b\\c/d"}`, `{"p":"a\"b\\c/d"}`},
		{"控制字符与DEL", "{\"t\": \"a\\nb\\tc\\u0001\\u007f\"}", `{"t":"a\nb\tc\u0001\u007f"}`},
		{"空对象", `{}`, `{}`},
		{"数组", `[1, "two", true, null]`, `[1,"two",true,null]`},
		{"标量整数", `42`, `42`},
		{"标量布尔", `true`, `true`},
		{"重复键后者胜且原位", `{"k": 1, "k": 2}`, `{"k":2}`},
		{"负零规范化", `-0`, `0`},
		{"码点序键排序", `{"中": "1", "é": "2", "b": "3", "A": "4", "": "5"}`,
			`{"":"5","A":"4","b":"3","\u00e9":"2","\u4e2d":"1"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := ParseValue(tc.input)
			if err != nil {
				t.Fatalf("ParseValue(%q) 失败: %v", tc.input, err)
			}
			if got := v.ArgsString(); got != tc.want {
				t.Fatalf("ArgsString() =\n  %q\n期望\n  %q", got, tc.want)
			}
		})
	}
}

func TestArgsString_RawStringPassthrough(t *testing.T) {
	// audit-log.py:31-32: args 为 str 时直接原文参与哈希(无引号无转义)。
	v := NewString("not valid json { at all")
	if got := v.ArgsString(); got != "not valid json { at all" {
		t.Fatalf("原始字符串 args_str = %q, 期望原文直传", got)
	}
}

func TestLineMode_MatchesPythonDumpsDefaultSeparators(t *testing.T) {
	// json.dumps(record, sort_keys=True): 默认分隔符 ", " 与 ": ", 嵌套同样生效。
	v, err := ParseValue(`{"z": 1, "args": {"b": 2, "a": 1}}`)
	if err != nil {
		t.Fatal(err)
	}
	got := encodeValue(v, modeLine).String()
	want := `{"args": {"a": 1, "b": 2}, "z": 1}`
	if got != want {
		t.Fatalf("line = %q, 期望 %q", got, want)
	}
}

func TestStdoutMode_MatchesPythonIndent2(t *testing.T) {
	// json.dumps(record, indent=2): 不排序、空对象单行、数组逐元素换行缩进。
	v, err := ParseValue(`{"timestamp": "T", "tool": "x", "args": {"b": 1, "a": {}, "c": [1, 2]}}`)
	if err != nil {
		t.Fatal(err)
	}
	got := encodeValue(v, modeStdout).String()
	want := strings.Join([]string{
		`{`,
		`  "timestamp": "T",`,
		`  "tool": "x",`,
		`  "args": {`,
		`    "b": 1,`,
		`    "a": {},`,
		`    "c": [`,
		`      1,`,
		`      2`,
		`    ]`,
		`  }`,
		`}`,
	}, "\n")
	if got != want {
		t.Fatalf("indent2 输出不符:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestParserRejectsMalformed(t *testing.T) {
	bad := []string{
		`{"a": 1,}`,         // 尾逗号
		`{'a': 1}`,          // 单引号
		`{"a": 1} trailing`, // 尾随内容
		`[1, `,              // 未闭合
		`{"a" 1}`,           // 缺冒号
		`tru`,               // 字面量残缺
		`01`,                // 前导零(Python 拒绝)
		`1.`,                // 小数点尾随
	}
	for _, s := range bad {
		if _, err := ParseValue(s); !errors.Is(err, ErrInvalidJSON) {
			t.Errorf("ParseValue(%q) 应报 ErrInvalidJSON, 实得 %v", s, err)
		}
	}
}

func TestParserAcceptsPythonCompatible(t *testing.T) {
	// 前后空白 / 转义 / 大整数保真(Python int 任意精度, 十进制直传字节一致)。
	for _, s := range []string{" \t{} ", `{"a":"é😀"}`, `123456789012345678901234567890`} {
		if _, err := ParseValue(s); err != nil {
			t.Errorf("ParseValue(%q) 失败: %v", s, err)
		}
	}
	v, err := ParseValue(`123456789012345678901234567890`)
	if err != nil {
		t.Fatal(err)
	}
	if got := v.ArgsString(); got != "123456789012345678901234567890" {
		t.Fatalf("大整数 args_str = %q", got)
	}
}

func TestDeepNestingRoundTrip(t *testing.T) {
	// 对抗性: 50 层嵌套 + 落单代理往返。
	depth := 50
	var input strings.Builder
	for i := 0; i < depth; i++ {
		input.WriteString(`{"l": `)
	}
	input.WriteString(`"x"`)
	input.WriteString(strings.Repeat("}", depth))
	v, err := ParseValue(input.String())
	if err != nil {
		t.Fatalf("深度 %d 解析失败: %v", depth, err)
	}
	wantDeep := strings.Repeat(`{"l":`, depth) + `"x"` + strings.Repeat("}", depth)
	if got := encodeValue(v, modeCompact).String(); got != wantDeep {
		t.Fatalf("深嵌套紧凑序列化不符:\n got=%s\nwant=%s", got, wantDeep)
	}
	// 嵌套超过上限按解析失败处理(CLI 回退原始字符串, 与 Python RecursionError 同构)
	tooDeep := strings.Repeat(`{"l": `, maxNestDepth+5) + `"x"` + strings.Repeat("}", maxNestDepth+5)
	if _, err := ParseValue(tooDeep); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("超深嵌套应报 ErrInvalidJSON, 实得 %v", err)
	}
}

func TestLoneSurrogateRoundTrip(t *testing.T) {
	// 落单代理 \ud800 无法以合法 UTF-8 承载 → CESU-8 约定存储, 序列化原样还原。
	v, err := ParseValue(`{"a": "\ud800x"}`)
	if err != nil {
		t.Fatalf("落单代理解析失败: %v", err)
	}
	if got := encodeValue(v, modeCompact).String(); got != `{"a":"\ud800x"}` {
		t.Fatalf("落单代理往返 = %q", got)
	}
	if got := v.ArgsString(); got != `{"a":"\ud800x"}` {
		t.Fatalf("落单代理 args_str = %q", got)
	}
}

func TestFormatTimestamp_QuirkParity(t *testing.T) {
	// datetime.isoformat(): 微秒==0 省略整个小数秒段; 否则恒 6 位; 后缀 +00:00。
	if got := FormatTimestamp(time.Date(2026, 8, 28, 1, 2, 3, 0, time.UTC)); got != "2026-08-28T01:02:03+00:00" {
		t.Fatalf("零微秒 = %q", got)
	}
	if got := FormatTimestamp(time.Date(2026, 8, 28, 1, 2, 3, 5*1000, time.UTC)); got != "2026-08-28T01:02:03.000005+00:00" {
		t.Fatalf("微秒=5(6位补零) = %q", got)
	}
	if got := FormatTimestamp(time.Date(2026, 8, 28, 1, 2, 3, 123456789, time.UTC)); got != "2026-08-28T01:02:03.123456+00:00" {
		t.Fatalf("纳秒截断微秒 = %q", got)
	}
	if got := FormatTimestamp(time.Date(2026, 8, 28, 1, 2, 3, 100*1000, time.FixedZone("CST", 8*3600))); got != "2026-08-27T17:02:03.000100+00:00" {
		t.Fatalf("非 UTC 输入须先归一 = %q", got)
	}
}

func TestComputeEntryHash_PayloadConcatOrder(t *testing.T) {
	// 与 tests/test_mcp_integration.py:344-346 三方一致的独立公式。
	h := ComputeEntryHash("TS", "id", "tool", "{}", "success", GenesisHash)
	// sha256("TSidtool{}success" + "0"*64) 的期望值由独立重算得出:
	want := sha256Hex(t, "TSidtool{}success"+GenesisHash)
	if h != want {
		t.Fatalf("哈希不符: %q vs %q", h, want)
	}
}
