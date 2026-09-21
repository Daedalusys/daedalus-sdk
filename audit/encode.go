package audit

import (
	"bytes"
	"encoding/hex"
	"slices"
	"unicode/utf8"
)

// encMode 描述一次 JSON 序列化的三个正交选项, 对应 Python json.dumps 的参数组合:
//
//	modeCompact: json.dumps(args, sort_keys=True, separators=(",", ":"))  → 哈希 args_str
//	modeLine:    json.dumps(record, sort_keys=True)  默认分隔符             → 日志行
//	modeStdout:  json.dumps(record, indent=2)  保序                        → CLI 标准输出
//
// 三者都隐含 ensure_ascii=True(audit-log.py 全部使用默认值)。
type encMode struct {
	sortKeys bool
	itemSep  string // 元素间分隔符(indent 模式下换行由缩进逻辑接管)
	keySep   string // 键与值之间分隔符
	indent   int    // <=0 表示不缩进
}

var (
	modeCompact = encMode{sortKeys: true, itemSep: ",", keySep: ":", indent: 0}
	modeLine    = encMode{sortKeys: true, itemSep: ", ", keySep: ": ", indent: 0}
	modeStdout  = encMode{sortKeys: false, itemSep: ",", keySep: ": ", indent: 2}
)

// lowerHex 复用标准库小写十六进制编码, 复刻 Python "%04x" 输出。
var lowerHex = hex.EncodeToString

// encodeValue 便捷入口: 以指定模式序列化 v 并返回文本缓冲。
func encodeValue(v *Value, m encMode) *bytes.Buffer {
	buf := &bytes.Buffer{}
	writeValue(buf, v, m, 0)
	return buf
}

// encodeValue 把 v 序列化为 Python json.dumps 语义的 JSON 文本, 写入 buf。
// depth 为当前容器(开括号所在)的缩进层级。
func writeValue(buf *bytes.Buffer, v *Value, m encMode, depth int) {
	switch v.kind {
	case kindNull:
		buf.WriteString("null")
	case kindBool:
		if v.b {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case kindString:
		writeEscapedString(buf, v.text)
	case kindNumber:
		buf.WriteString(v.text)
	case kindArray:
		buf.WriteByte('[')
		for i, el := range v.elems {
			writeElementSep(buf, m, depth, i)
			writeValue(buf, el, m, depth+1)
		}
		writeContainerClose(buf, m, depth, len(v.elems), ']')
	case kindObject:
		members := v.members
		if m.sortKeys {
			// UTF-8 字节序 == Unicode 码点序, 与 Python sorted() 的 str 比较一致
			members = slices.Clone(v.members)
			slices.SortStableFunc(members, func(a, b Member) int {
				return bytes.Compare([]byte(a.Key), []byte(b.Key))
			})
		}
		buf.WriteByte('{')
		for i, mem := range members {
			writeElementSep(buf, m, depth, i)
			writeEscapedString(buf, mem.Key)
			buf.WriteString(m.keySep)
			writeValue(buf, mem.Val, m, depth+1)
		}
		writeContainerClose(buf, m, depth, len(members), '}')
	}
}

// writeElementSep 输出第 i(>0) 个元素前的分隔符, indent 模式追转换行+缩进。
// Python 细节: indent 模式下 item 分隔符为 "," (默认 ", " 的尾空白被剥离)。
func writeElementSep(buf *bytes.Buffer, m encMode, depth, i int) {
	if i > 0 {
		buf.WriteString(m.itemSep)
	}
	if m.indent > 0 {
		buf.WriteByte('\n')
		buf.Write(bytes.Repeat([]byte(" "), m.indent*(depth+1)))
	}
}

// writeContainerClose 输出容器收尾。Python 细节: 空容器恒 "{}"/"[]", 不跨行。
func writeContainerClose(buf *bytes.Buffer, m encMode, depth, n int, closeByte byte) {
	if n > 0 && m.indent > 0 {
		buf.WriteByte('\n')
		buf.Write(bytes.Repeat([]byte(" "), m.indent*depth))
	}
	buf.WriteByte(closeByte)
}

// writeEscapedString 复刻 CPython c_encode_basestring_ascii(ensure_ascii=True):
//
//   - '"' → \" , '\\' → \\ ;
//   - 0x08/0x09/0x0a/0x0c/0x0d → \b \t \n \f \r ; 其余 <0x20 及 0x7f → \u00xx;
//   - 0x20..0x7e 原样输出: `<>&` 与 `/` 不转义(Go encoding/json 会转义 `<>&` → 断链, 故必须手写);
//   - >0x7e 一律 \uXXXX 小写十六进制; BMP 外码点拆 UTF-16 代理对两个 \uXXXX;
//   - CESU-8 落单代理(见 parse.go)还原为对应 \udXXX;
//   - 非法 UTF-8 字节按 surrogateescape 约定输出 \udcXX——与 Python 侧
//     argv 解码(str.from_entries surrogateescape)后的 dumps 结果字节一致。
func writeEscapedString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"':
			buf.WriteString(`\"`)
			i++
		case c == '\\':
			buf.WriteString(`\\`)
			i++
		case c == 0x08:
			buf.WriteString(`\b`)
			i++
		case c == 0x09:
			buf.WriteString(`\t`)
			i++
		case c == 0x0a:
			buf.WriteString(`\n`)
			i++
		case c == 0x0c:
			buf.WriteString(`\f`)
			i++
		case c == 0x0d:
			buf.WriteString(`\r`)
			i++
		case c < 0x20 || c == 0x7f:
			buf.WriteString(`\u00`)
			buf.WriteString(lowerHex([]byte{c})[0:2])
			i++
		case c < 0x7f:
			buf.WriteByte(c)
			i++
		case isCESUSurrogateAt(s, i):
			// CESU-8 三字节代理 → \udXXX
			cp := rune(s[i]&0x0F)<<12 | rune(s[i+1]&0x3F)<<6 | rune(s[i+2]&0x3F)
			writeU16(buf, cp)
			i += 3
		default:
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size == 1 {
				// 非法 UTF-8 字节: surrogateescape → U+DC00+b
				buf.WriteString(`\udc`)
				buf.WriteString(lowerHex([]byte{s[i]})[0:2])
				i++
				continue
			}
			if r <= 0xFFFF {
				writeU16(buf, r)
			} else {
				// BMP 外 → UTF-16 代理对, 两次 \uXXXX
				cp := r - 0x10000
				writeU16(buf, 0xD800+(cp>>10))
				writeU16(buf, 0xDC00+(cp&0x3FF))
			}
			i += size
		}
	}
	buf.WriteByte('"')
}

func writeU16(buf *bytes.Buffer, cp rune) {
	buf.WriteString(`\u`)
	buf.WriteString(lowerHex([]byte{byte(cp >> 8), byte(cp & 0xFF)}))
}

// isCESUSurrogateAt 报告 s[i:i+3] 是否为 U+D800..U+DFFF 的 CESU-8 编码
// (首字节 0xED + 第二字节 0xA0..0xBF——合法 UTF-8 解码器会拒绝该序列, 可安全判别)。
func isCESUSurrogateAt(s string, i int) bool {
	return i+2 < len(s) && s[i] == 0xED && s[i+1] >= 0xA0 && s[i+1] <= 0xBF &&
		s[i+2] >= 0x80 && s[i+2] <= 0xBF
}
