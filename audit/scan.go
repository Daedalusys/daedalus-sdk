package audit

// scan.go —— JSON 标量词法层(字符串/数字), 与 parse.go 的结构层分离。

import (
	"strconv"
	"strings"
)

// parseString 解析 JSON 字符串, 把转义序列解码进 Go 字符串。
//
// 代理码点约定(Go 无法用合法 UTF-8 承载 U+D800-U+DFFF):
//   - 合法代理对 \uDXXX\uDEXXX → 合并标量 → 标准 UTF-8;
//   - 落单代理 → 手写 CESU-8 三字节(ED A0-BF 80-BF), 由 encode.go 的自定义
//     解码路径识别并原样还原为 \udXXX, 保证字节级往返。
func (p *parser) parseString() (string, error) {
	p.pos++ // 开引号
	var b strings.Builder
	for {
		if p.pos >= len(p.src) {
			return "", p.errorf("字符串未闭合")
		}
		c := p.src[p.pos]
		switch {
		case c == '"':
			p.pos++
			return b.String(), nil
		case c == '\\':
			p.pos++
			if p.pos >= len(p.src) {
				return "", p.errorf("转义序列未闭合")
			}
			e := p.src[p.pos]
			switch e {
			case '"':
				b.WriteByte('"')
				p.pos++
			case '\\':
				b.WriteByte('\\')
				p.pos++
			case '/':
				b.WriteByte('/')
				p.pos++
			case 'b':
				b.WriteByte(0x08)
				p.pos++
			case 'f':
				b.WriteByte(0x0c)
				p.pos++
			case 'n':
				b.WriteByte('\n')
				p.pos++
			case 'r':
				b.WriteByte('\r')
				p.pos++
			case 't':
				b.WriteByte('\t')
				p.pos++
			case 'u':
				p.pos++ // 跳过 'u', 游标停在 4 个十六进制位上
				r, err := p.parseHex4()
				if err != nil {
					return "", err
				}
				if utf16IsLowSurrogate(r) {
					return "", p.errorf("落单低代理")
				}
				if utf16IsHighSurrogate(r) {
					// 高代理: 尝试消费紧跟的 \uDCXX 低代理并合并为标量码点;
					// 前视失败则把落单高代理按 CESU-8 存储(encode.go 原样还原)。
					if next, ok := p.consumeSurrogatePair(); ok {
						scalar := 0x10000 + ((r - 0xD800) << 10) + (next - 0xDC00)
						b.WriteRune(scalar)
						continue
					}
					writeCESUSurrogate(&b, r)
					continue
				}
				b.WriteRune(r)
			default:
				return "", p.errorf("未知转义 \\%c", e)
			}
		case c < 0x20:
			// Python strict 模式拒绝裸控制字符
			return "", p.errorf("字符串含裸控制字符")
		default:
			b.WriteByte(c)
			p.pos++
		}
	}
}

// parseHex4 读取当前 \u 后的 4 个十六进制位并返回码点。
func (p *parser) parseHex4() (rune, error) {
	if p.pos+4 > len(p.src) {
		return 0, p.errorf("\\u 截断")
	}
	v, err := strconv.ParseUint(p.src[p.pos:p.pos+4], 16, 32)
	if err != nil {
		return 0, p.errorf("非法 \\u 十六进制位")
	}
	p.pos += 4
	return rune(v), nil
}

// consumeSurrogatePair 尝试消费紧跟高代理之后的 \uDCXX 低代理转义。
// 成功时游标前移并返回低代理码点; 源串中不存在配对时不移动游标返回 false。
func (p *parser) consumeSurrogatePair() (rune, bool) {
	if p.pos+6 > len(p.src) || p.src[p.pos] != '\\' || p.src[p.pos+1] != 'u' {
		return 0, false
	}
	v, err := strconv.ParseUint(p.src[p.pos+2:p.pos+6], 16, 32)
	if err != nil || !utf16IsLowSurrogate(rune(v)) {
		return 0, false
	}
	p.pos += 6
	return rune(v), true
}

func utf16IsHighSurrogate(r rune) bool { return r >= 0xD800 && r <= 0xDBFF }
func utf16IsLowSurrogate(r rune) bool  { return r >= 0xDC00 && r <= 0xDFFF }

// writeCESUSurrogate 把落单代理码点按 CESU-8(三字节约定)写入 builder。
func writeCESUSurrogate(b *strings.Builder, r rune) {
	b.WriteByte(0xE0 | byte(r>>12))
	b.WriteByte(0x80 | byte((r>>6)&0x3F))
	b.WriteByte(0x80 | byte(r&0x3F))
}

// parseNumber 按 JSON 数字文法扫描 token 并做 Python 风格规范化。
func (p *parser) parseNumber() (*Value, error) {
	start := p.pos
	if p.pos < len(p.src) && p.src[p.pos] == '-' {
		p.pos++
	}
	digits := 0
	for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
		p.pos++
		digits++
		// Python 数字文法 (?:0|[1-9]\d*): "0" 后不允许再跟数字("01" 只消费 "0",
		// 尾随 "1" 由顶层的尾随内容检查报错, 与 Python 的 Extra data 同构)。
		if digits == 1 && p.src[p.pos-1] == '0' {
			break
		}
	}
	if digits == 0 {
		p.pos = start
		return nil, p.errorf("非法数字")
	}
	isFloat := false
	if p.pos < len(p.src) && p.src[p.pos] == '.' {
		isFloat = true
		p.pos++
		frac := 0
		for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
			p.pos++
			frac++
		}
		if frac == 0 {
			p.pos = start
			return nil, p.errorf("小数点后缺数字")
		}
	}
	if p.pos < len(p.src) && (p.src[p.pos] == 'e' || p.src[p.pos] == 'E') {
		isFloat = true
		p.pos++
		if p.pos < len(p.src) && (p.src[p.pos] == '+' || p.src[p.pos] == '-') {
			p.pos++
		}
		expDigits := 0
		for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
			p.pos++
			expDigits++
		}
		if expDigits == 0 {
			p.pos = start
			return nil, p.errorf("指数缺数字")
		}
	}
	tok := p.src[start:p.pos]
	if !isFloat {
		// 整数路径: 规范化以复刻 Python "-0" → 0 → "0" 的行为;
		// 超出 int64 的大整数 Python 原样输出十进制, 保留 token 即字节一致。
		if n, err := strconv.ParseInt(tok, 10, 64); err == nil {
			tok = strconv.FormatInt(n, 10)
		}
	}
	// 浮点: 保留原始 token(Python 端 repr 重排超出任务范围; 测试约定避免浮点)
	return &Value{kind: kindNumber, text: tok}, nil
}
