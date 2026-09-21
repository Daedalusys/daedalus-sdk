package audit

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidJSON 是解析失败的哨兵错误。
//
// CLI 语义与 audit-log.py:169-172 一致: --args 解析失败时按原始字符串处理,
// 因此调用方用 errors.Is(err, ErrInvalidJSON) 判别, 而不是依赖错误文案。
var ErrInvalidJSON = errors.New("audit: 非法 JSON")

// maxNestDepth 限制容器嵌套深度。
//
// CPython 的 json.loads 在 ~1000 层嵌套时触发 RecursionError(被 CLI 的
// except 捕获后退化为原始字符串); Go 没有可控的栈溢出, 这里取 1000 层封顶,
// 超限按解析失败处理, CLI 走原始字符串回退——行为与 Python 侧同构。
const maxNestDepth = 1000

// ParseValue 解析一段 JSON 文本(任意顶层值: 对象/数组/字符串/数字/布尔/null)。
//
// 与 Python json.loads(默认 strict) 对齐的细节:
//   - 首尾空白允许(' ' \t \n \r), 尾随内容报错;
//   - 字符串必须双引号, 不接受 NaN/Infinity 字面量, 不接受单引号/注释;
//   - \uXXXX 转义: 合法代理对合并编码为 UTF-8; 落单代理以 CESU-8 三字节约定
//     存储(Go 字符串无法承载标量代理), 序列化时原样还原为 \udXXX;
//   - 对象重复键: 后值覆盖前值且保持首次出现的插入位(Python dict 语义)。
func ParseValue(text string) (*Value, error) {
	p := &parser{src: text}
	p.skipSpace()
	v, err := p.parseValue(0)
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos != len(p.src) {
		return nil, p.errorf("尾随内容")
	}
	return v, nil
}

type parser struct {
	src string
	pos int
}

func (p *parser) errorf(format string, args ...any) error {
	return &parseError{
		msg: fmt.Sprintf("audit: 非法 JSON (offset %d): %s", p.pos, fmt.Sprintf(format, args...)),
	}
}

// parseError 携带位置信息, 通过 Unwrap 挂到 ErrInvalidJSON 哨兵上,
// 调用方用 errors.Is(err, ErrInvalidJSON) 判别原始字符串回退路径。
type parseError struct{ msg string }

func (e *parseError) Error() string { return e.msg }
func (e *parseError) Unwrap() error { return ErrInvalidJSON }

func (p *parser) skipSpace() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) parseValue(depth int) (*Value, error) {
	if depth > maxNestDepth {
		return nil, p.errorf("嵌套过深")
	}
	if p.pos >= len(p.src) {
		return nil, p.errorf("意外结束")
	}
	switch c := p.src[p.pos]; {
	case c == '{':
		return p.parseObject(depth)
	case c == '[':
		return p.parseArray(depth)
	case c == '"':
		s, err := p.parseString()
		if err != nil {
			return nil, err
		}
		return &Value{kind: kindString, text: s}, nil
	case c == 't':
		return p.parseLiteral("true", &Value{kind: kindBool, b: true})
	case c == 'f':
		return p.parseLiteral("false", &Value{kind: kindBool, b: false})
	case c == 'n':
		return p.parseLiteral("null", &Value{kind: kindNull})
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	default:
		return nil, p.errorf("意外的字符 %q", string(rune(c)))
	}
}

func (p *parser) parseLiteral(lit string, v *Value) (*Value, error) {
	if !strings.HasPrefix(p.src[p.pos:], lit) {
		return nil, p.errorf("期望 %s", lit)
	}
	p.pos += len(lit)
	return v, nil
}

func (p *parser) parseObject(depth int) (*Value, error) {
	p.pos++ // '{'
	obj := NewObject()
	p.skipSpace()
	if p.pos < len(p.src) && p.src[p.pos] == '}' {
		p.pos++
		return obj, nil
	}
	for {
		p.skipSpace()
		if p.pos >= len(p.src) || p.src[p.pos] != '"' {
			return nil, p.errorf("对象键必须为字符串")
		}
		key, err := p.parseString()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.pos >= len(p.src) || p.src[p.pos] != ':' {
			return nil, p.errorf("期望 ':'")
		}
		p.pos++
		p.skipSpace()
		val, err := p.parseValue(depth + 1)
		if err != nil {
			return nil, err
		}
		obj.set(key, val)
		p.skipSpace()
		if p.pos < len(p.src) {
			switch p.src[p.pos] {
			case ',':
				p.pos++
				continue
			case '}':
				p.pos++
				return obj, nil
			}
		}
		return nil, p.errorf("期望 ',' 或 '}'")
	}
}

func (p *parser) parseArray(depth int) (*Value, error) {
	p.pos++ // '['
	arr := &Value{kind: kindArray}
	p.skipSpace()
	if p.pos < len(p.src) && p.src[p.pos] == ']' {
		p.pos++
		return arr, nil
	}
	for {
		p.skipSpace()
		val, err := p.parseValue(depth + 1)
		if err != nil {
			return nil, err
		}
		arr.elems = append(arr.elems, val)
		p.skipSpace()
		if p.pos < len(p.src) {
			switch p.src[p.pos] {
			case ',':
				p.pos++
				continue
			case ']':
				p.pos++
				return arr, nil
			}
		}
		return nil, p.errorf("期望 ',' 或 ']'")
	}
}
