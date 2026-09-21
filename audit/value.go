// Package audit 实现与 audit-log.py 字节级兼容的哈希链仅追加审计日志。
//
// 本包是三层安全边界中"证据与验证边界"(Layer 3)的 Go 落地:
//   - SHA-256 哈希链: payload = timestamp+identity+tool+args_str+outcome+prev_hash,
//     字段顺序与 audit-log.py:36 完全一致, 严禁改动;
//   - JSON 规范化: 复刻 Python json.dumps(sort_keys=True, separators=..., ensure_ascii=True)
//     的字节级行为(非 ASCII → \uXXXX 小写十六进制、码点序键排序、`<>&` 与 `/` 不转义);
//   - 并发保护: 对日志文件本身 syscall.Flock(LOCK_EX), 等价 Python fcntl.flock(fd, LOCK_EX)。
//
// 金样向量位于 testdata/golden.jsonl, 由真实 Python CLI 连续追加生成,
// 测试重放每一条并断言 entry_hash 逐字节相等。
package audit

import "strconv"

// valueKind 是 JSON 值的判别标签(替代 interface{} 逃逸, 保证解析后无 any 类型)。
type valueKind uint8

const (
	kindNull   valueKind = iota // JSON null
	kindBool                    // JSON true/false
	kindString                  // JSON 字符串(原文; 可能含 CESU-8 代理编码, 见 encode.go)
	kindNumber                  // JSON 数字(规范化十进制文本; 浮点保留原始 token)
	kindArray                   // JSON 数组
	kindObject                  // JSON 对象(键按插入序保存, 等价 Python dict)
)

// Member 是 JSON 对象中的一个键值对。
//
// 键序必须保留插入顺序: Python json.loads 产出 dict(保序),
// CLI stdout 的 json.dumps(record, indent=2) 未指定 sort_keys,
// 因此嵌套 args 的输出顺序 = 输入文档顺序。
type Member struct {
	Key string
	Val *Value
}

// Value 是 Python json.loads 兼容的 JSON 值模型。
//
// 设计约束(决策 19 / 任务 2 规范 §4.1):
//   - Go 的 encoding/json 默认保留非 ASCII 原文且转义 `<>&`, 直接调用会断链,
//     因此本包自带手写解析器(parse.go)与序列化器(encode.go);
//   - kindNumber 的 text 为规范化十进制(整数路径, 含 Python "-0"→"0" 怪癖);
//     含小数点/指数的浮点保留原始 token——测试 payload 约定只用整数与字符串,
//     浮点的 Python repr 复刻超出本任务范围。
type Value struct {
	kind    valueKind
	text    string // kindString: 字符串原文; kindNumber: 数字文本
	b       bool   // kindBool
	elems   []*Value
	members []Member // kindObject: 插入序键值对
}

// NewObject 返回一个空 JSON 对象, 等价 Python 端的 args = {}。
func NewObject() *Value {
	return &Value{kind: kindObject}
}

// NewString 返回一个 JSON 字符串值。
//
// CLI 的 --args 传入非法 JSON 时按原始字符串处理(audit-log.py:171-172),
// 此时 args 参与哈希的 args_str 是该字符串本身(不带引号), 见 ArgsString。
func NewString(s string) *Value {
	return &Value{kind: kindString, text: s}
}

// NewInt64 返回一个 JSON 整数值: 无引号规范化十进制文本, 与解析器整数路径
// (scan.go parseNumber 的 strconv.FormatInt 规范化)逐字节一致, 即
// Python json.dumps(int) 的上线形态。kindNumber 此前仅由解析器产出,
// 本函数是唯一的导出生成器(tx_step 等数值记录字段专用)。
func NewInt64(n int64) *Value {
	return &Value{kind: kindNumber, text: strconv.FormatInt(n, 10)}
}

// IsObject 报告该值是否为 JSON 对象。
func (v *Value) IsObject() bool { return v.kind == kindObject }

// Lookup 返回对象中键 key 对应的成员值; 不存在时返回 (nil, false)。
func (v *Value) Lookup(key string) (*Value, bool) {
	if v == nil || v.kind != kindObject {
		return nil, false
	}
	for i := range v.members {
		if v.members[i].Key == key {
			return v.members[i].Val, true
		}
	}
	return nil, false
}

// LookupString 返回对象中键 key 的字符串值文本; 键不存在或值非字符串时 ok 为 false。
//
// 注意: 与 Python get_last_entry_hash 中 str(data["entry_hash"]) 的宽容行为不同,
// 本方法只接受字符串 kind——链上的哈希字段永远是 str, 非字符串视为损坏。
func (v *Value) LookupString(key string) (string, bool) {
	got, ok := v.Lookup(key)
	if !ok || got == nil || got.kind != kindString {
		return "", false
	}
	return got.text, true
}

// set 追加或原位更新对象键值对。
//
// 原位更新复刻 Python dict 语义: '{"k":1,"k":2}' 解析后 "k" 仍在首位且值为 2
// (json.loads 后 dumps 输出 {"k": 2})。仅供解析器与内部记录组装使用。
func (v *Value) set(key string, val *Value) {
	for i := range v.members {
		if v.members[i].Key == key {
			v.members[i].Val = val
			return
		}
	}
	v.members = append(v.members, Member{Key: key, Val: val})
}

// setIfNonEmpty 条件发射: 仅当值"有内容"时才写入键。
//
// 抑制规则(发射端防漂移, 与 lastNonTxRecord/Verify 的回读判据配套):
//   - val == nil → no-op;
//   - kindString 且 text 为空 → no-op(空字符串键不落盘);
//   - 其余 kind(含 NewInt64(0) 这类无"空值"形态的数字)→ 恒 set。
//
// 仅供 Record.toValue 的三个 tx 扩展键使用: 非 tx 记录据此保持原 8 键,
// 磁盘行与金样逐字节一致(载荷扩展见 payloadFor, 判据同为 TxID 非空)。
func (v *Value) setIfNonEmpty(key string, val *Value) {
	if val == nil {
		return
	}
	if val.kind == kindString && val.text == "" {
		return
	}
	v.set(key, val)
}

// ArgsString 计算参与哈希的 args_str, 字节级复刻 audit-log.py:30-34:
//
//	if isinstance(args, str): args_str = args          # 原始字符串直接参与拼接
//	else: args_str = json.dumps(args, sort_keys=True, separators=(",", ":"))
//
// 即: 字符串 kind 返回其原文(无引号、无转义); 其余 kind 用紧凑分隔符 +
// 递归键排序 + ensure_ascii(非 ASCII → \uXXXX 小写十六进制)序列化。
func (v *Value) ArgsString() string {
	if v == nil {
		return "{}"
	}
	if v.kind == kindString {
		return v.text
	}
	buf := encodeValue(v, modeCompact)
	return buf.String()
}
