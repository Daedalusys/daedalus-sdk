// 校验逻辑独立成文件:envelope.go 装类型与构造/查询方法,validate.go 装
// Validate 方法,二者互不交叉引用,改一处不需扫另一处。
package objectmodel

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

// uidMaxLen 与 k8s apiserver 同:留连接空间(多个 UID 拼成路径不超 unix NAME_MAX)。
const uidMaxLen = 253

// 控制字符检测:0x00–0x1f 与 0x7f。
func hasControlChar(s string) bool {
	for _, r := range s {
		if r == 0x7f || unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// Validate 聚合 Metadata 全部缺陷一次性返回(fail-closed,与 Resource.Validate 风格一致)。
func (m Metadata) Validate() error {
	var problems []string

	switch {
	case m.Name == "":
		problems = append(problems, `字段 "name" 缺失:必填`)
	default:
		if strings.IndexByte(m.Name, 0) >= 0 {
			problems = append(problems, `字段 "name" 非法:不得包含空字节(\0)`)
		}
		if strings.ContainsRune(m.Name, '/') {
			problems = append(problems, `字段 "name" 非法:不得包含路径分隔符 '/'`)
		}
		if strings.Contains(m.Name, "..") {
			problems = append(problems, `字段 "name" 非法:不得包含路径回溯段 ".."`)
		}
	}

	if m.UID != "" {
		if hasControlChar(m.UID) {
			problems = append(problems, `字段 "uid" 非法:不得包含控制字符`)
		}
		if len(m.UID) > uidMaxLen {
			problems = append(problems, fmt.Sprintf(`字段 "uid" 非法:长度 %d 超过上限 %d`, len(m.UID), uidMaxLen))
		}
	}
	if m.ResourceVersion != "" && strings.IndexByte(m.ResourceVersion, 0) >= 0 {
		problems = append(problems, `字段 "resource_version" 非法:不得包含空字节(\0)`)
	}

	seenFinalizers := make(map[Finalizer]struct{}, len(m.Finalizers))
	for i, f := range m.Finalizers {
		if f == "" {
			problems = append(problems, fmt.Sprintf(`字段 "finalizers[%d]" 非法:不得为空字符串`, i))
			continue
		}
		if strings.IndexByte(string(f), 0) >= 0 {
			problems = append(problems, fmt.Sprintf(`字段 "finalizers[%d]" 非法:不得包含空字节(\0)`, i))
			continue
		}
		if _, dup := seenFinalizers[f]; dup {
			problems = append(problems, fmt.Sprintf(`字段 "finalizers" 非法:finalizer %q 重复`, f))
		}
		seenFinalizers[f] = struct{}{}
	}

	for i, or := range m.OwnerReferences {
		prefix := fmt.Sprintf("owner_references[%d]", i)
		if or.Kind == "" {
			problems = append(problems, fmt.Sprintf(`字段 "%s.kind" 缺失:必填`, prefix))
		} else if !validKind(or.Kind) {
			problems = append(problems, fmt.Sprintf(`字段 "%s.kind" 非法:%q 不在资源类别枚举内`, prefix, or.Kind))
		}
		switch {
		case or.Name == "":
			problems = append(problems, fmt.Sprintf(`字段 "%s.name" 缺失:必填`, prefix))
		default:
			if strings.IndexByte(or.Name, 0) >= 0 {
				problems = append(problems, fmt.Sprintf(`字段 "%s.name" 非法:不得包含空字节(\0)`, prefix))
			}
			if strings.ContainsRune(or.Name, '/') {
				problems = append(problems, fmt.Sprintf(`字段 "%s.name" 非法:不得包含路径分隔符 '/'`, prefix))
			}
			if strings.Contains(or.Name, "..") {
				problems = append(problems, fmt.Sprintf(`字段 "%s.name" 非法:不得包含路径回溯段 ".."`, prefix))
			}
		}
		if or.UID != "" {
			if hasControlChar(or.UID) {
				problems = append(problems, fmt.Sprintf(`字段 "%s.uid" 非法:不得包含控制字符`, prefix))
			}
			if len(or.UID) > uidMaxLen {
				problems = append(problems, fmt.Sprintf(`字段 "%s.uid" 非法:长度 %d 超过上限 %d`, prefix, len(or.UID), uidMaxLen))
			}
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("objectmodel: Metadata 校验失败: %s", strings.Join(problems, "; "))
	}
	return nil
}

// Validate 聚合 Object 全部缺陷一次性返回。顺序:Kind → Metadata → Spec。
// Spec 走 json.Valid 空字符串视为合法(零值形态);非空但非合法 JSON 即拒。
func (o Object) Validate() error {
	var problems []string

	if o.Kind == "" {
		problems = append(problems, `字段 "kind" 缺失:必填`)
	} else if !validKind(o.Kind) {
		problems = append(problems, fmt.Sprintf(`字段 "kind" 非法:%q 不在资源类别枚举内`, o.Kind))
	}

	if err := o.Metadata.Validate(); err != nil {
		problems = append(problems, err.Error())
	}

	if len(o.Spec) > 0 && !json.Valid(o.Spec) {
		problems = append(problems, `字段 "spec" 非法:非合法 JSON`)
	}

	if len(problems) > 0 {
		return fmt.Errorf("objectmodel: Object 校验失败: %s", strings.Join(problems, "; "))
	}
	return nil
}
