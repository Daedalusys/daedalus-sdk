package blueprint

import (
	"errors"
	"strings"
)

// ErrSecretSourceUnavailable 是 v1 真值获取未接入时的统一错误。kwallet /
// credstore 的 D-Bus / LoadCredential 接入见 issue #033/#034;v1 只做引用校验 +
// 明确的"源不可用"错误(fail-closed:宁可拒绝,也不静默跳过或降级为明文)。
var ErrSecretSourceUnavailable = errors.New("blueprint: secret 源不可用(真值获取未接入,kwallet/credstore 接入归 #033/#034)")

// resolveKwallet 是 kwallet 真值获取的函数缝(注入点)。
//
// v1 恒返回 ErrSecretSourceUnavailable;#033 接入 D-Bus 后在此替换实现。
// 用函数变量而非接口,是为了让测试能直接注入假实现验证 happy path,
// 同时保持包级零依赖。
var resolveKwallet func(path string) (string, error) = func(path string) (string, error) {
	return "", ErrSecretSourceUnavailable
}

// resolveCredstore 是 credstore 真值获取的函数缝(注入点),v1 恒返回 ErrSecretSourceUnavailable。
var resolveCredstore func(name string) (string, error) = func(name string) (string, error) {
	return "", ErrSecretSourceUnavailable
}

// 只有以 secretRefPrefix 开头的输入才是合法引用;任何其他输入(明文、空串)
// 一律 fail-closed 拒绝,防止明文 secret 流入渲染结果或 audit 参数。
const secretRefPrefix = "secret://"

// ValidateSecretRef 校验 secret 引用的**格式与来源合法性**,不做真值获取。Render
// 阶段用它做明文检测:确认格式(前缀/source/path)合法即"声明合法"(真值解析推迟
// 到 apply);fail-closed——非 secret:// 输入(明文、空串)直接拒绝,调用方据此把
// 非 secret:// 的 password 类字段值判为明文 warning。
func ValidateSecretRef(ref string) error {
	if !strings.HasPrefix(ref, secretRefPrefix) {
		return errors.New("blueprint: secret 仅接受 secret:// 引用,拒绝明文: " + ref)
	}
	source, path, err := splitSecretRef(ref)
	if err != nil {
		return err
	}
	switch source {
	case "kwallet", "credstore":
		return validateSecretPath(path)
	default:
		return errors.New("blueprint: 未知 secret 源: " + source)
	}
}

// splitSecretRef 把合法前缀后的引用拆为 (source, path)。缺少 source/path
// 段时返回描述性错误(与前缀残缺的 fail-closed 语义一致)。
func splitSecretRef(ref string) (string, string, error) {
	rest := strings.TrimPrefix(ref, secretRefPrefix)
	source, path, ok := strings.Cut(rest, "/")
	if !ok {
		return "", "", errors.New("blueprint: secret 引用缺少 source/path 段: " + ref)
	}
	return source, path, nil
}

// ResolveSecret 解析 secret 引用,返回真值。支持 secret://kwallet/<path> 与
// secret://credstore/<name>;fail-closed:非 secret:// 输入(明文、空串)、path
// 含 ".."/空字节、未知 source 一律拒绝。v1 真值获取是占位(D-Bus/LoadCredential
// 未接入),先做引用校验 + 明确的"源不可用"错误。
func ResolveSecret(ref string) (string, error) {
	if err := ValidateSecretRef(ref); err != nil {
		return "", err
	}
	source, path, _ := splitSecretRef(ref)
	switch source {
	case "kwallet":
		return resolveKwallet(path)
	case "credstore":
		return resolveCredstore(path)
	default:
		// ValidateSecretRef 已挡未知源,此处仅防御性兜底(不应到达)。
		return "", errors.New("blueprint: 未知 secret 源: " + source)
	}
}

// validateSecretPath 校验 secret 引用路径段,任一约束不满足即返回描述性错误。
func validateSecretPath(path string) error {
	if path == "" {
		return errors.New("blueprint: secret 引用 path 不能为空")
	}
	if strings.Contains(path, "..") {
		return errors.New("blueprint: secret 引用 path 不能包含 '..'")
	}
	if strings.ContainsRune(path, '\x00') {
		return errors.New("blueprint: secret 引用 path 不能包含空字节")
	}
	return nil
}
