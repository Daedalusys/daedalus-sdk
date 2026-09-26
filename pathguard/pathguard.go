// Package pathguard 为 fs 能力服务器提供严格目录白名单的路径校验。
//
// 本包是生产 Deno 实现
// daedalus/files/system/opt/daedalus/deno/fs_server.ts 的逐条移植。
// Go 版本没有 Deno 的运行时权限标志(--allow-read/--allow-write),
// 因此白名单、规范化与符号链接解析全部以 in-code 方式强制执行。
package pathguard

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// AllowedDirs 是 fs 服务器可访问的目录白名单,逐字对齐 fs_server.ts 的
// ALLOWED_DIRS。任何增删改都必须先经过规格评审(测试会锁定其内容)。
//
// 单一事实源:本变量只是**内置默认/兜底**;服务器启动时
// 应经 policy.LoadOrDefault + WithAllowedDirs 注入 shared/policy.toml。
var AllowedDirs = []string{"/home", "/var/log", "/tmp"}

// WithAllowedDirs 用策略文件解析出的目录白名单覆盖 AllowedDirs(深拷贝,调用方
// 后续改动不反向渗透);只在服务器启动时调用一次,运行期不改。
func WithAllowedDirs(dirs []string) {
	AllowedDirs = slices.Clone(dirs)
}

// ValidatePath 依据白名单校验路径,并返回符号链接解析后的规范绝对路径。
//
// 规则(移植自 fs_server.ts):
//  1. 必须是非空字符串;
//  2. 拒绝包含空字节(\0)的路径;
//  3. 必须是以 '/' 开头的绝对路径;
//  4. 以 realpath(3) 语义规范化:目标存在时完整解析符号链接;
//     目标不存在时逐级解析已存在的最深父目录,剩余部分手动去掉 ./..;
//  5. 与 AllowedDirs 前缀匹配时必须带 '/' 边界(因此 /home2 被拒绝)。
//
// write 参数对应 ts 形参 _write:Deno 实现中它不参与任何判断,
// 此处仅为接口形态一致而保留(读取与写入执行同一套白名单规则)。
func ValidatePath(pathStr string, write bool) (string, error) {
	_ = write // 与 fs_server.ts 一致:write 标志不影响校验结果。

	if pathStr == "" {
		return "", errors.New("Path must be a non-empty string.")
	}
	if strings.ContainsRune(pathStr, 0) {
		return "", errors.New("Invalid path: null bytes are forbidden.")
	}
	if !strings.HasPrefix(pathStr, "/") {
		return "", fmt.Errorf("Invalid path '%s': only absolute paths are permitted.", pathStr)
	}

	// 尽可能规范化为 realpath;目标不存在时回退到"解析最深现存父目录 +
	// 词法规范化余部"(对应 fs_server.ts 的 realPath 失败回退,
	// 并封堵"末段不存在但父目录是逃逸符号链接"的漏洞)。
	canonicalPath := realpathLike(pathStr)

	for _, allowed := range AllowedDirs {
		allowedCanonical := realpathLike(allowed)
		cleanAllowed := strings.TrimRight(allowedCanonical, "/")
		if canonicalPath == cleanAllowed || strings.HasPrefix(canonicalPath, cleanAllowed+"/") {
			return canonicalPath, nil
		}
	}

	return "", fmt.Errorf(
		"Access denied: path '%s' (resolved: '%s') is outside allowed directories (%s).",
		pathStr, canonicalPath, strings.Join(AllowedDirs, ", "))
}

// realpathLike 以 realpath(3) 的语义解析路径:允许最末若干段不存在。Go 的
// EvalSymlinks 要求整条路径都存在,故目标缺失时逐级向上找到第一个可解析的现存
// 父目录,再拼接余下词法片段并规范化;连根目录都无法解析则退化为 normalizePath。
func realpathLike(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	for dir := filepath.Dir(p); ; dir = filepath.Dir(dir) {
		if resolvedDir, err := filepath.EvalSymlinks(dir); err == nil {
			return normalizePath(resolvedDir + strings.TrimPrefix(p, dir))
		}
		if dir == "/" {
			break
		}
	}
	return normalizePath(p)
}

// normalizePath 是 fs_server.ts 同名函数的词法移植(分段、丢 '.'、栈式消解
// '..'),不做符号链接解析,仅作为 realpath 失败时的回退。
func normalizePath(p string) string {
	var stack []string
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		stack = append(stack, part)
	}
	return "/" + strings.Join(stack, "/")
}
