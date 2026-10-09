// Package pathguard 为 fs 能力服务器提供严格目录白名单的路径校验。
//
// 本包是路径白名单校验的**权威实现**(历史原型为已删除的 Deno
// fs_server.ts,行为规格以本包与其测试为准)。Go 版本没有 Deno 的运行时
// 权限标志(--allow-read/--allow-write),因此白名单、规范化与符号链接
// 解析全部以 in-code 方式强制执行。
package pathguard

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// AllowedDirs 是 fs 服务器可访问的目录白名单。任何增删改都必须先经过
// 规格评审(测试会锁定其内容)。
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
// 规则:
//  1. 必须是非空字符串;
//  2. 拒绝包含空字节(\0)的路径;
//  3. 必须是以 '/' 开头的绝对路径;
//  4. 以 realpath(3) 语义规范化:目标存在时完整解析符号链接;
//     目标不存在时逐级解析已存在的最深父目录,剩余部分手动去掉 ./..;
//  5. 与 AllowedDirs 前缀匹配时必须带 '/' 边界(因此 /home2 被拒绝)。
//
// write 参数不参与任何判断,仅为接口形态保留(读取与写入执行同一套
// 白名单规则)。
func ValidatePath(pathStr string, write bool) (string, error) {
	_ = write // write 标志不影响校验结果。

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
	// 词法规范化余部",并封堵"末段不存在但父目录是逃逸符号链接"的漏洞。
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

// normalizePath 只做词法规范化(分段、丢 '.'、栈式消解 '..'),不做符号链接解析,
// 仅作为 realpath 失败时的回退。
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

// readOnlySystemDirs 是即便 AllowedDirs 后续被错配也绝对禁止写入的
// 系统只读目录清单。覆盖 composefs 只读 mount(/usr /boot /etc)与
// 伪文件系统(/proc /sys)与关键状态目录(/var/lib/rpm)。这些路径
// 的写入会破坏 bootc 原子性或写入物理不可达位置。
var readOnlySystemDirs = []string{
	"/proc",
	"/sys",
	"/boot",
	"/usr",
	"/etc",
	"/var/lib/rpm",
}

// forbiddenWritePatterns 是即便父目录在白名单内也禁止写入的敏感文件
// 通配清单。覆盖 PAM / 鉴权 / sudo 等任一被改即获权的关键路径。匹配
// 规则:精确等于或前缀匹配(目录末尾带 '/' 视为"目录下所有文件")。
var forbiddenWritePatterns = []string{
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
	"/etc/sudoers.d/",
	"/etc/gshadow",
	"/etc/pam.d/",
}

// ValidateWritePath 是 fs 写操作的二档粒度路径校验。
//
// 在 ValidatePath 既有规则(非空 / 拒空字节 / 必须绝对路径 / realpath
// 解析 / AllowedDirs 前缀边界)之上,叠加三条额外约束:
//
//  1. 拒写只读系统目录(readOnlySystemDirs):即便 AllowedDirs 后续被
//     错配放宽,/proc /sys /boot /usr /etc /var/lib/rpm 的写入依然
//     绝对禁止——这些路径的写入要么破坏 bootc 原子性(composefs 只读
//     mount),要么落点是伪文件系统(/proc /sys),要么直接拿到权限。
//
//  2. 拒写敏感文件(forbiddenWritePatterns):PAM / shadow / sudoers 等
//     通配路径直接拒绝,即便父目录在 AllowedDirs 内。这条防线独立于
//     AllowedDirs,防止攻击者通过创建关键文件名直接获得系统控制。
//
//  3. 强制完整 realpath:不允许 ValidatePath 的"末段不存在回退到词法
//     规范化"分支——写操作目标必须真实存在或父目录必须可解析。理由:
//     读可以 stat 失败的路径回退到词法校验(零副作用可恢复),写必须
//     明确知道落到哪。这是写比读严的核心理由。
//
// ValidateWritePath 不修改 AllowedDirs;消费方通过 pathguard.WithAllowedDirs
// 在进程启动时扩展写白名单(参见 fs / shell / dupe / disk-clean 等插件
// 的 applyPolicy 入口)。
func ValidateWritePath(pathStr string) (string, error) {
	if pathStr == "" {
		return "", errors.New("Path must be a non-empty string.")
	}
	if strings.ContainsRune(pathStr, 0) {
		return "", errors.New("Invalid path: null bytes are forbidden.")
	}
	if !strings.HasPrefix(pathStr, "/") {
		return "", fmt.Errorf("Invalid path '%s': only absolute paths are permitted.", pathStr)
	}

	// 强制完整 realpath:若 EvalSymlinks 失败,立即拒绝。
	// 末段不存在时回退"逐级解析最深现存父目录"的路径不允许用于写——
	// 写必须明确知道落到哪个 inode,不能"猜目标"。
	canonicalPath, err := filepath.EvalSymlinks(pathStr)
	if err != nil {
		return "", fmt.Errorf("write denied: cannot resolve realpath for %q: %w", pathStr, err)
	}

	// 只读系统目录检查:realpath 后命中 readOnlySystemDirs 任一前缀或
	// 精确等于,拒绝。
	for _, ro := range readOnlySystemDirs {
		cleanRO := strings.TrimRight(ro, "/")
		if canonicalPath == cleanRO || strings.HasPrefix(canonicalPath, cleanRO+"/") {
			return "", fmt.Errorf("write denied: path resolves to read-only system dir %q", ro)
		}
	}

	// 敏感文件通配检查:realpath 后命中 forbiddenWritePatterns 任一
	// 精确或前缀(目录型带 '/' 结尾视为子树匹配),拒绝。
	for _, pat := range forbiddenWritePatterns {
		cleanPat := strings.TrimRight(pat, "/")
		if strings.HasSuffix(pat, "/") {
			// 目录型通配:pattern = "/etc/sudoers.d/" → 匹配 "/etc/sudoers.d"
			// 与其下任何文件。
			if canonicalPath == cleanPat || strings.HasPrefix(canonicalPath, pat) {
				return "", fmt.Errorf("write denied: path %q falls under forbidden write pattern %q", canonicalPath, pat)
			}
		} else {
			// 文件型通配:精确等于。
			if canonicalPath == cleanPat {
				return "", fmt.Errorf("write denied: path %q is a forbidden write target", canonicalPath)
			}
		}
	}

	// AllowedDirs 前缀边界检查(与 ValidatePath 一致)。
	for _, allowed := range AllowedDirs {
		allowedCanonical := realpathLike(allowed)
		cleanAllowed := strings.TrimRight(allowedCanonical, "/")
		if canonicalPath == cleanAllowed || strings.HasPrefix(canonicalPath, cleanAllowed+"/") {
			return canonicalPath, nil
		}
	}

	return "", fmt.Errorf(
		"write denied: path '%s' (resolved: '%s') is outside allowed directories (%s).",
		pathStr, canonicalPath, strings.Join(AllowedDirs, ", "))
}
