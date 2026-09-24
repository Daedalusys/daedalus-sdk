// Package shellpolicy 为 shell 能力服务器提供命令/参数白名单策略。
//
// 生产 Deno 实现 shell_server.ts 的逐条移植:Go 无 --allow-run,命令/路径
// 白名单、argv 校验与环境净化全部 in-code 强制。单一事实源:包级值只是
// 内置默认,启动时经 policy.LoadOrDefault + WithPolicy 注入 policy.toml。
package shellpolicy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Daedalusys/daedalus-sdk/policy"
)

// 执行结果语义常量,逐条对应 shell_server.ts:验证失败 126(不是协议错误)、
// 超时 SIGKILL 后 124、进程启动失败 1、TIMEOUT_MS = 30000。
const (
	ValidationRejectionCode = 126
	TimeoutRejectionCode    = 124
	ExecutionFailureCode    = 1
	// TimeoutSeconds 对应 TIMEOUT_MS / 1000。
	TimeoutSeconds   = 30
	AuditPathEnv     = "DAEDALUS_AUDIT_LOG_PATH"
	DefaultAuditPath = "/var/log/daedalus/audit.jsonl"
)

// Timeout 是执行超时时长的 Duration 形式(30000ms)。
var Timeout = time.Duration(TimeoutSeconds) * time.Second

// DefaultAllowCommands 逐字对应 shell_server.ts 的 DEFAULT_ALLOW_COMMANDS,一字不可改动。
var DefaultAllowCommands = map[string]struct{}{
	"df": {}, "ls": {}, "cat": {}, "pwd": {}, "uname": {},
	"free": {}, "ps": {}, "uptime": {}, "whoami": {}, "ip": {},
	"arch": {}, "hostname": {}, "date": {}, "ping": {}, "systemctl": {},
}

var defaultPostCheckCommands = []string{"nginx", "haproxy", "psql", "redis-cli", "systemctl", "grep"}

// DefaultPostCheckAllowCommands 返回出厂默认集副本,调用方改动不污染包级默认值。
func DefaultPostCheckAllowCommands() map[string]struct{} {
	return stringSet(defaultPostCheckCommands)
}

// PostCheckAllowCommands 是 post_check / pre_check 脚本可执行命令的白名单,
// 与主白名单 DefaultAllowCommands 相互独立(主白名单管 shell 能力服务器的只读
// /诊断命令,本集只管蓝图 post_check 沙箱)。经 WithPolicy 注入
// [blueprints].post_check_commands 后为运行时镜像(同源 policy.toml)。
var PostCheckAllowCommands = DefaultPostCheckAllowCommands()

func IsPostCheckAllowed(cmd string) bool {
	_, ok := PostCheckAllowCommands[cmd]
	return ok
}

var AllowedBinDirs = map[string]struct{}{
	"/usr/bin": {}, "/bin": {}, "/usr/sbin": {}, "/sbin": {},
}

// AllowedPathPrefixes 是路径型参数允许的前缀白名单,逐字对应 shell_server.ts。
var AllowedPathPrefixes = []string{
	"/home",
	"/var/log",
	"/tmp",
	"/proc",
	"/sys",
	"/etc/os-release",
	"/usr/lib/os-release",
	"/etc/fedora-release",
	"/etc/almalinux-release",
}

// BlockedPaths 是显式禁止的敏感路径,逐字对应 shell_server.ts 的同名常量。
var BlockedPaths = []string{
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/sudoers.d",
	"/root",
}

// CleanEnv 是净化后的执行环境(os/exec 的 KEY=VALUE 切片形式),
// 逐字对应 shell_server.ts 的 CLEAN_ENV。子进程绝不继承其它环境变量。
var CleanEnv = []string{
	"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
	"LANG=C.UTF-8",
}

// ResolveAllowCommands 依据 ALLOW_COMMANDS 环境变量解析生效白名单,与
// shell_server.ts 行为一致:非空时**整体替换**(REPLACE,非并集)为逗号分隔、
// 逐项 trim、丢弃空项后的集合;为空时返回默认白名单的副本。默认集即
// DefaultAllowCommands,故 WithPolicy 注入后本函数自动跟随单一事实源。
func ResolveAllowCommands(envValue string) map[string]struct{} {
	if envValue == "" {
		return copySet(DefaultAllowCommands)
	}
	allow := make(map[string]struct{})
	for _, c := range strings.Split(envValue, ",") {
		if trimmed := strings.TrimSpace(c); trimmed != "" {
			allow[trimmed] = struct{}{}
		}
	}
	return allow
}

func copySet(src map[string]struct{}) map[string]struct{} {
	dst := make(map[string]struct{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// blueprintsPostCheckSource 是 post_check 命令白名单的策略注入钩子,注册前
// 保持出厂默认(前向解耦见 RegisterBlueprintsPostCheckSource)。
var blueprintsPostCheckSource func(p *policy.Policy) []string

// RegisterBlueprintsPostCheckSource 注册蓝图 post_check 命令白名单的读取
// 函数,供 policy 包在 Policy.Blueprints 结构落地后接线:
//
//	shellpolicy.RegisterBlueprintsPostCheckSource(func(p *policy.Policy) []string {
//		return p.Blueprints.PostCheckCommands
//	})
//
// 多次注册以后者为准;nil 入参被忽略(防御)。生效集合与
// [shell].allowed_commands 同为 policy.toml 单一事实源,由三点漂移测试把关。
func RegisterBlueprintsPostCheckSource(src func(p *policy.Policy) []string) {
	if src == nil {
		return // nil 读取函数视为未注册(防御,不改语义)。
	}
	blueprintsPostCheckSource = src
}

// WithPolicy 用 policy.toml 的解析结果覆盖本包的包级策略值。行为约定:
//   - 只在服务器启动时调用一次(main 注入),运行期不改。
//   - 传入的切片/映射一律深拷贝,调用方后续改动不会反向渗透策略。
//   - 不调用本函数即保持 shell_server.ts 的原始默认常量。
func WithPolicy(p *policy.Policy) {
	if p == nil {
		return // 空策略视为不注入,维持出厂常量(防御 nil 指针,不改语义)。
	}
	DefaultAllowCommands = stringSet(p.Shell.AllowedCommands)
	AllowedBinDirs = stringSet(p.Shell.BinaryDirs)
	AllowedPathPrefixes = slices.Clone(p.Shell.AllowedPathPrefixes)
	BlockedPaths = slices.Clone(p.Shell.BlockedPaths)
	CleanEnv = cleanEnvPairs(p.Shell.CleanEnv)
	Timeout = time.Duration(p.Shell.TimeoutMs) * time.Millisecond
	if blueprintsPostCheckSource != nil {
		// 注入空集也是 fail-closed 的合法结果(与 [shell].allowed_commands
		// 的注入模式一致:策略说了算,不合并默认值)。
		PostCheckAllowCommands = stringSet(blueprintsPostCheckSource(p))
	}
}

// stringSet 把字符串切片转为独立集合副本。
func stringSet(src []string) map[string]struct{} {
	dst := make(map[string]struct{}, len(src))
	for _, s := range src {
		dst[s] = struct{}{}
	}
	return dst
}

// cleanEnvPairs 把键值映射转成 os/exec 的 "KEY=VALUE" 切片;
// 按键名升序输出,保证注入结果的确定性(执行语义与顺序无关)。
func cleanEnvPairs(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+env[k])
	}
	return pairs
}

func IsPathLike(arg string) bool {
	if strings.ContainsRune(arg, 0) {
		return true
	}
	if strings.HasPrefix(arg, "/") ||
		strings.Contains(arg, "/") ||
		arg == "." ||
		arg == ".." ||
		strings.HasPrefix(arg, "..") {
		return true
	}
	return false
}

// ValidatePath 校验 shell 参数中的路径(对应 shell_server.ts):
// 解析为规范路径后,先查 BlockedPaths(精确或带 '/' 边界的子路径),
// 再查 AllowedPathPrefixes;违规以 error 返回(由调用方转成 126 结果)。
func ValidatePath(pathStr string) (string, error) {
	if pathStr == "" {
		return "", errors.New("Path must be a non-empty string.")
	}
	if strings.ContainsRune(pathStr, 0) {
		return "", errors.New("Null bytes are not allowed in path arguments.")
	}

	// 存在则取 realpath;否则相对路径先拼 cwd,再词法规范化。
	absolute := pathStr
	if !strings.HasPrefix(absolute, "/") {
		if cwd, err := os.Getwd(); err == nil {
			absolute = cwd + "/" + pathStr
		}
	}
	resolved := realpathLike(absolute)

	for _, blocked := range BlockedPaths {
		cleanBlocked := strings.TrimRight(blocked, "/")
		if resolved == cleanBlocked || strings.HasPrefix(resolved, cleanBlocked+"/") {
			return "", fmt.Errorf("Access to blocked path '%s' (%s) is forbidden.", pathStr, resolved)
		}
	}

	for _, prefix := range AllowedPathPrefixes {
		cleanPrefix := strings.TrimRight(prefix, "/")
		if resolved == cleanPrefix || strings.HasPrefix(resolved, cleanPrefix+"/") {
			return resolved, nil
		}
	}

	return "", fmt.Errorf(
		"Path '%s' (resolved: %s) is outside allowed directories: %s",
		pathStr, resolved, strings.Join(AllowedPathPrefixes, ", "))
}

func ValidateArg(arg string) error {
	if strings.ContainsRune(arg, 0) {
		return errors.New("Null bytes are not allowed in arguments.")
	}

	if strings.Contains(arg, "=") && strings.HasPrefix(arg, "-") {
		eqIdx := strings.Index(arg, "=")
		val := arg[eqIdx+1:]
		if IsPathLike(val) {
			_, err := ValidatePath(val)
			return err
		}
		return nil
	}
	if IsPathLike(arg) {
		_, err := ValidatePath(arg)
		return err
	}
	return nil
}

// ValidateCommand 校验命令并解析实际执行的基名:基名须命中白名单;命令含 '/'
// 时其所在目录 realpath 后须落在 AllowedBinDirs 之内。
func ValidateCommand(command string, allow map[string]struct{}) (string, error) {
	if command == "" {
		return "", errors.New("Command must be a non-empty string.")
	}
	if strings.ContainsRune(command, 0) {
		return "", errors.New("Null bytes are not allowed in command.")
	}

	trimmed := strings.TrimSpace(command)
	lastSlash := strings.LastIndex(trimmed, "/")
	cmdBase := trimmed
	if lastSlash >= 0 {
		cmdBase = trimmed[lastSlash+1:]
	}

	if _, ok := allow[cmdBase]; !ok {
		return "", fmt.Errorf("Command '%s' is not in ALLOW_COMMANDS allowlist.", command)
	}

	if strings.Contains(trimmed, "/") {
		cmdDir := trimmed[:lastSlash]
		// realpath 失败(目录不存在)时保持原样,
		// 原样目录几乎必然不在允许集合内 → 拒绝。
		if resolved, err := filepath.EvalSymlinks(cmdDir); err == nil {
			cmdDir = resolved
		}
		if _, ok := AllowedBinDirs[cmdDir]; !ok {
			return "", fmt.Errorf("Command path '%s' is not in a valid system bin directory.", command)
		}
	}

	return cmdBase, nil
}

// realpathLike 以 realpath(3) 的语义解析路径(允许末段不存在):EvalSymlinks
// 失败时逐级向上解析现存父目录,余部词法规范化。实现与 pathguard 一致,此处
// 独立复制以对应 ts 中两个服务器各自携带 normalizePath 的源码结构。
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
