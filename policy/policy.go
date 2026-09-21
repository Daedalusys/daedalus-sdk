// Package policy 从 shared/policy.toml 读取 Daedalus 能力策略的单一事实源。
//
// 设计(计划 todo 12 / 决策 12):shell/fs 白名单、路径规则、净化环境与
// 超时不再以"散落的硬编码"为权威,而是集中定义于
// daedalus/files/system/opt/daedalus/shared/policy.toml(镜像内
// /opt/daedalus/shared/policy.toml),由 Go 能力服务器在启动时读取并经
// shellpolicy.WithPolicy / pathguard.WithAllowedDirs 注入。
//
// 路径解析优先级:
//  1. DAEDALUS_POLICY_PATH 环境变量(显式指向,文件损坏/缺失一律报错,
//     绝不静默吞掉——这是测试与 systemd drop-in 的注入口);
//  2. 生产路径 /opt/daedalus/shared/policy.toml;
//  3. 开发态回溯:自当前工作目录逐级上溯,每层目录依次尝试
//     DevRelPaths 候选列表(跨仓平级 daedalus-core/... 与 SDK 仓自带
//     testdata/policy.toml 生产一致副本)。
//
// 三处皆无 → ErrNotFound(调用方经 LoadOrDefault 回退 Default(),
// 保证"无 policy 服务器也能启动");显式指向的 TOML 损坏或字段缺失 →
// 加载失败报错(拒绝启动,fail-closed)。
//
// ALLOW_COMMANDS 环境变量维持 REPLACE 语义(与 shellpolicy.
// ResolveAllowCommands 现状一致):存在且非空时逗号分隔集合整体替换
// 策略中的 allowed_commands,而非取并集。
package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// 环境变量名与候选路径常量。
const (
	// EnvPolicyPath 是策略文件的显式注入环境变量(测试/部署用)。
	EnvPolicyPath = "DAEDALUS_POLICY_PATH"
	// EnvAllowCommands 是命令白名单的整体替换环境变量(REPLACE 语义)。
	EnvAllowCommands = "ALLOW_COMMANDS"
	// ProductionPath 是镜像内的生产策略路径。
	ProductionPath = "/opt/daedalus/shared/policy.toml"
)

// DevRelPaths 是开发态回溯的候选相对路径列表(自 cwd 逐级上溯,
// 每层目录 × 每个候选嵌套匹配;导出以便测试与构建脚本引用)。
// 顺序即优先级:跨仓平级候选在前(3 仓平级 clone 时从 SDK 仓 walk-up
// 命中),SDK 仓自带 testdata 生产一致副本在后(Go test binary 的
// CWD = 包目录,testdata/ 在 level 1 即命中,实际优先于跨仓候选)。
var DevRelPaths = []string{
	"daedalus-core/files/system/opt/daedalus/shared/policy.toml", // 跨仓平级 clone 时命中
	"testdata/policy.toml",                                       // SDK 仓自带 fixture(CWD 级命中)
}

// ErrNotFound 表示按解析优先级未找到任何策略文件。
// 与"文件存在但损坏/字段缺失"(真解析错误)严格区分:前者可回退
// Default(),后者必须拒绝启动。
var ErrNotFound = errors.New("policy: 未找到 policy.toml(生产路径与仓库回溯均未命中)")

// Shell 对应 TOML [shell] 表:shell 能力服务器的全部强制策略值。
type Shell struct {
	// AllowedCommands 是命令基名白名单(对应 allowed_commands)。
	AllowedCommands []string `toml:"allowed_commands"`
	// BinaryDirs 是允许的二进制所在目录(对应 binary_dirs)。
	BinaryDirs []string `toml:"binary_dirs"`
	// AllowedPathPrefixes 是路径参数允许的前缀(对应 allowed_path_prefixes)。
	AllowedPathPrefixes []string `toml:"allowed_path_prefixes"`
	// BlockedPaths 是显式禁止的敏感路径(对应 blocked_paths)。
	BlockedPaths []string `toml:"blocked_paths"`
	// CleanEnv 是子进程净化环境(对应 clean_env 内嵌表)。
	CleanEnv map[string]string `toml:"clean_env"`
	// TimeoutMs 是执行超时毫秒数(对应 timeout_ms)。
	TimeoutMs int64 `toml:"timeout_ms"`
}

// FS 对应 TOML [fs] 表:文件系统能力服务器的目录白名单。
type FS struct {
	// AllowedDirs 是可访问目录前缀(对应 allowed_dirs)。
	AllowedDirs []string `toml:"allowed_dirs"`
}

// Audit 对应 TOML [audit] 表:审计日志落点。
type Audit struct {
	// LogPath 是哈希链审计日志路径(对应 log_path)。
	LogPath string `toml:"log_path"`
}

// ObjectModel 对应 TOML [objectmodel] 表:对象模型资源 kind 的正向启用白名单。
// 与 [shell]/[fs]/[audit] 并列的第四策略节——声明式列出**启用**哪些资源
// kind(未列入即未启用,fail-closed);具体 kind 的语义与校验规则由对象模型
// schema 的单一事实源 daedalus-sdk/objectmodel/objectmodel.go 定义
// (v1 仅 service 有 provider)。设计决策与执行模型见计划
// .omo/plans/aios-object-model-alignment.md 的 Object Model 段与决策 25。
type ObjectModel struct {
	// EnabledKinds 是启用的资源 kind 白名单(对应 enabled_kinds)。
	EnabledKinds []string `toml:"enabled_kinds"`
}

// Blueprints 对应 TOML [blueprints] 表:蓝图(blueprint)渲染/校验/重载/
// 密钥来源的全部强制策略值(计划 daedalus-blueprint-p1 决策 5 / todo 10)。
// 与 [shell]/[fs]/[audit]/[objectmodel] 并列的第五策略节,由 Go 能力服务器
// 与未来的 blueprint 插件在启动/运行期读取。
type Blueprints struct {
	// OutputDirs 是蓝图渲染输出的允许目录(前缀白名单,与 pathguard 联动,
	// 对应 output_dirs)。
	OutputDirs []string `toml:"output_dirs"`
	// PostCheckCommands 是 post_check / pre_check 可执行的命令白名单
	// (对应 post_check_commands;消费方经 shellpolicy 的
	// RegisterBlueprintsPostCheckSource 钩子注入,见 todo 16)。
	PostCheckCommands []string `toml:"post_check_commands"`
	// ReloadServices 是 reload 允许触发的服务名
	// (经 daedalus-tx 的 service.set 通道,对应 reload_services)。
	ReloadServices []string `toml:"reload_services"`
	// SecretSources 是 secret 引用解析来源(用户态,对应 secret_sources)。
	SecretSources []string `toml:"secret_sources"`
}

// Policy 是 policy.toml 的完整解析结果,字段与 TOML 一一对应。
type Policy struct {
	Shell       Shell       `toml:"shell"`
	FS          FS          `toml:"fs"`
	Audit       Audit       `toml:"audit"`
	ObjectModel ObjectModel `toml:"objectmodel"`
	Blueprints  Blueprints  `toml:"blueprints"`
}

// ResolvePath 按文档优先级解析策略文件路径。
// 未命中任何候选时返回包装 ErrNotFound 的错误;DAEDALUS_POLICY_PATH
// 指向的文件不存在**不算**未命中(由 Load 如实报读盘错误),
// 因为显式指向被静默降级会掩盖部署错误。
func ResolvePath() (string, error) {
	if p := os.Getenv(EnvPolicyPath); p != "" {
		return p, nil
	}
	if st, err := os.Stat(ProductionPath); err == nil && !st.IsDir() {
		return ProductionPath, nil
	}
	if wd, err := os.Getwd(); err == nil {
		// 嵌套循环:每层 dir × 每个 relPath 候选
		for dir := wd; ; {
			for _, rel := range DevRelPaths {
				cand := filepath.Join(dir, rel)
				if st, err := os.Stat(cand); err == nil && !st.IsDir() {
					return cand, nil
				}
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "", ErrNotFound
}

// Load 解析指定路径的策略文件;path 为空串时先经 ResolvePath 走优先级链。
// 报错条件(fail-closed):文件读不出、TOML 语法损坏、存在未知键
// (拦截拼写错误,杜绝"以为改了其实没改")、必需字段缺失或为空。
func Load(path string) (*Policy, error) {
	if path == "" {
		var err error
		if path, err = ResolvePath(); err != nil {
			return nil, err
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: 读取 %s 失败: %w", path, err)
	}
	var p Policy
	meta, err := toml.Decode(string(data), &p)
	if err != nil {
		return nil, fmt.Errorf("policy: 解析 %s 失败(TOML 损坏): %w", path, err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("policy: %s 含未知键(fail-closed,拒绝拼写错误/第二事实源): %s", path, strings.Join(keys, ", "))
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("policy: %s 校验失败: %w", path, err)
	}
	return &p, nil
}

// LoadOrDefault 是服务器启动入口:策略文件整体缺失时回退 Default()
// (保证无 policy 也能启动);文件存在但损坏/字段缺失时原样报错
// (调用方必须拒绝启动)。
func LoadOrDefault() (*Policy, error) {
	p, err := Load("")
	if errors.Is(err, ErrNotFound) {
		return Default(), nil
	}
	return p, err
}

// validate 钉死全部必需字段:任何缺段、缺键、空列表、空字符串、
// 非正超时都视为损坏策略。空列表一律拒绝是刻意的 fail-closed
// 设计——配置事故(误删整行)不得静默放宽或瘫痪安全边界。
func (p *Policy) validate() error {
	var missing []string
	requireList := func(name string, v []string) {
		if len(v) == 0 {
			missing = append(missing, name)
		}
	}
	requireList("shell.allowed_commands", p.Shell.AllowedCommands)
	requireList("shell.binary_dirs", p.Shell.BinaryDirs)
	requireList("shell.allowed_path_prefixes", p.Shell.AllowedPathPrefixes)
	requireList("shell.blocked_paths", p.Shell.BlockedPaths)
	requireList("fs.allowed_dirs", p.FS.AllowedDirs)
	// [objectmodel].enabled_kinds 只是放行网关;kind 词表与 Resource 形态的
	// 单一事实源在 daedalus-sdk/objectmodel/objectmodel.go
	// (计划 .omo/plans/aios-object-model-alignment.md 决策 25),三点漂移测试钉死两侧一致。
	requireList("objectmodel.enabled_kinds", p.ObjectModel.EnabledKinds)
	// [blueprints] 四字段一律非空(fail-closed):任一空列表视为损坏策略,
	// 拒绝启动。语义与 [shell]/[fs]/[audit] 的其它必需列表一致——配置事故
	// (误删整行)不得静默放宽蓝图输出目录或校验命令边界。
	requireList("blueprints.output_dirs", p.Blueprints.OutputDirs)
	requireList("blueprints.post_check_commands", p.Blueprints.PostCheckCommands)
	requireList("blueprints.reload_services", p.Blueprints.ReloadServices)
	requireList("blueprints.secret_sources", p.Blueprints.SecretSources)

	if len(p.Shell.CleanEnv) == 0 {
		missing = append(missing, "shell.clean_env")
	} else if _, ok := p.Shell.CleanEnv["PATH"]; !ok {
		// PATH 缺失会让 argv 直发的裸命令名永远查不到可执行文件,
		// 属配置事故,必须在启动时拒绝而不是运行期全量失败。
		missing = append(missing, "shell.clean_env.PATH")
	}
	if p.Shell.TimeoutMs <= 0 {
		missing = append(missing, "shell.timeout_ms")
	}
	if p.Audit.LogPath == "" {
		missing = append(missing, "audit.log_path")
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("缺失或为空的必需字段: %s", strings.Join(missing, ", "))
	}
	return nil
}

// AllocCommands 计算 shell 服务器的生效命令白名单:
// 读取 ALLOW_COMMANDS 环境变量并套用 REPLACE 语义(见 AllowedCommands)。
func AllocCommands(p *Policy) map[string]struct{} {
	return AllowedCommands(p, os.Getenv(EnvAllowCommands))
}

// AllowedCommands 是 AllocCommands 的纯函数形态(envValue 由调用方给出,
// 便于测试)。语义与 shellpolicy.ResolveAllowCommands 逐字对齐:
// envValue 非空 → 逗号分隔、逐项 trim、丢弃空项后的集合**整体替换**
// 策略白名单(非并集);envValue 为空 → 返回策略 allowed_commands 的集合副本。
func AllowedCommands(p *Policy, envValue string) map[string]struct{} {
	if envValue == "" {
		return commandSet(p.Shell.AllowedCommands)
	}
	allow := make(map[string]struct{})
	for _, c := range strings.Split(envValue, ",") {
		if trimmed := strings.TrimSpace(c); trimmed != "" {
			allow[trimmed] = struct{}{}
		}
	}
	return allow
}

// commandSet 把字符串切片转为集合(副本,防止调用方改动策略内部状态)。
func commandSet(cmds []string) map[string]struct{} {
	set := make(map[string]struct{}, len(cmds))
	for _, c := range cmds {
		set[c] = struct{}{}
	}
	return set
}

// Default 返回内嵌的出厂默认策略,值与 internal/shellpolicy、
// internal/pathguard 的既有硬编码常量逐项一致(15 命令 / 4 bin 目录 /
// 9 前缀 / 5 blocked / CLEAN_ENV / 30000ms / fs 3 目录 / 审计路径 /
// objectmodel 启用 1 kind),由 policy 包测试跨包比对钉死,防止双源漂移。
//
// 返回的是全新构造的实例(集合/映射均为独立副本),调用方可安全改动。
func Default() *Policy {
	return &Policy{
		Shell: Shell{
			AllowedCommands: []string{
				"df", "ls", "cat", "pwd", "uname", "free", "ps", "uptime",
				"whoami", "ip", "arch", "hostname", "date", "ping", "systemctl",
			},
			BinaryDirs: []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"},
			AllowedPathPrefixes: []string{
				"/home", "/var/log", "/tmp", "/proc", "/sys",
				"/etc/os-release", "/usr/lib/os-release", "/etc/fedora-release", "/etc/almalinux-release",
			},
			BlockedPaths: []string{
				"/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d", "/root",
			},
			CleanEnv: map[string]string{
				"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
				"LANG": "C.UTF-8",
			},
			TimeoutMs: 30000,
		},
		FS: FS{
			AllowedDirs: []string{"/home", "/var/log", "/tmp"},
		},
		Audit: Audit{
			LogPath: "/var/log/daedalus/audit.jsonl",
		},
		ObjectModel: ObjectModel{
			// v1 service 与 package kind 有 provider;其余保留枚举成员须经此白名单启用。
			// kind 词表的单一事实源:daedalus-sdk/objectmodel/objectmodel.go(决策 25)。
			EnabledKinds: []string{"service", "package"},
		},
		Blueprints: Blueprints{
			// 蓝图渲染输出目录 / post_check 命令 / reload 服务 / secret 来源,
			// 值与 shared/policy.toml [blueprints] 节逐字一致
			// (计划 daedalus-blueprint-p1 决策 5),由三点漂移测试(todo 9)钉死。
			// post_check 白名单消费方:shellpolicy.RegisterBlueprintsPostCheckSource
			// (todo 16 MCP server 启动时注册;本包不 import shellpolicy,避免循环)。
			OutputDirs:        []string{"/etc/nginx/conf.d", "/etc/haproxy", "/etc/postgresql", "/etc/redis"},
			PostCheckCommands: []string{"nginx", "haproxy", "psql", "redis-cli", "systemctl", "grep"},
			ReloadServices:    []string{"nginx", "haproxy", "postgresql", "redis"},
			SecretSources:     []string{"kwallet", "credstore"},
		},
	}
}
