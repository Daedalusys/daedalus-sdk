// Package policy 从 shared/policy.toml 读取 Daedalus 能力策略的单一事实源。
//
// shell/fs 白名单、路径规则、净化环境与超时的权威定义集中于共享
// policy.toml(镜像内 /opt/daedalus/shared/policy.toml),由 Go 能力服务器
// 启动时读取并经 shellpolicy.WithPolicy / pathguard.WithAllowedDirs 注入。
//
// 路径解析优先级:DAEDALUS_POLICY_PATH 环境变量(显式指向,文件损坏/缺失一律
// 报错,绝不静默吞掉)→ 生产路径 /opt/daedalus/shared/policy.toml → 开发态
// 自 cwd 逐级上溯尝试 DevRelPaths 候选。三处皆无 → ErrNotFound;LoadOrDefault
// 默认同样 fail-closed 拒绝启动(与"损坏拒绝启动"哲学一致),仅显式设置
// DAEDALUS_POLICY_MODE=development(开发/测试 opt-in)才回退 Default(),
// 不隐式猜测环境。
//
// ALLOW_COMMANDS 环境变量维持 REPLACE 语义(与 shellpolicy.ResolveAllowCommands
// 一致):非空时整体替换 allowed_commands,而非取并集。
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

const (
	// EnvPolicyPath 是策略文件的显式注入环境变量(测试/部署用)。
	EnvPolicyPath = "DAEDALUS_POLICY_PATH"
	// EnvAllowCommands 是命令白名单的整体替换环境变量(REPLACE 语义)。
	EnvAllowCommands = "ALLOW_COMMANDS"
	// EnvPolicyMode 是策略缺失时的回退开关:仅取值 development 才允许
	// LoadOrDefault 回退 Default();缺省(生产语义)fail-closed 拒绝启动。
	EnvPolicyMode = "DAEDALUS_POLICY_MODE"
	// PolicyModeDevelopment 是 EnvPolicyMode 唯一接受的取值。
	PolicyModeDevelopment = "development"
	ProductionPath        = "/opt/daedalus/shared/policy.toml"
)

// DevRelPaths 是开发态回溯的候选相对路径列表(自 cwd 逐级上溯,每层目录 ×
// 每个候选嵌套匹配)。顺序即优先级:跨仓平级候选在前,testdata 副本在后
// (Go test binary CWD = 包目录,level 1 即命中,实际优先于跨仓候选)。
var DevRelPaths = []string{
	"daedalus-core/files/system/opt/daedalus/shared/policy.toml", // 跨仓平级 clone 时命中
	"testdata/policy.toml", // SDK 仓自带 fixture(CWD 级命中)
}

// ErrNotFound 表示按解析优先级未找到任何策略文件(生产语义 fail-closed;
// 回退 Default() 需 DAEDALUS_POLICY_MODE=development 显式 opt-in);
// 与"文件存在但损坏/字段缺失"(真解析错误)严格区分,后者必须拒绝启动。
var ErrNotFound = errors.New("policy: 未找到 policy.toml(生产路径与仓库回溯均未命中)")

type Shell struct {
	AllowedCommands     []string          `toml:"allowed_commands"`
	BinaryDirs          []string          `toml:"binary_dirs"`
	AllowedPathPrefixes []string          `toml:"allowed_path_prefixes"`
	BlockedPaths        []string          `toml:"blocked_paths"`
	CleanEnv            map[string]string `toml:"clean_env"`
	TimeoutMs           int64             `toml:"timeout_ms"`
}

type FS struct {
	AllowedDirs []string `toml:"allowed_dirs"`
}

type Audit struct {
	LogPath string `toml:"log_path"`
}

// ObjectModel 对应 TOML [objectmodel] 表:资源 kind 的正向启用白名单
// (未列入即未启用,fail-closed);kind 词表单一事实源在 objectmodel 包。
type ObjectModel struct {
	EnabledKinds []string `toml:"enabled_kinds"`
}

// Blueprints 对应 TOML [blueprints] 表:蓝图渲染/校验/重载/密钥来源的强制策略值。
type Blueprints struct {
	// OutputDirs 是渲染输出的允许目录前缀,与 pathguard 联动。
	OutputDirs []string `toml:"output_dirs"`
	// PostCheckCommands 经 shellpolicy.RegisterBlueprintsPostCheckSource 钩子注入
	// (本包不 import shellpolicy,避免循环依赖)。
	PostCheckCommands []string `toml:"post_check_commands"`
	// ReloadServices 是 reload 允许触发的服务名,经 daedalus-tx 的 service.set 通道。
	ReloadServices []string `toml:"reload_services"`
	// SecretSources 是 secret 引用解析来源,限用户态。
	SecretSources []string `toml:"secret_sources"`
}

// Confirmation 对应 TOML [confirmation] 表:通用 confirm_token 单次性契约的
// 全局参数。TTLSeconds 与 confirmation.ConfirmTokenTTL(15 分钟)对齐,
// policy.toml 此处为文档/诊断参考;实际生效值在 confirmation 包内,改 TTL 必须
// 改 confirmation 常量并跑 drift 测试。MaxPendingTokens 是单进程最大未消费
// 令牌数(超限由 confirmation 包自行 purge),policy 仅文档化。
type Confirmation struct {
	TTLSeconds       int64 `toml:"ttl_seconds"`
	MaxPendingTokens int64 `toml:"max_pending_tokens"`
}

// DiskClean 对应 TOML [diskclean] 表:daedalus.disk-clean 插件的写白名单与
// 旧内核路径模板。AllowedWriteDirs 经 pathguard.ValidateWritePath 二档校验,
// 消费方在插件 applyPolicy 阶段把它合并进 pathguard.AllowedDirs。
type DiskClean struct {
	AllowedWriteDirs    []string `toml:"allowed_write_dirs"`
	OldKernelDirPattern string   `toml:"old_kernel_dir_pattern"`
}

// Policy 是 policy.toml 的完整解析结果。
type Policy struct {
	Shell        Shell        `toml:"shell"`
	FS           FS           `toml:"fs"`
	Audit        Audit        `toml:"audit"`
	ObjectModel  ObjectModel  `toml:"objectmodel"`
	Blueprints   Blueprints   `toml:"blueprints"`
	Confirmation Confirmation `toml:"confirmation"`
	DiskClean    DiskClean    `toml:"diskclean"`
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
// 报错条件(fail-closed):文件读不出、TOML 损坏、未知键(拦截拼写错误)、
// 必需字段缺失或为空。
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

// LoadOrDefault 是服务器启动入口:策略文件整体缺失时默认 fail-closed 报错
// (与损坏语义一致,拒绝启动);仅 DAEDALUS_POLICY_MODE=development 显式
// opt-in 才回退 Default()。文件存在但损坏/字段缺失时原样报错,调用方必须
// 拒绝启动。
func LoadOrDefault() (*Policy, error) {
	p, err := Load("")
	if errors.Is(err, ErrNotFound) {
		if os.Getenv(EnvPolicyMode) == PolicyModeDevelopment {
			return Default(), nil
		}
		return nil, fmt.Errorf("policy: 策略文件缺失,fail-closed 拒绝启动(开发/测试需回退内置默认请显式设置 %s=%s): %w",
			EnvPolicyMode, PolicyModeDevelopment, err)
	}
	return p, err
}

// validate 校验全部必需字段:缺段、缺键、空列表、空字符串、非正超时都视为损坏
// 策略。空列表一律拒绝是刻意的 fail-closed——配置事故不得静默放宽安全边界。
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
	requireList("objectmodel.enabled_kinds", p.ObjectModel.EnabledKinds)
	// [blueprints] 四字段一律非空(fail-closed):配置事故不得静默放宽蓝图
	// 输出目录或校验命令边界。
	requireList("blueprints.output_dirs", p.Blueprints.OutputDirs)
	requireList("blueprints.post_check_commands", p.Blueprints.PostCheckCommands)
	requireList("blueprints.reload_services", p.Blueprints.ReloadServices)
	requireList("blueprints.secret_sources", p.Blueprints.SecretSources)

	if len(p.Shell.CleanEnv) == 0 {
		missing = append(missing, "shell.clean_env")
	} else if _, ok := p.Shell.CleanEnv["PATH"]; !ok {
		// PATH 缺失会让 argv 直发的裸命令名查不到可执行文件,属配置事故。
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

func AllocCommands(p *Policy) map[string]struct{} {
	return AllowedCommands(p, os.Getenv(EnvAllowCommands))
}

// AllowedCommands 是 AllocCommands 的纯函数形态(envValue 由调用方给出,
// 便于测试),语义与 shellpolicy.ResolveAllowCommands 逐字对齐:envValue
// 非空 → 集合**整体替换**策略白名单(REPLACE,非并集);为空 → 返回副本。
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

func commandSet(cmds []string) map[string]struct{} {
	set := make(map[string]struct{}, len(cmds))
	for _, c := range cmds {
		set[c] = struct{}{}
	}
	return set
}

// Default 返回内嵌的出厂默认策略,值与 shellpolicy、pathguard 的既有硬编码
// 常量逐项一致,由跨包测试比对防止双源漂移。返回全新构造的实例,调用方可安全改动。
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
			EnabledKinds: []string{"service", "package"},
		},
		Blueprints: Blueprints{
			OutputDirs:        []string{"/etc/nginx/conf.d", "/etc/haproxy", "/etc/postgresql", "/etc/redis"},
			PostCheckCommands: []string{"nginx", "haproxy", "psql", "redis-cli", "systemctl", "grep"},
			ReloadServices:    []string{"nginx", "haproxy", "postgresql", "redis"},
			SecretSources:     []string{"kwallet", "credstore"},
		},
		// Confirmation 全局参数:TTL 与 confirmation.ConfirmTokenTTL 常量对齐,
		// policy.toml 此处为文档/诊断参考;MaxPendingTokens 是单进程未消费
		// 令牌上限(超限由 confirmation 包自行 purge)。
		Confirmation: Confirmation{
			TTLSeconds:       900, // 15 分钟,与 confirmation.ConfirmTokenTTL 默认值一致
			MaxPendingTokens: 1000,
		},
		// DiskClean 写白名单:plugin 启动时经 pathguard.WithAllowedDirs
		// 注入,与 [fs].allowed_dirs 是两层(全局 / 插件)关系。
		DiskClean: DiskClean{
			AllowedWriteDirs: []string{
				"/var/log/journal",
				"/var/cache/dnf",
				"/var/cache/PackageKit",
				"/var/lib/systemd/coredump",
				"/var/tmp",
				"/home",
			},
			OldKernelDirPattern: "/boot",
		},
	}
}
