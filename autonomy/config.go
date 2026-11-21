// 档位表配置:出厂预设、严格加载(未知键/非法值一律拒绝)、路径解析链。
package autonomy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

const (
	// ProductionPath 是档位表的生产路径:改它需要 root,AI 写不了 /etc。
	ProductionPath = "/etc/daedalus/agent-autonomy.toml"
	// EnvPath 覆盖档位表路径;值必须绝对路径(相对或空值直接报错)。
	EnvPath = "DAEDALUS_AUTONOMY_PATH"
)

// ErrNotFound 表示档位表不存在:调用方自行决定回退(缺省⇒全用出厂预设)。
var ErrNotFound = errors.New("autonomy: 档位表不存在")

// ErrEnvNotAbsolute 表示覆盖变量存在但不是绝对路径:直接拒绝,不静默忽略。
var ErrEnvNotAbsolute = errors.New("autonomy: 覆盖变量为空值或非绝对路径")

// Rule 是一条档位规则:作用域模式(可含 *)→ 请求档位。
// Tier 是请求档位:写 auto 的仍要过 Classify 的降档条件,不满足则降为 confirm。
// Relaxed 标记"显式放宽"(第三档降到第二档),只允许出现在 confirm 上。
type Rule struct {
	Scope   string
	Tier    Tier
	Relaxed bool
}

// Signer 是签发者及其签发上限;条子校验(名单/范围/时长/次数)在消费侧做。
type Signer struct {
	User     string
	MaxScope []string
	MaxTTL   time.Duration
	MaxUses  int
}

// Config 是档位表全量:出厂预设 + 用户规则 + 危险名单 + 签发者名单。
type Config struct {
	Presets     []Rule
	Rules       []Rule
	Deny        []string
	DenyNames   []string
	Signers     []Signer
	DenySigners []string
}

// Default 返回出厂配置:只有内置预设,用户规则/危险名单/签发者名单为空。
func Default() Config {
	return Config{Presets: defaultPresets()}
}

// defaultPresets 是出厂预设表:保守、fail-closed(未命中 ⇒ 第三档)。
//
// 表里 systemd:user 的 start 写作"confirm(条件成立时降 auto)";本包把 auto
// 统一实现为"仅在降档条件成立时生效,否则降为 confirm",预设与用户规则
// 一视同仁,所以此处直接存 auto。
func defaultPresets() []Rule {
	rules := []Rule{
		{Scope: "systemd:user:start:*", Tier: TierAuto},
		{Scope: "systemd:user:stop:*", Tier: TierConfirm},
		{Scope: "systemd:user:restart:*", Tier: TierConfirm},
		{Scope: "systemd:user:enable:*", Tier: TierConfirm},
		{Scope: "systemd:user:disable:*", Tier: TierConfirm},
	}
	// systemd:system 的"任意动作"按词表逐条 human 落地。
	for _, action := range actionVocabulary {
		rules = append(rules, Rule{Scope: "systemd:system:" + action + ":*", Tier: TierHuman})
	}
	for _, action := range []string{"start", "stop", "restart"} {
		rules = append(rules, Rule{Scope: "sysvinit:" + action + ":*", Tier: TierConfirm})
	}
	for _, runtime := range []string{"podman", "docker"} {
		for _, action := range []string{"start", "stop", "restart"} {
			rules = append(rules, Rule{Scope: runtime + ":" + action + ":*", Tier: TierConfirm})
		}
		for _, action := range []string{"remove", "update"} {
			rules = append(rules, Rule{Scope: runtime + ":" + action + ":*", Tier: TierHuman})
		}
	}
	// flatpak/snap 的版本类动作(含 install/remove)一律第三档:换版本=装包。
	for _, runtime := range []string{"flatpak", "snap"} {
		for _, action := range []string{"update", "install", "remove"} {
			rules = append(rules, Rule{Scope: runtime + ":" + action + ":*", Tier: TierHuman})
		}
	}
	return rules
}

// Load 解析档位表文件。文件不存在 ⇒ ErrNotFound(调用方自行决定回退);
// 语法错/未知键/非法值 ⇒ error(绝不退回默认:配置事故不得静默放宽自主权)。
// 合法文件只覆盖用户规则/危险名单/签发者名单,出厂预设恒来自 Default()。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		return nil, fmt.Errorf("autonomy: 读取 %s 失败: %w", path, err)
	}
	var file fileConfig
	meta, err := toml.Decode(string(data), &file)
	if err != nil {
		return nil, fmt.Errorf("autonomy: 解析 %s 失败: %w", path, err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("autonomy: %s 含未知键(fail-closed,拒绝拼写错误/第二事实源): %s", path, strings.Join(keys, ", "))
	}
	cfg := Default()
	if err := cfg.apply(file); err != nil {
		return nil, fmt.Errorf("autonomy: %s 校验失败: %w", path, err)
	}
	return &cfg, nil
}

// LoadConfigured 解析档位表路径:env 覆盖(必须绝对路径)→ 生产路径。
// 两者都不存在 ⇒ ErrNotFound。
func LoadConfigured() (*Config, error) {
	if v, ok := os.LookupEnv(EnvPath); ok {
		if !filepath.IsAbs(v) {
			return nil, fmt.Errorf("%w: %s=%q", ErrEnvNotAbsolute, EnvPath, v)
		}
		return Load(v)
	}
	return Load(ProductionPath)
}

// fileConfig 是档位表文件的结构;字段名即 TOML 键,未知键由 Undecoded 拦下。
type fileConfig struct {
	Deny        []string     `toml:"deny"`
	DenyNames   []string     `toml:"deny_names"`
	DenySigners []string     `toml:"deny_signers"`
	Rules       []fileRule   `toml:"rule"`
	Signers     []fileSigner `toml:"signer"`
}

// fileRule 是用户规则段([[rule]])。
type fileRule struct {
	Scope   string `toml:"scope"`
	Tier    string `toml:"tier"`
	Relaxed bool   `toml:"relaxed"`
}

// fileSigner 是签发者段([[signer]])。
type fileSigner struct {
	User     string   `toml:"user"`
	MaxScope []string `toml:"max_scope"`
	MaxTTL   string   `toml:"max_ttl"`
	MaxUses  int      `toml:"max_uses"`
}

// apply 校验文件内容并写入配置;任何非法取值都返回 error(不退默认)。
// 每个面都是整体赋值,不复用调用方已有的切片,避免同一 Config 被复用后静默叠加。
func (c *Config) apply(file fileConfig) error {
	rules := make([]Rule, 0, len(file.Rules))
	for i, rule := range file.Rules {
		scope, err := ParseScope(rule.Scope)
		if err != nil {
			return fmt.Errorf("第 %d 条 rule 的 scope 非法: %w", i+1, err)
		}
		if err := validPattern(scope.Target); err != nil {
			return fmt.Errorf("第 %d 条 rule 的 scope 非法: %w", i+1, err)
		}
		tier := Tier(rule.Tier)
		switch tier {
		case TierAuto, TierConfirm, TierHuman:
		default:
			return fmt.Errorf("第 %d 条 rule 的 tier %q 非法(只允许 auto/confirm/human)", i+1, rule.Tier)
		}
		// relaxed 是"显式放宽"的审计标记:只允许落在 confirm 上。
		if rule.Relaxed && tier != TierConfirm {
			return fmt.Errorf("第 %d 条 rule 的 relaxed=true 只能出现在 tier=\"confirm\" 上", i+1)
		}
		rules = append(rules, Rule{Scope: rule.Scope, Tier: tier, Relaxed: rule.Relaxed})
	}
	c.Rules = rules

	deny := make([]string, 0, len(file.Deny))
	for i, entry := range file.Deny {
		pattern, err := parsePattern(entry)
		if err != nil {
			return fmt.Errorf("第 %d 条 deny 非法: %w", i+1, err)
		}
		if err := validPattern(pattern.target); err != nil {
			return fmt.Errorf("第 %d 条 deny 非法: %w", i+1, err)
		}
		deny = append(deny, entry)
	}
	c.Deny = deny

	names := make([]string, 0, len(file.DenyNames))
	for i, name := range file.DenyNames {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("第 %d 条 deny_names 为空", i+1)
		}
		names = append(names, name)
	}
	c.DenyNames = names

	signers := make([]Signer, 0, len(file.Signers))
	// 同名签发者只允许一条:否则"再加一条更严的条目"会因首条命中而静默失效,
	// 配置看起来更严、实际更松。
	seenUsers := make(map[string]int, len(file.Signers))
	for i, signer := range file.Signers {
		if strings.TrimSpace(signer.User) == "" {
			return fmt.Errorf("第 %d 个 signer 缺少 user", i+1)
		}
		if prev, dup := seenUsers[signer.User]; dup {
			return fmt.Errorf("第 %d 个 signer 的 user %q 与第 %d 个重复(同一签发者只允许一条)", i+1, signer.User, prev)
		}
		seenUsers[signer.User] = i + 1
		parsed := Signer{User: signer.User, MaxUses: signer.MaxUses}
		// 上限必须显式写正数:缺省/0 若被当成"不限制",等于"少写一个字段就放宽"。
		if parsed.MaxUses <= 0 {
			return fmt.Errorf("第 %d 个 signer 的 max_uses 必须为正(缺省/0 不表示不限制)", i+1)
		}
		for j, maxScope := range signer.MaxScope {
			// 与消费侧同一套严格语法:加载期放行的形态必须真的能签出条子,
			// 否则会变成"配置说 OK、签发永远失败"的静默死配置。
			scope, err := ParseScope(maxScope)
			if err != nil {
				return fmt.Errorf("第 %d 个 signer 的第 %d 条 max_scope 非法(必须是含动作段的严格作用域): %w", i+1, j+1, err)
			}
			if err := validPattern(scope.Target); err != nil {
				return fmt.Errorf("第 %d 个 signer 的第 %d 条 max_scope 非法: %w", i+1, j+1, err)
			}
			parsed.MaxScope = append(parsed.MaxScope, maxScope)
		}
		if signer.MaxTTL == "" {
			return fmt.Errorf("第 %d 个 signer 缺少 max_ttl(必须显式写正时长,缺省不表示不限制)", i+1)
		}
		ttl, err := time.ParseDuration(signer.MaxTTL)
		if err != nil {
			return fmt.Errorf("第 %d 个 signer 的 max_ttl %q 非法: %w", i+1, signer.MaxTTL, err)
		}
		if ttl <= 0 {
			return fmt.Errorf("第 %d 个 signer 的 max_ttl 必须为正", i+1)
		}
		parsed.MaxTTL = ttl
		signers = append(signers, parsed)
	}
	c.Signers = signers
	c.DenySigners = file.DenySigners
	return nil
}
