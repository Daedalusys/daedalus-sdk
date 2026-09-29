// Package dirs 提供 state/tx 根路径的统一解析链。
//
// v1 执行模型:daedalus-tx 是调用用户自己的进程(无 systemd 单元),用户域限制由
// 适配器路径守卫无条件强制。
// 解析链:env 覆盖(必须绝对路径)→ 系统探测 → $HOME 兜底 → 显式错误;
// 全部候选不可用返回 ErrNoUsablePath,绝不静默回落到 "/"。
// 已知限制:宿侧 state 被 DynamicUser 隔离于 /var/lib/private/daedalus,
// 用户态不可见;v1 状态记忆按上下文隔离,禁止命名空间逃逸 hack。
package dirs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// EnvTxDir 覆盖事务日志根目录;值必须绝对路径(相对或空值直接报错)。
	EnvTxDir = "DAEDALUS_TX_DIR"
	// EnvStatePath 覆盖状态记忆文件路径;值必须绝对路径。
	EnvStatePath = "DAEDALUS_STATE_PATH"

	// TxSystemDir 是镜像内事务日志根目录(单元侧写入按上述已知限制隔离于上下文)。
	TxSystemDir = "/var/lib/daedalus/tx"
	TxHomeRel   = ".local/share/daedalus/tx"

	StateSystemFile = "/var/lib/daedalus/state.jsonl"
	StateHomeRel    = ".local/share/daedalus/state.jsonl"
)

// 哨兵错误:调用方可用 errors.Is 区分"误配置"与"无处可写"两类失败。
var (
	// ErrEnvNotAbsolute 表示覆盖变量存在但值为空或相对路径——直接拒绝,
	// 绝不静默忽略(与 policy 的 fail-closed 惯例同源)。
	ErrEnvNotAbsolute = errors.New("dirs: 覆盖变量为空值或非绝对路径")
	// ErrNoUsablePath 表示全部候选不可用——显式报错,绝不回落到 "/" 之类的静默路径。
	ErrNoUsablePath = errors.New("dirs: env/系统/$HOME 候选均不可用")
)

// Dir 解析目录型根(tx 日志目录等):env → 系统探测 → $HOME 兜底 → 显式错误。
// 命中的目录候选会被探测确保存在(系统/兜底候选亦然)。
func Dir(envVar, systemDir, homeRelDir string) (string, error) {
	return resolve(envVar, systemDir, homeRelDir, probeDir)
}

// File 解析文件型路径(state.jsonl 等):候选次序同 Dir;探测只作用于文件
// 所在父目录(绝不创建文件本体,内容由调用方写入)。
func File(envVar, systemFile, homeRelFile string) (string, error) {
	return resolve(envVar, systemFile, homeRelFile, func(p string) bool {
		return probeDir(filepath.Dir(p))
	})
}

func TxRoot() (string, error) { return Dir(EnvTxDir, TxSystemDir, TxHomeRel) }

func StateFile() (string, error) { return File(EnvStatePath, StateSystemFile, StateHomeRel) }

// resolve 是 Dir/File 共享的解析链:逐个过 usable 探测,首个可用即返回;
// 全部不可用 → ErrNoUsablePath。
func resolve(envVar, systemPath, homeRel string, usable func(string) bool) (string, error) {
	var candidates []string
	if v, ok := os.LookupEnv(envVar); ok {
		if !filepath.IsAbs(v) {
			return "", fmt.Errorf("%w: %s=%q", ErrEnvNotAbsolute, envVar, v)
		}
		candidates = append(candidates, v)
	}
	candidates = append(candidates, systemPath)
	if home := os.Getenv("HOME"); home != "" {
		candidates = append(candidates, filepath.Join(home, homeRel))
	}

	for _, c := range candidates {
		if usable(c) {
			return c, nil
		}
	}
	return "", fmt.Errorf("%w(候选: %v)", ErrNoUsablePath, candidates)
}

// probeDir 探测目录可用性:先 MkdirAll(含中间目录)再写入/删除唯一哨兵
// 文件——存在但不可写(如 mode 0500)同样判为不可用。任一步失败即不可用。
func probeDir(dir string) bool {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false
	}
	f, err := os.CreateTemp(dir, ".daedalus-dirs-probe-*")
	if err != nil {
		return false
	}
	if err := f.Close(); err != nil {
		return false
	}
	return os.Remove(f.Name()) == nil
}
