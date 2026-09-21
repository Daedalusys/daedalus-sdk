// Package dirs 提供 state/tx 根路径的统一解析链(计划 todo 16,v1 执行模型)。
//
// v1 执行模型钉死:daedalus-tx 是**调用用户自己的进程**(直接 CLI,或经 copilot
// 的 --allow-run 授权的 Deno 子进程),**没有 daedalus-tx systemd 单元**——
// 没人调用的单元纯属装饰(评审 round 1:DynamicUser 单元没有真实用户的
// XDG_RUNTIME_DIR/user bus,根本跑不了 systemctl --user;用户域限制由
// todo 22 适配器路径守卫**无条件**强制,不依赖任何 systemd 沙箱)。
// 因此 state/tx 根的解析统一收敛到本包,供 internal/tx 与 internal/state 调用。
//
// 解析链(两个导出函数共享同一条内部链,签名按 round-3 fold 钉死):
//  1. env 覆盖(envVar 存在即生效):值**必须绝对路径**——相对或空值直接报错
//     (fail-closed,绝不静默忽略误配置);可用则原样使用;
//  2. 系统默认(systemDir/systemFile):Dir 用 MkdirAll+哨兵文件探测,
//     File 探测父目录可写;不可用则继续下探,不报错;
//  3. $HOME 兜底:HOME 为空/未设 → 该候选直接不可用;
//  4. 全部候选不可用 → 显式错误(ErrNoUsablePath),**绝不静默回落到 "/"**。
//
// demo 态对 /var/lib/daedalus 的奇偶性由 scripts/justfile.demo 导出的
// DAEDALUS_STATE_PATH / DAEDALUS_TX_DIR 提供(paths_demo.go 重写清单只有
// /opt/daedalus 与 /usr/local/bin,不扩展;env 覆盖就是钉死的 demo 机制)。
//
// v1 KNOWN LIMITATION(round-2 fold,todo 31 记为决策 25 扩展):
// DynamicUser=yes 时 StateDirectory=daedalus 宿侧实路径在
// /var/lib/private/daedalus,仅在单元 mount namespace 内绑定于 /var/lib/daedalus,
// 沙箱化 daedalus-service 写的 state 对用户态读取者不可见——v1 状态记忆是
// **按上下文隔离**的(用户态读写对自洽;集成测试全程用户态)。跨上下文共享
// 可见性推迟到未来的特权 helper 阶段,v1 禁止任何命名空间逃逸 hack。
package dirs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// 调用点常量:tx/state 的 env 变量名与两级默认路径,集中于此,
// 调用方(internal/tx、internal/state)经 TxRoot()/StateFile() 消费,
// 不再各自复制字面量。
const (
	// EnvTxDir 覆盖事务日志根目录(绝对路径)。
	EnvTxDir = "DAEDALUS_TX_DIR"
	// EnvStatePath 覆盖状态记忆文件路径(绝对路径)。
	EnvStatePath = "DAEDALUS_STATE_PATH"

	// TxSystemDir 是镜像内事务日志根目录(单元侧写入按 KNOWN LIMITATION 隔离于上下文)。
	TxSystemDir = "/var/lib/daedalus/tx"
	// TxHomeRel 是相对 $HOME 的事务日志兜底子路径。
	TxHomeRel = ".local/share/daedalus/tx"

	// StateSystemFile 是镜像内状态记忆文件。
	StateSystemFile = "/var/lib/daedalus/state.jsonl"
	// StateHomeRel 是相对 $HOME 的状态文件兜底子路径。
	StateHomeRel = ".local/share/daedalus/state.jsonl"
)

// 哨兵错误:调用方可用 errors.Is 区分"误配置"与"无处可写"两类失败。
var (
	// ErrEnvNotAbsolute 表示覆盖变量存在但值为空或相对路径——直接拒绝,
	// 绝不静默忽略(与 policy 的显式指向 fail-closed 惯例同源)。
	ErrEnvNotAbsolute = errors.New("dirs: 覆盖变量为空值或非绝对路径")
	// ErrNoUsablePath 表示 env/系统/$HOME 全部候选不可用——显式报错,
	// 绝不回落到 "/" 之类的静默路径。
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

// TxRoot 解析事务日志根目录——internal/tx 的唯一入口(round-3 fold:
// tx 需要 DIR,故走 Dir 而非 File)。
func TxRoot() (string, error) { return Dir(EnvTxDir, TxSystemDir, TxHomeRel) }

// StateFile 解析状态记忆文件路径——internal/state(todo 19)的唯一入口。
func StateFile() (string, error) { return File(EnvStatePath, StateSystemFile, StateHomeRel) }

// resolve 是 Dir/File 共享的解析链:构造有序候选(env 在首位且已校验绝对),
// 逐个过 usable 探测,首个可用即原样返回;全部不可用 → ErrNoUsablePath。
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
	// HOME 为空/未设时不加兜底候选:该候选直接视为不可用。

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
