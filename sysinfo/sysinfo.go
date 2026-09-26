// Package sysinfo 是系统信息只读查询逻辑的 Go 移植,规格源为
// daedalus/files/system/opt/daedalus/servers/sysinfo_server.py(Python 参考实现)。
// os_release / hardware_info / network_status 三条查询的解析、回退与错误文案
// 逐条对齐 py 版(细节见各函数文档)。
//
// 可测性:外部命令经 ExecRunner 注入;文件读取根目录经 root 字段重定向
// (生产为 "/");磁盘用量经 DiskUsageFunc 注入,使全部逻辑在无 rpm/dnf/ip
// 的开发机上可做确定性单测。
package sysinfo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// execTimeout 是 Go 侧新增的防御性超时(py 版对挂死进程会无限等待):
// 只影响异常挂死路径,不改变成功路径行为。
const execTimeout = 30 * time.Second

// ExecRunner 是外部命令执行器的注入签名:按 argv 直接执行 name + args
// (绝不经过 shell 解释,对应 py 的 asyncio.create_subprocess_exec)。
// err 非 nil 当且仅当进程无法启动/等待(对应 py 中 except 捕获的异常),
// 此时 code 无意义;进程正常退出(含非零码)时 err 为 nil、code 为退出码。
type ExecRunner func(ctx context.Context, name string, args []string) (stdout, stderr string, code int, err error)

func ExecCommand(ctx context.Context, name string, args []string) (string, string, int, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String(), stderr.String(), 0, nil
	}
	// 非零退出码在 Python 侧不是异常,而是 returncode:归类为正常返回。
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return stdout.String(), stderr.String(), exitErr.ExitCode(), nil
	}
	return stdout.String(), stderr.String(), -1, err
}

type Service struct {
	exec ExecRunner // 命令执行器(network_status 使用)
	root string     // 文件读取根目录:生产为 "/",测试重定向到 testdata
	disk DiskUsageFunc
}

// NewService 构造系统信息服务;exec/root/disk 为零值时使用默认实现。
func NewService(exec ExecRunner, root string, disk DiskUsageFunc) *Service {
	if exec == nil {
		exec = ExecCommand
	}
	if root == "" {
		root = "/"
	}
	if disk == nil {
		disk = StatfsDiskUsage
	}
	return &Service{exec: exec, root: root, disk: disk}
}

// path 把 py 版硬编码的绝对路径拼接到注入的根目录下(仅限只读探测)。
// filepath.Join 同时完成清理,root="/" 时不会产生双斜杠。
func (s *Service) path(p string) string {
	return filepath.Join(s.root, strings.TrimPrefix(p, "/"))
}

// pyStrip 复刻 Python str.strip() 的默认空白集(空格/\t/\n/\v/\f/\r),
// 与 py 版逐字节的裁剪行为一致。
func pyStrip(s string) string {
	return strings.Trim(s, " \t\n\v\f\r")
}

// isRegularFile 对应 py 的 os.path.isfile(跟随符号链接,仅普通文件为真)。
func isRegularFile(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.Mode().IsRegular()
}

// splitLines 近似 Python 的 readlines()/splitlines() 行切分:
// 对 os-release、/proc 系列文本按 "\n" 切分并去掉行尾换行,
// 末行无换行符时不产生伪空行。
func splitLines(data string) []string {
	if data == "" {
		return nil
	}
	lines := strings.Split(data, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

// OSRelease 移植 sysinfo_server.py 的 os_release:
// 按候选顺序取第一个存在的文件,逐行解析 key=value(去引号、跳注释/空行/无 '=' 行);
// 文件缺失或读取失败时返回 {"error": ...} 字典(键与文案与 py 版逐字对齐)。
func (s *Service) OSRelease() map[string]any {
	candidates := []string{"/etc/os-release", "/usr/lib/os-release"}
	targetFile := ""
	for _, p := range candidates {
		if isRegularFile(s.path(p)) {
			targetFile = s.path(p)
			break
		}
	}
	if targetFile == "" {
		return map[string]any{"error": "Neither /etc/os-release nor /usr/lib/os-release found"}
	}

	data := map[string]any{}
	raw, err := os.ReadFile(targetFile)
	if err != nil {
		// 读取异常的 Go 等价错误串(python 为 OSError 消息,
		// 消息正文为 OS 原生,格式外壳逐字一致)。
		return map[string]any{"error": fmt.Sprintf("Failed to read os-release: %v", err)}
	}
	for _, line := range splitLines(string(raw)) {
		line = pyStrip(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		k, v, _ := strings.Cut(line, "=") // split("=", 1)
		k, v = pyStrip(k), pyStrip(v)
		// 成对双引号或单引号则去掉首尾各一字符;
		// Python 切片对长度为 1 的引号串取 [1:-1] 得空串,Go 显式复刻。
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		} else if len(v) == 1 && (v[0] == '"' || v[0] == '\'') {
			v = ""
		}
		data[k] = v
	}
	return data
}
