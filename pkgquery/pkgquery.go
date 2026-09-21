// Package pkgquery 是软件包只读查询逻辑的 Go 移植,规格源为
// daedalus/files/system/opt/daedalus/servers/pkg_server.py(Python 参考实现)。
//
// 行为逐条对齐 py 版:
//   - PACKAGE_PATTERN 白名单正则(py:15),拒绝 shell 元字符注入;
//   - 空名/非法字符拒绝,错误串逐字对齐 py:21、py:23;
//   - dnf_query:先 `rpm -q --info`,成功且有输出即返回(py:43-53);
//     否则回退 `dnf repoquery --info`(py:56-68),错误串逐字对齐 py:53/66/68;
//   - dnf_list_installed:`rpm -qa <pattern>`(默认 "*"),按行去空白、
//     排序返回(py:72-102),错误串逐字对齐 py:94/102。
//
// 可测性:一切外部命令执行经由 ExecRunner 注入,开发机没有 rpm/dnf
// 也能对回退序列与错误文案做确定性单测。
package pkgquery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// execTimeout 是 Go 侧新增的防御性超时(py 版无对应逻辑)。
// Python 的 create_subprocess_exec 对挂死的 rpm/dnf 会无限等待,
// Go 版统一以 30 秒上限防止单个工具调用永久占用服务器;
// 该超时只影响异常挂死路径,不改变任何成功路径的行为。
const execTimeout = 30 * time.Second

// packagePattern 允许的软件包名称模式,以防止命令行参数注入。
// 逐字移植 pkg_server.py:15 的 `^[a-zA-Z0-9_\-\.\*\+\:]+$`
// (Go RE2 接受字符类内对非字母数字字符的反斜杠转义,语义一致;
// py 的 `$` 允许尾随换行、Go 不允许,但两版都先做 strip,无实际差异)。
var packagePattern = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\*\+\:]+$`)

// IsValidPackageName 报告 name 是否匹配 PACKAGE_PATTERN 白名单（防命令行参数注入）。
// 这是 package_set.go 等跨包消费者的单一事实源：任何对包名做合法性校验的代码
// 必须调用本函数，不允许内联 packagePattern 副本。sanitizeQuery 内部仍以
// packagePattern.MatchString 实现（保持既有行为不变），不替换为 IsValidPackageName
// 调用，避免回退路径的语义变化。
func IsValidPackageName(name string) bool {
	return packagePattern.MatchString(name)
}

// ExecRunner 是外部命令执行器的注入签名:按 argv 直接执行 name + args
// (绝不经过 shell 解释,对应 py 的 asyncio.create_subprocess_exec)。
// err 非 nil 当且仅当进程无法启动/等待(对应 py 中 except 捕获的异常),
// 此时 code 无意义;进程正常退出(含非零码)时 err 为 nil、code 为退出码。
type ExecRunner func(ctx context.Context, name string, args []string) (stdout, stderr string, code int, err error)

// ExecCommand 是 ExecRunner 的默认实现(os/exec,argv 直发,无 shell 包装)。
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

// Service 封装注入了命令执行器的软件包查询逻辑。
type Service struct {
	exec ExecRunner
}

// NewService 构造查询服务;exec 为 nil 时使用默认的 os/exec 实现。
func NewService(exec ExecRunner) *Service {
	if exec == nil {
		exec = ExecCommand
	}
	return &Service{exec: exec}
}

// pyStrip 复刻 Python str.strip() 的默认空白集(空格/\t/\n/\v/\f/\r),
// 不引入 Unicode 空白,保证与 py 版逐字节的裁剪行为一致。
func pyStrip(s string) string {
	return strings.Trim(s, " \t\n\v\f\r")
}

// sanitizeQuery 移植 pkg_server.py:18-24 的 _sanitize_query:
// 先 strip,空名与不匹配白名单正则的名称都以 error 拒绝
// (py 侧抛 ValueError,Go 侧以 error 返回,消息逐字一致)。
func sanitizeQuery(pkg string) (string, error) {
	pkg = pyStrip(pkg)
	if pkg == "" {
		return "", errors.New("Package name/pattern cannot be empty.")
	}
	if !packagePattern.MatchString(pkg) {
		return "", fmt.Errorf("Invalid package name or pattern: %s", pkg)
	}
	return pkg, nil
}

// DnfQuery 移植 pkg_server.py:27-68 的 dnf_query。
// 返回的字符串与 py 版工具返回值逐字一致(包信息或错误消息);
// error 仅在包名校验失败(对应 py 的 ValueError)时非 nil。
func (s *Service) DnfQuery(ctx context.Context, name string) (string, error) {
	safeName, err := sanitizeQuery(name)
	if err != nil {
		return "", err
	}
	// Go 侧新增防御超时(见 execTimeout 注释),不改变成功路径行为。
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	// 1. 优先尝试查询本地已安装的 rpm(py:42-53)。
	stdout, _, code, execErr := s.exec(ctx, "rpm", []string{"-q", "--info", safeName})
	if execErr != nil {
		// py:53 —— rpm 无法启动即直接返回,不会再尝试 dnf(异常路径提前 return)。
		return fmt.Sprintf("Error executing rpm query: %v", execErr), nil
	}
	if code == 0 && stdout != "" {
		return pyStrip(stdout), nil
	}

	// 2. 未安装或 rpm 查询失败时,回退到 dnf repoquery 获取仓库信息(py:55-68)。
	var stderr string
	stdout, stderr, code, execErr = s.exec(ctx, "dnf", []string{"repoquery", "--info", safeName})
	if execErr != nil {
		return fmt.Sprintf("Error executing dnf repoquery: %v", execErr), nil
	}
	if code == 0 && stdout != "" {
		return pyStrip(stdout), nil
	}
	// py:66 —— stderr 先 strip,整句再 strip(回退串末尾空格被收敛)。
	notFound := fmt.Sprintf("Package '%s' not found locally or in repositories. %s", safeName, pyStrip(stderr))
	return pyStrip(notFound), nil
}

// DnfListInstalled 移植 pkg_server.py:71-102 的 dnf_list_installed。
// 返回的字符串切片与 py 版逐条等价(错误也以单元素列表形态返回,
// 对应 py:94、py:102 的 `[f"Error ..."]`);error 仅在 pattern 校验失败时非 nil。
// pattern 的默认值 "*" 由调用方(工具层)负责填充,与 py 的函数默认参数一致。
func (s *Service) DnfListInstalled(ctx context.Context, pattern string) ([]string, error) {
	safePattern, err := sanitizeQuery(pattern)
	if err != nil {
		return nil, err
	}
	// Go 侧新增防御超时(见 execTimeout 注释),不改变成功路径行为。
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	stdout, stderr, code, execErr := s.exec(ctx, "rpm", []string{"-qa", safePattern})
	if execErr != nil {
		// py:102
		return []string{fmt.Sprintf("Error executing rpm -qa: %v", execErr)}, nil
	}
	if code != 0 {
		// py:92-94
		return []string{fmt.Sprintf("Error listing packages: %s", pyStrip(stderr))}, nil
	}
	// py:96-100:strip 后为空则返回 [];否则逐行 strip、丢弃空行、排序。
	// rpm -qa 输出按行分隔(Go 以 "\n" 切分,与 py splitlines 在该输出上等价)。
	output := pyStrip(stdout)
	if output == "" {
		return []string{}, nil
	}
	lines := []string{}
	for _, line := range strings.Split(output, "\n") {
		if t := pyStrip(line); t != "" {
			lines = append(lines, t)
		}
	}
	sort.Strings(lines)
	return lines, nil
}
