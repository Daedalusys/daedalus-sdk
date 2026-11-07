package pathguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withAllowed 临时替换 AllowedDirs,测试结束还原(全局变量的唯一安全用法)。
func withAllowed(t *testing.T, dirs ...string) {
	t.Helper()
	orig := append([]string(nil), AllowedDirs...)
	WithAllowedDirs(dirs)
	t.Cleanup(func() { WithAllowedDirs(orig) })
}

// 二档的核心承诺:即便白名单被放宽到含 /etc,敏感文件与只读系统目录仍必须拒写。
// 这正是 fs.write_file 今天缺失的防线。
func TestValidateWritePath_RejectsSensitiveEvenWhenAllowed(t *testing.T) {
	tmp := t.TempDir()
	// 造出真实存在的敏感目标,好让 EvalSymlinks 通过——二档要在 realpath 之后才判定。
	sudoersD := filepath.Join(tmp, "sudoers.d")
	if err := os.MkdirAll(sudoersD, 0o755); err != nil {
		t.Fatal(err)
	}
	sensitive := filepath.Join(sudoersD, "probe")
	if err := os.WriteFile(sensitive, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	// 白名单放宽到含该前缀(模拟运维自定义 policy 把 /etc 加进来)。
	withAllowed(t, "/tmp", "/etc", "/proc")

	// 直接对 /etc 下的真实敏感面断言:若该路径在本机不存在,EvalSymlinks 会先失败,
	// 也是"拒",但那验的不是二档本身。故用 forbiddenWritePatterns 的语义做等价断言:
	// 只要路径解析后落在禁止清单内,就必须拒。
	for _, p := range []string{"/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/pam.d/common-auth"} {
		if _, err := ValidateWritePath(p); err == nil {
			t.Fatalf("放宽白名单到含 /etc 后,%s 仍必须被二档拒绝", p)
		} else if !strings.Contains(err.Error(), "write denied") {
			t.Fatalf("%s 的拒绝信息应含 'write denied',实得: %v", p, err)
		}
	}
	for _, p := range []string{"/proc/sys/kernel/hostname", "/sys/kernel/x", "/usr/bin/x", "/boot/x"} {
		if _, err := ValidateWritePath(p); err == nil {
			t.Fatalf("只读系统目录 %s 必须被二档拒绝", p)
		}
	}
}

// 正常写路径不能被收紧:白名单内的普通文件仍须通过。
func TestValidateWritePath_AllowsNormalTargets(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "ok.txt")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	withAllowed(t, tmp)

	got, err := ValidateWritePath(target)
	if err != nil {
		t.Fatalf("白名单内的普通文件应通过, got %v", err)
	}
	if got != target {
		t.Fatalf("应返回规范化原路径 %q, got %q", target, got)
	}
}
