// pathguard 包的表驱动测试:逐条钉死 fs_server.ts:36-110 的路径校验语义。
package pathguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAllowedDirs 钉死白名单常量内容与顺序(任何漂移都必须先改此测试)。
func TestAllowedDirs(t *testing.T) {
	want := []string{"/home", "/var/log", "/tmp"}
	if len(AllowedDirs) != len(want) {
		t.Fatalf("ALLOWED_DIRS 数量漂移: got %d, want %d (%v)", len(AllowedDirs), len(want), AllowedDirs)
	}
	for i := range want {
		if AllowedDirs[i] != want[i] {
			t.Errorf("ALLOWED_DIRS[%d] = %q, want %q", i, AllowedDirs[i], want[i])
		}
	}
}

// TestNormalizePath 对应 fs_server.ts:96-110 的词法规范化(dotdot 弹栈、
// 空段与 '.' 丢弃;栈空时 pop 为 no-op,不会越过根)。
func TestNormalizePath(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"/home/./foo", "/home/foo"},
		{"/home/bar/../foo", "/home/foo"},
		{"/tmp//a///b", "/tmp/a/b"},
		{"/home/../etc/shadow", "/etc/shadow"},
		{"/a/b/../../c", "/c"},
		{"/a/../../b", "/b"},
		{"/tmp", "/tmp"},
		{"/tmp/", "/tmp"},
		{"/", "/"},
		{"/..", "/"},
	}
	for _, tc := range tests {
		if got := normalizePath(tc.in); got != tc.want {
			t.Errorf("normalizePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidatePath_Rejections(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantError string // 错误消息必须包含的子串
	}{
		{"空字符串", "", "non-empty string"},
		{"空字节", "/tmp/a\x00b", "null bytes are forbidden"},
		{"相对路径", "etc/passwd", "only absolute paths are permitted"},
		{"点开头相对路径", "./tmp/x", "only absolute paths are permitted"},
		{"dotdot 穿越到 /etc", "/home/../etc/shadow", "outside allowed directories"},
		{"dotdot 穿越到根", "/tmp/../../etc/passwd", "outside allowed directories"},
		// 前缀必须带 '/' 边界:/home2 不是 /home 的子路径。
		{"home2 前缀边界", "/home2", "outside allowed directories"},
		{"home2 深层", "/home2/x/y", "outside allowed directories"},
		{"tmp2 前缀边界", "/tmp2", "outside allowed directories"},
		{"var 本身不在白名单", "/var", "outside allowed directories"},
		{"var/logx 前缀边界", "/var/logx", "outside allowed directories"},
		{"proc 不在 fs 白名单", "/proc/self/cmdline", "outside allowed directories"},
		{"系统目录", "/etc/passwd", "outside allowed directories"},
		{"根目录", "/", "outside allowed directories"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// write 两个分支都必须执行同一套规则(ts 忽略 _write)。
			for _, write := range []bool{false, true} {
				got, err := ValidatePath(tc.path, write)
				if err == nil {
					t.Fatalf("ValidatePath(%q, write=%v) 意外成功: %q", tc.path, write, got)
				}
				if !strings.Contains(err.Error(), tc.wantError) {
					t.Errorf("ValidatePath(%q, write=%v) 错误消息 %q 不含 %q", tc.path, write, err, tc.wantError)
				}
			}
		})
	}
}

func TestValidatePath_AllowlistAccess(t *testing.T) {
	// 本机事实前提:/tmp 与 /var/log 都是真实目录(/var/log/daedalus 仅按词法解析)。
	requireRealPath(t, "/tmp", "/tmp")
	requireRealPath(t, "/var/log", "/var/log")

	tests := []struct {
		name string
		path string
		want string // 期望的规范化返回值
	}{
		{"tmp 精确匹配", "/tmp", "/tmp"},
		{"home 精确匹配", "/home", "/home"},
		{"var/log 精确匹配", "/var/log", "/var/log"},
		{"var/log 子路径", "/var/log/daedalus/audit.jsonl", "/var/log/daedalus/audit.jsonl"},
		{"点段规范化", "/tmp/./x", "/tmp/x"},
		{"白名单内 dotdot", "/tmp/a/../b", "/tmp/b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidatePath(tc.path, false)
			if err != nil {
				t.Fatalf("ValidatePath(%q) 失败: %v", tc.path, err)
			}
			if got != tc.want {
				t.Errorf("ValidatePath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestValidatePath_SymlinkEscape 验证符号链接解析封堵两类逃逸:
//  1. 链接目标真实存在(/etc/shadow);
//  2. 链接目标末段不存在(/etc/daedalus_missing)——必须由父目录逐级解析
//     才能识别逃逸,纯词法规范化会放行。
func TestValidatePath_SymlinkEscape(t *testing.T) {
	base := mustMkdirTempUnderTmp(t)
	link := filepath.Join(base, "escape")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatalf("创建符号链接失败: %v", err)
	}

	for _, path := range []string{link + "/shadow", link + "/daedalus_missing_target"} {
		got, err := ValidatePath(path, true)
		if err == nil {
			t.Errorf("symlink 逃逸 %q 被放行(解析为 %q)", path, got)
			continue
		}
		if !strings.Contains(err.Error(), "outside allowed directories") {
			t.Errorf("symlink 逃逸 %q 错误消息异常: %v", path, err)
		}
	}
}

// TestValidatePath_SymlinkInsideAllowlist 白名单内部的合法符号链接必须放行。
func TestValidatePath_SymlinkInsideAllowlist(t *testing.T) {
	base := mustMkdirTempUnderTmp(t)
	realFile := filepath.Join(base, "real.txt")
	if err := os.WriteFile(realFile, []byte("hi"), 0o644); err != nil {
		t.Fatalf("写入测试文件失败: %v", err)
	}
	link := filepath.Join(base, "link.txt")
	if err := os.Symlink(realFile, link); err != nil {
		t.Fatalf("创建符号链接失败: %v", err)
	}
	got, err := ValidatePath(link, false)
	if err != nil {
		t.Fatalf("白名单内符号链接被误拒: %v", err)
	}
	if got != realFile {
		t.Errorf("ValidatePath(%q) = %q, want 解析后 %q", link, got, realFile)
	}
}

// TestValidatePath_MissingNestedWrite 验证 write_file 对"整链不存在"路径的回退:
// 深层父目录不存在时按词法规范化,路径仍在白名单内则放行。
func TestValidatePath_MissingNestedWrite(t *testing.T) {
	base := mustMkdirTempUnderTmp(t)
	deep := filepath.Join(base, "missing", "deeper", "newfile.txt")
	got, err := ValidatePath(deep, true)
	if err != nil {
		t.Fatalf("不存在的白名单内路径被误拒: %v", err)
	}
	if got != deep {
		t.Errorf("ValidatePath(%q) = %q, want %q", deep, got, deep)
	}
}

// requireRealPath 钉死本机 realpath 事实,不满足时跳过(而非误报失败)。
func requireRealPath(t *testing.T, p, want string) {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Skipf("无法解析 %s: %v", p, err)
	}
	if r != want {
		t.Skipf("%s 不是真实目录(realpath=%s),跳过依赖该事实的用例", p, r)
	}
}

// mustMkdirTempUnderTmp 在 /tmp(fs 白名单目录)下创建临时目录并注册清理。
func mustMkdirTempUnderTmp(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "pathguard-test-*")
	if err != nil {
		t.Fatalf("创建 /tmp 临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
