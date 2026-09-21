// VerifyDir(已安装插件目录校验)的测试:宿主 daedalus-host 的
// verify/list 依赖它与 Verify 共用同一校验核心,本文件钉死
// "安装目录被篡改必须被拒绝"的交接约束(todo 6 → todo 7)。
package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installPlugin 走完整的构建期安装链:源目录 → Pack 成 zip → ExtractZip
// 解压到安装目录,返回安装目录路径(即镜像内 /opt/daedalus/plugins/<id>/ 的等价物)。
func installPlugin(t *testing.T, srcDir string) string {
	t.Helper()
	zipPath := filepath.Join(t.TempDir(), "plugin.daedalus")
	if _, err := Pack(srcDir, zipPath); err != nil {
		t.Fatalf("Pack 失败: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "installed")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractZip(zipPath, dest); err != nil {
		t.Fatalf("ExtractZip 失败: %v", err)
	}
	return dest
}

func TestVerifyDir_RoundTrip(t *testing.T) {
	// Given: 一个经打包器正常安装的插件目录。
	src := writeMinimalPlugin(t, "")
	dest := installPlugin(t, src)

	// When: 对安装目录执行 VerifyDir。
	m, err := VerifyDir(dest)

	// Then: 校验通过且返回 manifest 字段完整。
	if err != nil {
		t.Fatalf("VerifyDir 应通过: %v", err)
	}
	if m.ID != "daedalus.copilot" || m.Executable != "bin/main" {
		t.Errorf("返回 manifest 不符: %+v", m)
	}
}

func TestVerifyDir_Rejections(t *testing.T) {
	tests := []struct {
		name    string
		tamper  func(t *testing.T, dest string)
		wantSub string
	}{
		{
			// 篡改文件字节:与 zip 校验同口径的 "checksum 不匹配"。
			name: "file_tampered",
			tamper: func(t *testing.T, dest string) {
				writeFileAt(t, filepath.Join(dest, "share", "notes.txt"), []byte("evil\n"), 0o644)
			},
			wantSub: "checksum 不匹配",
		},
		{
			// 注入额外文件:有文件无摘要 → 拒绝(不许放宽)。
			name: "extra_file",
			tamper: func(t *testing.T, dest string) {
				writeFileAt(t, filepath.Join(dest, "inject.sh"), []byte("#!/bin/sh\n"), 0o755)
			},
			wantSub: "checksum 缺失",
		},
		{
			// 删除文件:有摘要无文件 → 同样拒绝。
			name: "file_removed",
			tamper: func(t *testing.T, dest string) {
				if err := os.Remove(filepath.Join(dest, "share", "notes.txt")); err != nil {
					t.Fatal(err)
				}
			},
			wantSub: "checksum 多余",
		},
		{
			// 可执行位丢失:mode&0o111 判定与 zip 侧一致。
			name: "exec_bit_lost",
			tamper: func(t *testing.T, dest string) {
				if err := os.Chmod(filepath.Join(dest, "bin", "main"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantSub: "缺少可执行位",
		},
		{
			// 目录内植入符号链接:已安装目录同样不容许逃逸通道。
			name: "symlink_injected",
			tamper: func(t *testing.T, dest string) {
				if err := os.Symlink("/etc/passwd", filepath.Join(dest, "escape")); err != nil {
					t.Fatal(err)
				}
			},
			wantSub: "符号链接",
		},
		{
			// manifest 被改写(去掉 checksums 注入痕迹):规范化自摘要必须失败。
			name: "manifest_rewritten",
			tamper: func(t *testing.T, dest string) {
				manifest := filepath.Join(dest, ManifestFileName)
				m := validManifest()
				m.Executable = "bin/main"
				// 安装后的 manifest 是只读 0444(打包器落盘模式),
				// 篡改者(或构建事故)得先拿到写权限才改得动。
				if err := os.Chmod(manifest, 0o644); err != nil {
					t.Fatal(err)
				}
				writeFileAt(t, manifest, []byte(marshalManifestJSON(t, m)), 0o444)
			},
			wantSub: "checksums",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := writeMinimalPlugin(t, "")
			dest := installPlugin(t, src)
			tc.tamper(t, dest)

			_, err := VerifyDir(dest)
			if err == nil {
				t.Fatalf("篡改后 VerifyDir 应失败,却通过了")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("错误原因 = %q, want 含 %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestVerifyDir_MissingDir(t *testing.T) {
	// Given: 目录根本不存在(宿主传入畸形 id 时的兜底路径)。
	_, err := VerifyDir(filepath.Join(t.TempDir(), "nope"))
	if err == nil || !strings.Contains(err.Error(), "不存在") {
		t.Fatalf("应报目录不存在,实得: %v", err)
	}
}
