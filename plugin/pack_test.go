// pack.go 的往返测试:构造最小插件目录 → 打包 → 校验,并钉死打包器的
// 前置拒绝(缺文件/缺可执行位/符号链接/非法 manifest)。
package plugin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeMinimalPlugin 在 t.TempDir() 下搭出最小合法 native 插件目录:
//
//	<root>/daedalus.plugin.json
//	<root>/bin/main        (0755, 可执行)
//	<root>/share/notes.txt (0644, 资源)
//
// manifestJSON 为 "" 时使用字段齐全的合法清单。
func writeMinimalPlugin(t *testing.T, manifestJSON string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "share"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFileAt(t, filepath.Join(root, "bin", "main"), []byte("#!/bin/sh\necho hi\n"), 0o755)
	writeFileAt(t, filepath.Join(root, "share", "notes.txt"), []byte("resource\n"), 0o644)
	if manifestJSON == "" {
		m := validManifest()
		m.Executable = "bin/main"
		manifestJSON = marshalManifestJSON(t, m)
	}
	writeFileAt(t, filepath.Join(root, ManifestFileName), []byte(manifestJSON), 0o644)
	return root
}

func writeFileAt(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func marshalManifestJSON(t *testing.T, m *Manifest) string {
	t.Helper()
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestPackVerifyRoundTrip 是核心验收:打包产物必须通过校验,
// 且 checksums 覆盖全部条目(含 manifest 自身)。
func TestPackVerifyRoundTrip(t *testing.T) {
	src := writeMinimalPlugin(t, "")
	zipPath := filepath.Join(t.TempDir(), "out.zip")

	m, err := Pack(src, zipPath)
	if err != nil {
		t.Fatalf("Pack 失败: %v", err)
	}
	// 期望 checksum 条目:bin/main + share/notes.txt + manifest 自身。
	if len(m.Checksums) != 3 {
		t.Fatalf("checksums 条目数 = %d, want 3 (%v)", len(m.Checksums), m.Checksums)
	}
	for _, name := range []string{"bin/main", "share/notes.txt", ManifestFileName} {
		if !validChecksum(m.Checksums[name]) {
			t.Errorf("checksums[%q] = %q 不是合法 sha256 摘要", name, m.Checksums[name])
		}
	}

	dest := t.TempDir()
	got, err := Verify(zipPath, dest)
	if err != nil {
		t.Fatalf("Verify 失败: %v", err)
	}
	if got.ID != "daedalus.copilot" || got.Executable != "bin/main" {
		t.Errorf("校验返回的 manifest 漂移: %+v", got)
	}
	// 解压产物内容、权限必须与源一致。
	data, err := os.ReadFile(filepath.Join(dest, "bin", "main"))
	if err != nil || string(data) != "#!/bin/sh\necho hi\n" {
		t.Errorf("解压 bin/main 内容不符: %q, %v", data, err)
	}
	fi, err := os.Stat(filepath.Join(dest, "bin", "main"))
	if err != nil || fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("解压 bin/main 丢失可执行位: %v", err)
	}
}

// TestPackDeterministic 证明同输入两次打包产出逐字节相同的 zip(固定时间戳)。
func TestPackDeterministic(t *testing.T) {
	src := writeMinimalPlugin(t, "")
	zipA := filepath.Join(t.TempDir(), "a.zip")
	zipB := filepath.Join(t.TempDir(), "b.zip")
	if _, err := Pack(src, zipA); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(src, zipB); err != nil {
		t.Fatal(err)
	}
	a, b := mustRead(t, zipA), mustRead(t, zipB)
	if string(a) != string(b) {
		t.Errorf("两次打包产出不一致(%d vs %d 字节),可复现性被破坏", len(a), len(b))
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestPack_Rejections 钉死打包器的输入侧拒绝规则。
func TestPack_Rejections(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) string // 返回插件根目录
		wantErr string
	}{
		{
			name: "manifest 缺 id",
			setup: func(t *testing.T) string {
				m := validManifest()
				m.ID = ""
				return writeMinimalPlugin(t, marshalManifestJSON(t, m))
			},
			wantErr: "id",
		},
		{
			name: "executable 指向不存在文件",
			setup: func(t *testing.T) string {
				m := validManifest()
				m.Executable = "bin/nope"
				return writeMinimalPlugin(t, marshalManifestJSON(t, m))
			},
			wantErr: "不存在",
		},
		{
			name: "executable 含 .. 直接被清单校验拒绝",
			setup: func(t *testing.T) string {
				m := validManifest()
				m.Executable = "../escape"
				return writeMinimalPlugin(t, marshalManifestJSON(t, m))
			},
			wantErr: "..",
		},
		{
			name: "包内容含符号链接",
			setup: func(t *testing.T) string {
				root := writeMinimalPlugin(t, "")
				if err := os.Symlink("/etc/passwd", filepath.Join(root, "share", "link")); err != nil {
					t.Fatal(err)
				}
				return root
			},
			wantErr: "符号链接",
		},
		{
			name: "executable 无执行位",
			setup: func(t *testing.T) string {
				root := writeMinimalPlugin(t, "")
				if err := os.Chmod(filepath.Join(root, "bin", "main"), 0o644); err != nil {
					t.Fatal(err)
				}
				return root
			},
			wantErr: "可执行位",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.setup(t)
			out := filepath.Join(t.TempDir(), "x.zip")
			_, err := Pack(src, out)
			if err == nil {
				t.Fatalf("应打包失败,错误包含 %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("错误消息 %q 不包含 %q", err.Error(), tc.wantErr)
			}
		})
	}
}
