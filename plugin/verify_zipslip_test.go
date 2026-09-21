// verify_zipslip_test.go: extract.go 的 zip-slip 对抗测试——用 stdlib archive/zip
// 手工构造各类逃逸/畸形包,钉死拒绝路径与"解压目录之外零落盘"两条断言。
package plugin

import (
	"archive/zip"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildZip 按给定的条目(name → content,附可选 mode)在 diskPath 处写出 zip。
// dir 为 true 时写目录条目;symlinkTo 非空时写符号链接条目。
type evilEntry struct {
	name    string
	content []byte
	mode    fs.FileMode
	dir     bool
	symlink bool
}

func buildZip(t *testing.T, diskPath string, entries []evilEntry) {
	t.Helper()
	f, err := os.Create(diskPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		switch {
		case e.dir:
			hdr.SetMode(fs.ModeDir | 0o755)
		case e.symlink:
			hdr.SetMode(fs.ModeSymlink | 0o777)
		default:
			if e.mode == 0 {
				e.mode = 0o644
			}
			hdr.SetMode(e.mode)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestVerify_ZipSlipRejections 构造各类逃逸 zip:必须拒绝,
// 且绝不允许在解压目录之外落盘任何文件。
func TestVerify_ZipSlipRejections(t *testing.T) {
	manifestGood := func(t *testing.T) []byte {
		m := validManifest()
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	tests := []struct {
		name    string
		entries func(t *testing.T) []evilEntry
		wantErr string
	}{
		{
			name: "经典 zip-slip:../evil 条目",
			entries: func(t *testing.T) []evilEntry {
				return []evilEntry{
					{name: "../escaped.txt", content: []byte("pwn")},
					{name: ManifestFileName, content: manifestGood(t)},
				}
			},
			wantErr: "zip-slip 拒绝",
		},
		{
			name: "嵌套 dotdot:sub/../../evil",
			entries: func(t *testing.T) []evilEntry {
				return []evilEntry{
					{name: "sub/../../escaped.txt", content: []byte("pwn")},
					{name: ManifestFileName, content: manifestGood(t)},
				}
			},
			wantErr: "zip-slip 拒绝",
		},
		{
			name: "绝对路径条目",
			entries: func(t *testing.T) []evilEntry {
				return []evilEntry{
					{name: "/tmp/daedalus-zipslip-abs.test", content: []byte("pwn")},
					{name: ManifestFileName, content: manifestGood(t)},
				}
			},
			wantErr: "绝对路径",
		},
		{
			name: "Windows 反斜杠路径",
			entries: func(t *testing.T) []evilEntry {
				return []evilEntry{
					{name: `sub\..\..\escaped.txt`, content: []byte("pwn")},
					{name: ManifestFileName, content: manifestGood(t)},
				}
			},
			wantErr: "反斜杠",
		},
		{
			name: "空字节条目名",
			entries: func(t *testing.T) []evilEntry {
				return []evilEntry{
					{name: "bin/main\x00.txt", content: []byte("pwn")},
					{name: ManifestFileName, content: manifestGood(t)},
				}
			},
			wantErr: "空字节",
		},
		{
			name: "符号链接条目指向包外",
			entries: func(t *testing.T) []evilEntry {
				return []evilEntry{
					{name: "bin/main", symlink: true, content: []byte("/etc/passwd")},
					{name: ManifestFileName, content: manifestGood(t)},
				}
			},
			wantErr: "符号链接",
		},
		{
			name: "缺 manifest",
			entries: func(t *testing.T) []evilEntry {
				return []evilEntry{{name: "bin/main", content: []byte("x"), mode: 0o755}}
			},
			wantErr: "缺少",
		},
		{
			name: "重复条目名",
			entries: func(t *testing.T) []evilEntry {
				return []evilEntry{
					{name: "bin/main", content: []byte("good"), mode: 0o755},
					{name: "bin/main", content: []byte("evil"), mode: 0o755},
					{name: ManifestFileName, content: manifestGood(t)},
				}
			},
			wantErr: "重复",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			zipPath := filepath.Join(t.TempDir(), "evil.zip")
			buildZip(t, zipPath, tc.entries(t))
			dest := t.TempDir()
			_, err := Verify(zipPath, dest)
			if err == nil {
				t.Fatalf("恶意 zip 被接受(期望错误包含 %q)", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("错误消息 %q 不包含 %q", err.Error(), tc.wantErr)
			}
			// 逃逸断言:解压目录之外不得出现任何被写入的文件。
			if _, statErr := os.Stat(filepath.Join(filepath.Dir(dest), "escaped.txt")); statErr == nil {
				t.Error("zip-slip 成功:escaped.txt 被写到解压目录之外")
			}
			if _, statErr := os.Stat("/tmp/daedalus-zipslip-abs.test"); statErr == nil {
				t.Error("zip-slip 成功:绝对路径条目落盘")
			}
		})
	}
}

// TestVerify_SymlinkAncestorEscape 钉死两道防线之外的第三道:
// 即使解压目标目录里预先存在指向外部的符号链接目录,
// 写入途经它的条目也必须被 ensureSafeDir 的逐级 lstat 拦截。
func TestVerify_SymlinkAncestorEscape(t *testing.T) {
	outside := t.TempDir()
	dest := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dest, "bin")); err != nil {
		t.Fatal(err)
	}
	m := validManifest()
	zipPath := filepath.Join(t.TempDir(), "pkg.zip")
	buildZip(t, zipPath, []evilEntry{
		{name: "bin/main", content: []byte("#!/bin/sh\n"), mode: 0o755},
		{name: ManifestFileName, content: mustJSON(t, m)},
	})
	_, err := Verify(zipPath, dest)
	if err == nil || !strings.Contains(err.Error(), "符号链接") {
		t.Fatalf("途经符号链接的写入未被拦截: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "main")); statErr == nil {
		t.Error("逃逸成功:文件经符号链接写到了外部目录")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
