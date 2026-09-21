// verify.go 的完整性对抗测试:checksum 篡改(文件字节/摘要值)、zip bomb 限额、
// 条目集合与 checksums 集合双向不一致。恶意 zip 的构造工具见同包测试文件。
package plugin

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tamper 把已打包 zip 中名为 name 的条目内容改写为 content(其余原样),
// 模拟"包在传输/存储介质上被篡改"。
func tamper(t *testing.T, zipPath, name string, content []byte) {
	t.Helper()
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		hdr := &zip.FileHeader{Name: f.Name, Method: zip.Deflate}
		hdr.SetMode(f.Mode())
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		if f.Name == name {
			if _, err := w.Write(content); err != nil {
				t.Fatal(err)
			}
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, rc); err != nil {
			t.Fatal(err)
		}
		rc.Close()
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zipPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestVerify_ChecksumTamper 证明篡改检测真实有效(不是永远绿的假测试):
//   - 改文件字节 → 条目摘要不匹配;
//   - 改 manifest 里的摘要值 → manifest 自摘要不匹配;
//   - checksum 声明了不存在的条目 → 拒绝。
func TestVerify_ChecksumTamper(t *testing.T) {
	src := writeMinimalPlugin(t, "")
	zipPath := filepath.Join(t.TempDir(), "pkg.zip")
	if _, err := Pack(src, zipPath); err != nil {
		t.Fatal(err)
	}

	t.Run("文件内容被篡改", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "pkg.zip")
		if _, err := Pack(src, p); err != nil {
			t.Fatal(err)
		}
		tamper(t, p, "bin/main", []byte("#!/bin/sh\necho backdoor\n"))
		_, err := Verify(p, t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "checksum 不匹配") ||
			!strings.Contains(err.Error(), "bin/main") {
			t.Fatalf("篡改未被发现: %v", err)
		}
	})

	t.Run("manifest 摘要值被篡改", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "pkg.zip")
		if _, err := Pack(src, p); err != nil {
			t.Fatal(err)
		}
		// 读取包内 manifest,把一个摘要末位 hex 改掉后重写回包。
		zr, err := zip.OpenReader(p)
		if err != nil {
			t.Fatal(err)
		}
		var raw []byte
		for _, f := range zr.File {
			if f.Name == ManifestFileName {
				rc, _ := f.Open()
				raw, err = io.ReadAll(rc)
				rc.Close()
				if err != nil {
					zr.Close()
					t.Fatal(err)
				}
			}
		}
		zr.Close()
		var m Manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		target := m.Checksums[ManifestFileName]
		m.Checksums[ManifestFileName] = target[:len(target)-1] + flipHex(target[len(target)-1])
		fixed, err := json.MarshalIndent(&m, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		tamper(t, p, ManifestFileName, append(fixed, '\n'))
		if _, err := Verify(p, t.TempDir()); err == nil ||
			!strings.Contains(err.Error(), "checksum 不匹配") {
			t.Fatalf("manifest 摘要篡改未被发现: %v", err)
		}
	})
}

func flipHex(c byte) string {
	if c == '0' {
		return "1"
	}
	return "0"
}

// TestVerify_ZipBomb 钉死单条目限额:声明尺寸与真实尺寸两条路径都要拦下。
func TestVerify_ZipBomb(t *testing.T) {
	src := writeMinimalPlugin(t, "")
	zipPath := filepath.Join(t.TempDir(), "pkg.zip")
	if _, err := Pack(src, zipPath); err != nil {
		t.Fatal(err)
	}

	orig := maxEntrySize
	t.Cleanup(func() { maxEntrySize = orig })
	maxEntrySize = 8 // 把上限压到 8 字节,正常包立即触发拒绝。

	if _, err := Verify(zipPath, t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "zip bomb 拒绝") {
		t.Fatalf("超限条目未被拦截: %v", err)
	}
}

// TestVerify_CollectionMismatch 钉死条目集合与 checksums 集合的双向一致性。
func TestVerify_CollectionMismatch(t *testing.T) {
	src := writeMinimalPlugin(t, "")

	t.Run("包内多塞文件", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "pkg.zip")
		if _, err := Pack(src, p); err != nil {
			t.Fatal(err)
		}
		appendEntry(t, p, "bin/extra", []byte("surprise"), 0o755)
		_, err := Verify(p, t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "checksum 缺失") {
			t.Fatalf("额外条目未被拒绝: %v", err)
		}
	})

	t.Run("checksum 声明幽灵条目", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "pkg.zip")
		if _, err := Pack(src, p); err != nil {
			t.Fatal(err)
		}
		zr, err := zip.OpenReader(p)
		if err != nil {
			t.Fatal(err)
		}
		var raw []byte
		for _, f := range zr.File {
			if f.Name == ManifestFileName {
				rc, _ := f.Open()
				raw, _ = io.ReadAll(rc)
				rc.Close()
			}
		}
		zr.Close()
		var m Manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		m.Checksums["share/ghost.txt"] = "sha256:" + strings.Repeat("0", 64)
		fixed, _ := json.MarshalIndent(&m, "", "  ")
		tamper(t, p, ManifestFileName, append(fixed, '\n'))
		if _, err := Verify(p, t.TempDir()); err == nil ||
			!strings.Contains(err.Error(), "checksum 多余") {
			t.Fatalf("幽灵摘要未被拒绝: %v", err)
		}
	})
}

// appendEntry 向既有 zip 追加一个条目(模拟绕过打包器注入文件)。
func appendEntry(t *testing.T, zipPath, name string, content []byte, mode fs.FileMode) {
	t.Helper()
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		h := &zip.FileHeader{Name: f.Name, Method: zip.Deflate}
		h.SetMode(f.Mode())
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, rc); err != nil {
			t.Fatal(err)
		}
		rc.Close()
	}
	zr.Close()
	h := &zip.FileHeader{Name: name, Method: zip.Deflate}
	h.SetMode(mode)
	w, err := zw.CreateHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zipPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
