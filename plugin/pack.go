// pack.go: 目录 → daedalus-plugin zip 打包器。
//
// 打包流程:读取 srcDir/daedalus.plugin.json 并校验 → 递归收集包内文件
// (拒绝符号链接与非常规文件)→ 计算每个条目的 sha256 注入 manifest 的
// checksums 字段(manifest 自身以"剔除 checksums 后的规范化 JSON"参与哈希,
// 打破自引用)→ 以确定性顺序写出 zip,保留可执行位。
package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	archivezip "archive/zip"
)

// zipEpoch 是包内所有条目的固定修改时间戳(MS-DOS 时间合法下限):
// 同输入目录两次打包产出逐字节相同的 zip。
var zipEpoch = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

// MaxManifestSize 是 manifest 文件的读取上限(1 MiB):
// 防恶意/失控的清单文件耗尽内存(zip 条目本身在打包时不做解压放大攻击面)。
const MaxManifestSize = 1 << 20

// checksumPattern 匹配 "sha256:<64 位小写十六进制>"。
var checksumPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// validChecksum 判断 checksum 字符串的形态。
func validChecksum(sum string) bool { return checksumPattern.MatchString(sum) }

// Sha256Hex 返回数据字节的 "sha256:<hex>" 摘要(打包器与校验器共用)。
func Sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// readFileLimited 读取至多 limit 字节;超出即报错(不静默截断)。
func readFileLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("无法读取 %s: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("无法读取 %s: %w", path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s 超过大小上限 %d 字节,拒绝加载", path, limit)
	}
	return data, nil
}

// packEntry 是打包过程中的单个待写入条目。
type packEntry struct {
	name string // zip 内 POSIX 相对路径
	path string // 磁盘绝对路径
	mode os.FileMode
}

// manifestSelfHash 计算 manifest 的规范化自摘要:
// 把 Checksums 置 nil 后用 encoding/json 序列化(Go 对 struct 按字段声明序、
// 对 map 按键升序输出,结果确定),再取 sha256。校验端用同一规则还原。
func manifestSelfHash(m *Manifest) (string, error) {
	clone := *m
	clone.Checksums = nil
	// Entrypoint/Tools 空切片与 nil 在 omitempty 下坍缩,不影响规范化。
	clone.Permissions = normalizePermissions(clone.Permissions)
	data, err := json.Marshal(&clone)
	if err != nil {
		return "", fmt.Errorf("manifest 规范化失败: %w", err)
	}
	return Sha256Hex(data), nil
}

// normalizePermissions 把空切片归一为 nil,保证规范化 JSON 稳定
// (打包写入的 [] 与校验重解析得到的 [] 哈希一致)。
func normalizePermissions(p *Permissions) *Permissions {
	if p == nil {
		return nil
	}
	out := *p
	if len(out.Read) == 0 {
		out.Read = nil
	}
	if len(out.Write) == 0 {
		out.Write = nil
	}
	if len(out.Run) == 0 {
		out.Run = nil
	}
	if out.Read == nil && out.Write == nil && out.Run == nil {
		return nil
	}
	return &out
}

// Pack 把 srcDir 打成 outPath 处的 daedalus-plugin zip 包。
// 返回注入 checksums 之后的最终 manifest,供 CLI 打印摘要。
func Pack(srcDir, outPath string) (*Manifest, error) {
	m, err := LoadManifestFile(filepath.Join(srcDir, ManifestFileName))
	if err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("manifest 校验失败: %w", err)
	}

	entries, err := collectEntries(srcDir)
	if err != nil {
		return nil, err
	}

	// executable 必须真实存在于包内。
	found := false
	for _, e := range entries {
		if e.name == m.Executable {
			found = true
			if e.mode&0o111 == 0 {
				return nil, fmt.Errorf("字段 executable 非法:%q 在 %s 缺少可执行位", m.Executable, e.path)
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("字段 executable 非法:%q 在输入目录 %s 中不存在", m.Executable, srcDir)
	}

	// 计算 checksums:每个文件条目 + manifest 自身(规范化摘要)。
	checksums := make(map[string]string, len(entries)+1)
	for _, e := range entries {
		data, err := os.ReadFile(e.path)
		if err != nil {
			return nil, fmt.Errorf("无法读取 %s: %w", e.path, err)
		}
		checksums[e.name] = Sha256Hex(data)
	}
	self, err := manifestSelfHash(m)
	if err != nil {
		return nil, err
	}
	final := *m
	final.Checksums = checksums
	final.Checksums[ManifestFileName] = self

	if err := writeZip(outPath, entries, &final); err != nil {
		return nil, err
	}
	return &final, nil
}

// collectEntries 递归收集 srcDir 下的普通文件(不含 manifest 本体),
// 按名称排序保证 zip 输出确定性;拒绝符号链接与设备/管道等特殊文件。
func collectEntries(srcDir string) ([]packEntry, error) {
	info, err := os.Stat(srcDir)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("输入目录 %s 不存在或不是目录", srcDir)
	}
	var entries []packEntry
	err = filepath.WalkDir(srcDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return fmt.Errorf("无法计算 %s 相对 %s 的路径: %w", path, srcDir, err)
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			// 目录本身不作为 zip 条目:条目名自带前缀目录,拒绝空目录条目歧义。
			return nil
		}
		if rel == ManifestFileName {
			return nil // manifest 单独注入 checksums 后写入。
		}
		fi, err := d.Info()
		if err != nil {
			return fmt.Errorf("无法 stat %s: %w", path, err)
		}
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("包内容 %s 是符号链接,拒绝打包(防止解压逃逸)", rel)
		case !fi.Mode().IsRegular():
			return fmt.Errorf("包内容 %s 不是普通文件,拒绝打包", rel)
		}
		if err := ValidateRelativePath("包条目名", rel); err != nil {
			return err
		}
		entries = append(entries, packEntry{name: rel, path: path, mode: fi.Mode().Perm()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	return entries, nil
}

// writeZip 写出 zip:内容文件按排序顺序,manifest 置于最后,
// 文件模式原样保留(executable 的可执行位随之入包)。
func writeZip(outPath string, entries []packEntry, m *Manifest) error {
	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("无法创建 %s: %w", outPath, err)
	}
	zw := archivezip.NewWriter(out)

	writeFile := func(name string, mode os.FileMode, content func(io.Writer) error) error {
		hdr := &archivezip.FileHeader{
			Name:     name,
			Method:   archivezip.Deflate,
			Modified: zipEpoch, // 固定时间戳,保证同输入同输出(可复现包)。
		}
		hdr.SetMode(mode)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return fmt.Errorf("写入 zip 条目 %s 失败: %w", name, err)
		}
		return content(w)
	}

	for _, e := range entries {
		src := e.path
		if err := writeFile(e.name, e.mode, func(w io.Writer) error {
			f, err := os.Open(src)
			if err != nil {
				return fmt.Errorf("无法读取 %s: %w", src, err)
			}
			defer f.Close()
			_, err = io.Copy(w, f)
			return err
		}); err != nil {
			out.Close()
			return err
		}
	}

	manifestData, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		out.Close()
		return fmt.Errorf("序列化 manifest 失败: %w", err)
	}
	manifestData = append(manifestData, '\n')
	if err := writeFile(ManifestFileName, 0o444, func(w io.Writer) error {
		_, err := w.Write(manifestData)
		return err
	}); err != nil {
		out.Close()
		return err
	}

	if err := zw.Close(); err != nil {
		out.Close()
		return fmt.Errorf("收尾 zip 失败: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("关闭 %s 失败: %w", outPath, err)
	}
	return nil
}
