// extract.go: 带 zip-slip 防护的安全解压引擎(校验器专用)。
//
// 威胁模型与逐条防线(计划草案决策 22,"安全重点"):
//  1. 条目名含 '..' 段           → 拒绝;
//  2. 条目名为绝对路径('/' 开头) → 拒绝;
//  3. 条目名含反斜杠(Windows 分隔符/UNC)→ 拒绝;
//  4. 条目名含空字节             → 拒绝;
//  5. 符号链接/硬链接/设备文件条目 → 一律拒绝(插件包只允许普通文件;
//     任何软链都可能成为指向目录外的逃逸通道);
//  6. 解压落盘前逐级 lstat 目标父目录链:任一层已存在条目若是符号链接
//     或非目录 → 拒绝(封堵"先释放软链目录、再经它写外部"的两步攻击);
//  7. 文件落盘使用 O_CREAT|O_EXCL|O_NOFOLLOW:已存在即失败,符号链接
//     即失败,不追随任何既有链接;
//  8. 重复条目名 → 拒绝(防止同名覆盖前一条目的校验结果);
//  9. zip bomb:单条目声明大小、单条目实际解压字节、全包解压总量
//     三道上限,任一超限即拒绝(声明尺寸在打开数据前就先查,不喂炸弹)。
package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	archivezip "archive/zip"
)

// 解压规模上限:单条目 256 MiB,整包 1 GiB。正常 Daedalus 插件(Deno 脚本
// 或静态二进制)远小于此;测试通过覆写变量注入更小的上限来验证拒绝路径。
var (
	maxEntrySize int64 = 256 << 20
	maxTotalSize int64 = 1 << 30
)

// ExtractedEntry 描述一个已成功落盘的普通文件条目。
type ExtractedEntry struct {
	Name string // 包内相对路径(已验证安全)
	SHA  string // "sha256:<hex>",解压时流式计算
}

// safeEntryName 校验 zip 条目名并归类。返回:
//   - rel:  相对 destDir 的净化路径;
//   - isDir:条目是否表示目录(名以 '/' 结尾);
//   - err:  违反任何 zip-slip 规则时的拒绝原因。
func safeEntryName(name string) (rel string, isDir bool, err error) {
	if name == "" {
		return "", false, fmt.Errorf("zip-slip 拒绝:存在空条目名")
	}
	if strings.IndexByte(name, 0) >= 0 {
		return "", false, fmt.Errorf("zip-slip 拒绝:条目 %q 含空字节", name)
	}
	if strings.Contains(name, `\`) {
		return "", false, fmt.Errorf("zip-slip 拒绝:条目 %q 含反斜杠路径分隔符", name)
	}
	if strings.HasPrefix(name, "/") || path.IsAbs(name) {
		return "", false, fmt.Errorf("zip-slip 拒绝:条目 %q 是绝对路径", name)
	}
	if len(name) >= 2 && name[1] == ':' {
		return "", false, fmt.Errorf("zip-slip 拒绝:条目 %q 疑似 Windows 盘符路径", name)
	}
	isDir = strings.HasSuffix(name, "/")
	trimmed := strings.TrimSuffix(name, "/")
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == ".." {
			return "", false, fmt.Errorf("zip-slip 拒绝:条目 %q 含 '..' 穿越段", name)
		}
	}
	cleaned := path.Clean(trimmed)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false, fmt.Errorf("zip-slip 拒绝:条目 %q 规范化后逃逸解压根", name)
	}
	return cleaned, isDir, nil
}

// ensureSafeDir 逐级检查/创建 rel 的父目录链。
// 每一层若已存在:必须是真实目录且不是符号链接(lstat 视角),否则拒绝;
// 若不存在:以 0755 创建。
func ensureSafeDir(destDir, rel string) error {
	dir := filepath.Dir(rel)
	if dir == "." {
		return nil
	}
	var built string
	for _, seg := range strings.Split(dir, "/") {
		if built == "" {
			built = seg
		} else {
			built = built + "/" + seg
		}
		full := filepath.Join(destDir, filepath.FromSlash(built))
		fi, err := os.Lstat(full)
		switch {
		case os.IsNotExist(err):
			if mkErr := os.Mkdir(full, 0o755); mkErr != nil {
				return fmt.Errorf("创建解压目录 %s 失败: %w", full, mkErr)
			}
		case err != nil:
			return fmt.Errorf("检查解压目录 %s 失败: %w", full, err)
		case fi.Mode()&fs.ModeSymlink != 0:
			return fmt.Errorf("zip-slip 拒绝:解压路径 %s 途经符号链接,可能逃逸出目标目录", full)
		case !fi.IsDir():
			return fmt.Errorf("zip-slip 拒绝:解压路径 %s 已存在同名非目录条目", full)
		}
	}
	return nil
}

// ExtractZip 把 srcPath 指向的 zip 安全解压到 destDir(必须已存在且为空),
// 返回全部落盘文件条目及其 sha256。任何 zip-slip/超限/类型违规都整体失败。
func ExtractZip(srcPath, destDir string) ([]ExtractedEntry, error) {
	zr, err := archivezip.OpenReader(srcPath)
	if err != nil {
		return nil, fmt.Errorf("无法打开 zip %s: %w", srcPath, err)
	}
	defer zr.Close()

	seen := make(map[string]bool, len(zr.File))
	var out []ExtractedEntry
	var total int64

	for _, f := range zr.File {
		rel, isDir, err := safeEntryName(f.Name)
		if err != nil {
			return nil, err
		}
		mode := f.Mode()
		if isDir {
			if err := ensureSafeDir(destDir, rel+"/x"); err != nil {
				return nil, err
			}
			continue
		}
		if mode&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("zip-slip 拒绝:条目 %q 是符号链接,插件包只允许普通文件", rel)
		}
		if !mode.IsRegular() && mode != 0 {
			// mode==0 表示 zip 未携带 unix 模式位,按普通文件处理。
			return nil, fmt.Errorf("zip 拒绝:条目 %q 不是普通文件(mode=%v)", rel, mode)
		}
		if seen[rel] {
			return nil, fmt.Errorf("zip 拒绝:条目 %q 重复出现", rel)
		}
		seen[rel] = true
		if int64(f.UncompressedSize64) > maxEntrySize {
			return nil, fmt.Errorf("zip bomb 拒绝:条目 %q 声明尺寸 %d 超过单条目上限 %d",
				rel, f.UncompressedSize64, maxEntrySize)
		}
		if err := ensureSafeDir(destDir, rel); err != nil {
			return nil, err
		}
		perm := mode.Perm()
		if perm == 0 {
			perm = 0o444 // zip 未携带 unix 模式位时按只读普通文件落盘。
		}
		entry, size, err := extractOneFile(f, filepath.Join(destDir, filepath.FromSlash(rel)), rel, perm)
		if err != nil {
			return nil, err
		}
		total += size
		if total > maxTotalSize {
			return nil, fmt.Errorf("zip bomb 拒绝:累计解压尺寸 %d 超过整包上限 %d 字节", total, maxTotalSize)
		}
		out = append(out, *entry)
	}
	return out, nil
}

// extractOneFile 以 O_EXCL|O_NOFOLLOW 独占新建方式落盘单个条目,
// 流式计算 sha256 并强制实际尺寸上限(不信任声明值),返回摘要与实际字节数。
func extractOneFile(f *archivezip.File, destPath, rel string, perm fs.FileMode) (*ExtractedEntry, int64, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, 0, fmt.Errorf("无法读取 zip 条目 %q: %w", rel, err)
	}
	defer rc.Close()

	fd, err := syscall.Open(destPath,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, uint32(perm))
	if err != nil {
		return nil, 0, fmt.Errorf("无法创建解压文件 %s: %w", destPath, err)
	}
	dst := os.NewFile(uintptr(fd), destPath)
	defer dst.Close()

	// 至多读取 maxEntrySize+1 字节:超限的炸弹在写入阶段即被截停。
	shaStr, n, err := hashCopyN(dst, io.LimitReader(rc, maxEntrySize+1))
	if err != nil {
		return nil, 0, fmt.Errorf("解压条目 %q 失败: %w", rel, err)
	}
	if n > maxEntrySize {
		return nil, 0, fmt.Errorf("zip bomb 拒绝:条目 %q 实际解压超过单条目上限 %d 字节", rel, maxEntrySize)
	}
	if err := dst.Close(); err != nil {
		return nil, 0, fmt.Errorf("关闭解压文件 %s 失败: %w", destPath, err)
	}
	// 落盘后显式 chmod:确保权限位与 zip 存储模式一致(不受 umask 干扰)。
	if err := os.Chmod(destPath, perm); err != nil {
		return nil, 0, fmt.Errorf("设置 %s 权限位失败: %w", destPath, err)
	}
	return &ExtractedEntry{Name: rel, SHA: shaStr}, n, nil
}

// hashCopyN 把 src 拷入 dst 的同时计算 sha256,返回 "sha256:<hex>" 与计数。
func hashCopyN(dst io.Writer, src io.Reader) (string, int64, error) {
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), src)
	if err != nil {
		return "", n, err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), n, nil
}
