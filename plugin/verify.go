// verify.go: daedalus-plugin 包校验器。
//
// 校验链(任一环节失败即整体拒绝;Verify 面向 zip 包,VerifyDir 面向已安装目录,
// 两者共用第 2-5 步同一核心):
//  1. (zip 路径) 通过 ExtractZip 把包安全解压到 destDir(zip-slip/符号链接/zip bomb 防线);
//     (目录路径) 通过 collectEntries 安全收集已落盘文件(拒绝符号链接/特殊文件);
//  2. 解析并逐条校验根目录的 daedalus.plugin.json;
//  3. checksums 必须存在,且其键集合与实际文件条目集合完全相等
//     (既不允许"有文件无摘要",也不允许"有摘要无文件");
//  4. 每个文件条目的实际 sha256 必须与 checksums 一致;
//     manifest 自身按"剔除 checksums 的规范化 JSON"摘要比对;
//  5. executable 必须已落盘且带可执行位。
package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Verify 校验 zipPath 插件包,安全解压到 destDir(须为空目录),
// 返回最终 manifest 供调用方打印摘要。
func Verify(zipPath, destDir string) (*Manifest, error) {
	entries, err := ExtractZip(zipPath, destDir)
	if err != nil {
		return nil, err
	}
	return verifyExtracted(destDir, entries)
}

// VerifyDir 校验已安装(解压落盘)的插件目录:对目录内全部文件重算
// sha256 并与 manifest 的 checksums 比对。它与 Verify 共用第 2-5 步校验核心
// (manifest 解析/逐条校验、checksums 双向集合相等、逐条目摘要与 manifest 自摘要
// 比对、executable 落盘且可执行),宿主 daedalus-host 的 verify/list 依赖本函数,
// 严禁在宿主侧重复实现摘要比对逻辑(计划 todo 7 MUST DO)。
//
// 目录遍历复用打包器的安全收集规则:符号链接、非普通文件、含 '..'/绝对形态的
// 路径名一律拒绝(已安装目录同样不容许逃逸通道)。
func VerifyDir(dir string) (*Manifest, error) {
	entries, err := collectEntries(dir)
	if err != nil {
		return nil, err
	}
	// collectEntries 按设计跳过 manifest 本体;目录校验必须把它算进
	// "实际条目集合"(checksums 双向相等规则要求 manifest 自身在集合内)。
	manifestPath := filepath.Join(dir, ManifestFileName)
	fi, err := os.Lstat(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("校验失败:目录 %s 缺少 %s:%w", dir, ManifestFileName, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("校验失败:%s 必须是普通文件(当前 mode=%v)", ManifestFileName, fi.Mode())
	}
	manifestSHA, err := sha256File(manifestPath)
	if err != nil {
		return nil, err
	}
	extracted := make([]ExtractedEntry, 0, len(entries)+1)
	for _, e := range entries {
		sha, err := sha256File(e.path)
		if err != nil {
			return nil, err
		}
		extracted = append(extracted, ExtractedEntry{Name: e.name, SHA: sha})
	}
	extracted = append(extracted, ExtractedEntry{Name: ManifestFileName, SHA: manifestSHA})
	return verifyExtracted(dir, extracted)
}

// verifyExtracted 是 Verify(zip 路径)与 VerifyDir(已安装目录)共用的
// 第 2-5 步校验核心:manifest 存在性与字段合法性、checksums 集合双向相等、
// 逐条目 sha256 比对(含 manifest 规范化自摘要)、executable 可执行位。
func verifyExtracted(destDir string, entries []ExtractedEntry) (*Manifest, error) {
	// —— 第 2 步:manifest 必须存在于解压结果中 ——
	hasManifest := false
	for _, e := range entries {
		if e.Name == ManifestFileName {
			hasManifest = true
		}
	}
	if !hasManifest {
		return nil, fmt.Errorf("校验失败:包根目录缺少 %s", ManifestFileName)
	}
	data, err := readFileLimited(filepath.Join(destDir, ManifestFileName), MaxManifestSize)
	if err != nil {
		return nil, err
	}
	m, err := ParseManifest(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ManifestFileName, err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("manifest 校验失败: %w", err)
	}

	// —— 第 3 步:checksums 存在性与集合相等 ——
	if len(m.Checksums) == 0 {
		return nil, fmt.Errorf("校验失败:manifest 缺少 checksums 字段(包未经打包器注入,拒绝信任)")
	}
	extracted := make(map[string]string, len(entries))
	for _, e := range entries {
		extracted[e.Name] = e.SHA
	}
	for name := range extracted {
		if _, ok := m.Checksums[name]; !ok {
			return nil, fmt.Errorf("checksum 缺失:条目 %q 没有对应摘要(疑似包被注入额外文件)", name)
		}
	}
	for name := range m.Checksums {
		if name == ManifestFileName {
			continue // 按规范化自摘要单独比对。
		}
		if _, ok := extracted[name]; !ok {
			return nil, fmt.Errorf("checksum 多余:摘要声明了条目 %q,但包内不存在该文件", name)
		}
	}

	// —— 第 4 步:逐条目 sha256 比对 ——
	for name, actual := range extracted {
		if name == ManifestFileName {
			continue
		}
		if expected := m.Checksums[name]; expected != actual {
			return nil, fmt.Errorf("checksum 不匹配:条目 %q 期望 %s,实际 %s", name, expected, actual)
		}
	}
	self, err := manifestSelfHash(m)
	if err != nil {
		return nil, err
	}
	if expected := m.Checksums[ManifestFileName]; expected != self {
		return nil, fmt.Errorf("checksum 不匹配:manifest %s 期望 %s,实际 %s", ManifestFileName, expected, self)
	}

	// —— 第 5 步:executable 落盘且可执行 ——
	execPath := filepath.Join(destDir, filepath.FromSlash(m.Executable))
	fi, err := os.Stat(execPath)
	if err != nil {
		return nil, fmt.Errorf("校验失败:可执行文件 %s 不存在:%w", m.Executable, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("校验失败:可执行文件 %s 不是普通文件", m.Executable)
	}
	if fi.Mode()&0o111 == 0 {
		return nil, fmt.Errorf("校验失败:可执行文件 %s 缺少可执行位", m.Executable)
	}
	return m, nil
}

// sha256File 以流式方式计算单个文件的 "sha256:<hex>" 摘要,
// 超过单条目上限(maxEntrySize)即拒绝,不整读进内存。
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("无法读取 %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxEntrySize+1))
	if err != nil {
		return "", fmt.Errorf("无法读取 %s: %w", path, err)
	}
	if n > maxEntrySize {
		return "", fmt.Errorf("文件 %s 超过单条目上限 %d 字节,拒绝校验", path, maxEntrySize)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
