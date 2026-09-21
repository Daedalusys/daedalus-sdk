// 注册表实现(todo 3):嵌入式蓝图注册表。
//
// Load 从注入的 fs.FS 加载蓝图。fs.FS 抽象保证可测试性——测试侧注入
// testing/fstest.MapFS,生产侧由 cmd 的 //go:embed 产物(embed.FS)注入
// (embed 指令归 todo 15 的 blueprints_embed.go,本文件不写 embed)。
package blueprint

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// manifestFileName 是蓝图目录内的清单文件名。
const manifestFileName = "manifest.json"

// Load 从 dirFS 根下的目录加载全部蓝图。
//
// 对根下每个目录 <name>:读取 <name>/manifest.json,反序列化为
// BlueprintManifest,校验目录名 == manifest id,再经 New 构造 + 校验。
// 根下的非目录条目(普通文件)不是蓝图,直接跳过。
//
// fail-closed:任一目录缺失/损坏 manifest、目录名与 id 不一致或
// 蓝图校验失败,都聚合进同一个错误一次性返回(nil, err),绝不返回
// 部分加载的注册表(与 internal/policy 的聚合报错同风格)。返回的切片
// 按 manifest id 字典序排序,顺序稳定。
func Load(dirFS fs.FS) ([]*Blueprint, error) {
	entries, err := fs.ReadDir(dirFS, ".")
	if err != nil {
		return nil, fmt.Errorf("blueprint: 读取注册表根目录失败: %w", err)
	}

	var problems []string
	blueprints := make([]*Blueprint, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue // 根下普通文件不是蓝图目录
		}
		name := e.Name()
		b, err := loadOne(dirFS, name)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		blueprints = append(blueprints, b)
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("blueprint: 注册表加载失败,共 %d 处缺陷: %s",
			len(problems), strings.Join(problems, "; "))
	}

	// 按 id 排序:即便底层 FS 的 ReadDir 不保证文件名顺序,返回顺序仍稳定。
	sort.Slice(blueprints, func(i, j int) bool { return blueprints[i].ID < blueprints[j].ID })
	return blueprints, nil
}

// loadOne 加载单个蓝图目录 <name>:读 manifest.json → 反序列化 →
// 目录名与 id 一致性校验 → New 构造 + 校验。
func loadOne(dirFS fs.FS, name string) (*Blueprint, error) {
	data, err := fs.ReadFile(dirFS, path.Join(name, manifestFileName))
	if err != nil {
		return nil, fmt.Errorf("读取 %s 失败: %w", manifestFileName, err)
	}
	var m BlueprintManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s 解析失败(非法 JSON): %w", manifestFileName, err)
	}
	if m.ID != name {
		return nil, fmt.Errorf("目录名 %q 与 manifest id %q 不一致", name, m.ID)
	}
	b, err := New(&m)
	if err != nil {
		return nil, fmt.Errorf("蓝图校验失败: %w", err)
	}
	return b, nil
}

// MustLoad 是 Load 的 panic 形态,供 cmd 侧 init 调用。
//
// 蓝图是构建期嵌入的静态资源,运行时加载失败属不可恢复的初始化事故
// (构建期校验失效或嵌入数据损坏),panic 比静默降级更能暴露故障——
// 与计划"初始化时 6 个蓝图齐全,缺一即 panic"的语义一致。
func MustLoad(dirFS fs.FS) []*Blueprint {
	bs, err := Load(dirFS)
	if err != nil {
		panic(fmt.Sprintf("blueprint: 注册表加载失败(初始化必需): %v", err))
	}
	return bs
}
