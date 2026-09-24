// 注册表实现:嵌入式蓝图注册表。Load 从注入的 fs.FS 加载(测试注
// fstest.MapFS,生产注 embed.FS;embed 指令归 blueprints_embed.go)。
package blueprint

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

const manifestFileName = "manifest.json"

// Load 从 dirFS 根下的目录加载全部蓝图:每个子目录 <name> 读 <name>/manifest.json
// 并校验目录名 == manifest id,再经 New 构造 + 校验;非目录条目跳过。fail-closed:
// 任一目录缺失/损坏 manifest、id 不一致或校验失败,都聚合进同一个错误一次性返回,
// 绝不返回部分加载的注册表。返回切片按 manifest id 字典序排序。
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

	sort.Slice(blueprints, func(i, j int) bool { return blueprints[i].ID < blueprints[j].ID })
	return blueprints, nil
}

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

// MustLoad 是 Load 的 panic 形态,供 cmd 侧 init 调用。蓝图是构建期嵌入的静态
// 资源,运行时加载失败属不可恢复的初始化事故,panic 比静默降级更能暴露故障。
func MustLoad(dirFS fs.FS) []*Blueprint {
	bs, err := Load(dirFS)
	if err != nil {
		panic(fmt.Sprintf("blueprint: 注册表加载失败(初始化必需): %v", err))
	}
	return bs
}
