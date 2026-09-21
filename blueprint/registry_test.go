package blueprint

import (
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

// fakeManifest 生成测试用完整 manifest.json 内容(id 与目录名一致的合法清单)。
func fakeManifest(id, version, tmpl string, tools []string) string {
	return `{
  "id": "` + id + `",
  "display_name": "` + id + `",
  "version": "` + version + `",
  "description": "测试蓝图",
  "category": "test",
  "output_path_template": "` + tmpl + `",
  "reload_service": "test-svc",
  "required_tools": ["` + strings.Join(tools, `", "`) + `"]
}`
}

// fakeDir 构造 MapFS 里的一个蓝图目录条目(dir 占位 + manifest 文件)。
func fakeDir(mfs *fstest.MapFS, name string, manifest string) {
	(*mfs)[name+"/."] = &fstest.MapFile{Mode: fs.ModeDir}
	(*mfs)[name+"/manifest.json"] = &fstest.MapFile{Data: []byte(manifest)}
}

// TestRegistry_Load_Happy 验证从 MapFS 加载 3 个合法蓝图:
// 返回全部 3 个,且按 manifest id 字典序排序(顺序稳定)。
func TestRegistry_Load_Happy(t *testing.T) {
	mfs := fstest.MapFS{}
	fakeDir(&mfs, "charlie", fakeManifest("charlie", "1.0.0", "/etc/c/{x}.conf", []string{"c", "systemctl"}))
	fakeDir(&mfs, "alpha", fakeManifest("alpha", "1.0.0", "/etc/a/{x}.conf", []string{"a", "systemctl"}))
	fakeDir(&mfs, "bravo", fakeManifest("bravo", "1.0.0", "/etc/b/{x}.conf", []string{"b", "systemctl"}))

	bs, err := Load(mfs)
	if err != nil {
		t.Fatalf("Load 返回错误,期望 nil: %v", err)
	}
	if len(bs) != 3 {
		t.Fatalf("加载蓝图数 = %d,期望 3", len(bs))
	}
	// MapFS 底层是 map,迭代顺序随机;断言返回顺序必须按 id 字典序稳定。
	got := []string{bs[0].ID, bs[1].ID, bs[2].ID}
	want := []string{"alpha", "bravo", "charlie"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("返回顺序 = %v,期望按 id 字典序 %v", got, want)
		}
	}
}

// TestRegistry_Load_SkipsPlainFiles 验证根下的普通文件被跳过(不是蓝图目录)。
func TestRegistry_Load_SkipsPlainFiles(t *testing.T) {
	mfs := fstest.MapFS{}
	mfs["README.md"] = &fstest.MapFile{Data: []byte("not a blueprint")}
	fakeDir(&mfs, "alpha", fakeManifest("alpha", "1.0.0", "/etc/a/{x}.conf", []string{"a"}))

	bs, err := Load(mfs)
	if err != nil {
		t.Fatalf("Load 返回错误,期望 nil: %v", err)
	}
	if len(bs) != 1 || bs[0].ID != "alpha" {
		t.Fatalf("加载结果 = %v,期望仅 alpha", bs)
	}
}

// TestRegistry_Load_MissingManifest 验证某目录缺 manifest.json → 整体 error。
func TestRegistry_Load_MissingManifest(t *testing.T) {
	mfs := fstest.MapFS{}
	fakeDir(&mfs, "alpha", fakeManifest("alpha", "1.0.0", "/etc/a/{x}.conf", []string{"a"}))
	mfs["broken/."] = &fstest.MapFile{Mode: fs.ModeDir} // 目录存在但无 manifest.json

	if _, err := Load(mfs); err == nil {
		t.Fatal("Load 返回 nil 错误,期望因缺 manifest.json 失败")
	}
}

// TestRegistry_Load_InvalidManifest 验证 manifest.json 为非法 JSON → 整体 error。
func TestRegistry_Load_InvalidManifest(t *testing.T) {
	mfs := fstest.MapFS{}
	fakeDir(&mfs, "alpha", fakeManifest("alpha", "1.0.0", "/etc/a/{x}.conf", []string{"a"}))
	fakeDir(&mfs, "broken", `{"id": `) // 截断的 JSON

	if _, err := Load(mfs); err == nil {
		t.Fatal("Load 返回 nil 错误,期望因非法 JSON 失败")
	}
}

// TestRegistry_Load_InvalidBlueprint 验证 manifest 合法但字段非法(如空版本,
// id 与目录名一致、绕过一致性检查) → 整体 error(New 校验路径)。
func TestRegistry_Load_InvalidBlueprint(t *testing.T) {
	mfs := fstest.MapFS{}
	fakeDir(&mfs, "alpha", fakeManifest("alpha", "1.0.0", "/etc/a/{x}.conf", []string{"a"}))
	fakeDir(&mfs, "bad", fakeManifest("bad", "", "/etc/b/{x}.conf", []string{"b"})) // 空 version

	if _, err := Load(mfs); err == nil {
		t.Fatal("Load 返回 nil 错误,期望因蓝图校验失败")
	}
}

// TestRegistry_Load_DirNameMismatch 验证目录名与 manifest id 不一致 → 整体 error
// (一致性校验,MUST DO)。
func TestRegistry_Load_DirNameMismatch(t *testing.T) {
	mfs := fstest.MapFS{}
	fakeDir(&mfs, "alpha", fakeManifest("beta", "1.0.0", "/etc/b/{x}.conf", []string{"b"})) // 目录 alpha,id beta

	if _, err := Load(mfs); err == nil {
		t.Fatal("Load 返回 nil 错误,期望因目录名与 id 不一致失败")
	}
}

// TestRegistry_Load_AggregatesAllProblems 验证多蓝图同时损坏时,缺陷全部聚合
// 进同一个错误(而非只报第一个),与 internal/policy 的 fail-closed 同风格。
func TestRegistry_Load_AggregatesAllProblems(t *testing.T) {
	mfs := fstest.MapFS{}
	mfs["bad-a/."] = &fstest.MapFile{Mode: fs.ModeDir}                                  // 缺 manifest
	fakeDir(&mfs, "bad-b", `{invalid`)                                                  // 非法 JSON
	fakeDir(&mfs, "bad-c", fakeManifest("bad-c", "", "/etc/c/{x}.conf", []string{"c"})) // 空 version

	_, err := Load(mfs)
	if err == nil {
		t.Fatal("Load 返回 nil 错误,期望聚合报错")
	}
	for _, name := range []string{"bad-a", "bad-b", "bad-c"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("聚合错误缺少缺陷 %q: %v", name, err)
		}
	}
}

// TestRegistry_MustLoad_Panic 验证 MustLoad 在加载失败时 panic。
func TestRegistry_MustLoad_Panic(t *testing.T) {
	mfs := fstest.MapFS{}
	mfs["broken/."] = &fstest.MapFile{Mode: fs.ModeDir} // 无 manifest.json → 失败

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("MustLoad 未 panic,期望加载失败时 panic")
		}
	}()
	MustLoad(mfs)
}

// TestRegistry_MustLoad_Happy 验证 MustLoad 成功时正常返回(不 panic)。
func TestRegistry_MustLoad_Happy(t *testing.T) {
	mfs := fstest.MapFS{}
	fakeDir(&mfs, "alpha", fakeManifest("alpha", "1.0.0", "/etc/a/{x}.conf", []string{"a"}))

	bs := MustLoad(mfs) // panic 会直接 fail 本测试
	if len(bs) != 1 || bs[0].ID != "alpha" {
		t.Fatalf("MustLoad 结果 = %v,期望仅 alpha", bs)
	}
}

// TestRegistry_Load_RealBlueprints 用真实蓝图数据做集成测试。
//
// 相对路径 ../../../plugin/blueprint/blueprints 从本包目录
// (daedalus/core/internal/blueprint,go test 的 cwd 即包目录)上溯到
// daedalus/plugin/blueprint/blueprints。若相对路径在某个执行环境下不稳
// (文件不存在),Skip 而非失败——真实嵌入数据的加载验证归属 todo 15 的
// //go:embed + TestRegistry_LoadEmbedded。
func TestRegistry_Load_RealBlueprints(t *testing.T) {
	const dir = "../../../plugin/blueprint/blueprints"
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("真实蓝图目录 %s 不可达(%v);嵌入数据加载验证归 todo 15", dir, err)
	}
	bs, err := Load(os.DirFS(dir))
	if err != nil {
		t.Fatalf("Load 真实蓝图失败: %v", err)
	}
	if len(bs) != 6 {
		t.Fatalf("真实蓝图数 = %d,期望 6", len(bs))
	}
	// 6 个真实蓝图按 id 字典序齐全,且与前一个 todo 的脚手架数据一致。
	wantIDs := []string{
		"haproxy-backend", "nginx-reverse-proxy", "nginx-vhost",
		"postgres-db", "postgres-user", "redis-acl",
	}
	for i, want := range wantIDs {
		if bs[i].ID != want {
			t.Errorf("第 %d 个蓝图 id = %q,期望 %q(顺序须稳定)", i, bs[i].ID, want)
		}
	}
}
