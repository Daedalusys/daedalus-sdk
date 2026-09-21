// manifest.go 的表驱动测试:钉死计划规定的逐条校验规则。
// 每个拒绝用例同时断言错误消息包含字段名与原因关键词。
package plugin

import (
	"strings"
	"testing"
)

// validManifest 返回一份字段完整的合法清单,测试用例在其上做单点变异。
func validManifest() *Manifest {
	return &Manifest{
		ID:          "daedalus.copilot",
		Name:        "Daedalus Copilot",
		Version:     "1.0.0",
		Type:        TypeCopilot,
		Runtime:     RuntimeNative,
		Executable:  "bin/main",
		Entrypoint:  []string{"run", "--allow-all"},
		APIVersion:  "0.1.0",
		License:     "Apache-2.0",
		Maintainer:  "team@daedalusys.io",
		Permissions: &Permissions{
			Read:  []string{"/home"},
			Write: []string{"/tmp"},
			Run:   []string{"/usr/bin/deno"},
		},
		Tools: []string{"shell_exec", "read_file"},
	}
}

// TestValidate_AcceptsLegalManifests 证明合法样本(含可选字段省略)全部通过。
func TestValidate_AcceptsLegalManifests(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*Manifest)
	}{
		{"完整清单", func(*Manifest) {}},
		{"capability 类型", func(m *Manifest) { m.Type = TypeCapability }},
		{"controller 类型(声明性预留)", func(m *Manifest) { m.Type = TypeController }},
		{"deno 运行时", func(m *Manifest) { m.Runtime = RuntimeDeno }},
		{"省略可选 entrypoint", func(m *Manifest) { m.Entrypoint = nil }},
		{"省略可选 permissions/tools", func(m *Manifest) { m.Permissions = nil; m.Tools = nil }},
		{"带预置 checksums", func(m *Manifest) {
			m.Checksums = map[string]string{"bin/main": "sha256:" + strings.Repeat("a", 64)}
		}},
		{"语义化版本含预发布与构建元数据", func(m *Manifest) { m.Version = "1.2.3-rc.1+build.007" }},
		{"多级 id", func(m *Manifest) { m.ID = "org.daedalus.os.shellserver" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest()
			tc.mut(m)
			if err := m.Validate(); err != nil {
				t.Fatalf("合法清单被拒绝: %v", err)
			}
		})
	}
}

// TestValidate_Rejections 逐条钉死拒绝规则:字段名 + 原因都必须出现在错误消息里。
func TestValidate_Rejections(t *testing.T) {
	tests := []struct {
		name      string
		mut       func(*Manifest)
		wantInMsg string // 错误消息必须包含的子串
	}{
		{"缺 id", func(m *Manifest) { m.ID = "" }, "id"},
		{"id 大写", func(m *Manifest) { m.ID = "Daedalus.Copilot" }, "id"},
		{"id 非法分层(空段)", func(m *Manifest) { m.ID = "daedalus..copilot" }, "id"},
		{"id 含下划线", func(m *Manifest) { m.ID = "daedalus_copilot" }, "id"},
		{"id 含连字符(计划文法仅允许 [a-z0-9])", func(m *Manifest) { m.ID = "daedalus-copilot" }, "id"},
		{"id 以点开头", func(m *Manifest) { m.ID = ".daedalus" }, "id"},
		{"id 以点结尾", func(m *Manifest) { m.ID = "daedalus." }, "id"},
		{"缺 name", func(m *Manifest) { m.Name = "" }, "name"},
		{"缺 version", func(m *Manifest) { m.Version = "" }, "version"},
		{"version 非语义化", func(m *Manifest) { m.Version = "1.0" }, "version"},
		{"version 前导零", func(m *Manifest) { m.Version = "1.02.3" }, "version"},
		{"version v 前缀", func(m *Manifest) { m.Version = "v1.0.0" }, "version"},
		{"type 非法枚举", func(m *Manifest) { m.Type = "plugin" }, "type"},
		{"type 为空", func(m *Manifest) { m.Type = "" }, "type"},
		{"runtime 非法枚举", func(m *Manifest) { m.Runtime = Runtime{Name: "node"} }, "runtime"},
		{"缺 executable", func(m *Manifest) { m.Executable = "" }, "executable"},
		{"executable 绝对路径", func(m *Manifest) { m.Executable = "/bin/sh" }, "executable"},
		{"executable 含 ..", func(m *Manifest) { m.Executable = "../evil" }, "executable"},
		{"executable 内嵌 ..", func(m *Manifest) { m.Executable = "bin/../../etc/passwd" }, "executable"},
		{"executable 含空字节", func(m *Manifest) { m.Executable = "bin/m\x00ain" }, "executable"},
		{"executable 含反斜杠", func(m *Manifest) { m.Executable = `bin\main` }, "executable"},
		{"executable 目录形(尾斜杠)", func(m *Manifest) { m.Executable = "bin/main/" }, "executable"},
		{"entrypoint 空元素", func(m *Manifest) { m.Entrypoint = []string{"run", ""} }, "entrypoint[1]"},
		{"entrypoint 含空字节", func(m *Manifest) { m.Entrypoint = []string{"ru\x00n"} }, "entrypoint[0]"},
		{"tools 空元素", func(m *Manifest) { m.Tools = []string{"ok", ""} }, "tools[1]"},
		{"permissions.read 空元素", func(m *Manifest) { m.Permissions.Read = []string{""} }, "permissions.read[0]"},
		{"permissions.run 空字节", func(m *Manifest) { m.Permissions.Run = []string{"a\x00b"} }, "permissions.run[0]"},
		{"checksums 键绝对路径", func(m *Manifest) {
			m.Checksums = map[string]string{"/etc/passwd": "sha256:" + strings.Repeat("f", 64)}
		}, "checksums 键"},
		{"checksums 值格式错", func(m *Manifest) {
			m.Checksums = map[string]string{"bin/main": "md5:deadbeef"}
		}, "checksums"},
		{"checksums 值非小写hex", func(m *Manifest) {
			m.Checksums = map[string]string{"bin/main": "sha256:" + strings.Repeat("Z", 64)}
		}, "checksums"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest()
			tc.mut(m)
			err := m.Validate()
			if err == nil {
				t.Fatalf("非法清单被接受(期望错误包含 %q)", tc.wantInMsg)
			}
			if !strings.Contains(err.Error(), tc.wantInMsg) {
				t.Errorf("错误消息缺少字段名/原因: got %q, want 包含 %q", err.Error(), tc.wantInMsg)
			}
		})
	}
}

// TestParseManifest 钉死 JSON 边界:语法错误、未知字段、尾随内容都必须拒绝;
// prompt injection 面:name/tools 只是数据,解析与校验绝不执行。
func TestParseManifest(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr string
		wantOK  bool
	}{
		{"合法", `{"id":"a.b","name":"N","version":"1.0.0","type":"capability","runtime":"native","executable":"bin/x"}`, "", true},
		{"语法错误", `{"id": `, "manifest 解析失败", false},
		{"未知字段", `{"id":"a.b","name":"N","version":"1.0.0","type":"capability","runtime":"native","executable":"bin/x","vendor":"evil"}`, "unknown field", false},
		{"尾随内容", `{"id":"a.b","name":"N","version":"1.0.0","type":"capability","runtime":"native","executable":"bin/x"} {"id":"x"}`, "尾随内容", false},
		{"顶层非对象", `[1,2]`, "manifest 解析失败", false},
		{"注入文本仅为数据", `{"id":"a.b","name":"$(rm -rf /); ` + "`id`" + `","version":"1.0.0","type":"capability","runtime":"native","executable":"bin/x","tools":["; curl evil"]}`, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParseManifest([]byte(tc.json))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got err=%v, want 包含 %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if !tc.wantOK {
				t.Fatal("期望失败却成功")
			}
			if m == nil {
				t.Fatal("返回 nil manifest")
			}
			// 注入用例:恶意字符串原样保留,绝不影响结构字段。
			if strings.Contains(tc.json, "rm -rf") && m.Name != "$(rm -rf /); `id`" {
				t.Errorf("name 字段被篡改: %q", m.Name)
			}
		})
	}
}

// TestValidateRelativePath 钉死共用路径校验器的边界组合。
func TestValidateRelativePath(t *testing.T) {
	rejects := []string{"", "/abs", "a/../../b", "..", "../x", "x/..", "a\x00b", `a\b`, "dir/", "/"}
	for _, p := range rejects {
		if err := ValidateRelativePath("executable", p); err == nil {
			t.Errorf("ValidateRelativePath(%q) 应拒绝却通过", p)
		}
	}
	accepts := []string{"bin/main", "a/b/c.txt", "share/deno/main.ts", "x.Y", "..name", "na..me"}
	for _, p := range accepts {
		if err := ValidateRelativePath("executable", p); err != nil {
			t.Errorf("ValidateRelativePath(%q) 应通过: %v", p, err)
		}
	}
}

// TestManifestAPIVersion 钉死 api_version 字段:必填 + 语义化版本格式。
func TestManifestAPIVersion(t *testing.T) {
	accepts := []string{"0.1.0", "1.2.3", "v2.0.0", "1.2.3-rc.1", "10.20.30+build.7"}
	for _, v := range accepts {
		m := validManifest()
		m.APIVersion = v
		if err := m.Validate(); err != nil {
			t.Errorf("api_version %q 应通过: %v", v, err)
		}
	}
	rejects := []struct{ v, want string }{
		{"", "api_version"},
		{"1.0", "api_version"},
		{"abc", "api_version"},
	}
	for _, tc := range rejects {
		m := validManifest()
		m.APIVersion = tc.v
		err := m.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("api_version %q 应被拒(含 %q),got %v", tc.v, tc.want, err)
		}
	}
}

// TestManifestLicense 钉死 license 字段:必填 + SPDX 标识格式。
func TestManifestLicense(t *testing.T) {
	accepts := []string{"Apache-2.0", "MIT", "GPL-3.0-or-later", "BSD-2-Clause", "0BSD"}
	for _, v := range accepts {
		m := validManifest()
		m.License = v
		if err := m.Validate(); err != nil {
			t.Errorf("license %q 应通过: %v", v, err)
		}
	}
	rejects := []struct{ v, want string }{
		{"", "license"},
		{"Apache 2.0", "license"},
		{"MIT/BSD", "license"},
		{"GPLv3+", "license"},
	}
	for _, tc := range rejects {
		m := validManifest()
		m.License = tc.v
		err := m.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("license %q 应被拒(含 %q),got %v", tc.v, tc.want, err)
		}
	}
}

// TestManifestMaintainer 钉死 maintainer 字段:必填 + 邮箱格式。
func TestManifestMaintainer(t *testing.T) {
	accepts := []string{"team@daedalusys.io", "a.b+c@example.co.jp", "dev@localhost.io"}
	for _, v := range accepts {
		m := validManifest()
		m.Maintainer = v
		if err := m.Validate(); err != nil {
			t.Errorf("maintainer %q 应通过: %v", v, err)
		}
	}
	rejects := []struct{ v, want string }{
		{"", "maintainer"},
		{"not-an-email", "maintainer"},
		{"a@b", "maintainer"},
		{"a b@c.d", "maintainer"},
	}
	for _, tc := range rejects {
		m := validManifest()
		m.Maintainer = tc.v
		err := m.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("maintainer %q 应被拒(含 %q),got %v", tc.v, tc.want, err)
		}
	}
}

// TestManifestRuntimeStruct 钉死 Runtime 结构化形态:
//   - 老 manifest("runtime": "deno" 字符串)经 UnmarshalJSON 仍能反序列化为
//     Runtime{Name: "deno"}(todo 11 改 6 插件 manifest 前,校验器必须能读);
//   - 新形态对象 {"name": "deno", "version": "2.1.4"} 照常解析;
//   - String() 输出与 Runtime 值常量可直接比较。
func TestManifestRuntimeStruct(t *testing.T) {
	t.Run("老形态字符串", func(t *testing.T) {
		m, err := ParseManifest([]byte(`{"id":"a.b","name":"N","version":"1.0.0","type":"capability","runtime":"deno","executable":"bin/x","api_version":"0.1.0","license":"MIT","maintainer":"dev@example.io"}`))
		if err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if m.Runtime != (Runtime{Name: "deno"}) {
			t.Errorf("老形态字符串应得 Runtime{Name: deno},got %+v", m.Runtime)
		}
		if err := m.Validate(); err != nil {
			t.Fatalf("老形态 manifest Validate 失败: %v", err)
		}
	})
	t.Run("新形态对象", func(t *testing.T) {
		m, err := ParseManifest([]byte(`{"id":"a.b","name":"N","version":"1.0.0","type":"capability","runtime":{"name":"deno","version":"2.1.4"},"executable":"bin/x","api_version":"0.1.0","license":"MIT","maintainer":"dev@example.io"}`))
		if err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if m.Runtime.Name != "deno" || m.Runtime.Version != "2.1.4" {
			t.Errorf("新形态对象解析错误: %+v", m.Runtime)
		}
	})
	t.Run("String 输出", func(t *testing.T) {
		if RuntimeDeno.String() != "deno" {
			t.Errorf("RuntimeDeno.String() = %q,want deno", RuntimeDeno.String())
		}
		if (Runtime{Name: "deno", Version: "2.1.4"}).String() != "deno 2.1.4" {
			t.Errorf("带版本 String() 错误: %q", (Runtime{Name: "deno", Version: "2.1.4"}).String())
		}
	})
	t.Run("常量可直接比较", func(t *testing.T) {
		m := validManifest()
		m.Runtime = RuntimeDeno
		if m.Runtime != RuntimeDeno {
			t.Errorf("Runtime 值常量比较失败: %+v", m.Runtime)
		}
	})
}
