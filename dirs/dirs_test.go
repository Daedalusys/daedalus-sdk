// dirs 解析链测试:env(绝对必填)→ 系统探测 → $HOME 兜底 → 显式错误。
// 全部系统候选用 t.TempDir() 注入,绝不触碰真实 /var/lib/daedalus(新检出安全)。
package dirs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// requireNoErr 是 stdlib 风格的错误断言helper。
func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("预期无错误,实得: %v", err)
	}
}

// mustExist 断言路径存在(目录或文件)。
func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("路径 %s 应已存在: %v", path, err)
	}
}

// unwritableDir 构造 mode 0500(不可写)临时目录,cleanup 恢复权限以便 TempDir 回收。
// root 会绕过 DAC,该夹具失效时直接 skip。
func unwritableDir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root 绕过 DAC 权限位,不可写夹具不适用")
	}
	d := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(d, 0o700); err != nil {
			t.Errorf("恢复权限失败: %v", err)
		}
	})
	return d
}

// ──── Dir ────

func TestDirs_Dir_EnvWinsWhenAbsolute(t *testing.T) {
	// Given: env 指向一个尚不存在的绝对路径,系统候选同样可用(证明优先级)。
	envDir := filepath.Join(t.TempDir(), "chosen")
	sysDir := filepath.Join(t.TempDir(), "sys")
	t.Setenv("TEST_DIRS_DIR", envDir)

	// When
	got, err := Dir("TEST_DIRS_DIR", sysDir, "rel/fallback")

	// Then: env 原样返回,且探测已把目录建出来;系统候选未被选。
	requireNoErr(t, err)
	if got != envDir {
		t.Fatalf("应返回 env 值 %q,实得 %q", envDir, got)
	}
	mustExist(t, envDir)
	if _, err := os.Stat(sysDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("env 命中时不应触碰系统候选,实得 stat err=%v", err)
	}
}

func TestDirs_Dir_EnvRelativeRejected(t *testing.T) {
	t.Setenv("TEST_DIRS_DIR", "relative/path")
	got, err := Dir("TEST_DIRS_DIR", filepath.Join(t.TempDir(), "sys"), "rel")
	if !errors.Is(err, ErrEnvNotAbsolute) {
		t.Fatalf("相对 env 应报 ErrEnvNotAbsolute,实得: %v", err)
	}
	if got != "" {
		t.Fatalf("出错时必须返回空串,实得 %q", got)
	}
}

func TestDirs_Dir_EnvEmptyRejected(t *testing.T) {
	// Given: 变量存在但值为空("value present but not absolute")。
	t.Setenv("TEST_DIRS_DIR", "")
	if _, err := Dir("TEST_DIRS_DIR", filepath.Join(t.TempDir(), "sys"), "rel"); !errors.Is(err, ErrEnvNotAbsolute) {
		t.Fatalf("空值 env 应报 ErrEnvNotAbsolute,实得: %v", err)
	}
}

func TestDirs_Dir_SystemProbeFailFallsBackToHome(t *testing.T) {
	// Given: 系统候选不可写,HOME 指向干净临时目录。
	sys := unwritableDir(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	// When
	got, err := Dir("TEST_DIRS_DIR_MISSING", sys, ".local/share/daedalus/tx")

	// Then: 落 $HOME 拼接目录,且目录已被探测创建。
	requireNoErr(t, err)
	want := filepath.Join(home, ".local/share/daedalus/tx")
	if got != want {
		t.Fatalf("应返回 %q,实得 %q", want, got)
	}
	mustExist(t, got)
}

func TestDirs_Dir_SystemAbsentCreated(t *testing.T) {
	// Given: 系统候选可写(临时父目录)但自身不存在 → MkdirAll 应创建。
	sys := filepath.Join(t.TempDir(), "lib/daedalus/tx")

	// When
	got, err := Dir("TEST_DIRS_DIR_MISSING", sys, "rel")

	// Then
	requireNoErr(t, err)
	if got != sys {
		t.Fatalf("应返回系统候选 %q,实得 %q", sys, got)
	}
	mustExist(t, got)
}

func TestDirs_Dir_HomeEmptyYieldsExplicitError(t *testing.T) {
	// Given: 系统候选不可写 + HOME 置空(Failure QA 钉死的复现夹具)。
	sys := unwritableDir(t)
	t.Setenv("HOME", "")

	// When
	got, err := Dir("TEST_DIRS_DIR_MISSING", sys, "rel/tx")

	// Then: 显式错误,绝不静默回落 "/"。
	if !errors.Is(err, ErrNoUsablePath) {
		t.Fatalf("应报 ErrNoUsablePath,实得: %v", err)
	}
	if got == "/" || got == filepath.Join("/", "rel/tx") {
		t.Fatalf("绝不允许回落到 / 派生路径,实得 %q", got)
	}
}

func TestDirs_Dir_BothUnwritableYieldsError(t *testing.T) {
	// Given: 系统不可写,HOME 亦指向不可写目录。
	sys := unwritableDir(t)
	t.Setenv("HOME", unwritableDir(t))

	// When
	_, err := Dir("TEST_DIRS_DIR_MISSING", sys, "rel/tx")

	// Then
	if !errors.Is(err, ErrNoUsablePath) {
		t.Fatalf("双候选皆不可写应报 ErrNoUsablePath,实得: %v", err)
	}
}

func TestDirs_Dir_EnvUnusableFallsThroughChain(t *testing.T) {
	// Given: env 为绝对但不可写(其父被 chmod 0500)→ 链继续走系统候选。
	parent := unwritableDir(t)
	t.Setenv("TEST_DIRS_DIR", filepath.Join(parent, "want"))
	sys := filepath.Join(t.TempDir(), "sys")

	// When
	got, err := Dir("TEST_DIRS_DIR", sys, "rel")

	// Then
	requireNoErr(t, err)
	if got != sys {
		t.Fatalf("env 不可用时应落系统候选 %q,实得 %q", sys, got)
	}
}

// ──── File ────

func TestDirs_File_EnvWinsWhenAbsolute(t *testing.T) {
	// Given: env 指向新目录下的文件路径,父目录尚不存在(探测需 MkdirAll 父)。
	dir := filepath.Join(t.TempDir(), "sub")
	envFile := filepath.Join(dir, "state.jsonl")
	t.Setenv("TEST_DIRS_FILE", envFile)

	// When
	got, err := File("TEST_DIRS_FILE", filepath.Join(t.TempDir(), "sys/state.jsonl"), "rel/state.jsonl")

	// Then: 原样返回;文件本身不被创建(内容属调用方),仅父目录被探测创建。
	requireNoErr(t, err)
	if got != envFile {
		t.Fatalf("应返回 env 值 %q,实得 %q", envFile, got)
	}
	mustExist(t, dir)
	if _, err := os.Stat(envFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("File 探测不得创建文件本体,实得 stat err=%v", err)
	}
}

func TestDirs_File_EnvRelativeRejected(t *testing.T) {
	t.Setenv("TEST_DIRS_FILE", "state.jsonl")
	if _, err := File("TEST_DIRS_FILE", "/tmp/x/state.jsonl", "rel"); !errors.Is(err, ErrEnvNotAbsolute) {
		t.Fatalf("相对 env 应报 ErrEnvNotAbsolute,实得: %v", err)
	}
}

func TestDirs_File_SystemParentUnwritableFallsBackToHome(t *testing.T) {
	// Given: 系统文件的父目录不可写。
	home := t.TempDir()
	t.Setenv("HOME", home)

	// When
	got, err := File("TEST_DIRS_FILE_MISSING", filepath.Join(unwritableDir(t), "state.jsonl"), ".local/share/daedalus/state.jsonl")

	// Then
	requireNoErr(t, err)
	want := filepath.Join(home, ".local/share/daedalus/state.jsonl")
	if got != want {
		t.Fatalf("应返回 %q,实得 %q", want, got)
	}
	mustExist(t, filepath.Dir(want))
}

func TestDirs_File_AllUnusableYieldsError(t *testing.T) {
	sysFile := filepath.Join(unwritableDir(t), "state.jsonl")
	t.Run("HOME未设", func(t *testing.T) {
		t.Setenv("HOME", "")
		_, err := File("TEST_DIRS_FILE_MISSING", sysFile, "rel/state.jsonl")
		if !errors.Is(err, ErrNoUsablePath) {
			t.Fatalf("应报 ErrNoUsablePath,实得: %v", err)
		}
	})
	t.Run("HOME不可写", func(t *testing.T) {
		t.Setenv("HOME", unwritableDir(t))
		_, err := File("TEST_DIRS_FILE_MISSING", sysFile, "rel/state.jsonl")
		if !errors.Is(err, ErrNoUsablePath) {
			t.Fatalf("应报 ErrNoUsablePath,实得: %v", err)
		}
	})
}

// ──── 调用点辅助(TxRoot / StateFile)────

func TestDirs_TxRoot_HappyChain(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tx")
	t.Setenv(EnvTxDir, dir)

	got, err := TxRoot()
	requireNoErr(t, err)
	if got != dir {
		t.Fatalf("TxRoot 应返回 env 目录 %q,实得 %q", dir, got)
	}
	mustExist(t, got)

	// 常量一致性:TxRoot 与显式 Dir(常量) 同 env 下逐字节一致。
	viaConst, err := Dir(EnvTxDir, TxSystemDir, TxHomeRel)
	requireNoErr(t, err)
	if viaConst != got {
		t.Fatalf("TxRoot 与 Dir(常量) 不一致: %q vs %q", got, viaConst)
	}
}

func TestDirs_StateFile_HappyChain(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.jsonl")
	t.Setenv(EnvStatePath, file)

	got, err := StateFile()
	requireNoErr(t, err)
	if got != file {
		t.Fatalf("StateFile 应返回 env 路径 %q,实得 %q", file, got)
	}

	viaConst, err := File(EnvStatePath, StateSystemFile, StateHomeRel)
	requireNoErr(t, err)
	if viaConst != got {
		t.Fatalf("StateFile 与 File(常量) 不一致: %q vs %q", got, viaConst)
	}
}

func TestDirs_TxRoot_EnvRelativeRejected(t *testing.T) {
	t.Setenv(EnvTxDir, "tx/relative")
	if _, err := TxRoot(); !errors.Is(err, ErrEnvNotAbsolute) {
		t.Fatalf("TxRoot 相对 env 应报 ErrEnvNotAbsolute,实得: %v", err)
	}
}
