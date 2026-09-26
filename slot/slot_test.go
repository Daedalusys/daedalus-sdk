package slot

import "testing"

// slot_test.go —— 钉 Level token 全集与接入门(线协议逐字节冻结)。

func TestLevelTokens(t *testing.T) {
	for _, l := range []Level{LevelBuild, LevelRestart, LevelRuntime, LevelHotSwap} {
		if !l.Valid() {
			t.Errorf("%q 应属分级全集", l)
		}
	}
	if got := []string{string(LevelBuild), string(LevelRestart), string(LevelRuntime), string(LevelHotSwap)}; len(got) != 4 ||
		got[0] != "L0" || got[3] != "L3" {
		t.Fatalf("token 形状漂移: %v", got)
	}
	for _, bad := range []Level{"", "l1", "L4", "L2 ", "runtime"} {
		if bad.Valid() {
			t.Errorf("表外 token 应被拒: %q", bad)
		}
	}
}
