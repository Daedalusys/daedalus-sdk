// version_test.go 锁定「发布 tag 必须与 version.Version 一致」这道门禁的存在。
// 常量与 tag 漂过一次(v0.5.0 发布时常量还停在 0.4.0),所以门禁本身要被测到。
package version

import (
	"os"
	"strings"
	"testing"
)

// TestVersionConstantPinsReleaseTarget 把「本次要发的版本」钉在测试里。
// release.yml 的比对只在推 tag 时生效,常量漏改要等 tag 上去才炸;这条断言让
// 发版前的常规 CI 当场变红。
func TestVersionConstantPinsReleaseTarget(t *testing.T) {
	const want = "0.6.0"
	if Version != want {
		t.Errorf("version.Version=%q,期望 %q", Version, want)
	}
}

func TestReleaseWorkflowGuardsTagAgainstVersionConstant(t *testing.T) {
	data, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatalf("读 release.yml 失败: %v", err)
	}
	text := string(data)
	for _, needle := range []string{"version/version.go", "GITHUB_REF_NAME"} {
		if !strings.Contains(text, needle) {
			t.Errorf("release.yml 缺少版本一致性门禁的关键内容 %q", needle)
		}
	}
}
