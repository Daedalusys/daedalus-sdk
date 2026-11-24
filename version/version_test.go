// version_test.go 锁定「发布 tag 必须与 version.Version 一致」这道门禁的存在。
// 常量与 tag 漂过一次(v0.5.0 发布时常量还停在 0.4.0),所以门禁本身要被测到。
package version

import (
	"os"
	"strings"
	"testing"
)

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
