// policy 包输出上限键的行为测试(内部测试包:直接调用未导出的 validate)。
//
// 外部测试包 policy_test 拿不到 validate(未导出),而 fail-closed 语义正是
// 本文件要钉的东西——故用内部测试包;此处不 import shellpolicy / pathguard,
// 避免与被测包构成导入环。
package policy

import "testing"

// TestPolicy_OutputLimits_Defaulted 锁定两个输出上限键的出厂默认值。
func TestPolicy_OutputLimits_Defaulted(t *testing.T) {
	p := Default()
	if p.FS.MaxReadBytes != 1048576 {
		t.Errorf("FS.MaxReadBytes 默认值漂移: got %d, want 1048576", p.FS.MaxReadBytes)
	}
	if p.Shell.MaxOutputBytes != 1048576 {
		t.Errorf("Shell.MaxOutputBytes 默认值漂移: got %d, want 1048576", p.Shell.MaxOutputBytes)
	}
}

// TestPolicy_OutputLimits_MissingIsFailClosed 锁定上限键缺失即 fail-closed:
// 上限缺失会让读取与命令输出退化成"无上限",把撑爆 MCP 响应的路径重新打开。
func TestPolicy_OutputLimits_MissingIsFailClosed(t *testing.T) {
	p := Default()
	p.FS.MaxReadBytes = 0
	p.Shell.MaxOutputBytes = 0
	if err := p.validate(); err == nil {
		t.Fatal("两个上限键同时为 0 时 validate 必须报错")
	}
}
