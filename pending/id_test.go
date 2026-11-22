package pending

import "testing"

// id 派生规则与 plugins 现有的 pendingIDFor 逐字同款:连接顺序或取字节数一变,
// 所有历史 id 全变,已签的批准记录会全部对不上。金样值用来钉住这一点。
func TestDeriveID_Golden(t *testing.T) {
	const (
		kind        = "service"
		unit        = "web.service"
		desired     = "restarted"
		scope       = "systemd:user:restart:web.service"
		stopDesired = "stopped"
		stopScope   = "systemd:user:stop:web.service"
	)

	cases := []struct {
		name         string
		desiredState string
		scope        string
		executorUID  uint32
		want         string
	}{
		{"普通用户", desired, scope, 1000, "p-517e2253edd4d4a9"},
		{"另一个用户", desired, scope, 1001, "p-74cbd221436f0ade"},
		{"root 自己", desired, scope, 0, "p-08e7d2815da59af7"},
		{"停止意图", stopDesired, stopScope, 1000, "p-0cdfaf10d33702f4"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveID(kind, unit, tc.desiredState, tc.scope, tc.executorUID)
			if got != tc.want {
				t.Errorf("DeriveID(...) = %q, want %q", got, tc.want)
			}
			if err := ValidateID(got); err != nil {
				t.Errorf("派生出的 id %q 没过形状门: %v", got, err)
			}
		})
	}
}

// 同一输入必须永远得到同一 id:AI 第二次对同一意图调用时靠它找到人批过的那一条。
func TestDeriveID_Stable(t *testing.T) {
	first := DeriveID("service", "web.service", "restarted", "systemd:user:restart:web.service", 1000)
	for i := 0; i < 3; i++ {
		if got := DeriveID("service", "web.service", "restarted", "systemd:user:restart:web.service", 1000); got != first {
			t.Fatalf("同输入第 %d 次派生出不同 id: %q != %q", i+2, got, first)
		}
	}
}

// 执行者必须并进派生输入:不带 uid 时两个用户对同一意图会撞同一个 id,
// root 批一份就等于批给了所有人。
func TestDeriveID_SeparatesExecutors(t *testing.T) {
	a := DeriveID("service", "web.service", "restarted", "systemd:user:restart:web.service", 1000)
	b := DeriveID("service", "web.service", "restarted", "systemd:user:restart:web.service", 1001)
	root := DeriveID("service", "web.service", "restarted", "systemd:user:restart:web.service", 0)
	if a == b || a == root || b == root {
		t.Fatalf("不同执行者派生出相同 id: 1000=%q 1001=%q root=%q", a, b, root)
	}
}

// id 会直接拼进文件路径,形状门必须在触路径之前挡住路径分隔符与控制字符。
func TestValidateID(t *testing.T) {
	valid := []string{
		"p-517e2253edd4d4a9",
		"p-a",
		"p-a.b_c-d",
		"p-0",
	}
	for _, id := range valid {
		if err := ValidateID(id); err != nil {
			t.Errorf("ValidateID(%q) 应通过, 实得 %v", id, err)
		}
	}

	invalid := []string{
		"",
		"p-",
		"p-a/b",
		`p-a\b`,
		"p-../x",
		"p-a b",
		"pp-abc",
		"p-a\x01b",
		"p-a\x7fb",
		"p-\x00a",
	}
	for _, id := range invalid {
		if err := ValidateID(id); err == nil {
			t.Errorf("ValidateID(%q) 应被拒, 实得 nil", id)
		}
	}
}
