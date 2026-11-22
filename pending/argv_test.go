package pending

import "testing"

// 指纹是跨仓契约:core 与 plugins 已按同一算法写下历史批准记录,
// 连接方式或分隔符一变,所有历史批准都会失效。金样值独立于实现存在,
// 用来证明 SDK 的实现与旧实现逐字一致。
func TestArgvSHA256_Golden(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want string
	}{
		{
			"重启用户单元",
			[]string{"systemctl", "--user", "restart", "web.service"},
			"013995b36a7a6e5a76e5c9f28a81bd0d25ee4409664d349d3af44a339e4c7100",
		},
		{
			// 这条是 core 侧手算的常量,不是从任何实现里跑出来的。
			"停止用户单元",
			[]string{"systemctl", "--user", "stop", "nginx.service"},
			"802d8be0ec50f15ec1cff1b7187c5f7867d52f1e49891389b44051954c532251",
		},
		{
			"两个短参数",
			[]string{"a", "b"},
			"59b271ae1bbcb1d31d41929817f4b16fb439eb4f31520b5ad1d5ce98920a7138",
		},
		{
			"含空格的单参数",
			[]string{"a b"},
			"c8687a08aa5d6ed2044328fa6a697ab8e96dc34291e8c2034ae8c38e6fcc6d65",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ArgvSHA256(tc.argv); got != tc.want {
				t.Errorf("ArgvSHA256(%q) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// 分隔符必须让「一个参数里带空格」与「两个参数」分得开:
// 用空格连接时这两种 argv 会撞成同一个指纹,批准就绑错了命令。
func TestArgvSHA256_SeparatorIsUnambiguous(t *testing.T) {
	if ArgvSHA256([]string{"a b"}) == ArgvSHA256([]string{"a", "b"}) {
		t.Fatal("[\"a b\"] 与 [\"a\",\"b\"] 的指纹相同:分隔符选错了")
	}
}
