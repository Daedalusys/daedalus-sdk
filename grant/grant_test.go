// 条子解析/覆盖判定/签发者授权的测试:全部走公开 API,断言错误语义而非具体文案。
package grant_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Daedalusys/daedalus-sdk/autonomy"
	"github.com/Daedalusys/daedalus-sdk/grant"
)

// grantJSON 拼一份合法条子再逐字段覆盖;覆盖值为 nil 表示删掉该键。
func grantJSON(t *testing.T, overrides map[string]any) []byte {
	t.Helper()
	doc := map[string]any{
		"id":         "g-1",
		"scope":      []string{"systemd:user:restart:nginx.service"},
		"issued_by":  "alice",
		"issued_at":  "2026-11-20T10:00:00Z",
		"expires_at": "2026-11-20T12:00:00Z",
		"max_uses":   1,
		"note":       "半夜 nginx 挂了就重启",
	}
	for k, v := range overrides {
		if v == nil {
			delete(doc, k)
			continue
		}
		doc[k] = v
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("拼条子 JSON 失败: %v", err)
	}
	return data
}

func mustParse(t *testing.T, data []byte) *grant.Grant {
	t.Helper()
	g, err := grant.Parse(data)
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	return g
}

func assertErrContains(t *testing.T, err error, want ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("期望报错,实际 nil")
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("错误 %q 未含 %q", err.Error(), w)
		}
	}
}

func TestParseGrant(t *testing.T) {
	g := mustParse(t, grantJSON(t, nil))
	if g.ID != "g-1" {
		t.Errorf("ID = %q, 期望 g-1", g.ID)
	}
	if len(g.Scope) != 1 || g.Scope[0] != "systemd:user:restart:nginx.service" {
		t.Errorf("Scope = %v, 期望单条 systemd:user:restart:nginx.service", g.Scope)
	}
	if g.IssuedBy != "alice" {
		t.Errorf("IssuedBy = %q, 期望 alice", g.IssuedBy)
	}
	if g.MaxUses != 1 {
		t.Errorf("MaxUses = %d, 期望 1", g.MaxUses)
	}
	if g.Note != "半夜 nginx 挂了就重启" {
		t.Errorf("Note = %q", g.Note)
	}
	wantIssued := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	if !g.IssuedAt.Equal(wantIssued) {
		t.Errorf("IssuedAt = %s, 期望 %s", g.IssuedAt, wantIssued)
	}
	wantExpires := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	if !g.ExpiresAt.Equal(wantExpires) {
		t.Errorf("ExpiresAt = %s, 期望 %s", g.ExpiresAt, wantExpires)
	}
	if g.ExpiresAt.Location() != time.UTC {
		t.Errorf("ExpiresAt 时区 = %s, 期望 UTC", g.ExpiresAt.Location())
	}
}

func TestParseGrantNormalizesToUTC(t *testing.T) {
	g := mustParse(t, grantJSON(t, map[string]any{
		"issued_at":  "2026-11-20T18:00:00+08:00",
		"expires_at": "2026-11-20T20:00:00+08:00",
	}))
	want := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	if !g.IssuedAt.Equal(want) {
		t.Errorf("IssuedAt = %s, 期望 %s(UTC 归一)", g.IssuedAt, want)
	}
	if g.IssuedAt.Location() != time.UTC || g.ExpiresAt.Location() != time.UTC {
		t.Errorf("时间字段未归一到 UTC")
	}
}

func TestParseGrantMultipleScopes(t *testing.T) {
	g := mustParse(t, grantJSON(t, map[string]any{
		"scope": []string{"systemd:user:restart:nginx.service", "podman:stop:test-web"},
	}))
	if len(g.Scope) != 2 {
		t.Fatalf("Scope = %v, 期望两条", g.Scope)
	}
	if g.Scope[1] != "podman:stop:test-web" {
		t.Errorf("Scope[1] = %q", g.Scope[1])
	}
}

func TestParseGrantTreatsIssuedByAsClueOnly(t *testing.T) {
	// issued_by 只作线索(权威身份是文件属主),缺了也不该拒绝解析。
	g := mustParse(t, grantJSON(t, map[string]any{"issued_by": nil}))
	if g.IssuedBy != "" {
		t.Errorf("IssuedBy = %q, 期望空串", g.IssuedBy)
	}
}

func TestParseGrantRejects(t *testing.T) {
	cases := []struct {
		name      string
		overrides map[string]any
	}{
		{"缺 id", map[string]any{"id": nil}},
		{"id 为空串", map[string]any{"id": ""}},
		{"id 含路径分隔符", map[string]any{"id": "../g-1"}},
		{"缺 scope", map[string]any{"scope": nil}},
		{"scope 为空数组", map[string]any{"scope": []string{}}},
		{"scope 条目为空串", map[string]any{"scope": []string{""}}},
		{"scope 条目非法", map[string]any{"scope": []string{"systemd:start:x.service"}}},
		{"scope 条目运行时不在词表", map[string]any{"scope": []string{"unknown:start:x"}}},
		{"scope 目标通配非法", map[string]any{"scope": []string{"systemd:user:restart:["}}},
		{"缺 issued_at", map[string]any{"issued_at": nil}},
		{"issued_at 非 RFC3339", map[string]any{"issued_at": "2026-11-20 10:00:00"}},
		{"缺 expires_at", map[string]any{"expires_at": nil}},
		{"expires_at 早于 issued_at", map[string]any{"expires_at": "2026-11-20T09:00:00Z"}},
		{"expires_at 等于 issued_at", map[string]any{"expires_at": "2026-11-20T10:00:00Z"}},
		{"max_uses 为 0", map[string]any{"max_uses": 0}},
		{"max_uses 为负", map[string]any{"max_uses": -1}},
		{"未知字段", map[string]any{"forged": "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := grant.Parse(grantJSON(t, tc.overrides)); err == nil {
				t.Fatalf("期望拒绝,实际解析通过")
			}
		})
	}
}

func TestParseGrantRejectsBrokenJSON(t *testing.T) {
	const valid = `{"id":"g-1","scope":["systemd:user:restart:x.service"],"issued_at":"2026-11-20T10:00:00Z","expires_at":"2026-11-20T12:00:00Z","max_uses":1}`
	cases := map[string][]byte{
		"非 JSON":   []byte("not json"),
		"JSON 语法错": []byte(`{"id":"g-1",`),
		"对象后有残余":   []byte(valid + ` {}`),
		// 紧跟的 ] / } 是 dec.More() 的盲区:这三种尾串都必须被拒。
		"对象后残余 ]":     []byte(valid + `]`),
		"对象后残余 }":     []byte(valid + `}`),
		"对象后残余 空格}":   []byte(valid + ` }`),
		"JSON 数组而非对象": []byte(`[]`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := grant.Parse(data); err == nil {
				t.Fatalf("期望拒绝,实际解析通过")
			}
		})
	}
}

func TestGrantMarshalRoundTrip(t *testing.T) {
	// MarshalJSON 与 Parse 必须互为逆运算:条子文件的读写两端只有一个事实源。
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	want := &grant.Grant{
		ID:        "g-1",
		Scope:     []string{"systemd:user:restart:nginx.service", "podman:stop:test-web"},
		IssuedBy:  "alice",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		MaxUses:   2,
		Note:      "半夜 nginx 挂了就重启",
		ForUser:   "alice",
	}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal 失败: %v", err)
	}
	got, err := grant.Parse(data)
	if err != nil {
		t.Fatalf("Marshal 的产物必须能被 Parse 读回: %v", err)
	}
	if got.ID != want.ID || got.IssuedBy != want.IssuedBy || got.MaxUses != want.MaxUses || got.Note != want.Note {
		t.Fatalf("往返后字段不一致: %+v", got)
	}
	if got.ForUser != want.ForUser {
		t.Fatalf("往返后 for_user 丢失: %q, 期望 %q", got.ForUser, want.ForUser)
	}
	if !got.IssuedAt.Equal(want.IssuedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("往返后时间不一致: %s / %s", got.IssuedAt, got.ExpiresAt)
	}
	if len(got.Scope) != len(want.Scope) || got.Scope[0] != want.Scope[0] || got.Scope[1] != want.Scope[1] {
		t.Fatalf("往返后范围不一致: %v", got.Scope)
	}
	// 时间字段必须是 UTC RFC3339,不随本机时区变形。
	if !strings.Contains(string(data), `"expires_at":"2026-11-20T11:00:00Z"`) {
		t.Fatalf("到期时间未按 UTC RFC3339 输出: %s", data)
	}
}

func TestGrantCovers(t *testing.T) {
	g := &grant.Grant{Scope: []string{"systemd:user:restart:*", "podman:stop:test-web"}}
	nginx := autonomy.Scope{Runtime: "systemd", Domain: "user", Action: "restart", Target: "nginx.service"}
	if !g.Covers(nginx) {
		t.Errorf("条子应覆盖 %s", nginx.String())
	}
	stop := autonomy.Scope{Runtime: "systemd", Domain: "user", Action: "stop", Target: "nginx.service"}
	if g.Covers(stop) {
		t.Errorf("条子不应覆盖 %s(动作不同)", stop.String())
	}
	system := autonomy.Scope{Runtime: "systemd", Domain: "system", Action: "restart", Target: "nginx.service"}
	if g.Covers(system) {
		t.Errorf("条子不应覆盖 %s(域不同)", system.String())
	}
	podman := autonomy.Scope{Runtime: "podman", Action: "stop", Target: "test-web"}
	if !g.Covers(podman) {
		t.Errorf("条子应覆盖 %s", podman.String())
	}
}

func TestGrantCoversFailsClosedOnBrokenScope(t *testing.T) {
	// 坏条目排在有效条目之后也必须整张作废:否则坏条目会被静默跳过。
	g := &grant.Grant{Scope: []string{"systemd:user:restart:*", "systemd:start:x.service"}}
	nginx := autonomy.Scope{Runtime: "systemd", Domain: "user", Action: "restart", Target: "nginx.service"}
	if g.Covers(nginx) {
		t.Errorf("含坏作用域的条子不应覆盖任何对象")
	}
}

func TestGrantExpired(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	g := &grant.Grant{ExpiresAt: now.Add(time.Minute)}
	if g.Expired(now) {
		t.Errorf("未到期不应判过期")
	}
	if !g.Expired(now.Add(time.Minute)) {
		t.Errorf("到期瞬间应判过期")
	}
	if !g.Expired(now.Add(time.Hour)) {
		t.Errorf("过期后应判过期")
	}
	var nilGrant *grant.Grant
	if !nilGrant.Expired(now) {
		t.Errorf("空条子应判过期(fail-closed)")
	}
}

// aliceConfig 是「alice 可签 systemd:user:restart:*、最长 1 小时、最多 2 次」的名单。
func aliceConfig() *autonomy.Config {
	return &autonomy.Config{Signers: []autonomy.Signer{{
		User:     "alice",
		MaxScope: []string{"systemd:user:restart:*"},
		MaxTTL:   time.Hour,
		MaxUses:  2,
	}}}
}

func baseGrant(now time.Time) *grant.Grant {
	return &grant.Grant{
		ID:        "g-1",
		Scope:     []string{"systemd:user:restart:nginx.service"},
		IssuedBy:  "alice",
		IssuedAt:  now.Add(-time.Minute),
		ExpiresAt: now.Add(30 * time.Minute),
		MaxUses:   1,
	}
}

func TestAuthorizeGrant(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cfg := aliceConfig()
	if err := grant.Authorize(cfg, baseGrant(now), 1000, "alice", now); err != nil {
		t.Fatalf("alice 在名单内、范围与时长都合规时应放行,实际: %v", err)
	}
}

func TestAuthorizeGrantRejectsUnlistedIssuer(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	err := grant.Authorize(aliceConfig(), baseGrant(now), 1000, "bob", now)
	assertErrContains(t, err, "无权")
}

func TestAuthorizeGrantRejectsScopeBeyondMaxScope(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	g := baseGrant(now)
	g.Scope = []string{"systemd:user:remove:nginx.service"}
	err := grant.Authorize(aliceConfig(), g, 1000, "alice", now)
	assertErrContains(t, err, "范围")
}

func TestAuthorizeGrantRejectsScopeBeyondMaxScopeForWildcard(t *testing.T) {
	// 条子范围比签发者的 max_scope 更宽 ⇒ 越权(签发者无权签出这么宽的条子)。
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cfg := &autonomy.Config{Signers: []autonomy.Signer{{
		User:     "alice",
		MaxScope: []string{"systemd:user:restart:nginx.service"},
		MaxTTL:   time.Hour,
		MaxUses:  2,
	}}}
	g := baseGrant(now)
	g.Scope = []string{"systemd:user:restart:*"}
	err := grant.Authorize(cfg, g, 1000, "alice", now)
	assertErrContains(t, err, "范围")
}

func TestAuthorizeGrantRejectsTTLOverSignerMax(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cfg := &autonomy.Config{Signers: []autonomy.Signer{{
		User:     "alice",
		MaxScope: []string{"systemd:user:restart:*"},
		MaxTTL:   30 * time.Minute,
		MaxUses:  2,
	}}}
	g := baseGrant(now)
	g.ExpiresAt = now.Add(2 * time.Hour)
	err := grant.Authorize(cfg, g, 1000, "alice", now)
	assertErrContains(t, err, "有效期")
}

func TestAuthorizeGrantRejectsUsesOverSignerMax(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	g := baseGrant(now)
	g.MaxUses = 3
	err := grant.Authorize(aliceConfig(), g, 1000, "alice", now)
	assertErrContains(t, err, "次数")
}

func TestAuthorizeGrantIgnoresSelfReportedIssuer(t *testing.T) {
	// 条子自称 root 也没用:权威身份是调用方给的属主/属主名。
	// 这里的 alice 不在签发者名单内,签发者身份不会因为条子自称而成立。
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cfg := &autonomy.Config{Signers: []autonomy.Signer{{
		User:     "bob",
		MaxScope: []string{"systemd:user:restart:*"},
		MaxTTL:   time.Hour,
		MaxUses:  2,
	}}}
	g := baseGrant(now)
	g.IssuedBy = "root"
	err := grant.Authorize(cfg, g, 1000, "alice", now)
	assertErrContains(t, err, "无权")
}

func TestAuthorizeGrantIgnoresSelfReportedIssuerOfOtherSigner(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	g := baseGrant(now)
	g.IssuedBy = "alice"
	err := grant.Authorize(aliceConfig(), g, 1000, "bob", now)
	assertErrContains(t, err, "无权")
}

func TestDenySignerWins(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cfg := aliceConfig()
	cfg.DenySigners = []string{"alice"}
	err := grant.Authorize(cfg, baseGrant(now), 1000, "alice", now)
	// 断言到「禁用签发者」这一具体原因:与「不在名单」共用「无权」时,
	// 交换两处文案或合并成一句都不会变红。
	assertErrContains(t, err, "无权", "禁用签发者")
}

func TestDenySignerWinsOverWildcardGrant(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cfg := aliceConfig()
	cfg.DenySigners = []string{"alice"}
	g := baseGrant(now)
	g.Scope = []string{"systemd:user:restart:*"}
	err := grant.Authorize(cfg, g, 1000, "alice", now)
	assertErrContains(t, err, "无权", "禁用签发者")
}

func TestAuthorizeRootBypassesSignerList(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cfg := &autonomy.Config{}
	if err := grant.Authorize(cfg, baseGrant(now), 0, "root", now); err != nil {
		t.Fatalf("root 应可签(空名单只挡非 root),实际: %v", err)
	}
}

func TestAuthorizeRootStillBoundByGlobalCaps(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cfg := &autonomy.Config{}

	g := baseGrant(now)
	g.MaxUses = 11
	assertErrContains(t, grant.Authorize(cfg, g, 0, "root", now), "次数")

	g = baseGrant(now)
	g.ExpiresAt = now.Add(25 * time.Hour)
	assertErrContains(t, grant.Authorize(cfg, g, 0, "root", now), "有效期")
}

func TestAuthorizeRejectsDangerousScopeForRoot(t *testing.T) {
	// 危险对象不该有自主条子:root 也不例外。
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cfg := &autonomy.Config{Deny: []string{"systemd:user:db-*"}}
	g := baseGrant(now)
	g.Scope = []string{"systemd:user:restart:db-1.service"}
	err := grant.Authorize(cfg, g, 0, "root", now)
	assertErrContains(t, err, "危险名单")
}

func TestAuthorizeRejectsDangerousNameForSigner(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cfg := aliceConfig()
	cfg.DenyNames = []string{"sshd"}
	g := baseGrant(now)
	g.Scope = []string{"systemd:user:restart:sshd.service"}
	err := grant.Authorize(cfg, g, 1000, "alice", now)
	assertErrContains(t, err, "危险名单")
}

func TestAuthorizeAllowsNonDangerousScopeWithDenyList(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cfg := aliceConfig()
	cfg.Deny = []string{"systemd:user:db-*"}
	cfg.DenyNames = []string{"sshd"}
	if err := grant.Authorize(cfg, baseGrant(now), 1000, "alice", now); err != nil {
		t.Fatalf("不命中危险名单应放行,实际: %v", err)
	}
}

func TestAuthorizeRejectsExpiredGrant(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	g := baseGrant(now)
	g.ExpiresAt = now.Add(-time.Minute)
	// 「已过期」与「有效期超过上限」是两回事:下游要能区分「续签一张过期的」
	// 与「把 TTL 写短点」,所以文案必须不同。
	assertErrContains(t, grant.Authorize(aliceConfig(), g, 1000, "alice", now), "已过期")
}

func TestAuthorizeRejectsBrokenScope(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	g := baseGrant(now)
	g.Scope = []string{"systemd:start:x.service"}
	assertErrContains(t, grant.Authorize(aliceConfig(), g, 1000, "alice", now), "范围")
}

func TestAuthorizeRejectsEmptyScope(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	g := baseGrant(now)
	g.Scope = nil
	assertErrContains(t, grant.Authorize(aliceConfig(), g, 1000, "alice", now), "范围")
}

func TestAuthorizeRejectsZeroUses(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	g := baseGrant(now)
	g.MaxUses = 0
	assertErrContains(t, grant.Authorize(aliceConfig(), g, 1000, "alice", now), "次数")
}

func TestAuthorizeRejectsZeroSignerBounds(t *testing.T) {
	// 上限 0 只能来自程序内构造的配置(加载期已要求必填):必须 fail-closed 拒,
	// 绝不能当成"不额外限制"。否则「少写一个字段 ⇒ 权限变大」。
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	scope := []string{"systemd:user:restart:*"}
	cases := []struct {
		name   string
		signer autonomy.Signer
		want   string
	}{
		{"缺 max_ttl", autonomy.Signer{User: "alice", MaxScope: scope, MaxUses: 2}, "max_ttl"},
		{"缺 max_uses", autonomy.Signer{User: "alice", MaxScope: scope, MaxTTL: time.Hour}, "max_uses"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &autonomy.Config{Signers: []autonomy.Signer{tc.signer}}
			assertErrContains(t, grant.Authorize(cfg, baseGrant(now), 1000, "alice", now), tc.want)
		})
	}

	// 也不得退回全局硬上限:零上限签发者签 20h / 10 次同样要拒。
	cfg := &autonomy.Config{Signers: []autonomy.Signer{{User: "alice", MaxScope: scope}}}
	g := baseGrant(now)
	g.ExpiresAt = now.Add(20 * time.Hour)
	g.MaxUses = 10
	assertErrContains(t, grant.Authorize(cfg, g, 1000, "alice", now), "max_ttl")
}

func TestAuthorizeRejectsDuplicateSigner(t *testing.T) {
	// 手工构造的 Config 可能绕过加载期去重:消费侧自己也要拒多条。
	// 挑首条会让「后加的收紧条目」静默失效(配置更严、行为更松)。
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cfg := &autonomy.Config{Signers: []autonomy.Signer{
		// 宽在前:按首条会放行这张 30 分钟 / 1 次的条子。
		{User: "alice", MaxScope: []string{"systemd:user:restart:*"}, MaxTTL: time.Hour, MaxUses: 5},
		// 严在后:10 分钟 / 1 次。
		{User: "alice", MaxScope: []string{"systemd:user:restart:nginx.service"}, MaxTTL: 10 * time.Minute, MaxUses: 1},
	}}
	err := grant.Authorize(cfg, baseGrant(now), 1000, "alice", now)
	assertErrContains(t, err, "重复")
}

func TestAuthorizeTTLUsesNowAsBasis(t *testing.T) {
	// TTL 按「现在起的剩余时长」判,不按签发时刻的总寿命:
	// 30 小时前签发、只剩 1 小时的条子,在 max_ttl=2h 下必须放行。
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cfg := &autonomy.Config{Signers: []autonomy.Signer{{
		User:     "alice",
		MaxScope: []string{"systemd:user:restart:*"},
		MaxTTL:   2 * time.Hour,
		MaxUses:  2,
	}}}
	g := &grant.Grant{
		ID:        "g-1",
		Scope:     []string{"systemd:user:restart:nginx.service"},
		IssuedBy:  "alice",
		IssuedAt:  now.Add(-30 * time.Hour),
		ExpiresAt: now.Add(time.Hour),
		MaxUses:   1,
	}
	if err := grant.Authorize(cfg, g, 1000, "alice", now); err != nil {
		t.Fatalf("TTL 应以 now 为基准(剩余 1h < 上限 2h),实际: %v", err)
	}
}

func TestAuthorizeSignerWithoutMaxScopeCoversNothing(t *testing.T) {
	// max_scope 为空 = 没有范围授权(不得当成"不限范围")。
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cfg := &autonomy.Config{Signers: []autonomy.Signer{{
		User:    "alice",
		MaxTTL:  time.Hour,
		MaxUses: 2,
	}}}
	err := grant.Authorize(cfg, baseGrant(now), 1000, "alice", now)
	assertErrContains(t, err, "范围")
}

func TestAuthorizeLooseMaxScopeEntryDoesNotGrantCoverage(t *testing.T) {
	// 名单里省略动作段的写法在 autonomy 侧合法,但 grant 侧只认可解析的作用域;
	// 解析不了就当"没覆盖"(fail-closed),不得据此放行。
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cfg := &autonomy.Config{Signers: []autonomy.Signer{{
		User:     "alice",
		MaxScope: []string{"systemd:user:db-*"},
		MaxTTL:   time.Hour,
		MaxUses:  2,
	}}}
	g := baseGrant(now)
	g.Scope = []string{"systemd:user:restart:db-1.service"}
	err := grant.Authorize(cfg, g, 1000, "alice", now)
	assertErrContains(t, err, "范围")
}

func TestAuthorizeNilConfigRejectsNonRoot(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	err := grant.Authorize(nil, baseGrant(now), 1000, "alice", now)
	assertErrContains(t, err, "无权")
}

func TestAuthorizeNilGrantRejected(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	if err := grant.Authorize(aliceConfig(), nil, 0, "root", now); err == nil {
		t.Fatalf("空条子应被拒绝")
	}
}

func TestBindExecutor(t *testing.T) {
	// 签发者(文件属主)与执行者(消费侧进程身份)必须分开:
	// 一张没绑执行者的条子就是节点级通行证,任何本地用户的 agent 都能拿去用。
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	g := baseGrant(now)
	cases := []struct {
		name       string
		forUser    string
		ownerUID   uint32
		ownerName  string
		execUID    uint32
		execName   string
		wantErr    bool
		wantSubstr string
	}{
		{name: "属主=执行者 ⇒ 自己的条子自己用", ownerUID: 1000, ownerName: "alice", execUID: 1000, execName: "alice"},
		{name: "root 签给你 ⇒ 放行", forUser: "alice", ownerUID: 0, ownerName: "root", execUID: 1000, execName: "alice"},
		{name: "root 签的没写给谁 ⇒ 拒", ownerUID: 0, ownerName: "root", execUID: 1000, execName: "alice", wantErr: true, wantSubstr: "for_user"},
		{name: "root 签给别人 ⇒ 拒", forUser: "bob", ownerUID: 0, ownerName: "root", execUID: 1000, execName: "alice", wantErr: true, wantSubstr: "给"},
		{name: "别人的条子 ⇒ 拒", forUser: "alice", ownerUID: 1001, ownerName: "bob", execUID: 1000, execName: "alice", wantErr: true, wantSubstr: "属于"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := *g
			got.ForUser = tc.forUser
			err := grant.BindExecutor(&got, tc.ownerUID, tc.ownerName, tc.execUID, tc.execName)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("期望拒绝,实际放行")
				}
				if !strings.Contains(err.Error(), tc.wantSubstr) {
					t.Fatalf("错误信息应含 %q: %v", tc.wantSubstr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("期望放行,实际: %v", err)
			}
		})
	}
}

func TestBindExecutorNilGrant(t *testing.T) {
	if err := grant.BindExecutor(nil, 1000, "alice", 1000, "alice"); err == nil {
		t.Fatalf("空条子应被拒绝")
	}
}

func TestParseAcceptsForUser(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	raw := fmt.Sprintf(`{"id":"g-1","scope":["systemd:user:restart:x.service"],"issued_by":"root","issued_at":"%s","expires_at":"%s","max_uses":1,"for_user":"alice"}`,
		now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
	g, err := grant.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("带 for_user 的条子应能解析: %v", err)
	}
	if g.ForUser != "alice" {
		t.Fatalf("for_user 解析结果 = %q", g.ForUser)
	}
}

func TestParseRejectsBadForUser(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	base := fmt.Sprintf(`"id":"g-1","scope":["systemd:user:restart:x.service"],"issued_by":"root","issued_at":"%s","expires_at":"%s","max_uses":1`,
		now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
	for _, bad := range []string{"a/b", "a b", "a\\b", "a\x00b", "a:b"} {
		raw := fmt.Sprintf("{%s,\"for_user\":%q}", base, bad)
		if _, err := grant.Parse([]byte(raw)); err == nil {
			t.Fatalf("非法 for_user %q 竟被接受", bad)
		}
	}
}
