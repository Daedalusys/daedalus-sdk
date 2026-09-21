package blueprint

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// confirmTokenTTL 是确认令牌的有效期。
//
// 过期后即使未消费也不可再用(与消费态同判为"校验失败")。
const confirmTokenTTL = 15 * time.Minute

// consumedTokens 记录已消费的确认令牌。
//
// 进程内 map 即可满足 v1 契约(单次有效);跨进程持久化归后续
// (与 plan_id 存储一起做,见 plan wave 5)。
//
// 并发安全:mu 保护"检查未消费 → 标记消费"的原子序列(F2 审查修复:
// sync.Map 的 Load→Store 两步非原子,并发双消费可击穿单次性——两 goroutine
// 同时 Load 都 miss,再各自 Store,令牌被消费两次)。互斥锁把检查与消费
// 包进同一临界区,任意并发下消费至多一次。
var consumedTokens = struct {
	sync.Mutex
	m map[string]struct{}
}{m: make(map[string]struct{})}

// GenerateConfirmToken 为 planID 生成单次有效的确认令牌。
//
// Token 是 32 字节 crypto/rand 随机数的十六进制编码(不可预测);
// Expires 取 Unix 毫秒,由当前时间 + confirmTokenTTL 得出。
func GenerateConfirmToken(planID string) ConfirmToken {
	return ConfirmToken{
		Token:   newTokenSecret(),
		PlanID:  planID,
		Expires: time.Now().Add(confirmTokenTTL).UnixMilli(),
	}
}

// VerifyConfirmToken 校验 token 与 planID 配对且未消费;消费后 token 失效。
//
// 校验顺序(任一失败即返回,不继续):
//  1. 空 token → 拒绝;
//  2. PlanID 不匹配 → 拒绝;
//  3. 已消费(token 在 consumedTokens 中)→ 拒绝;
//  4. 已过期(Expires 早于当前毫秒)→ 拒绝(过期令牌即使未消费也不可用)。
//
// 校验全部通过才标记消费,保证"成功即消费、单次有效"的原子语义。
// 注意:明文 secret 永不进 audit log 是框架层强约束,本函数只处理令牌
// 本身(随机串),不涉及任何 secret 真值。
func VerifyConfirmToken(planID string, tok ConfirmToken) error {
	if tok.Token == "" {
		return errors.New("blueprint: confirm token 不能为空")
	}
	if tok.PlanID != planID {
		return errors.New("blueprint: confirm token 的 plan_id 不匹配")
	}
	if tok.Expires != 0 && tok.Expires < time.Now().UnixMilli() {
		return errors.New("blueprint: confirm token 已过期")
	}
	// 检查未消费 → 标记消费,同一临界区内完成(F2 审查修复:防并发双消费)。
	consumedTokens.Lock()
	defer consumedTokens.Unlock()
	if _, consumed := consumedTokens.m[tok.Token]; consumed {
		return errors.New("blueprint: confirm token 已被消费")
	}
	consumedTokens.m[tok.Token] = struct{}{}
	return nil
}

// newTokenSecret 生成 32 字节 crypto/rand 随机数的十六进制编码。
//
// 使用 crypto/rand 而非 math/rand,保证令牌不可预测
// (确认令牌是安全敏感凭证,不能用可预测的伪随机数)。
func newTokenSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败意味着系统熵源故障,panic(fail-closed)。
		panic("blueprint: crypto/rand 读取失败: " + err.Error())
	}
	return hex.EncodeToString(b)
}
