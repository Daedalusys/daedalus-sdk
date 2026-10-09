package confirmation

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// ConfirmTokenTTL 是确认令牌的有效期;过期后即使未消费也不可再用。
// 导出为常量便于调用方(blueprint 薄包装、policy.toml drift 校验)引用。
const ConfirmTokenTTL = 15 * time.Minute

// ConfirmToken 是确认令牌的对外凭证形态。
//
// Token 单次有效,校验通过后即失效;SubjectID/Expires 是对外展示形态,
// 权威状态以本包签发登记表为准,自报字段既不能伪造配对也不能放宽有效期。
type ConfirmToken struct {
	// Token 是 32 字节 crypto/rand 随机数的十六进制编码(不可预测)。
	Token string
	// SubjectID 是被本令牌授权的操作对象(blueprint 的 plan_id、disk-clean
	// 的 plan_id、organize 的 plan_id 等)。
	SubjectID string
	// Expires 是 Unix 毫秒过期时间。
	Expires int64
}

// tokenRecord 是签发时固化的权威事实:subject 配对、过期时刻、是否已消费。
// 校验只认签发记录,绝不采信令牌携带方自报的 SubjectID/Expires——
// VerifyConfirmToken 的入参 ConfirmToken 由调用方(甚至客户端)构造,
// 自报字段全部可伪造。
type tokenRecord struct {
	subject  string
	expires  int64
	consumed bool
}

// tokens 是签发登记表:GenerateConfirmToken 写入,VerifyConfirmToken 查表。
// 进程内即可满足契约——签发(render/scan/plan)与消费(apply/clean)本就在同一
// MCP 服务器会话内;进程重启后旧令牌查无记录即拒绝,是 fail-closed 而非缺陷
// (用户重新生成拿新令牌)。
//
// 并发安全:mu 保护"查未消费 → 标记消费"的原子序列。sync.Map 的
// Load→Store 两步非原子,并发双消费可击穿单次性——两 goroutine 同时 Load
// 都 miss,再各自 Store,令牌被消费两次。互斥锁把检查与消费包进同一临界区,
// 任意并发下消费至多一次。
var tokens = struct {
	sync.Mutex
	m map[string]*tokenRecord
}{m: make(map[string]*tokenRecord)}

// GenerateConfirmToken 为 subjectID 生成单次有效的确认令牌,并登记签发事实。
//
// Token 是 32 字节 crypto/rand 随机数的十六进制编码(不可预测);
// Expires 是 Unix 毫秒时间戳。返回的 ConfirmToken 是对外凭证形态,
// 权威状态以本包签发登记为准。
func GenerateConfirmToken(subjectID string) ConfirmToken {
	secret := newTokenSecret()
	now := time.Now().UnixMilli()
	expires := now + ConfirmTokenTTL.Milliseconds()
	tokens.Lock()
	defer tokens.Unlock()
	purgeExpiredTokensLocked(now)
	tokens.m[secret] = &tokenRecord{subject: subjectID, expires: expires}
	return ConfirmToken{Token: secret, SubjectID: subjectID, Expires: expires}
}

// VerifyConfirmToken 校验 token 确为本包签发、subjectID 配对、未过期且未消费;
// 成功即消费,单次有效。
//
// 未登记的 token(伪造串、跨进程旧令牌)一律拒绝;入参 ConfirmToken 的
// SubjectID/Expires 不作为通过依据——SubjectID 与签发登记比对,Expires 只允许
// 把有效期往早了收(自报更早则采信自报),绝不采信"永不过期"之类的放宽。
// 全部通过才标记消费,保证"成功即消费、单次有效"的原子语义。
//
// 注意:明文 secret 永不进 audit log 是框架层强约束,本函数只处理令牌
// 本身(随机串),不涉及任何 secret 真值。
func VerifyConfirmToken(subjectID string, tok ConfirmToken) error {
	if tok.Token == "" {
		return errors.New("confirmation: token 不能为空")
	}
	tokens.Lock()
	defer tokens.Unlock()
	rec, issued := tokens.m[tok.Token]
	if !issued {
		return errors.New("confirmation: token 未经本进程签发(伪造或已失效)")
	}
	now := time.Now().UnixMilli()
	// 过期判定以签发记录为准;自报 Expires 非零时只能提前、不能豁免过期。
	// 记录本身过期才删条目;仅自报更早而记录未过期时保留,拒绝这一次比对。
	if rec.expires < now {
		delete(tokens.m, tok.Token)
		return errors.New("confirmation: token 已过期")
	}
	effective := rec.expires
	if tok.Expires != 0 && tok.Expires < effective {
		effective = tok.Expires
	}
	if effective < now {
		return errors.New("confirmation: token 已过期")
	}
	if rec.subject != subjectID {
		return errors.New("confirmation: token 的 subject_id 不匹配")
	}
	if rec.consumed {
		return errors.New("confirmation: token 已被消费")
	}
	rec.consumed = true
	return nil
}

// purgeExpiredTokensLocked 清理签发登记中已过期的条目(含已消费),
// 防止长跑服务器进程里登记表无界增长。须持有 tokens.mu 调用。
func purgeExpiredTokensLocked(now int64) {
	for secret, rec := range tokens.m {
		if rec.expires < now {
			delete(tokens.m, secret)
		}
	}
}

// newTokenSecret 生成 32 字节 crypto/rand 随机数的十六进制编码。
//
// 使用 crypto/rand 而非 math/rand,保证令牌不可预测
// (确认令牌是安全敏感凭证,不能用可预测的伪随机数)。
func newTokenSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败意味着系统熵源故障,panic(fail-closed)。
		panic("confirmation: crypto/rand 读取失败: " + err.Error())
	}
	return hex.EncodeToString(b)
}
