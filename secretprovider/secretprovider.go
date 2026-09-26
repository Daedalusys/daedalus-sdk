// Package secretprovider 钉 SecretProvider slot 的第一批 contract
// (daedalus-sdk#2,消费者议题 #33 KWallet / #34 systemd-creds)。
//
// 职责边界(契约缝·零运行时,镜像 internal/controller 先例):
//   - 本包只有接口、引用形状、脱敏值类型与哨兵错误,**没有任何实现**、
//     没有注册表;provider 接线归消费方 cmd/daemon 构造期。
//   - 语义单一事实源见仓内 docs/provider-slot.md §2;接口形状改动
//     = SDK 公开面增量,须联动文档与评审。
//
// 引用模型:调用方只持 `secret://<scheme>/<path>` 引用,明文只在解析
// 瞬间存在于 L0 调用栈。用户态(KWallet)与服务态(LoadCredential/credstore)
// 共用同一 Ref 词汇表,不互相复制实现。
//
// 框架级硬约束(不靠实现者自律):Secret 的 String/GoString 恒脱敏、
// MarshalJSON 直接报错——明文在类型层就进不了审计行、日志行与任何
// JSON 序列化路径;错误字符串不得内嵌值内容(contract 义务,评审门)。
package secretprovider

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/Daedalusys/daedalus-sdk/slot"
)

// 哨兵错误:实现包装底层细节必须用 %w 保留哨兵,消费者以 errors.Is 判别。
// ErrNotFound 的设计义务:与"存在但无权访问"不可区分(防探测枚举)。
var (
	// ErrRefInvalid 表示引用未通过 Ref 形状门。
	ErrRefInvalid = errors.New("secretprovider: 引用形状非法")
	// ErrSchemeMismatch 表示 provider 收到非本 scheme 的引用(拒读拒写)。
	ErrSchemeMismatch = errors.New("secretprovider: 引用 scheme 与本 provider 不符")
	// ErrNotFound 表示引用不存在(或不向调用方暴露其存在)。
	ErrNotFound = errors.New("secretprovider: 引用不存在")
	// ErrLocked 表示后端锁定/未解锁(如 KWallet collection 未解锁)。
	ErrLocked = errors.New("secretprovider: 后端未解锁")
	// ErrUnavailable 表示后端不可达;与 blueprint 渲染侧
	// ErrSecretSourceUnavailable 同一姿势:解析失败 ≠ 返回空串。
	ErrUnavailable = errors.New("secretprovider: 后端不可用")
)

// refPattern 锁定引用形状:`secret://<scheme>/<path>`。
// scheme 为小写字母开头的 [a-z0-9_-]*;path 非空、不含空字节与空白
// (空白会撕裂日志行,空字节是路径注入原料,一律在形状门外拒掉)。
var refPattern = regexp.MustCompile(`^secret://[a-z][a-z0-9_-]*/[^\x00\s]+$`)

// Ref 是指向凭据的不透明引用——调用方持有的只有它,永远不是明文。
type Ref string

// Validate 执行形状门。通过仅代表语法合法,不代表引用存在或可解引用。
func (r Ref) Validate() error {
	if !refPattern.MatchString(string(r)) {
		return fmt.Errorf("%w: %q", ErrRefInvalid, r)
	}
	return nil
}

// Scheme 返回引用的 provider 段(`secret://<scheme>/...`);仅对
// 通过 Validate 的引用有定义。
func (r Ref) Scheme() string {
	body := string(r)[len("secret://"):]
	for i := 0; i < len(body); i++ {
		if body[i] == '/' {
			return body[:i]
		}
	}
	return body
}

// Secret 是明文凭据值类型。全部序列化面被钉死为脱敏:
// String/GoString 恒返回占位,MarshalJSON 直接报错(框架级红线)。
type Secret []byte

// String 恒脱敏(Secret 永不因 %v/%s 泄露进日志)。
func (s Secret) String() string { return "<redacted>" }

// GoString 恒脱敏(%#v 同样封堵)。
func (s Secret) GoString() string { return `secretprovider.Secret("<redacted>")` }

// MarshalJSON 拒绝序列化:明文不得出现在任何 JSON 输出
// (审计行、工具回包、快照)。需要落盘/回包的是 Ref,不是 Secret。
func (s Secret) MarshalJSON() ([]byte, error) {
	return nil, errors.New("secretprovider: 拒绝序列化明文凭据(序列化对象应为 Ref)")
}

// Zeroize 就地清零;Get 的用毕义务(调用方应尽量短命持有)。
func (s Secret) Zeroize() {
	for i := range s {
		s[i] = 0
	}
}

// Provider 是 SecretProvider slot 的稳定 contract,方法与 #33 工具面
// 一一对应(collections/list/get/set/delete)。实现者义务:
//   - 错误必须经 %w 携带本包哨兵,且不得内嵌值内容;
//   - 对非本 Scheme 的 Ref 一律 ErrSchemeMismatch(读写皆拒);
//   - 审计日志(action 侧)只允许记录 Ref,绝不记录 Secret。
type Provider interface {
	// Scheme 返回本 provider 认领的引用段(如 "kwallet"、"credstore")。
	Scheme() string
	// Swappability 声明替换上限;平台承诺永不超过它(见 slot.Level)。
	Swappability() slot.Level
	// Collections 列出可寻址容器(#33 secrets_collections)。
	Collections(ctx context.Context) ([]string, error)
	// List 按容器 + 前缀列出引用(#33 secrets_list)。
	List(ctx context.Context, collection, prefix string) ([]Ref, error)
	// Get 解析引用为明文(#33 secrets_get;明文仅在 L0 调用栈)。
	Get(ctx context.Context, ref Ref) (Secret, error)
	// Set 写入凭据(#33 secrets_set;确认令牌归工具面,不在此层)。
	Set(ctx context.Context, ref Ref, value Secret) error
	// Delete 删除凭据(#33 secrets_delete)。
	Delete(ctx context.Context, ref Ref) error
}
