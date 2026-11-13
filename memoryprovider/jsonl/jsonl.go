// Package jsonl 提供 MemoryProvider 的 JSONL 文件后端(swappability=L1:
// 重启级替换,换实现只需换构造期接线)。
//
// 文件形状:一行一条 JSON 记录,纯追加。删除写墓碑记录(`deleted:true`),
// 不在原地改写文件 —— 追加式写入让「写一半崩了」只影响最后一行,不会毁掉
// 已有内容。读取时把整个文件重放到内存索引,过期条目按 TTL 现场判定。
//
// 语义边界(与契约包 memoryprovider 一致):
//   - 只服务 ScopeUser;system scope 与非法 scope 一律 ErrScopeDenied
//     (跨用户/系统共享不在本实现范围内,见 daedalus-sdk#25)。
//   - Search 不提供语义检索,恒回 ErrSearchUnavailable —— 不许静默返回空集。
//   - 记忆值只承载 `secret://` 引用这一点由调用方保证:本包按字节原样存取,
//     不做明文检测(类型层无法强制,契约已明示)。
package jsonl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Daedalusys/daedalus-sdk/memoryprovider"
	"github.com/Daedalusys/daedalus-sdk/slot"
)

// ErrInvalidKey 表示键不满足扁平命名空间约束(非空、不含空白)。
var ErrInvalidKey = errors.New("memoryprovider/jsonl: 记忆键非法(不能为空且不能含空白)")

// Options 是构造开关。Now 供测试注入时钟,生产留空即用 time.Now。
type Options struct {
	Now func() time.Time
}

// record 是落盘的一行。Value 为 nil 且 Deleted 为真时是墓碑。
type record struct {
	Key     string               `json:"key"`
	Value   json.RawMessage      `json:"value,omitempty"`
	Scope   memoryprovider.Scope `json:"scope"`
	TTL     time.Duration        `json:"ttl_ns,omitempty"`
	SetAt   time.Time            `json:"set_at"`
	Deleted bool                 `json:"deleted,omitempty"`
}

// Provider 是 JSONL 文件后端。并发安全(单进程内串行化写入)。
// 多进程共享同一文件不在支持范围内:没有跨进程锁,后写者会看到旧索引。
type Provider struct {
	path string
	now  func() time.Time

	mu      sync.Mutex
	file    *os.File
	entries map[string]record // scope\x00key → 最新记录
}

// New 打开(不存在则创建)path 指向的 JSONL 文件并重放成内存索引。
//
// 重放遇到解析不了的行直接报错(fail-closed):静默跳过会把「文件被截断」
// 变成「记忆莫名丢了」,那是更难查的故障。
func New(path string, opts Options) (*Provider, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	p := &Provider{path: path, now: now, entries: map[string]record{}}
	if err := p.replay(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("memoryprovider/jsonl: 打开 %s 失败: %w", path, err)
	}
	p.file = f
	return p, nil
}

// replay 把文件内容读进内存索引;文件不存在视为空库。
func (p *Provider) replay() error {
	raw, err := os.ReadFile(p.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("memoryprovider/jsonl: 读取 %s 失败: %w", p.path, err)
	}
	var line int
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		line++
		var r record
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			return fmt.Errorf("memoryprovider/jsonl: %s 第 %d 行不是合法 JSON: %w", p.path, line, err)
		}
		k := indexKey(r.Scope, r.Key)
		if r.Deleted {
			delete(p.entries, k)
			continue
		}
		p.entries[k] = r
	}
	return nil
}

func indexKey(scope memoryprovider.Scope, key string) string {
	return string(scope) + "\x00" + key
}

// Swappability 声明替换上限:内置文件后端是 L1(重启时替换实现)。
func (p *Provider) Swappability() slot.Level { return slot.LevelRestart }

// Get 按 scope+key 取一条;不存在或已过期都回 ErrKeyNotFound(过期不当墓碑)。
func (p *Provider) Get(_ context.Context, scope memoryprovider.Scope, key string) (memoryprovider.Entry, error) {
	if err := checkScope(scope); err != nil {
		return memoryprovider.Entry{}, err
	}
	if err := checkKey(key); err != nil {
		return memoryprovider.Entry{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.entries[indexKey(scope, key)]
	if !ok || p.expired(r) {
		return memoryprovider.Entry{}, memoryprovider.ErrKeyNotFound
	}
	return r.entry(), nil
}

// Set 追加写入一条记录。
func (p *Provider) Set(_ context.Context, e memoryprovider.Entry) error {
	if err := checkScope(e.Scope); err != nil {
		return err
	}
	if err := checkKey(e.Key); err != nil {
		return err
	}
	r := record{Key: e.Key, Value: e.Value, Scope: e.Scope, TTL: e.TTL, SetAt: p.now()}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.append(r); err != nil {
		return err
	}
	p.entries[indexKey(r.Scope, r.Key)] = r
	return nil
}

// Delete 写墓碑;不存在或已过期回 ErrKeyNotFound(与 Get 的口径一致)。
func (p *Provider) Delete(_ context.Context, scope memoryprovider.Scope, key string) error {
	if err := checkScope(scope); err != nil {
		return err
	}
	if err := checkKey(key); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k := indexKey(scope, key)
	r, ok := p.entries[k]
	if !ok || p.expired(r) {
		return memoryprovider.ErrKeyNotFound
	}
	tomb := record{Key: key, Scope: scope, SetAt: p.now(), Deleted: true}
	if err := p.append(tomb); err != nil {
		return err
	}
	delete(p.entries, k)
	return nil
}

// List 按 scope + 前缀列键(只回键,不回值),过期条目不计入。
func (p *Provider) List(_ context.Context, scope memoryprovider.Scope, prefix string) ([]string, error) {
	if err := checkScope(scope); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var keys []string
	for _, r := range p.entries {
		if r.Scope != scope || p.expired(r) {
			continue
		}
		if strings.HasPrefix(r.Key, prefix) {
			keys = append(keys, r.Key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// Search 恒回 ErrSearchUnavailable:本后端没有语义检索,空结果不等于没命中。
func (p *Provider) Search(_ context.Context, _ string, _ int) ([]memoryprovider.Entry, error) {
	return nil, fmt.Errorf("%w: JSONL 文件后端不支持语义检索", memoryprovider.ErrSearchUnavailable)
}

// append 写一行并落盘。写入失败时内存索引不动,调用方看到的是完整失败。
func (p *Provider) append(r record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("memoryprovider/jsonl: 序列化记录失败: %w", err)
	}
	if _, err := p.file.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("memoryprovider/jsonl: 写 %s 失败: %w", p.path, err)
	}
	return nil
}

func (p *Provider) expired(r record) bool {
	return r.TTL > 0 && p.now().Sub(r.SetAt) >= r.TTL
}

func (r record) entry() memoryprovider.Entry {
	return memoryprovider.Entry{Key: r.Key, Value: r.Value, Scope: r.Scope, TTL: r.TTL}
}

// checkScope 只放行 user scope:跨用户/系统共享不在本实现范围内。
func checkScope(s memoryprovider.Scope) error {
	if !s.Valid() || s != memoryprovider.ScopeUser {
		return memoryprovider.ErrScopeDenied
	}
	return nil
}

func checkKey(k string) error {
	if k == "" || strings.ContainsFunc(k, unicode.IsSpace) {
		return ErrInvalidKey
	}
	return nil
}
