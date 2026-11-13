// Package jsonl 是 MemoryProvider 的 JSONL 文件后端(swappability=L1)。
//
// 落盘 = 一行一条 JSON、纯追加;删除写墓碑,不在原地改文件。开库时重放成内存
// 索引并顺手压缩(墓碑 / 过期 / 半截尾行一并折叠掉),崩溃只可能损坏最后一行。
// 语义边界见 README:只服务 ScopeUser、Search 恒不可用、每文件单实例。
package jsonl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// ErrInvalidValue 表示值不是合法 JSON:空值(或半截 JSON)写进去,下次重放就会
// 变成一条读不出来的记录 —— 在写入口拒掉比留一颗定时炸弹好。
var ErrInvalidValue = errors.New("memoryprovider/jsonl: 记忆值必须是合法 JSON")

// Options 是构造开关。Now 供测试注入时钟,生产留空即用 time.Now。
type Options struct {
	Now func() time.Time
}

// record 是落盘的一行。Deleted 为真时是墓碑,Value 无意义。
type record struct {
	Key     string               `json:"key"`
	Value   json.RawMessage      `json:"value"`
	Scope   memoryprovider.Scope `json:"scope"`
	TTL     time.Duration        `json:"ttl_ns,omitempty"`
	SetAt   time.Time            `json:"set_at"`
	Deleted bool                 `json:"deleted,omitempty"`
}

// Provider 是 JSONL 文件后端。
//
// 并发:同实例内串行化写入。**每文件单实例** —— 索引是 per-instance 的,
// 同一路径开两个实例会各持一份旧索引(没有跨进程/跨实例锁)。
//
// 持久性边界:写操作不 fsync。进程崩溃(含被 SIGKILL)最多损坏最后一行,
// 下次开库会把它折掉;机器掉电可能丢掉 page cache 里尚未回写的若干行。
// 需要"返回 nil 即已落盘"的调用方请显式 Close(它会 Sync)。
type Provider struct {
	path string
	now  func() time.Time

	mu      sync.Mutex
	file    *os.File
	entries map[string]record // scope\x00key → 最新记录
}

var _ memoryprovider.Provider = (*Provider)(nil)

// New 打开(不存在则创建)path 并重放成内存索引;需要时顺手压缩文件。
func New(path string, opts Options) (*Provider, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	p := &Provider{path: path, now: now, entries: map[string]record{}}
	if err := p.load(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("memoryprovider/jsonl: 打开 %s 失败: %w", path, err)
	}
	p.file = f
	return p, nil
}

// load 重放文件并决定是否压缩。
func (p *Provider) load() error {
	recs, truncated, err := readRecords(p.path)
	if err != nil {
		return err
	}
	for _, r := range recs {
		k := indexKey(r.Scope, r.Key)
		if r.Deleted {
			delete(p.entries, k)
			continue
		}
		if p.expired(r) {
			// 后写的记录覆盖先写的:这条已过期 ⇒ 这个键现在不存在。
			delete(p.entries, k)
			continue
		}
		p.entries[k] = r
	}
	// 压缩条件:尾部有半截写,或落盘行数与存活条数不一致(墓碑 / 过期 / 重复 Set)。
	if truncated || len(recs) != len(p.entries) {
		return p.rewrite()
	}
	return nil
}

// readRecords 只容忍**最后一行**不完整(写到一半被杀 / 掉电):那是追加式写入
// 唯一可能损坏的位置。中间行损坏一律 fail-closed —— 静默跳过等于把「文件被
// 改坏」伪装成「记忆自己丢了」。
func readRecords(path string) ([]record, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("memoryprovider/jsonl: 读取 %s 失败: %w", path, err)
	}
	lines := strings.Split(string(raw), "\n")
	last := -1
	for i, ln := range lines {
		if strings.TrimSpace(ln) != "" {
			last = i
		}
	}
	var out []record
	for i, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var r record
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			if i == last {
				return out, true, nil
			}
			return nil, false, fmt.Errorf("memoryprovider/jsonl: %s 第 %d 行损坏: %w", path, i+1, err)
		}
		out = append(out, r)
	}
	return out, false, nil
}

// rewrite 把存活记录写成新文件再原子替换。调用方已持有 p.mu 或尚未共享 p。
func (p *Provider) rewrite() error {
	tmp, err := os.CreateTemp(filepath.Dir(p.path), ".memory-*.tmp")
	if err != nil {
		return fmt.Errorf("memoryprovider/jsonl: 建临时文件失败: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name) // rename 成功后这次删除失败,忽略
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("memoryprovider/jsonl: 设置临时文件权限失败: %w", err)
	}
	w := bufio.NewWriter(tmp)
	keys := make([]string, 0, len(p.entries))
	for k := range p.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b, err := json.Marshal(p.entries[k])
		if err != nil {
			tmp.Close()
			return fmt.Errorf("memoryprovider/jsonl: 序列化记录失败: %w", err)
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			tmp.Close()
			return fmt.Errorf("memoryprovider/jsonl: 写临时文件失败: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		return fmt.Errorf("memoryprovider/jsonl: flush 临时文件失败: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("memoryprovider/jsonl: sync 临时文件失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("memoryprovider/jsonl: 关闭临时文件失败: %w", err)
	}
	if err := os.Rename(name, p.path); err != nil {
		return fmt.Errorf("memoryprovider/jsonl: 替换 %s 失败: %w", p.path, err)
	}
	return nil
}

// Close 落盘并释放 fd。可重复调用。关闭后再写会报错。
func (p *Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file == nil {
		return nil
	}
	err := p.file.Sync()
	if cerr := p.file.Close(); err == nil {
		err = cerr
	}
	p.file = nil
	return err
}

func indexKey(scope memoryprovider.Scope, key string) string {
	return string(scope) + "\x00" + key
}

// Swappability 声明替换上限:内置文件后端是 L1(重启时替换实现)。
func (p *Provider) Swappability() slot.Level { return slot.LevelRestart }

// Get 按 scope+key 取一条;不存在或已过期都回 ErrKeyNotFound。
// 返回的 Entry.TTL 是**写入时设定的原值**,不是剩余寿命。
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
	if !json.Valid(e.Value) {
		return ErrInvalidValue
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

// Delete 写墓碑;不存在或已过期回 ErrKeyNotFound(与 Get 同口径)。
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
		if r.Scope != scope || p.expired(r) || !strings.HasPrefix(r.Key, prefix) {
			continue
		}
		keys = append(keys, r.Key)
	}
	sort.Strings(keys)
	return keys, nil
}

// Search 恒回 ErrSearchUnavailable:本后端没有语义检索,空结果不等于没命中。
func (p *Provider) Search(_ context.Context, _ string, _ int) ([]memoryprovider.Entry, error) {
	return nil, fmt.Errorf("%w: JSONL 文件后端不支持语义检索", memoryprovider.ErrSearchUnavailable)
}

// append 写一行。写入失败时内存索引不动,调用方看到的是完整失败。
func (p *Provider) append(r record) error {
	if p.file == nil {
		return errors.New("memoryprovider/jsonl: provider 已关闭")
	}
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
