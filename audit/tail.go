package audit

// tail.go —— 轮转播种:活跃文件为空时从 <logPath>.tail 取上一段尾哈希。
//
// 设计动机:哈希链的 prev_hash 只在单个文件内回溯。轮转把旧文件 rename 走后,
// 新活跃文件为空,lastEntryHash 会返回 GenesisHash,链即断。`rotate` 在把活跃
// 文件变空之前,先把上一段尾哈希原子写入 <logPath>.tail;LogAudit 在 size==0
// 时读它播种(见 audit.go)。路径可由 LogPath 推出,写者无需读 policy。

import (
	"encoding/hex"
	"os"
	"strings"
)

// TailPath 返回活跃文件对应的 .tail 路径:与 LogPath 同目录,后缀 + ".tail"。
func TailPath(logPath string) string { return logPath + ".tail" }

// readChainSeed 读 <logPath>.tail,返回合法的 64 字符小写十六进制哈希;
// 文件不存在 / 内容为空 / 格式非法 → 返回 ""(调用方降级到 GenesisHash)。
//
// 只在活跃文件 size==0 时调用,避免掩盖非空文件的尾部损坏。
func readChainSeed(logPath string) string {
	data, err := os.ReadFile(TailPath(logPath))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(data))
	if len(s) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	return s
}
