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

// readChainSeed 读 <logPath>.tail 的**第一行**,返回合法的 64 字符小写十六进制
// 哈希;文件不存在 / 内容为空 / 格式非法 → 返回 ""(调用方降级到 GenesisHash)。
//
// 只在活跃文件 size==0 时调用,避免掩盖非空文件的尾部损坏。
func readChainSeed(logPath string) string {
	lines := readTailLines(logPath)
	if len(lines) < 1 {
		return ""
	}
	return validHash(lines[0])
}

// readLastNonTxSeed 读 <logPath>.tail 的**第二行**(上一段最后一条非 tx 记录
// 的 entry_hash);单行旧格式/缺失/非法 → ""。供轮转后空活跃文件的 tx begin
// 播种(tx_prev_hash 必须接上一段最后的非 tx,而非 Genesis)。
func readLastNonTxSeed(logPath string) string {
	lines := readTailLines(logPath)
	if len(lines) < 2 {
		return ""
	}
	return validHash(lines[1])
}

// readTailLines 读 .tail 并按行拆(去尾部空白);读取失败 → nil。
func readTailLines(logPath string) []string {
	data, err := os.ReadFile(TailPath(logPath))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func validHash(s string) string {
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	return s
}
