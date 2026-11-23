package pending

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// ArgvSHA256 是「被批准的是哪条 argv」的规范指纹:逐元素用 NUL 连接后取 sha256。
//
// 分隔符必须是不可能出现在 argv 里的字节:用空格连接会让 ["a b"] 与 ["a","b"]
// 撞成一个指纹,批准就绑到了另一条命令上。NUL 进不了 argv 元素(解析期已拒),
// 所以这里的连接是单射的。
func ArgvSHA256(argv []string) string {
	sum := sha256.Sum256([]byte(strings.Join(argv, "\x00")))
	return hex.EncodeToString(sum[:])
}
