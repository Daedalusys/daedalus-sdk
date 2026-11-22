package pending

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// idPattern 是待办 id 的形状门。id 会从命令行来、会被拼进文件路径,
// 所以只允许安全文件名字符,且首字符不能是点(堵掉 . / .. 一类相对路径记号)。
var idPattern = regexp.MustCompile(`^p-[A-Za-z0-9][A-Za-z0-9._-]*$`)

// DeriveID 由意图 + 执行者 uid 派生待办 id。
//
// 确定性是这套机制能闭合的原因:AI 第二次对同一意图调用时不需要记住上次的 id,
// 就能找到人批准的那一条;改动任何参数都会得到新 id,也就没有可用的批准。
//
// 执行者必须并进派生输入:两个用户的助手对同一意图会撞同一个 id,于是 root 批一份,
// 两个人的 agent 都能用;带上执行者,批准才只对一个人成立。
//
// 连接顺序与取前 8 字节是跨仓契约 —— 消费侧已经按它发过 id,改了会让历史批准
// 全部对不上,只能改派生算法以外的部分。
func DeriveID(kind, unit, desiredState, scope string, executorUID uint32) string {
	intent := strings.Join([]string{
		kind, unit, desiredState, scope, strconv.FormatUint(uint64(executorUID), 10),
	}, "\x00")
	sum := sha256.Sum256([]byte(intent))
	return "p-" + hex.EncodeToString(sum[:8])
}

// ValidateID 是待办 id 的形状门:命令行参数触碰任何路径之前先过这道门。
func ValidateID(id string) error {
	if id == "" {
		return fmt.Errorf("待办 id 为空")
	}
	if !idPattern.MatchString(id) {
		return fmt.Errorf("待办 id %q 非法(需匹配 %s)", id, idPattern)
	}
	return nil
}
