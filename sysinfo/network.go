// network.go 移植 sysinfo_server.py 的 network_status
// (`ip -j addr show` → `ip addr show` → /proc/net/dev 三级回退)。
package sysinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// NetworkStatus 移植 sysinfo_server.py 的 network_status。
// 三级回退顺序与 py 逐条一致;返回键名 interfaces / raw_output / error
// 与 py 完全相同。
func (s *Service) NetworkStatus(ctx context.Context) map[string]any {
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	// py 的外层 try/except 把"命令无法启动"与"JSON 解析失败"都吞掉转入下一级。
	stdout, _, code, execErr := s.exec(ctx, "ip", []string{"-j", "addr", "show"})
	if execErr == nil && code == 0 && stdout != "" {
		var parsed any
		if json.Unmarshal([]byte(stdout), &parsed) == nil {
			return map[string]any{"interfaces": parsed}
		}
	}

	stdout, _, code, execErr = s.exec(ctx, "ip", []string{"addr", "show"})
	if execErr == nil && code == 0 && stdout != "" {
		return map[string]any{"raw_output": pyStrip(stdout)}
	}

	if devPath := s.path("/proc/net/dev"); isRegularFile(devPath) {
		raw, err := os.ReadFile(devPath)
		if err != nil {
			// f"Failed reading /proc/net/dev: {e}" 的 Go 等价外壳。
			return map[string]any{"error": fmt.Sprintf("Failed reading /proc/net/dev: %v", err)}
		}
		if parsed, err := parseNetDev(string(raw)); err != nil {
			return map[string]any{"error": fmt.Sprintf("Failed reading /proc/net/dev: %v", err)}
		} else {
			return map[string]any{"interfaces": parsed}
		}
	}

	return map[string]any{"error": "Unable to determine network status"}
}

// parseNetDev 移植 sysinfo_server.py 的 /proc/net/dev 解析:
// 跳过前两行表头,按首个 ":" 拆接口名与统计列,取 rx_bytes=stats[0]、
// tx_bytes=stats[8](列数不足时以 0 兜底,对应 py 的 len(stats) 守卫);
// 整数解析失败向上抛错,由调用方转为同款 error 字典。
func parseNetDev(data string) (map[string]any, error) {
	interfaces := map[string]any{}
	lines := splitLines(data)
	// lines[2:] 切片对不足两行的文件天然为空,Go 显式守卫。
	if len(lines) <= 2 {
		return interfaces, nil
	}
	for _, line := range lines[2:] {
		line = pyStrip(line)
		if line == "" {
			continue
		}
		iface, statsStr, ok := strings.Cut(line, ":") // split(":", 1)
		if !ok {
			continue
		}
		stats := strings.Fields(statsStr) // split() 任意空白分割
		entry := map[string]any{"rx_bytes": int64(0), "tx_bytes": int64(0)}
		if len(stats) > 0 {
			v, err := strconv.ParseInt(stats[0], 10, 64)
			if err != nil {
				// int(stats[0]) 抛 ValueError 的 Go 等价错误。
				return nil, fmt.Errorf("invalid stats value %q: %v", stats[0], err)
			}
			entry["rx_bytes"] = v
		}
		if len(stats) > 8 {
			v, err := strconv.ParseInt(stats[8], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid stats value %q: %v", stats[8], err)
			}
			entry["tx_bytes"] = v
		}
		interfaces[pyStrip(iface)] = entry
	}
	return interfaces, nil
}
