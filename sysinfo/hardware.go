// hardware.go 移植 sysinfo_server.py:58-129 的 hardware_info
// (CPU / 内存 / 磁盘三个部分的读取与聚合)。
package sysinfo

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// DiskUsage 是单个文件系统挂载点的用量(字节),对应 shutil.disk_usage 的三元组。
type DiskUsage struct {
	Total int64 // 总容量 = blocks * frsize
	Used  int64 // 已用 = (blocks - bfree) * frsize
	Free  int64 // 可用 = bavail * frsize(非特权用户实际可得)
}

// DiskUsageFunc 是磁盘用量的注入签名(生产实现见 StatfsDiskUsage)。
type DiskUsageFunc func(path string) (DiskUsage, error)

// StatfsDiskUsage 用 stdlib syscall.Statfs 复刻 shutil.disk_usage:
// Python os.statvfs 的 f_frsize/f_blocks/f_bfree/f_bavail 与
// Statfs_t 的 Frsize/Blocks/Bfree/Bavail 一一对应(Go 无 os.statvfs,
// 这是零新增依赖的等价实现)。
func StatfsDiskUsage(path string) (DiskUsage, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return DiskUsage{}, err
	}
	frsize := int64(st.Frsize)
	total := int64(st.Blocks) * frsize
	used := (int64(st.Blocks) - int64(st.Bfree)) * frsize
	free := int64(st.Bavail) * frsize
	return DiskUsage{Total: total, Used: used, Free: free}, nil
}

// HardwareInfo 移植 sysinfo_server.py:58-129 的 hardware_info:
// 返回 {"cpu": ..., "memory": ..., "disk": ...} 三层结构,
// 各部分缺失/出错时以 {"error": ...} 子字典替代(键名与文案逐字对齐 py;
// 读取异常的消息正文为 OS 原生文本,即 py str(e) 的 Go 等价)。
func (s *Service) HardwareInfo() map[string]any {
	// py:68-72 初始骨架:三部分都是空字典。
	result := map[string]any{
		"cpu":    map[string]any{},
		"memory": map[string]any{},
		"disk":   map[string]any{},
	}

	// —— 1. 从 /proc/cpuinfo 获取 CPU 信息(py:74-94)——
	if cpuPath := s.path("/proc/cpuinfo"); isRegularFile(cpuPath) {
		raw, err := os.ReadFile(cpuPath)
		if err != nil {
			result["cpu"] = map[string]any{"error": err.Error()} // py:91-92
		} else {
			model := ""
			haveModel := false // 对应 py 的 "model_name is None" 判定
			cores := 0
			for _, line := range splitLines(string(raw)) {
				// py:81-86 —— "processor" 前缀计核数;首个含 ":" 的
				// "model name" 行取值,后续行不再覆盖。
				if strings.HasPrefix(line, "processor") {
					cores++
				} else if !haveModel && strings.HasPrefix(line, "model name") {
					if _, rest, ok := strings.Cut(line, ":"); ok {
						model = pyStrip(rest)
						haveModel = true
					}
				}
			}
			// py:88 —— model_name or "Unknown":空串与 None 一样落 "Unknown"。
			if model == "" {
				model = "Unknown"
			}
			result["cpu"] = map[string]any{"model": model, "cores": cores}
		}
	} else {
		result["cpu"] = map[string]any{"error": "/proc/cpuinfo not available"} // py:94
	}

	// —— 2. 从 /proc/meminfo 获取内存信息(py:96-112)——
	if memPath := s.path("/proc/meminfo"); isRegularFile(memPath) {
		raw, err := os.ReadFile(memPath)
		if err != nil {
			result["memory"] = map[string]any{"error": err.Error()} // py:109-110
		} else {
			mem := map[string]any{}
			for _, line := range splitLines(string(raw)) {
				key, val, ok := strings.Cut(line, ":")
				if !ok {
					continue // py:102-103 —— len(parts) != 2 的行跳过
				}
				key, val = pyStrip(key), pyStrip(val)
				// py:106 —— 白名单五键,其余全部过滤。
				switch key {
				case "MemTotal", "MemFree", "MemAvailable", "SwapTotal", "SwapFree":
					mem[key] = val
				}
			}
			result["memory"] = mem
		}
	} else {
		result["memory"] = map[string]any{"error": "/proc/meminfo not available"} // py:112
	}

	// —— 3. "/" 的磁盘使用情况(py:114-127)——
	usage, err := s.disk("/")
	if err != nil {
		result["disk"] = map[string]any{"error": err.Error()} // py:126-127
		return result
	}
	const gib = 1024.0 * 1024.0 * 1024.0
	result["disk"] = map[string]any{
		"path":        "/",
		"total_bytes": usage.Total,
		"used_bytes":  usage.Used,
		"free_bytes":  usage.Free,
		"total_gb":    round2(float64(usage.Total) / gib),
		"used_gb":     round2(float64(usage.Used) / gib),
		"free_gb":     round2(float64(usage.Free) / gib),
	}
	return result
}

// round2 复刻 Python round(x, 2)。CPython 的 round 是对二进制 double 真值
// 做"正确舍入 + ties-to-even"的十进制舍入;先乘 100 再地板判断会被
// 中间浮点误差扭曲(如 2.675*100 恰好落到 267.5 而误判)。Go 的
// strconv.FormatFloat(v,'f',2,64) 正是"对该 double 真值保留 2 位小数、
// 四舍六入五成双"的正确舍入,与其 CPython 语义逐位一致,故借十进制
// 字符串往返实现。
func round2(v float64) float64 {
	r, err := strconv.ParseFloat(strconv.FormatFloat(v, 'f', 2, 64), 64)
	if err != nil {
		// NaN/±Inf 场景 FormatFloat/ParseFloat 可无损往返,理论不可达;
		// 兜底原样返回,绝不 panic。
		return v
	}
	return r
}
