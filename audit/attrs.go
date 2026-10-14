package audit

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// ErrAttrsUnsupported 表示当前 fs 不支持 append-only attrs(例如 tmpfs /
// 某些容器 overlay)。调用方应走 best-effort 路径(允许 rename / 接受窗口),
// 不要把这条 err 当致命失败。
var ErrAttrsUnsupported = errors.New("audit: append-only attribute not supported on this filesystem")

// fsAppendFL 是 ext4/xfs 等 Linux fs 的 FS_APPEND_FL 位掩码(linux/fs.h)。
// x/sys/unix 未导出该常量(与 arch 无关,使用裸值);SDK 依赖此位做轮转时的
// append-only 切换。内核 ABI 稳定,变更风险低。
const fsAppendFL = 0x20

// AppendOnlyOps 是 chattr +a 的可注入抽象。默认实现 xattrOps 用 FS_IOC_*;
// 测试可注入 fake 来免 root。
type AppendOnlyOps interface {
	// HasAppend 报告 path 上是否置了 FS_APPEND_FL。
	// 探测期间发现 fs 不支持 → 返回 (false, ErrAttrsUnsupported)。
	HasAppend(path string) (bool, error)
	// ClearAppend 清除 FS_APPEND_FL;权限不足 → 返回 os.ErrPermission 包裹的错。
	ClearAppend(path string) error
	// SetAppend 设置 FS_APPEND_FL。
	SetAppend(path string) error
}

// xattrOps 是默认实现,使用 x/sys/unix 的 FS_IOC_GETFLAGS / FS_IOC_SETFLAGS
// 直接走内核 ioctl,不依赖 chattr / lsattr shell 工具。
type xattrOps struct{}

func (xattrOps) HasAppend(p string) (bool, error) {
	f, err := os.Open(p)
	if err != nil {
		return false, err
	}
	defer f.Close()
	flags, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		// 内核回报"非字符设备"或"不支持"即视为 fs 不支持 attrs。
		if errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS) {
			return false, ErrAttrsUnsupported
		}
		return false, err
	}
	return flags&fsAppendFL != 0, nil
}

func (xattrOps) ClearAppend(p string) error {
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	flags, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return err
	}
	return unix.IoctlSetInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, flags&^fsAppendFL)
}

func (xattrOps) SetAppend(p string) error {
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	flags, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return err
	}
	return unix.IoctlSetInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, flags|fsAppendFL)
}

// appendOnlyOps 是当前生效的实现(包级单例);SetAppendOnlyOps 替换。
// 并发不安全,仅启动期调用。
var appendOnlyOps AppendOnlyOps = xattrOps{}

// SetAppendOnlyOps 注入自定义实现(测试用);传 nil 不被允许。
func SetAppendOnlyOps(ops AppendOnlyOps) { appendOnlyOps = ops }

// CurrentAppendOnlyOps 返回当前实例(rotate 调用)。
func CurrentAppendOnlyOps() AppendOnlyOps { return appendOnlyOps }
