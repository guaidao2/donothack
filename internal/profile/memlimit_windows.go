//go:build windows

package profile

import (
	"syscall"
	"unsafe"
)

// memoryStatusEx 对应 Win32 的 MEMORYSTATUSEX。
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// detectMemoryLimitPlatform 在 Windows 上读物理内存总量。
//
// 只调 kernel32，不引 x/sys：本项目刻意把依赖压到"标准库 + yaml"。
// 注意这是**整机物理内存**，不是 cgroup 限额 —— 所以来源字符串必须写清楚，
// 免得有人以为它等于容器的内存上限。
func detectMemoryLimitPlatform() (int64, string, bool) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GlobalMemoryStatusEx")

	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(&ms)))
	if r == 0 || ms.TotalPhys == 0 {
		return 0, "", false
	}
	return int64(ms.TotalPhys), "windows GlobalMemoryStatusEx（整机物理内存）", true
}
