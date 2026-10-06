//go:build windows

package audit

import (
	"syscall"
	"unsafe"
)

// diskFree 返回指定目录所在卷的可用字节数。
//
// 用 kernel32 的 GetDiskFreeSpaceExW，不引 x/sys：本项目刻意把依赖压到
// "标准库 + yaml"。取的是**调用方可用**的空间（已扣除配额），比总剩余更保守。
func diskFree(path string) (int64, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetDiskFreeSpaceExW")

	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var freeToCaller, totalBytes, totalFree uint64
	r, _, callErr := proc.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&freeToCaller)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r == 0 {
		return 0, callErr
	}
	return int64(freeToCaller), nil
}
