//go:build !windows

package audit

import "syscall"

// diskFree 返回指定目录所在文件系统的可用字节数（Bavail 是非特权用户可用块数）。
func diskFree(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
