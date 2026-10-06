//go:build !windows

package profile

// detectMemoryLimitPlatform 在非 Windows 平台没有额外的兜底来源：
// Linux 已经由 cgroup 与 /proc/meminfo 覆盖，其它平台靠 GOMEMLIMIT 环境变量。
func detectMemoryLimitPlatform() (int64, string, bool) {
	return 0, "", false
}
