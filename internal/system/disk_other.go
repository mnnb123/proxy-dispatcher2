//go:build !linux && !darwin && !freebsd

package system

func readDiskInfo() (int64, int64) { return 0, 0 }
