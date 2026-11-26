//go:build !linux

package engine

// ReserveOutputPorts is a no-op outside Linux.
func ReserveOutputPorts(ports []int) error { return nil }
