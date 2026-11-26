//go:build linux

package engine

import "os"

// ReserveOutputPorts stops Linux from picking the output ports as source
// ports of outgoing connections (net.ipv4.ip_local_reserved_ports). Without
// it a port closed for a while (or not yet open at startup) can be taken by
// an outgoing connection, and reopening it fails with "address already in
// use". Explicit binds to a reserved port still work.
func ReserveOutputPorts(ports []int) error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_local_reserved_ports", []byte(PortRanges(ports)+"\n"), 0o644)
}
