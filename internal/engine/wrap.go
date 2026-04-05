package engine

import "bufio"

// WrapPrefixAsBuffered wraps a PrefixConn into a BufferedConn so handlers
// that expect *BufferedConn can work with replayed bytes.
func WrapPrefixAsBuffered(pc *PrefixConn) *BufferedConn {
	return &BufferedConn{
		reader: bufio.NewReaderSize(pc, 4096),
		Conn:   pc,
	}
}
