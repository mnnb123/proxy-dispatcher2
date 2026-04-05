package engine

import (
	"bufio"
	"net"
	"time"
)

// BufferedConn wraps a net.Conn with a bufio.Reader so peeked bytes are
// not lost to subsequent Reads.
type BufferedConn struct {
	reader *bufio.Reader
	net.Conn
}

// Read reads from the buffered reader to preserve peeked data.
func (b *BufferedConn) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

// DetectProtocol peeks one byte from the connection without consuming it
// and classifies the protocol as "socks5", "http" or "unknown".
func DetectProtocol(conn net.Conn) (string, *BufferedConn, error) {
	reader := bufio.NewReaderSize(conn, 4096)
	buffConn := &BufferedConn{reader: reader, Conn: conn}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	b, err := reader.Peek(1)
	if err != nil {
		return "unknown", buffConn, err
	}

	first := b[0]
	switch {
	case first == 0x05:
		return "socks5", buffConn, nil
	case first >= 0x20 && first <= 0x7E:
		return "http", buffConn, nil
	default:
		return "unknown", buffConn, nil
	}
}
