package engine

import (
	"io"
	"sync/atomic"
)

// StreamCounter wraps an io.Reader, counting bytes and firing a one-time
// callback when a threshold is exceeded.
type StreamCounter struct {
	reader      io.Reader
	count       atomic.Int64
	threshold   int64
	onThreshold func(int64)
	triggered   atomic.Bool
}

// NewStreamCounter creates a StreamCounter.
func NewStreamCounter(reader io.Reader, threshold int64, onThreshold func(int64)) *StreamCounter {
	return &StreamCounter{
		reader:      reader,
		threshold:   threshold,
		onThreshold: onThreshold,
	}
}

// Read reads from the underlying reader and tracks byte count.
func (sc *StreamCounter) Read(p []byte) (int, error) {
	n, err := sc.reader.Read(p)
	if n > 0 {
		total := sc.count.Add(int64(n))
		if total >= sc.threshold && !sc.triggered.Load() {
			if sc.triggered.CompareAndSwap(false, true) {
				go sc.onThreshold(total)
			}
		}
	}
	return n, err
}

// BytesRead returns the total bytes read so far.
func (sc *StreamCounter) BytesRead() int64 {
	return sc.count.Load()
}
