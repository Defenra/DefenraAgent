package proxy

import (
	"bufio"
	"net"
	"net/http"
	"sync"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024) // 32KB buffer
		return &b
	},
}

// GetBuffer returns a buffer from the pool
func GetBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// PutBuffer returns a buffer to the pool
func PutBuffer(b *[]byte) {
	bufferPool.Put(b)
}

// CountingWriter wraps http.ResponseWriter to count bytes written
type CountingWriter struct {
	http.ResponseWriter
	BytesWritten int64
	StatusCode   int
}

func NewCountingWriter(w http.ResponseWriter) *CountingWriter {
	return &CountingWriter{
		ResponseWriter: w,
		StatusCode:     http.StatusOK, // Default status
	}
}

func (w *CountingWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.BytesWritten += int64(n)
	return n, err
}

func (w *CountingWriter) WriteHeader(statusCode int) {
	w.StatusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// Flush implements http.Flusher
func (w *CountingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker
func (w *CountingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Push implements http.Pusher
func (w *CountingWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}
