package proxy

import (
	"bytes"
	"io"
	"sync"
)

// InjectionReader wraps an io.Reader to inject content into HTML stream
type InjectionReader struct {
	reader       io.Reader
	injection    []byte
	injected     bool
	buffer       []byte
	bufLen       int
	match        []byte
	matchLen     int
	foundMatch   bool
	bytesRead    int64
	maxScanBytes int64 // Don't scan forever, give up after X bytes
}

var (
	headTag = []byte("<head>")
	// Use a reasonable buffer size for scanning (must be larger than match tag)
	scanBufferSize = 4096
	// Stop scanning after 64KB (if <head> isn't in first 64KB, likely not valid HTML or weird structure)
	defaultMaxScanBytes = int64(64 * 1024)
)

// NewInjectionReader creates a reader that injects content after the first occurrence of <head>
func NewInjectionReader(r io.Reader, content []byte) *InjectionReader {
	return &InjectionReader{
		reader:       r,
		injection:    content,
		match:        headTag,
		matchLen:     len(headTag),
		buffer:       make([]byte, 0, scanBufferSize),
		maxScanBytes: defaultMaxScanBytes,
	}
}

func (r *InjectionReader) Read(p []byte) (n int, err error) {
	// If already injected or gave up scanning, just pass through
	if r.injected || (r.bytesRead > r.maxScanBytes && !r.foundMatch) {
		// Flush any remaining buffer first
		if len(r.buffer) > 0 {
			n = copy(p, r.buffer)
			r.buffer = r.buffer[n:]
			return n, nil
		}
		return r.reader.Read(p)
	}

	// Read into internal buffer to scan
	// We need enough data to match
	if len(r.buffer) < r.matchLen {
		tempBuf := make([]byte, len(p))
		readN, readErr := r.reader.Read(tempBuf)
		if readN > 0 {
			r.buffer = append(r.buffer, tempBuf[:readN]...)
			r.bytesRead += int64(readN)
		}
		if readErr != nil {
			if readErr == io.EOF && len(r.buffer) > 0 {
				// We hit EOF but have data in buffer, process it
				err = nil // Clear EOF for now, will return it next call
			} else {
				// Real error or empty buffer EOF
				return readN, readErr
			}
		}
	}

	// Check for match
	idx := bytes.Index(r.buffer, r.match)
	if idx != -1 {
		// Found <head>!
		r.foundMatch = true
		r.injected = true

		// Construct the output: part before match + match + injection + part after match
		// Actually, we replace "<head>" with "<head>INJECTION"
		
		// Copy up to end of match
		endOfMatch := idx + r.matchLen
		
		// We have to be careful not to overflow p
		// Strategy: Create a composed buffer of everything we want to send, then copy to p
		// Since Read contract allows short reads, we can return what fits
		
		var output bytes.Buffer
		output.Write(r.buffer[:endOfMatch])
		output.Write(r.injection)
		output.Write(r.buffer[endOfMatch:])
		
		// Replace internal buffer with the composed result
		r.buffer = output.Bytes()
	}

	// If buffer is getting full and no match, flush some of it to make space/progress
	// But keep enough bytes to handle a split match (matchLen - 1)
	if len(r.buffer) > scanBufferSize && !r.foundMatch {
		toFlush := len(r.buffer) - r.matchLen
		n = copy(p, r.buffer[:toFlush])
		r.buffer = r.buffer[n:]
		return n, nil
	}
	
	// If we successfully injected (or just flushing buffer), copy to p
	if len(r.buffer) > 0 {
		n = copy(p, r.buffer)
		r.buffer = r.buffer[n:]
		return n, nil
	}

	return 0, io.EOF
}

// scriptInjectionCache stores pre-generated script tags
var (
	scriptInjectionCache sync.Map
)

func GetInjectionScript(path string) []byte {
	if val, ok := scriptInjectionCache.Load(path); ok {
		return val.([]byte)
	}
	
	// Default script tag
	script := []byte(`<script src="` + path + `" async></script>`)
	scriptInjectionCache.Store(path, script)
	return script
}
