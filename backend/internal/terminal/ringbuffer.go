package terminal

import "sync"

// RingBuffer holds the most recent output of a session so a reattaching browser
// can be shown what it missed.
//
// This is what makes session persistence real rather than cosmetic (ADR 0004).
// Reload the page mid-`apt upgrade` and the output produced while the socket was
// down is replayed, once, in order.
//
// Absolute byte offsets ("sequence numbers") are the mechanism: the buffer counts
// every byte ever written, so a client that still holds part of the stream asks
// for the delta from its own offset instead of re-rendering everything. When the
// gap is larger than the buffer, the client is told so and the display is reset
// rather than being silently spliced together with a hole in it.
type RingBuffer struct {
	mu     sync.Mutex
	buf    []byte
	size   int
	start  int    // index in buf of the oldest retained byte
	length int    // retained bytes
	seq    uint64 // total bytes ever written
}

// NewRingBuffer creates a buffer of the given size in bytes.
func NewRingBuffer(size int) *RingBuffer {
	if size < 4096 {
		size = 4096
	}
	return &RingBuffer{buf: make([]byte, size), size: size}
}

// Write appends output, discarding the oldest bytes when full.
func (r *RingBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if n == 0 {
		return 0, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.seq += uint64(n)

	// A single write larger than the buffer: only its tail can be retained.
	if n >= r.size {
		copy(r.buf, p[n-r.size:])
		r.start = 0
		r.length = r.size
		return n, nil
	}

	end := (r.start + r.length) % r.size
	written := copy(r.buf[end:], p)
	if written < n {
		copy(r.buf, p[written:])
	}

	if r.length+n > r.size {
		overflow := r.length + n - r.size
		r.start = (r.start + overflow) % r.size
		r.length = r.size
	} else {
		r.length += n
	}
	return n, nil
}

// Seq returns the total number of bytes ever written.
func (r *RingBuffer) Seq() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seq
}

// Since returns the bytes written after absolute offset from.
//
// gap reports that some output between from and what is still retained has been
// discarded. The caller must then tell the client to clear its display: appending
// to a partial screen after a hole produces corrupted output that looks like a
// terminal bug rather than a missing chunk.
func (r *RingBuffer) Since(from uint64) (data []byte, seq uint64, gap bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if from >= r.seq {
		// Caller is current, or ahead of us after a session restart.
		return nil, r.seq, false
	}

	oldest := r.seq - uint64(r.length)
	if from < oldest {
		from = oldest
		gap = true
	}

	skip := int(from - oldest)
	out := make([]byte, r.length-skip)
	if len(out) == 0 {
		return nil, r.seq, gap
	}

	idx := (r.start + skip) % r.size
	written := copy(out, r.buf[idx:])
	if written < len(out) {
		copy(out[written:], r.buf)
	}
	return out, r.seq, gap
}

// Snapshot returns everything currently retained.
func (r *RingBuffer) Snapshot() (data []byte, seq uint64) {
	data, seq, _ = r.Since(0)
	return data, seq
}

// Len returns how many bytes are retained.
func (r *RingBuffer) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.length
}

// Reset clears the buffer without resetting the sequence counter, so clients can
// still tell that a discontinuity happened.
func (r *RingBuffer) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.start = 0
	r.length = 0
}
