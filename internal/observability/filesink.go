package observability

import (
	"io"
	"sync"
	"sync/atomic"
)

// tolerantWriter never propagates a failure from a secondary sink.
//
// io.MultiWriter stops at the first error, so a log file that fills its disk
// would take the system log down with it. That inverts the priority: the system
// log is the sink an operator is guaranteed to have, and losing it to protect a
// copy is the wrong trade in every case.
//
// So writes here always report success. What actually failed is counted, and
// said once — a line per failed write would itself be the flood.
type tolerantWriter struct {
	w io.Writer

	// mu serializes writes to the underlying file.
	//
	// slog handlers already serialize their own writes, but this writer is
	// reachable from anywhere the logger is, and a torn line in a log is a line
	// nobody can parse.
	mu sync.Mutex

	// reported marks that the failure has been announced.
	reported atomic.Bool

	// dropped counts records this sink lost.
	dropped atomic.Uint64
}

// Write sends the record to the file, reporting success regardless.
func (t *tolerantWriter) Write(p []byte) (int, error) {
	t.mu.Lock()
	_, err := t.w.Write(p)
	t.mu.Unlock()

	if err != nil {
		t.dropped.Add(1)
	}

	// The caller is io.MultiWriter, and telling it the truth would stop it from
	// reaching the sinks after this one. The count is what preserves the truth.
	return len(p), nil
}

// Dropped reports how many records this sink lost.
func (t *tolerantWriter) Dropped() uint64 { return t.dropped.Load() }

// TakeFailure reports a failure once, for a caller that wants to announce it.
//
// It answers true the first time there is something to announce and false
// afterwards, so a caller can put it in a loop without producing the flood this
// type exists to avoid.
func (t *tolerantWriter) TakeFailure() (uint64, bool) {
	dropped := t.dropped.Load()
	if dropped == 0 {
		return 0, false
	}
	if t.reported.Swap(true) {
		return dropped, false
	}
	return dropped, true
}
