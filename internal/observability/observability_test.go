package observability

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Without a file, the logger writes to the supervisor's stream alone.
func TestWithoutAFileEverythingGoesToTheSystemLog(t *testing.T) {
	var stderr bytes.Buffer

	log, closer, err := New(Options{Level: slog.LevelInfo, Format: FormatJSON}, &stderr)
	if err != nil {
		t.Fatalf("building the logger: %v", err)
	}
	defer func() { _ = closer.Close() }()

	log.Info("hello", slog.String("event", "test"))

	if !strings.Contains(stderr.String(), `"event":"test"`) {
		t.Errorf("the system log did not receive the record: %q", stderr.String())
	}
}

// A configured file receives a copy, and the system log still receives it.
//
// The copy is the whole point of the second sink: an operator who configured a
// file and finds it empty while the journal has the records has a sink that
// exists and does nothing.
func TestAConfiguredFileGetsACopyOfEveryRecord(t *testing.T) {
	var stderr bytes.Buffer
	path := filepath.Join(t.TempDir(), "nostmesh.log")

	log, closer, err := New(Options{Level: slog.LevelInfo, Format: FormatJSON, FilePath: path}, &stderr)
	if err != nil {
		t.Fatalf("building the logger: %v", err)
	}

	log.Info("hello", slog.String("event", "test"))

	if err := closer.Close(); err != nil {
		t.Fatalf("closing the file: %v", err)
	}

	written, err := os.ReadFile(path) //nolint:gosec // path is the test's own temporary directory
	if err != nil {
		t.Fatalf("reading the log file: %v", err)
	}

	if !strings.Contains(string(written), `"event":"test"`) {
		t.Errorf("the file did not receive the record: %q", written)
	}
	if !strings.Contains(stderr.String(), `"event":"test"`) {
		t.Errorf("the system log stopped receiving records once a file was configured: %q", stderr.String())
	}
}

// The file is created readable only by the user that wrote it.
//
// A log carries endpoints, peer identifiers and, under the diagnostic gate,
// addresses. The unit's UMask already forces this, but a umask only removes
// permissions and the binary also runs without systemd.
func TestTheLogFileIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nostmesh.log")

	_, closer, err := New(Options{Level: slog.LevelInfo, Format: FormatJSON, FilePath: path}, io.Discard)
	if err != nil {
		t.Fatalf("building the logger: %v", err)
	}
	defer func() { _ = closer.Close() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if mode := info.Mode().Perm(); mode != fileMode {
		t.Errorf("log file mode is %#o, want %#o", mode, fileMode)
	}
}

// A file that cannot be opened stops the caller rather than degrading quietly.
func TestAnUnopenableFileIsReported(t *testing.T) {
	// A path under a file rather than a directory cannot be created.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("preparing: %v", err)
	}

	_, _, err := New(Options{
		Level: slog.LevelInfo, Format: FormatJSON,
		FilePath: filepath.Join(blocker, "nostmesh.log"),
	}, io.Discard)

	if err == nil {
		t.Fatal("a log file that cannot be opened was accepted")
	}
	if !strings.Contains(err.Error(), "nostmesh.log") {
		t.Errorf("the error does not name the path, which is the one thing the operator needs: %v", err)
	}
}

// Appending is what makes a restart keep the previous log.
func TestReopeningAppendsRatherThanTruncating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nostmesh.log")

	for _, message := range []string{"first", "second"} {
		log, closer, err := New(Options{Level: slog.LevelInfo, Format: FormatJSON, FilePath: path}, io.Discard)
		if err != nil {
			t.Fatalf("building the logger: %v", err)
		}
		log.Info(message, slog.String("event", "test"))
		if err := closer.Close(); err != nil {
			t.Fatalf("closing: %v", err)
		}
	}

	written, err := os.ReadFile(path) //nolint:gosec // path is the test's own temporary directory
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	if !strings.Contains(string(written), "first") {
		t.Error("reopening the log truncated what was already there")
	}
	if !strings.Contains(string(written), "second") {
		t.Error("the second run did not reach the file")
	}
}

// The level filters both sinks identically.
func TestTheLevelAppliesToBothSinks(t *testing.T) {
	var stderr bytes.Buffer
	path := filepath.Join(t.TempDir(), "nostmesh.log")

	log, closer, err := New(Options{Level: slog.LevelInfo, Format: FormatJSON, FilePath: path}, &stderr)
	if err != nil {
		t.Fatalf("building the logger: %v", err)
	}

	log.Debug("quiet", slog.String("event", "debug.record"))

	if err := closer.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	written, err := os.ReadFile(path) //nolint:gosec // path is the test's own temporary directory
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	if strings.Contains(string(written), "debug.record") {
		t.Error("a debug record reached the file with the level at info")
	}
	if strings.Contains(stderr.String(), "debug.record") {
		t.Error("a debug record reached the system log with the level at info")
	}
}

// Component tags a line with the layer that emitted it.
func TestComponentTagsTheEmitter(t *testing.T) {
	var stderr bytes.Buffer

	log, closer, err := New(Options{Level: slog.LevelInfo, Format: FormatJSON}, &stderr)
	if err != nil {
		t.Fatalf("building the logger: %v", err)
	}
	defer func() { _ = closer.Close() }()

	Component(log, ComponentNostr).Info("connected", slog.String("event", "relay.connected"))

	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stderr.Bytes()), &record); err != nil {
		t.Fatalf("the record is not valid JSON: %v", err)
	}
	if record["component"] != ComponentNostr {
		t.Errorf("component is %v, want %q", record["component"], ComponentNostr)
	}
}

// A nil logger yields a discard logger rather than a panic.
//
// Every constructor takes an optional logger, so the nil case is the ordinary
// one for a package nobody wired up, not an error.
func TestComponentToleratesANilLogger(t *testing.T) {
	Component(nil, ComponentSession).Info("this must not panic")
}

// Discard drops records without a sink.
func TestDiscardEmitsNothing(t *testing.T) {
	if Discard().Enabled(t.Context(), slog.LevelError) {
		t.Error("the discard logger reports itself enabled, so callers will build arguments for nothing")
	}
}

// An unrecognised level takes the default rather than silencing the node.
func TestAnUnknownLevelFallsBackToInfo(t *testing.T) {
	for _, name := range []string{"", "verbose", "TRACE", "nonsense"} {
		if got := ParseLevel(name); got != slog.LevelInfo {
			t.Errorf("ParseLevel(%q) = %v, want info", name, got)
		}
	}
}

func TestKnownLevelsParse(t *testing.T) {
	for name, want := range map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"DEBUG":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
	} {
		if got := ParseLevel(name); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", name, got, want)
		}
	}
}

// A failing file must not take any other sink down with it.
//
// io.MultiWriter writes in order and returns at the first error, so a sink that
// fails silences every sink after it. Today the system log happens to be written
// first, which means an unwrapped file would look fine — the guard has to test
// the property rather than the current argument order, because the ordering is
// exactly what a later change would break without noticing.
//
// So the assertion is made on the wrapper New actually installs: a sink placed
// after it receives the record only because the failure was absorbed.
func TestAFailingFileDoesNotSilenceASinkAfterIt(t *testing.T) {
	var later bytes.Buffer

	// A real file, closed behind the logger's back so that every write fails
	// with a genuine os.File error. Filling a disk is the true cause and is not
	// something a test can arrange; this is the closest reproducible stand-in.
	path := filepath.Join(t.TempDir(), "nostmesh.log")
	file, err := openLogFile(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	log := slog.New(slog.NewJSONHandler(io.MultiWriter(
		&tolerantWriter{w: file}, &later,
	), nil))
	log.Info("hello", slog.String("event", "after.failure"))

	if !strings.Contains(later.String(), `"event":"after.failure"`) {
		t.Errorf("a failing file silenced the sink after it: %q", later.String())
	}
}

// New installs the wrapper, rather than handing the file over unprotected.
//
// The guard above proves the wrapper works; this proves it is used. Separating
// them is deliberate: a correct wrapper that nothing installs protects nothing,
// and that is the failure a single test would miss.
func TestNewWrapsTheFileSink(t *testing.T) {
	var stderr bytes.Buffer
	path := filepath.Join(t.TempDir(), "nostmesh.log")

	log, closer, err := New(Options{Level: slog.LevelInfo, Format: FormatJSON, FilePath: path}, &stderr)
	if err != nil {
		t.Fatalf("building the logger: %v", err)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	// With the file closed, an unwrapped sink returns an error to the handler.
	// slog reports a handler error through its own error path rather than
	// panicking, so the observable difference is in what the wrapper counts —
	// which requires reaching it, so the check is on the write succeeding.
	handler := log.Handler()
	record := slog.NewRecord(time.Now(), slog.LevelInfo, "hello", 0)
	if err := handler.Handle(t.Context(), record); err != nil {
		t.Errorf("a closed file sink propagated its error out of the handler: %v", err)
	}
}

// Without the wrapper, a failing sink silences the ones after it.
//
// This is the failure mode the wrapper exists to remove, asserted directly so
// the guard above is known to be testing something real.
func TestAnUnwrappedFailingSinkSilencesTheSinksAfterIt(t *testing.T) {
	var later bytes.Buffer

	log := slog.New(slog.NewJSONHandler(io.MultiWriter(brokenWriter{}, &later), nil))
	log.Info("hello", slog.String("event", "test"))

	if strings.Contains(later.String(), `"event":"test"`) {
		t.Error("io.MultiWriter no longer stops at the first failure, so the tolerant wrapper is protecting nothing")
	}
}

// The wrapper absorbs the failure and counts what it lost.
func TestTheTolerantWriterCountsWhatItDrops(t *testing.T) {
	failing := &tolerantWriter{w: brokenWriter{}}

	if _, err := failing.Write([]byte("x")); err != nil {
		t.Fatalf("the tolerant writer propagated an error: %v", err)
	}
	if dropped := failing.Dropped(); dropped != 1 {
		t.Errorf("dropped = %d, want 1; a silent loss is one nobody can account for", dropped)
	}
}

// A failure is announced once, not per record.
func TestAFailingSinkIsReportedOnce(t *testing.T) {
	failing := &tolerantWriter{w: brokenWriter{}}

	if _, ok := failing.TakeFailure(); ok {
		t.Error("a sink that has not failed reported a failure")
	}

	for range 3 {
		if _, err := failing.Write([]byte("x")); err != nil {
			t.Fatalf("the tolerant writer returned an error: %v", err)
		}
	}

	dropped, ok := failing.TakeFailure()
	if !ok {
		t.Fatal("a failing sink reported nothing")
	}
	if dropped != 3 {
		t.Errorf("dropped = %d, want 3", dropped)
	}
	if _, ok := failing.TakeFailure(); ok {
		t.Error("the failure was announced twice; a line per failed write is the flood this avoids")
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }
