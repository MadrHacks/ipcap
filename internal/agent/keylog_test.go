package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"ipcap/internal/proto"
)

// drainKeylog runs one emitNew and returns the keylog lines it relayed.
func drainKeylog(t *testing.T, k *keylogTailer) []string {
	t.Helper()
	var buf bytes.Buffer
	s := &streamer{out: &buf, srcID: 1, seq: map[proto.FrameType]uint64{}}
	if err := k.emitNew(s); err != nil {
		t.Fatal(err)
	}
	var lines []string
	r := bytes.NewReader(buf.Bytes())
	for {
		f, err := proto.ReadFrame(r)
		if err != nil {
			break
		}
		if f.Type == proto.FrameTLSKeylog {
			lines = append(lines, string(f.Payload))
		}
	}
	return lines
}

// TestKeylogTailerSingleFile covers the original single-file behaviour: only
// newly-appended lines are relayed on each tick.
func TestKeylogTailerSingleFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "keys.log")
	os.WriteFile(p, []byte("CLIENT_RANDOM aaa 111\n"), 0o644)

	k := newKeylogTailer(p)
	defer k.Close()
	if got := drainKeylog(t, k); len(got) != 1 || got[0] != "CLIENT_RANDOM aaa 111" {
		t.Fatalf("first tick = %v", got)
	}
	if got := drainKeylog(t, k); len(got) != 0 {
		t.Fatalf("re-tick relayed already-sent lines: %v", got)
	}
	// Appended lines are picked up.
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("CLIENT_RANDOM bbb 222\n")
	f.Close()
	if got := drainKeylog(t, k); len(got) != 1 || got[0] != "CLIENT_RANDOM bbb 222" {
		t.Fatalf("append tick = %v", got)
	}
}

// TestKeylogTailerDirectoryManualDropIn is the operator fallback: a directory is
// tailed by globbing *.log, so a keylog file dropped in by hand (mitmproxy, an
// SSLKEYLOGFILE env, a custom setup) is relayed even though no eCapture produced
// it — and a file dropped mid-connection is picked up on the next tick.
func TestKeylogTailerDirectoryManualDropIn(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ecapture.log"), []byte("CLIENT_RANDOM e1 1\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "manual-mitmproxy.log"), []byte("CLIENT_RANDOM a1 2\nCLIENT_RANDOM a2 3\n"), 0o644)
	// A subdirectory (the orchestrator's internal per-target outputs) must NOT be
	// descended into, so those keys are not double-relayed. The line is itself a
	// valid keylog line, so the test proves exclusion (not mere rejection).
	os.MkdirAll(filepath.Join(dir, "targets"), 0o755)
	os.WriteFile(filepath.Join(dir, "targets", "x.log"), []byte("CLIENT_RANDOM deadbeef 9\n"), 0o644)

	k := newKeylogTailer(dir)
	defer k.Close()

	got := drainKeylog(t, k)
	want := map[string]bool{"CLIENT_RANDOM e1 1": true, "CLIENT_RANDOM a1 2": true, "CLIENT_RANDOM a2 3": true}
	if len(got) != 3 {
		t.Fatalf("first tick relayed %d lines, want 3: %v", len(got), got)
	}
	for _, l := range got {
		if !want[l] {
			t.Fatalf("unexpected line relayed (subdir leaked?): %q", l)
		}
	}

	// Operator drops a new keylog file mid-connection -> picked up next tick.
	os.WriteFile(filepath.Join(dir, "manual-mitmproxy2.log"), []byte("CLIENT_RANDOM a3 4\n"), 0o644)
	if got := drainKeylog(t, k); len(got) != 1 || got[0] != "CLIENT_RANDOM a3 4" {
		t.Fatalf("drop-in tick = %v", got)
	}
}
