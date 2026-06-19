package spool

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"ipcap/internal/pcapio"
)

func mkRec(i int) pcapio.Record {
	data := []byte(fmt.Sprintf("packet-%06d-payload", i))
	return pcapio.Record{
		TsSec:   uint32(1_700_000_000 + i),
		TsUsec:  uint32(i % 1_000_000),
		OrigLen: uint32(len(data)),
		Data:    data,
	}
}

// drainAll reads every available record from a reader until it catches up.
func drainAll(t *testing.T, r *Reader, startGpidx int) (count int) {
	t.Helper()
	want := startGpidx
	for {
		rec, gp, err := r.Next()
		if err == ErrNoData {
			return count
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if gp != uint64(want) {
			t.Fatalf("gpidx out of order: got %d want %d", gp, want)
		}
		if string(rec.Data) != string(mkRec(want).Data) {
			t.Fatalf("payload mismatch at gpidx %d: %q", gp, rec.Data)
		}
		want++
		count++
	}
}

func writeN(t *testing.T, w *Writer, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		gp, err := w.WritePacket(mkRec(i))
		if err != nil {
			t.Fatalf("WritePacket %d: %v", i, err)
		}
		if gp != uint64(i) {
			t.Fatalf("gpidx: got %d want %d", gp, i)
		}
	}
}

func TestRoundTripAndResume(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, SrcID: 1, Snaplen: 65536, LinkType: 1, RotateBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	const N = 1000
	writeN(t, w, N)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Full read from the start.
	r, from, reaped, err := OpenReader(dir, 1, 65536, 0)
	if err != nil {
		t.Fatal(err)
	}
	if reaped || from != 0 {
		t.Fatalf("unexpected resume clamp: from=%d reaped=%v", from, reaped)
	}
	if got := drainAll(t, r, 0); got != N {
		t.Fatalf("read %d packets, want %d", got, N)
	}
	r.Close()

	// Resume from the middle: must yield exactly [200, N).
	r2, from2, _, err := OpenReader(dir, 1, 65536, 200)
	if err != nil {
		t.Fatal(err)
	}
	if from2 != 200 {
		t.Fatalf("resume from %d, want 200", from2)
	}
	if got := drainAll(t, r2, 200); got != N-200 {
		t.Fatalf("resume read %d packets, want %d", got, N-200)
	}
	r2.Close()

	// Multiple segments must have been produced (rotation exercised).
	seqs, _ := listSegmentFiles(dir, 1)
	if len(seqs) < 2 {
		t.Fatalf("expected rotation into multiple segments, got %d", len(seqs))
	}
}

func TestCrashRecoveryTruncatesTornTail(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, SrcID: 7, Snaplen: 65536, LinkType: 1, RotateBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	const N = 100
	writeN(t, w, N)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a hard crash mid-record: append a partial (torn) record to the
	// single active segment file.
	active := filepath.Join(dir, segmentName(7, 0))
	f, err := os.OpenFile(active, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0x10, 0x20, 0x30, 0x40, 0x05, 0x00}); err != nil { // 6 bytes of a 16-byte header
		t.Fatal(err)
	}
	f.Close()

	// Reopen: recovery must truncate the torn tail and resume the head at N.
	w2, err := NewWriter(Config{Dir: dir, SrcID: 7, Snaplen: 65536, LinkType: 1, RotateBytes: 1 << 30})
	if err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if h := w2.Head(); h != N {
		t.Fatalf("recovered head = %d, want %d", h, N)
	}
	// The next packet must take gpidx N (no reissue, no gap).
	gp, err := w2.WritePacket(mkRec(N))
	if err != nil {
		t.Fatal(err)
	}
	if gp != N {
		t.Fatalf("post-recovery gpidx = %d, want %d", gp, N)
	}
	w2.Close()

	// Reader must see exactly N+1 valid packets, contiguous.
	r, _, _, err := OpenReader(dir, 7, 65536, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := drainAll(t, r, 0); got != N+1 {
		t.Fatalf("post-recovery read %d packets, want %d", got, N+1)
	}
}

func TestRecoveryReseatsTornManifestLine(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, SrcID: 9, Snaplen: 65536, LinkType: 1, RotateBytes: 2048})
	if err != nil {
		t.Fatal(err)
	}
	const N = 1500
	writeN(t, w, N)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a torn manifest write: drop the last sealed line, so that
	// segment's file exists on disk with no manifest entry.
	mpath := filepath.Join(dir, manifestName)
	raw, err := os.ReadFile(mpath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	if len(lines) < 2 {
		t.Fatalf("expected multiple sealed segments, got %d", len(lines))
	}
	kept := bytes.Join(lines[:len(lines)-1], []byte("\n"))
	if len(kept) > 0 {
		kept = append(kept, '\n')
	}
	if err := os.WriteFile(mpath, kept, 0o644); err != nil {
		t.Fatal(err)
	}

	// Recovery must re-derive the orphaned segment's gpidx from the chain, re-seal
	// it, and resume the head at exactly N — no loss, no reissue.
	w2, err := NewWriter(Config{Dir: dir, SrcID: 9, Snaplen: 65536, LinkType: 1, RotateBytes: 2048})
	if err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if h := w2.Head(); h != N {
		t.Fatalf("recovered head = %d, want %d", h, N)
	}
	w2.Close()

	// The re-sealed segment must be back in the manifest and the reader must see
	// every packet contiguously.
	r, _, _, err := OpenReader(dir, 9, 65536, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := drainAll(t, r, 0); got != N {
		t.Fatalf("post-recovery read %d packets, want %d", got, N)
	}
}

// TestJanitorSkipsLockedSegment asserts the reaper will not delete a segment a
// reader is actively replaying (shared-lock held), so bytes are never yanked
// from under an in-flight serve.
func TestJanitorSkipsLockedSegment(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, SrcID: 5, Snaplen: 65536, LinkType: 1, RotateBytes: 2048})
	if err != nil {
		t.Fatal(err)
	}
	writeN(t, w, 2000)
	w.Close()

	// Reader positioned in the oldest segment holds a shared lock on it.
	r, _, _, err := OpenReader(dir, 5, 65536, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, _, err := r.Next(); err != nil { // opens + shared-locks the oldest segment
		t.Fatal(err)
	}
	oldestFile := filepath.Join(dir, segmentName(5, 0))
	if _, err := os.Stat(oldestFile); err != nil {
		t.Fatalf("oldest segment should exist: %v", err)
	}

	w2, err := NewWriter(Config{Dir: dir, SrcID: 5, Snaplen: 65536, LinkType: 1, RotateBytes: 2048})
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if _, err := w2.Reap(2048); err != nil { // aggressive cap; would reap oldest first
		t.Fatal(err)
	}
	if _, err := os.Stat(oldestFile); err != nil {
		t.Fatalf("locked oldest segment must NOT be reaped: %v", err)
	}
}

func TestResumeOlderThanRetentionReaps(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, SrcID: 3, Snaplen: 65536, LinkType: 1, RotateBytes: 2048})
	if err != nil {
		t.Fatal(err)
	}
	writeN(t, w, 2000)
	// Force retention down so the oldest segments are reaped.
	if _, err := w.Reap(2048); err != nil {
		t.Fatal(err)
	}
	oldest := w.OldestGpidx()
	w.Close()
	if oldest == 0 {
		t.Fatal("expected retention to advance oldestGpidx above 0")
	}

	// A resume from 0 is older than retention -> clamp to oldest + reaped flag.
	r, from, reaped, err := OpenReader(dir, 3, 65536, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !reaped {
		t.Fatal("expected reaped=true for resume below retention")
	}
	if from != oldest {
		t.Fatalf("clamped resume = %d, want oldest %d", from, oldest)
	}
}

// TestOpenReaderResumePastHeadServesOldest covers the wiped-spool signature: a
// resume gpidx newer than everything the spool holds is only possible when the
// collector's commit point came from a previous spool instance. The reader must
// then serve from the oldest retained packet (so the collector gets all the
// fresh data and realigns via the epoch), not clamp to head and stall.
func TestOpenReaderResumePastHeadServesOldest(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, SrcID: 1, Snaplen: 65536, LinkType: 1})
	if err != nil {
		t.Fatal(err)
	}
	writeN(t, w, 20)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	r, from, reaped, err := OpenReader(dir, 1, 65536, 9999)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if reaped {
		t.Fatal("wipe case must not flag reaped (no GAP frame; epoch handles realignment)")
	}
	if from != 0 {
		t.Fatalf("from=%d, want 0 (oldest) so the fresh spool's data is fully served", from)
	}
	if got := drainAll(t, r, 0); got != 20 {
		t.Fatalf("served %d packets, want 20", got)
	}
}

// TestEpochReadOrCreate verifies the spool epoch is stable across calls and
// reflects a wipe (fresh directory -> new id).
func TestEpochReadOrCreate(t *testing.T) {
	dir := t.TempDir()
	a, err := Epoch(dir)
	if err != nil || a == "" {
		t.Fatalf("Epoch: %q err=%v", a, err)
	}
	b, err := Epoch(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("epoch not stable across calls: %q != %q", a, b)
	}
	// A fresh directory (a wipe) yields a different epoch.
	c, err := Epoch(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if c == a {
		t.Fatal("a wiped spool must get a new epoch")
	}
}
