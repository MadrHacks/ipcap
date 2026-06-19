package e2e

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ipcap/internal/agent"
	"ipcap/internal/collector"
	"ipcap/internal/pcapio"
)

func bigPayload(i int) []byte {
	return []byte(fmt.Sprintf("%08d:", i) + strings.Repeat("abcdefgh", 128)) // ~1 KiB
}

func genBigPcap(t *testing.T, path string, n int) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := pcapio.GlobalHeader{Snaplen: 65536, LinkType: linkEthernet}.AppendTo(nil)
	for i := 0; i < n; i++ {
		p := bigPayload(i)
		buf = pcapio.Record{TsSec: uint32(1_700_000_000 + i), OrigLen: uint32(len(p)), Data: p}.AppendTo(buf)
	}
	if _, err := f.Write(buf); err != nil {
		t.Fatal(err)
	}
}

func captureBig(t *testing.T, pcapPath, spoolDir string) {
	t.Helper()
	if err := agent.RunCapture(context.Background(), agent.CaptureOptions{
		SpoolDir: spoolDir, SrcID: 1, PcapFile: pcapPath, Snaplen: 65536, RotateBytes: 256 << 10,
	}); err != nil {
		t.Fatalf("capture: %v", err)
	}
}

// runConnection runs one in-process serve<->demux session over pipes, resuming
// from `resume`, until stop() reports true or the stream ends. It returns when
// the session is torn down.
func runConnection(t *testing.T, spoolDir string, mirror *collector.Mirror, resume uint64, stop func() bool) {
	t.Helper()
	demuxIn, serveOut := io.Pipe()    // serve writes frames -> demux reads
	serveIn, demuxAckOut := io.Pipe() // demux writes acks -> serve reads
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		_ = agent.RunServe(ctx, agent.ServeOptions{
			SpoolDir: spoolDir, SrcID: 1, Resume: resume, In: serveIn, Out: serveOut,
		})
		serveOut.Close()
	}()

	demux := collector.NewDemux(1, "resume-test", mirror, demuxAckOut)
	done := make(chan struct{})
	go func() {
		_ = demux.Run(ctx, demuxIn)
		close(done)
	}()

	deadline := time.Now().Add(20 * time.Second)
	for !stop() {
		select {
		case <-done:
			goto teardown
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("connection stall: committed=%d", mirror.Committed())
		}
		time.Sleep(2 * time.Millisecond)
	}
teardown:
	cancel()
	serveIn.Close()
	demuxAckOut.Close()
	demuxIn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

// TestResumeExactlyOnce cuts the drain mid-stream, reopens the mirror (exercising
// truncate-to-committed), resumes from a point *behind* the commit head to force
// the dedup path, and asserts the mirror ends byte-identical with exactly N
// packets — no loss, no duplication.
func TestResumeExactlyOnce(t *testing.T) {
	const N = 2000
	root := t.TempDir()
	spoolDir := filepath.Join(root, "spool")
	mirrorDir := filepath.Join(root, "mirror")
	if err := os.MkdirAll(spoolDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pcapPath := filepath.Join(root, "gen.pcap")
	genBigPcap(t, pcapPath, N)
	captureBig(t, pcapPath, spoolDir)

	gh := pcapio.GlobalHeader{Snaplen: 65536, LinkType: linkEthernet}

	// Round 1: drain until ~25% committed, then cut.
	mirror, err := collector.OpenMirror(mirrorDir, 1, gh)
	if err != nil {
		t.Fatal(err)
	}
	runConnection(t, spoolDir, mirror, mirror.Committed(), func() bool {
		return mirror.Committed() >= N/4
	})
	cut := mirror.Committed()
	if cut == 0 || cut >= N {
		t.Fatalf("round 1 committed %d, want a mid-stream cut", cut)
	}
	mirror.Close()
	t.Logf("round 1 committed %d/%d, reconnecting", cut, N)

	// Reopen the mirror (truncate-to-committed recovery path).
	mirror2, err := collector.OpenMirror(mirrorDir, 1, gh)
	if err != nil {
		t.Fatal(err)
	}
	if mirror2.Committed() != cut {
		t.Fatalf("reopened committed %d, want %d", mirror2.Committed(), cut)
	}

	// Round 2: resume from *behind* the commit head to force the dedup path.
	resume := uint64(0)
	if mirror2.Committed() > 100 {
		resume = mirror2.Committed() - 100
	}
	runConnection(t, spoolDir, mirror2, resume, func() bool {
		return mirror2.Committed() >= N
	})
	if got := mirror2.Committed(); got != N {
		t.Fatalf("final committed %d, want %d", got, N)
	}
	mirror2.Close()

	// The mirror must be exactly N records, in order, byte-identical.
	verifyBigMirror(t, mirrorDir, N)
}

func verifyBigMirror(t *testing.T, dir string, n int) {
	t.Helper()
	f, err := os.Open(mirrorFile(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var gh [pcapio.GlobalHeaderLen]byte
	if _, err := io.ReadFull(f, gh[:]); err != nil {
		t.Fatal(err)
	}
	idx := 0
	_, count, err := pcapio.ScanRecords(f, 65536, func(rec pcapio.Record) error {
		if string(rec.Data) != string(bigPayload(idx)) {
			return fmt.Errorf("mirror record %d mismatch (got prefix %q)", idx, firstN(rec.Data, 9))
		}
		idx++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if int(count) != n {
		t.Fatalf("mirror has %d records, want %d (no dup, no loss)", count, n)
	}
}

func firstN(b []byte, n int) string {
	if len(b) < n {
		n = len(b)
	}
	return string(b[:n])
}
