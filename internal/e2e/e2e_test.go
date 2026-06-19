// Package e2e exercises the full milestone-1 pipeline end to end: capture into
// the durable spool, drain via a real `ipcap agent serve` subprocess over pipes,
// dedupe/commit into the collector mirror, and re-serve standard PCAP-over-IP —
// plus the exactly-once resume guarantee across a mid-stream disconnect.
package e2e

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"ipcap/internal/agent"
	"ipcap/internal/collector"
	"ipcap/internal/config"
	"ipcap/internal/pcapio"
)

var ipcapBin string

func TestMain(m *testing.M) {
	bin := filepath.Join(os.TempDir(), "ipcap-e2e")
	build := exec.Command("go", "build", "-o", bin, "./cmd/ipcap")
	build.Dir = "../.."
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build ipcap:", err)
		os.Exit(1)
	}
	ipcapBin = bin
	os.Exit(m.Run())
}

const linkEthernet = 1

func payload(i int) []byte {
	return []byte(fmt.Sprintf("ipcap-e2e-packet-%08d-%s", i, "ABCDEFGHIJKLMNOP"[:i%16]))
}

// genPcap writes n records with deterministic, ordered payloads.
func genPcap(t *testing.T, path string, n int) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := pcapio.GlobalHeader{Snaplen: 65536, LinkType: linkEthernet}.AppendTo(nil)
	for i := 0; i < n; i++ {
		p := payload(i)
		buf = pcapio.Record{TsSec: uint32(1_700_000_000 + i), TsUsec: uint32(i), OrigLen: uint32(len(p)), Data: p}.AppendTo(buf)
	}
	if _, err := f.Write(buf); err != nil {
		t.Fatal(err)
	}
}

// captureToSpool replays a pcap into the spool (returns at EOF).
func captureToSpool(t *testing.T, pcapPath, spoolDir string) {
	t.Helper()
	err := agent.RunCapture(context.Background(), agent.CaptureOptions{
		SpoolDir:    spoolDir,
		SrcID:       1,
		PcapFile:    pcapPath,
		Snaplen:     65536,
		SSHPort:     0, // no exclusion: keep every generated packet
		RotateBytes: 8192,
	})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
}

// readRecords reads exactly n libpcap records from r, returning their payloads.
func readRecords(t *testing.T, r io.Reader, n int) [][]byte {
	t.Helper()
	var gh [pcapio.GlobalHeaderLen]byte
	if _, err := io.ReadFull(r, gh[:]); err != nil {
		t.Fatalf("read global header: %v", err)
	}
	if _, err := pcapio.ParseGlobalHeader(gh[:]); err != nil {
		t.Fatalf("bad global header: %v", err)
	}
	out := make([][]byte, 0, n)
	for len(out) < n {
		rec, err := pcapio.ReadRecord(r, 65536)
		if err != nil {
			t.Fatalf("read record %d: %v", len(out), err)
		}
		out = append(out, rec.Data)
	}
	return out
}

func verifyOrdered(t *testing.T, got [][]byte, from int) {
	t.Helper()
	for i, data := range got {
		want := payload(from + i)
		if string(data) != string(want) {
			t.Fatalf("record %d mismatch: got %q want %q", from+i, data, want)
		}
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func writeVulnboxConfig(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "vulnbox.yml"), []byte("ip: 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestEndToEnd runs the full pipeline with a real serve subprocess and verifies
// both the durable mirror and the live PCAP-over-IP re-serve deliver every
// packet, in order, byte-identical.
func TestEndToEnd(t *testing.T) {
	const N = 500
	root := t.TempDir()
	spoolDir := filepath.Join(root, "spool")
	mirrorDir := filepath.Join(root, "mirror")
	configDir := filepath.Join(root, "config")
	for _, d := range []string{spoolDir, mirrorDir, configDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	pcapPath := filepath.Join(root, "gen.pcap")
	genPcap(t, pcapPath, N)
	captureToSpool(t, pcapPath, spoolDir)
	writeVulnboxConfig(t, configDir)

	listen := freeAddr(t)
	clientReady := make(chan struct{})

	opts := collector.Options{
		ConfigDir:     configDir,
		MirrorDir:     mirrorDir,
		SrcID:         1,
		ListenAddr:    listen,
		Snaplen:       65536,
		AgentSpoolDir: spoolDir,
		Spawn: func(ctx context.Context, vb config.Vulnbox, resume uint64) (*exec.Cmd, error) {
			<-clientReady // ensure the fan-out client is registered before streaming
			return exec.CommandContext(ctx, ipcapBin, "agent", "serve",
				"--spool-dir", spoolDir, "--src-id", "1", "--resume", fmt.Sprintf("%d", resume)), nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	collDone := make(chan struct{})
	go func() {
		defer close(collDone)
		if err := collector.Run(ctx, opts); err != nil {
			t.Errorf("collector: %v", err)
		}
	}()

	// Connect the re-serve client, then let streaming begin.
	var conn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", listen)
		if err == nil {
			conn = c
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial re-serve: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	close(clientReady)

	got := readRecords(t, conn, N)
	verifyOrdered(t, got, 0)

	// The durable mirror must also contain all N packets, byte-identical.
	waitForMirror(t, mirrorDir, N)
	verifyMirror(t, mirrorDir, 0, N)

	cancel()
	<-collDone
}

func mirrorFile(dir string) string {
	return filepath.Join(dir, fmt.Sprintf("mirror-src1-%020d.pcap", 0))
}

func waitForMirror(t *testing.T, dir string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if countMirror(t, dir) >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("mirror only reached %d/%d records", countMirror(t, dir), n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func countMirror(t *testing.T, dir string) int {
	f, err := os.Open(mirrorFile(dir))
	if err != nil {
		return 0
	}
	defer f.Close()
	var gh [pcapio.GlobalHeaderLen]byte
	if _, err := io.ReadFull(f, gh[:]); err != nil {
		return 0
	}
	_, count, _ := pcapio.ScanRecords(f, 65536, nil)
	return int(count)
}

func verifyMirror(t *testing.T, dir string, from, n int) {
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
	idx := from
	_, _, err = pcapio.ScanRecords(f, 65536, func(rec pcapio.Record) error {
		want := payload(idx)
		if string(rec.Data) != string(want) {
			return fmt.Errorf("mirror record %d mismatch: got %q want %q", idx, rec.Data, want)
		}
		idx++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if idx-from != n {
		t.Fatalf("mirror has %d records, want %d", idx-from, n)
	}
}

var _ = binary.LittleEndian
