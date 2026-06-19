// Package e2e exercises the full pipeline end to end over the real Noise
// transport: capture into the durable spool, a Noise listener on the "vulnbox",
// a collector that dials it (mutually authenticated), dedupe/commit into the
// mirror, and the PCAP-over-IP fan-out.
package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ipcap/internal/agent"
	"ipcap/internal/collector"
	"ipcap/internal/pcapio"
	"ipcap/internal/pcapoverip"
	"ipcap/internal/transport"
)

const linkEthernet = 1

func payload(i int) []byte {
	return []byte(fmt.Sprintf("ipcap-e2e-packet-%08d-%s", i, "ABCDEFGHIJKLMNOP"[:i%16]))
}

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

func captureToSpool(t *testing.T, pcapPath, spoolDir string) {
	t.Helper()
	err := agent.RunCapture(context.Background(), agent.CaptureOptions{
		SpoolDir:     spoolDir,
		SrcID:        1,
		PcapFile:     pcapPath,
		Snaplen:      65536,
		ExcludePorts: nil,
		RotateBytes:  8192,
	})
	if err != nil {
		t.Fatalf("capture: %v", err)
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

// TestEndToEndNoise drives capture -> spool -> Noise listener -> collector dial
// -> demux -> durable mirror, and verifies the mirror is byte-identical.
func TestEndToEndNoise(t *testing.T) {
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

	agentKey, _ := transport.Generate()
	collectorKey, _ := transport.Generate()

	// Noise listener on the "vulnbox".
	listenAddr := freeAddr(t)
	host, port, _ := net.SplitHostPort(listenAddr)
	lctx, lcancel := context.WithCancel(context.Background())
	defer lcancel()
	go func() {
		_ = agent.RunListen(lctx, agent.ListenOptions{
			SpoolDir:     spoolDir,
			SrcID:        1,
			ListenAddr:   listenAddr,
			Key:          agentKey,
			AllowedPeers: [][]byte{collectorKey.Public},
		})
	}()

	// Config the collector dials: vulnbox ip/port + the agent's pinned pubkey.
	cfg := fmt.Sprintf("ip: %s\nnoise_port: %s\nnoise_pubkey: %s\n", host, port, agentKey.PublicB64())
	if err := os.WriteFile(filepath.Join(configDir, "vulnbox.yml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	cctx, ccancel := context.WithCancel(context.Background())
	defer ccancel()
	go func() {
		_ = collector.Run(cctx, collector.Options{
			ConfigDir: configDir,
			MirrorDir: mirrorDir,
			SrcID:     1,
			Snaplen:   65536,
			Key:       collectorKey,
		})
	}()

	waitForMirror(t, mirrorDir, N)
	verifyMirror(t, mirrorDir, N)
}

// TestFanout verifies the PCAP-over-IP re-serve delivers a live stream to a
// connected client, byte-identical and in order.
func TestFanout(t *testing.T) {
	const N = 300
	gh := pcapio.GlobalHeader{Snaplen: 65536, LinkType: linkEthernet}
	srv := pcapoverip.NewServer(gh, 4096)

	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Listen(ctx, addr) }()

	var conn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			conn = c
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Reading the global header proves the client is registered; only then
	// broadcast, so nothing is missed.
	var ghBuf [pcapio.GlobalHeaderLen]byte
	if _, err := io.ReadFull(conn, ghBuf[:]); err != nil {
		t.Fatalf("read global header: %v", err)
	}
	if _, err := pcapio.ParseGlobalHeader(ghBuf[:]); err != nil {
		t.Fatalf("bad global header: %v", err)
	}
	for i := 0; i < N; i++ {
		p := payload(i)
		srv.Broadcast(pcapio.Record{TsSec: uint32(i), OrigLen: uint32(len(p)), Data: p})
	}
	for i := 0; i < N; i++ {
		rec, err := pcapio.ReadRecord(conn, 65536)
		if err != nil {
			t.Fatalf("read record %d: %v", i, err)
		}
		if string(rec.Data) != string(payload(i)) {
			t.Fatalf("record %d mismatch", i)
		}
	}
}

func mirrorFile(dir string) string {
	return filepath.Join(dir, fmt.Sprintf("mirror-src1-%020d.pcap", 0))
}

func waitForMirror(t *testing.T, dir string, n int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if countMirror(dir) >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("mirror only reached %d/%d records", countMirror(dir), n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func countMirror(dir string) int {
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

func verifyMirror(t *testing.T, dir string, n int) {
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
		if string(rec.Data) != string(payload(idx)) {
			return fmt.Errorf("mirror record %d mismatch: got %q", idx, rec.Data)
		}
		idx++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if int(count) != n {
		t.Fatalf("mirror has %d records, want %d", count, n)
	}
}
