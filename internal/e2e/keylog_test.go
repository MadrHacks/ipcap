package e2e

import (
	"context"
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

// TestKeylogRelay verifies that NSS keylog lines written next to the agent are
// relayed as TLS_KEYLOG frames over the link and land, deduplicated, in the
// collector's SSLKEYLOGFILE.
func TestKeylogRelay(t *testing.T) {
	root := t.TempDir()
	spoolDir := filepath.Join(root, "spool")
	mirrorDir := filepath.Join(root, "mirror")
	if err := os.MkdirAll(spoolDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A little spooled traffic so serve reaches its idle/beat path quickly.
	pcapPath := filepath.Join(root, "gen.pcap")
	genPcap(t, pcapPath, 20)
	captureToSpool(t, pcapPath, spoolDir)

	// The keylog file eCapture would write.
	keys := []string{
		"CLIENT_RANDOM 1111111111111111111111111111111111111111111111111111111111111111 aaaa",
		"CLIENT_RANDOM 2222222222222222222222222222222222222222222222222222222222222222 bbbb",
		"SERVER_HANDSHAKE_TRAFFIC_SECRET 3333333333333333333333333333333333333333333333333333333333333333 cccc",
	}
	keylogPath := filepath.Join(root, "ssl_keys.log")
	if err := os.WriteFile(keylogPath, []byte(strings.Join(keys, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sslOut := filepath.Join(root, "sslkeylog.txt")
	sink, err := collector.OpenKeylogSink(sslOut)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	gh := pcapio.GlobalHeader{Snaplen: 65536, LinkType: linkEthernet}
	mirror, err := collector.OpenMirror(mirrorDir, 1, gh)
	if err != nil {
		t.Fatal(err)
	}
	defer mirror.Close()

	demuxIn, serveOut := io.Pipe()
	serveIn, demuxAckOut := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = agent.RunServe(ctx, agent.ServeOptions{
			SpoolDir: spoolDir, SrcID: 1, Resume: 0, KeylogFile: keylogPath,
			In: serveIn, Out: serveOut,
		})
		serveOut.Close()
	}()
	demux := collector.NewDemux(1, "keylog-test", mirror, demuxAckOut, nil, sink)
	go func() { _ = demux.Run(ctx, demuxIn) }()

	// Wait until all three keys appear in the SSLKEYLOGFILE.
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, _ := os.ReadFile(sslOut)
		if countKeys(string(got)) >= len(keys) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("keylog not relayed in time; got:\n%s", got)
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	serveIn.Close()
	demuxAckOut.Close()
	demuxIn.Close()

	got, _ := os.ReadFile(sslOut)
	for _, k := range keys {
		if !strings.Contains(string(got), k) {
			t.Fatalf("missing key in SSLKEYLOGFILE: %q", k)
		}
	}
	// Dedup: each key appears exactly once even though serve re-sends from the start.
	if n := countKeys(string(got)); n != len(keys) {
		t.Fatalf("SSLKEYLOGFILE has %d keys, want %d (dedup failed)", n, len(keys))
	}
}

func countKeys(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}
