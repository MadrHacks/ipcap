package collector

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"ipcap/internal/config"
	"ipcap/internal/pcapio"
	"ipcap/internal/pcapoverip"
	"ipcap/internal/proto"
	"ipcap/internal/transport"
)

// Options configures a single-source collector.
type Options struct {
	ConfigDir  string
	MirrorDir  string
	SrcID      uint16
	SrcName    string
	ListenAddr string // local PCAP-over-IP re-serve, e.g. ":4242"
	Snaplen    uint32
	Key        transport.Keypair // collector's own static keypair
}

// Run holds the mirror lock, starts the re-serve listener, and supervises the
// Noise drain: dial the vulnbox agent (pinning its static key), and on any
// failure reconnect from the last durable commit point with backoff and config
// reload.
func Run(ctx context.Context, opts Options) error {
	if opts.Snaplen == 0 {
		opts.Snaplen = 65536
	}
	if opts.SrcName == "" {
		opts.SrcName = fmt.Sprintf("ipcap-src%d", opts.SrcID)
	}
	if err := os.MkdirAll(opts.MirrorDir, 0o755); err != nil {
		return err
	}
	unlock, err := flockDir(opts.MirrorDir)
	if err != nil {
		return err
	}
	defer unlock()

	gh := pcapio.GlobalHeader{Snaplen: opts.Snaplen, LinkType: 1} // Ethernet until preamble
	mirror, err := OpenMirror(opts.MirrorDir, opts.SrcID, gh)
	if err != nil {
		return err
	}
	defer mirror.Close()

	if opts.ListenAddr != "" {
		server := pcapoverip.NewServer(mirror)
		go func() {
			if err := server.Listen(ctx, opts.ListenAddr); err != nil {
				log.Printf("collector: listener: %v", err)
			}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		vb, _, cerr := config.Load(opts.ConfigDir)
		if cerr != nil {
			log.Printf("collector: config load: %v", cerr)
		}
		if vb.IP == "" || vb.NoisePubKey == "" {
			log.Printf("collector: waiting for vulnbox ip + noise_pubkey in config")
			if sleepCtx(ctx, 5*time.Second) {
				return nil
			}
			continue
		}
		agentPub, perr := transport.ParsePublicKey(vb.NoisePubKey)
		if perr != nil {
			log.Printf("collector: bad noise_pubkey: %v", perr)
			if sleepCtx(ctx, 5*time.Second) {
				return nil
			}
			continue
		}

		resume := mirror.Committed()
		if err := runOnce(ctx, opts, vb, agentPub, mirror, resume); err != nil {
			log.Printf("collector: src%d session ended: %v", opts.SrcID, err)
		}
		if sleepCtx(ctx, 2*time.Second) {
			return nil
		}
	}
}

// runOnce dials the agent, sends the resume point, and drains until the session
// ends.
func runOnce(ctx context.Context, opts Options, vb config.Vulnbox, agentPub []byte, mirror *Mirror, resume uint64) error {
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	addr := net.JoinHostPort(vb.IP, strconv.Itoa(vb.Port()))
	conn, err := transport.Dial(sessCtx, addr, opts.Key, agentPub)
	if err != nil {
		return err
	}
	defer conn.Close()
	go func() {
		<-sessCtx.Done()
		conn.Close()
	}()
	log.Printf("collector: src%d connected to %s, resume from gpidx %d", opts.SrcID, addr, resume)

	// The resume point is authoritative and sent over the wire as the first ACK.
	initial := proto.Frame{
		Type:     proto.FrameAck,
		SourceID: opts.SrcID,
		Payload:  proto.Ack{SrcID: opts.SrcID, AckedGpidx: resume}.Encode(),
	}
	if _, err := initial.WriteTo(conn); err != nil {
		return err
	}

	demux := NewDemux(opts.SrcID, opts.SrcName, mirror, conn)
	return demux.Run(sessCtx, conn)
}

// flockDir takes an exclusive, non-blocking lock so two collectors can never
// corrupt the same mirror.
func flockDir(dir string) (func(), error) {
	lockPath := filepath.Join(dir, ".collector.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("mirror dir %s is locked by another collector: %w", dir, err)
	}
	return func() {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}, nil
}

func sleepCtx(ctx context.Context, d time.Duration) (cancelled bool) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-t.C:
		return false
	}
}
