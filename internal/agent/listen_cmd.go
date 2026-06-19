package agent

import (
	"context"
	"errors"
	"log"
	"net"
	"time"

	"ipcap/internal/proto"
	"ipcap/internal/transport"
)

var errNoPeers = errors.New("listen: no authorized collector keys configured (--peer)")

// ListenOptions configures the persistent Noise responder on the vulnbox. It is
// read-only on the spool and crash-isolated from the capture process.
type ListenOptions struct {
	SpoolDir     string
	SrcID        uint16
	SrcName      string
	ListenAddr   string
	Compress     bool   // zstd-compress PKT_BATCH payloads on the link
	KeylogFile   string // NSS keylog file (from eCapture) to relay as TLS_KEYLOG
	Key          transport.Keypair
	AllowedPeers [][]byte // allowlisted collector static public keys
}

// RunListen accepts authenticated collector connections and streams the spool
// to each, resuming from the gpidx the collector requests. Each connection is
// handled in its own goroutine; a stalled or unauthorized peer cannot block the
// accept loop or affect capture.
func RunListen(ctx context.Context, opts ListenOptions) error {
	if len(opts.AllowedPeers) == 0 {
		return errNoPeers
	}
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", opts.ListenAddr)
	if err != nil {
		return err
	}
	log.Printf("listen: src=%d on %s, %d authorized collector key(s)", opts.SrcID, opts.ListenAddr, len(opts.AllowedPeers))
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		raw, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go serveConn(ctx, raw, opts)
	}
}

func serveConn(ctx context.Context, raw net.Conn, opts ListenOptions) {
	_ = raw.SetDeadline(time.Now().Add(transport.HandshakeTimeout))
	conn, err := transport.ServerHandshake(raw, opts.Key, opts.AllowedPeers)
	if err != nil {
		raw.Close()
		log.Printf("listen: handshake from %s rejected: %v", raw.RemoteAddr(), err)
		return
	}
	_ = raw.SetDeadline(time.Time{})
	defer conn.Close()
	log.Printf("listen: collector %s connected", raw.RemoteAddr())

	// The collector's first frame is an ACK carrying the authoritative resume
	// point (next gpidx it needs).
	f, err := proto.ReadFrame(conn)
	if err != nil {
		log.Printf("listen: read resume: %v", err)
		return
	}
	if f.Type != proto.FrameAck {
		log.Printf("listen: expected resume ACK, got %s", f.Type)
		return
	}
	ack, err := proto.DecodeAck(f.Payload)
	if err != nil {
		log.Printf("listen: decode resume: %v", err)
		return
	}

	if err := RunServe(ctx, ServeOptions{
		SpoolDir:   opts.SpoolDir,
		SrcID:      opts.SrcID,
		SrcName:    opts.SrcName,
		Resume:     ack.AckedGpidx,
		Compress:   opts.Compress,
		KeylogFile: opts.KeylogFile,
		In:         conn,
		Out:        conn,
	}); err != nil {
		log.Printf("listen: serve ended: %v", err)
	}
}
