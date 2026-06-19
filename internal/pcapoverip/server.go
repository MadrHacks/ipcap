// Package pcapoverip re-serves a source's committed packets as a standard,
// uncompressed PCAP-over-IP stream on a local TCP port: a 24-byte libpcap
// global header followed by records, byte-identical to what the tulip assembler
// (pcap.OpenOfflineFile), suricata (socat | suricata -r /dev/stdin), and tshark
// (-i TCP@host:port) expect.
//
// Each client is served by a dedicated goroutine that tails the durable mirror
// file from its own byte cursor. The mirror IS the per-client buffer: a slow
// consumer simply lags its cursor on disk — it never drops a packet, never
// blocks ingest, and never head-of-line-blocks other clients. This is why a
// non-reconnecting consumer (suricata -r /dev/stdin) is safe.
package pcapoverip

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"time"

	"ipcap/internal/pcapio"
)

// Source is the durable mirror the fan-out tails (implemented by the collector).
type Source interface {
	// Snapshot returns the active session sequence, its on-disk file, the durable
	// byte length readable so far, and the libpcap header.
	Snapshot() (sessionSeq uint64, file string, committedLen int64, gh pcapio.GlobalHeader)
}

// Server fans out one source's committed packets to connected TCP clients.
type Server struct {
	src  Source
	poll time.Duration
}

// NewServer creates a fan-out server tailing src.
func NewServer(src Source) *Server {
	return &Server{src: src, poll: 20 * time.Millisecond}
}

// Listen accepts clients on addr until the context is cancelled.
func (s *Server) Listen(ctx context.Context, addr string) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go s.serve(ctx, conn)
	}
}

// serve streams the mirror to one client from the live head onward (a fresh
// session per connect, matching the assembler's per-connection model).
func (s *Server) serve(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	session, file, cursor, gh := s.src.Snapshot()
	if _, err := conn.Write(gh.AppendTo(nil)); err != nil {
		return
	}
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()

	var hdr [pcapio.RecordHeaderLen]byte
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		curSession, _, committedLen, _ := s.src.Snapshot()
		if curSession != session {
			return // a GAP rotated the session; the client reconnects fresh
		}
		progressed := false
		for cursor+pcapio.RecordHeaderLen <= committedLen {
			if _, err := f.ReadAt(hdr[:], cursor); err != nil {
				break // not durably present yet; retry after poll
			}
			capLen := int64(binary.LittleEndian.Uint32(hdr[8:]))
			recEnd := cursor + pcapio.RecordHeaderLen + capLen
			if recEnd > committedLen {
				break
			}
			body := make([]byte, capLen)
			if _, err := f.ReadAt(body, cursor+pcapio.RecordHeaderLen); err != nil {
				break
			}
			if _, err := conn.Write(hdr[:]); err != nil {
				return
			}
			if _, err := conn.Write(body); err != nil {
				return
			}
			cursor = recEnd
			progressed = true
		}
		if !progressed {
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.poll):
			}
		}
	}
}
