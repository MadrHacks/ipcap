// Package pcapoverip re-serves a source's committed packets as a standard,
// uncompressed PCAP-over-IP stream on a local TCP port: a 24-byte libpcap
// global header followed by records, byte-identical to what the tulip assembler
// (pcap.OpenOfflineFile), suricata (socat | suricata -r /dev/stdin), and tshark
// (-i TCP@host:port) expect. Each client has its own goroutine and bounded
// buffer, so a slow consumer never blocks ingest or other clients.
package pcapoverip

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"ipcap/internal/pcapio"
)

// Server fans out one source's committed packets to connected TCP clients.
type Server struct {
	mu      sync.Mutex
	header  pcapio.GlobalHeader
	clients map[*client]struct{}
	bufSize int
}

type client struct {
	conn    net.Conn
	ch      chan pcapio.Record
	dropped atomic.Uint64
}

// NewServer creates a fan-out server with the given initial global header.
func NewServer(header pcapio.GlobalHeader, bufSize int) *Server {
	if bufSize <= 0 {
		bufSize = 1 << 16
	}
	return &Server{header: header, clients: map[*client]struct{}{}, bufSize: bufSize}
}

// SetHeader updates the global header sent to future clients (e.g. once the
// link type is learned from the agent preamble). It does not affect clients
// already streaming.
func (s *Server) SetHeader(h pcapio.GlobalHeader) {
	s.mu.Lock()
	s.header = h
	s.mu.Unlock()
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
		s.addClient(ctx, conn)
	}
}

func (s *Server) addClient(ctx context.Context, conn net.Conn) {
	s.mu.Lock()
	header := s.header
	cl := &client{conn: conn, ch: make(chan pcapio.Record, s.bufSize)}
	s.clients[cl] = struct{}{}
	s.mu.Unlock()
	go s.run(ctx, cl, header)
}

func (s *Server) removeClient(cl *client) {
	s.mu.Lock()
	if _, ok := s.clients[cl]; ok {
		delete(s.clients, cl)
		close(cl.ch)
	}
	s.mu.Unlock()
	cl.conn.Close()
}

func (s *Server) run(ctx context.Context, cl *client, header pcapio.GlobalHeader) {
	defer s.removeClient(cl)
	if _, err := cl.conn.Write(header.AppendTo(nil)); err != nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case rec, ok := <-cl.ch:
			if !ok {
				return
			}
			if _, err := cl.conn.Write(rec.AppendTo(nil)); err != nil {
				return
			}
		}
	}
}

// Broadcast queues a committed record to every client. It never blocks ingest:
// a client whose buffer is full drops the record (counted). The block-for-
// suricata / drop-only-reconnecting policy is milestone-2 hardening; the M1
// buffer is large enough that drops only occur under sustained consumer stall.
func (s *Server) Broadcast(rec pcapio.Record) {
	s.mu.Lock()
	for cl := range s.clients {
		select {
		case cl.ch <- rec:
		default:
			if n := cl.dropped.Add(1); n%10000 == 1 {
				log.Printf("pcapoverip: client %s slow, dropped %d records", cl.conn.RemoteAddr(), n)
			}
		}
	}
	s.mu.Unlock()
}

// ResetSession closes all current clients so they reconnect with a fresh global
// header and a new assembler source name. The collector calls this after a GAP
// so a lost range never appears as a silent discontinuity in a live stream.
func (s *Server) ResetSession(header pcapio.GlobalHeader) {
	s.mu.Lock()
	s.header = header
	clients := make([]*client, 0, len(s.clients))
	for cl := range s.clients {
		clients = append(clients, cl)
	}
	s.mu.Unlock()
	for _, cl := range clients {
		s.removeClient(cl)
	}
}
