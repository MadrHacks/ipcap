// Package capture abstracts a packet source feeding the spool. The agent uses
// the AF_PACKET TPACKETv3 source on the vulnbox; tests and offline use drive the
// identical downstream path from a libpcap file.
package capture

import (
	"errors"
	"time"
)

// ErrTimeout is returned by a Source's ReadPacket when no packet arrived within
// the poll interval. The capture loop treats it as an idle tick — a safe point
// to observe context cancellation — so it never has to close the source from
// another goroutine (which would race an in-flight ring read).
var ErrTimeout = errors.New("capture: read timeout")

// Stats is a capture-time counter snapshot.
type Stats struct {
	Received      uint64
	DroppedKernel uint64 // ring overflow (CPU starvation) before the spool
	DroppedIface  uint64 // NIC-reported drops
}

// Source yields captured packets in order. ReadPacket returns data owned by the
// source only until the next call; the caller must copy what it keeps.
type Source interface {
	ReadPacket() (ts time.Time, data []byte, origLen int, err error)
	LinkType() uint32
	Stats() (Stats, error)
	Close() error
}
