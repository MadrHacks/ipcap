package collector

import (
	"bufio"
	"bytes"
	"os"
	"strings"
	"sync"

	"ipcap/internal/keylog"
)

// KeylogSink appends received NSS keylog lines to an SSLKEYLOGFILE, validated and
// deduplicated (the agent re-sends all keys on every reconnect, and keys are
// idempotent), so a future tulip TLS pass can decrypt the captured traffic.
// Malformed, oversized, or duplicate keys are dropped — this never affects packet
// capture.
type KeylogSink struct {
	mu   sync.Mutex
	f    *os.File
	seen map[string]struct{}
}

// OpenKeylogSink opens (creating, appending to) the keylog file and primes the
// dedupe set from any VALID lines already present. It streams the existing file
// and skips over-long lines so a previously-bloated keylog can never exhaust
// memory or stall priming.
func OpenKeylogSink(path string) (*KeylogSink, error) {
	seen := map[string]struct{}{}
	if existing, err := os.Open(path); err == nil {
		br := bufio.NewReader(existing)
		for {
			line, rerr := br.ReadSlice('\n')
			if keylog.Valid(line) {
				seen[string(bytes.TrimSpace(line))] = struct{}{}
			}
			if rerr != nil {
				if rerr == bufio.ErrBufferFull {
					discardLine(br) // over-long line; not a key — skip its remainder
					continue
				}
				break // io.EOF or read error
			}
		}
		existing.Close()
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &KeylogSink{f: f, seen: seen}, nil
}

// discardLine drops the remainder of an over-long line up to and including the
// next newline, so priming resyncs after garbage instead of buffering it.
func discardLine(br *bufio.Reader) {
	for {
		if _, err := br.ReadSlice('\n'); err != bufio.ErrBufferFull {
			return
		}
	}
}

// Write appends one keylog line if it is well-formed and not already present.
// Nil-safe. Malformed or oversized lines (e.g. zero-padded eCapture garbage) are
// silently dropped so the SSLKEYLOGFILE stays clean and bounded.
func (s *KeylogSink) Write(line []byte) error {
	if s == nil {
		return nil
	}
	if !keylog.Valid(line) {
		return nil
	}
	key := strings.TrimSpace(string(line))
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[key]; ok {
		return nil
	}
	s.seen[key] = struct{}{}
	_, err := s.f.WriteString(key + "\n")
	return err
}

// Close closes the underlying file. Nil-safe.
func (s *KeylogSink) Close() error {
	if s == nil || s.f == nil {
		return nil
	}
	return s.f.Close()
}
