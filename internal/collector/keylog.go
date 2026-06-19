package collector

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

// KeylogSink appends received NSS keylog lines to an SSLKEYLOGFILE, deduplicated
// (the agent re-sends all keys on every reconnect, and keys are idempotent), so
// a future tulip TLS pass can decrypt the captured traffic. Missing or duplicate
// keys are harmless — this never affects packet capture.
type KeylogSink struct {
	mu   sync.Mutex
	f    *os.File
	seen map[string]struct{}
}

// OpenKeylogSink opens (creating, appending to) the keylog file and primes the
// dedupe set from any lines already present.
func OpenKeylogSink(path string) (*KeylogSink, error) {
	seen := map[string]struct{}{}
	if existing, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(existing)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				seen[line] = struct{}{}
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

// Write appends one keylog line if not already present. Nil-safe.
func (s *KeylogSink) Write(line []byte) error {
	if s == nil {
		return nil
	}
	key := strings.TrimSpace(string(line))
	if key == "" {
		return nil
	}
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
