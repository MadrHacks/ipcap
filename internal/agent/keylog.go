package agent

import (
	"bytes"
	"os"
	"path/filepath"
)

// keylogTailer streams NSS keylog lines over the link as TLS_KEYLOG frames, so a
// future tulip TLS pass can decrypt the captured traffic. It re-sends from the
// start on every connection (keys are idempotent — the collector dedupes), so no
// separate resume state is needed; missing a key only costs decryptability of
// that one flow, never packet capture.
//
// The source may be a single file OR a directory. A directory is tailed by
// globbing "*.log", so the eCapture orchestrator's output and any keylog files
// the operator drops in manually (from mitmproxy, an SSLKEYLOGFILE env, a custom
// setup, …) are all relayed — the manual path works even if eCapture never ran.
type keylogTailer struct {
	path  string
	files map[string]*keylogSource
}

// keylogSource tails one keylog file, tracking its read offset and any partial
// trailing line across reads.
type keylogSource struct {
	f       *os.File
	offset  int64
	partial []byte
}

func newKeylogTailer(path string) *keylogTailer {
	return &keylogTailer{path: path, files: map[string]*keylogSource{}}
}

// sources resolves the set of keylog files to tail: the single file, or every
// "*.log" directly under the directory (re-globbed each tick so files dropped
// mid-connection are picked up). Subdirectories are not descended into, so the
// orchestrator's internal per-target outputs (in a subdir) are not double-read.
func (k *keylogTailer) sources() []string {
	if k.path == "" {
		return nil
	}
	if fi, err := os.Stat(k.path); err == nil && fi.IsDir() {
		m, _ := filepath.Glob(filepath.Join(k.path, "*.log"))
		return m
	}
	return []string{k.path}
}

// emitNew sends any keylog lines appended since the last call across all current
// sources. It is called from the single serve goroutine, so it shares the
// streamer without locking. A missing/unreadable file is skipped (it may appear
// later) and never fails the relay.
func (k *keylogTailer) emitNew(s *streamer) error {
	for _, p := range k.sources() {
		src := k.files[p]
		if src == nil {
			f, err := os.Open(p)
			if err != nil {
				continue // not readable yet; retry next tick
			}
			src = &keylogSource{f: f}
			k.files[p] = src
		}
		if err := src.emit(s); err != nil {
			return err
		}
	}
	return nil
}

// emit sends lines appended to one source since its last read.
func (s *keylogSource) emit(str *streamer) error {
	buf := make([]byte, 64<<10)
	for {
		n, err := s.f.ReadAt(buf, s.offset)
		if n > 0 {
			s.offset += int64(n)
			s.partial = append(s.partial, buf[:n]...)
			for {
				i := bytes.IndexByte(s.partial, '\n')
				if i < 0 {
					break
				}
				line := s.partial[:i]
				s.partial = s.partial[i+1:]
				if len(bytes.TrimSpace(line)) > 0 {
					if werr := str.sendKeylog(line); werr != nil {
						return werr
					}
				}
			}
		}
		// io.EOF at the current tail, a transient read error, or up-to-date:
		// stop for now and resume from the same offset next tick.
		if err != nil || n == 0 {
			return nil
		}
	}
}

func (k *keylogTailer) Close() {
	for _, src := range k.files {
		if src.f != nil {
			src.f.Close()
		}
	}
	k.files = map[string]*keylogSource{}
}
