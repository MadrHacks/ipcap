package agent

import (
	"bytes"
	"io"
	"os"
)

// keylogTailer streams NSS keylog lines (written by eCapture's `tls -m keylog`
// mode) over the link as TLS_KEYLOG frames, so a future tulip TLS pass can
// decrypt the captured traffic. It re-sends from the start on every connection
// (keys are idempotent — the collector dedupes), so no separate resume state is
// needed; missing a key only costs decryptability of that one flow, never
// packet capture.
type keylogTailer struct {
	path    string
	f       *os.File
	offset  int64
	partial []byte
}

func newKeylogTailer(path string) *keylogTailer {
	return &keylogTailer{path: path}
}

// emitNew sends any keylog lines appended since the last call. It is called from
// the single serve goroutine, so it shares the streamer without locking. A
// missing file (eCapture not running yet) is not an error — it retries later.
func (k *keylogTailer) emitNew(s *streamer) error {
	if k.path == "" {
		return nil
	}
	if k.f == nil {
		f, err := os.Open(k.path)
		if err != nil {
			return nil
		}
		k.f = f
	}
	buf := make([]byte, 64<<10)
	for {
		n, err := k.f.ReadAt(buf, k.offset)
		if n > 0 {
			k.offset += int64(n)
			k.partial = append(k.partial, buf[:n]...)
			for {
				i := bytes.IndexByte(k.partial, '\n')
				if i < 0 {
					break
				}
				line := k.partial[:i]
				k.partial = k.partial[i+1:]
				if len(bytes.TrimSpace(line)) > 0 {
					if werr := s.sendKeylog(line); werr != nil {
						return werr
					}
				}
			}
		}
		if err != nil { // io.EOF at the current tail, or a real error
			if err == io.EOF {
				return nil
			}
			return nil // transient read error; retry next tick
		}
		if n == 0 {
			return nil
		}
	}
}

func (k *keylogTailer) Close() {
	if k.f != nil {
		k.f.Close()
		k.f = nil
	}
}
