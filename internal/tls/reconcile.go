package tls

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ipcap/internal/keylog"
)

// Reconciler keeps the set of running eCapture hooks in sync with the desired
// targets (auto-discovered + operator overrides), reconciling on an interval so
// it picks up container restarts and live config edits. It is the durable,
// self-healing core of the TLS keylog capture.
type Reconciler struct {
	Disco      *Discoverer
	Hooker     Hooker
	ConfigPath string        // live-editable override file ("" = auto only)
	KeylogDir  string        // per-target eCapture keylog outputs
	RelayFile  string        // merged, deduped keylog the listener relays
	Interval   time.Duration // reconcile cadence (default 10s)
	DryRun     bool          // log intended hooks without starting them
}

type hookState struct {
	target Target
	cancel context.CancelFunc
}

// Run reconciles until the context is cancelled. It never returns an error for a
// per-target failure — a failed hook is retried, an unparseable config keeps the
// last good state — so a transient problem never disrupts capture or a service.
func (r *Reconciler) Run(ctx context.Context) error {
	if err := os.MkdirAll(r.KeylogDir, 0o700); err != nil {
		return err
	}
	interval := r.Interval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	go r.mergeLoop(ctx)

	running := map[string]*hookState{}
	defer func() {
		for _, st := range running {
			st.cancel()
		}
	}()

	t := time.NewTicker(interval)
	defer t.Stop()
	r.reconcileOnce(ctx, running)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.reconcileOnce(ctx, running)
		}
	}
}

func (r *Reconciler) reconcileOnce(ctx context.Context, running map[string]*hookState) {
	cfg, err := LoadConfig(r.ConfigPath)
	if err != nil {
		log.Printf("tls: bad override config %s (%v); keeping current hooks", r.ConfigPath, err)
		return
	}
	var auto []Target
	if cfg.AutoEnabled() {
		if a, derr := r.Disco.Discover(); derr != nil {
			log.Printf("tls: discovery error: %v", derr)
		} else {
			auto = a
		}
	}
	desired := map[string]Target{}
	for _, tg := range cfg.Plan(auto) {
		desired[tg.Key] = tg
	}

	for key, st := range running {
		if _, ok := desired[key]; !ok {
			st.cancel()
			delete(running, key)
			log.Printf("tls: unhooked %s", key)
		}
	}
	for key, tg := range desired {
		if _, ok := running[key]; ok {
			continue
		}
		if r.DryRun {
			log.Printf("tls: [dry-run] would hook %s lib=%s path=%s cgroup=%s", key, tg.Library, tg.LibPath, tg.CGroupPath)
			continue
		}
		hctx, hcancel := context.WithCancel(ctx)
		running[key] = &hookState{target: tg, cancel: hcancel}
		go r.runHook(hctx, tg)
		log.Printf("tls: hooking %s lib=%s path=%s cgroup=%s (%s)", key, tg.Library, tg.LibPath, tg.CGroupPath, tg.Source)
	}
}

// runHook runs (and restarts, with backoff) one target's hook until its context
// is cancelled by the reconciler. A crashing eCapture is retried; an
// intentionally stopped one exits cleanly.
func (r *Reconciler) runHook(ctx context.Context, t Target) {
	klf := filepath.Join(r.KeylogDir, sanitizeKey(t.Key)+".log")
	backoff := time.Second
	for ctx.Err() == nil {
		err := r.Hooker.Start(ctx, t, klf)
		if ctx.Err() != nil {
			return
		}
		log.Printf("tls: hook %s exited (%v); retrying in %s", t.Key, err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// mergeLoop merges all per-target keylog files into the single relay file,
// deduplicated, so the listener relays each key once regardless of how many
// hooks (or reconnects) produced it.
func (r *Reconciler) mergeLoop(ctx context.Context) {
	if r.RelayFile == "" {
		return
	}
	seen := loadSeen(r.RelayFile)
	out, err := os.OpenFile(r.RelayFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("tls: open relay keylog %s: %v", r.RelayFile, err)
		return
	}
	defer out.Close()
	states := map[string]*mergeState{}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.mergeOnce(out, seen, states)
		}
	}
}

// mergeState tracks, per per-target keylog file, how far it has been relayed and
// whether we are mid-skip through an oversized (garbage) line that spans reads.
type mergeState struct {
	off      int64
	skipping bool
}

func (r *Reconciler) mergeOnce(out *os.File, seen map[string]struct{}, states map[string]*mergeState) {
	files, _ := filepath.Glob(filepath.Join(r.KeylogDir, "*.log"))
	for _, fp := range files {
		st := states[fp]
		if st == nil {
			st = &mergeState{}
			states[fp] = st
		}
		f, err := os.Open(fp)
		if err != nil {
			continue
		}
		mergeTail(f, st, out, seen)
		f.Close()
	}
}

// mergeTail relays complete, valid keylog lines appended to f since st.off,
// writing each unseen one to out. It reads in bounded chunks and never buffers
// more than one capped line, so a runaway per-target file — e.g. a
// never-terminating zero-padded line from a buggy eCapture build — can neither
// exhaust memory nor bloat the relay. An unterminated trailing line is left for
// the next tick by rewinding st.off to its start.
func mergeTail(f *os.File, st *mergeState, out *os.File, seen map[string]struct{}) {
	buf := make([]byte, 64<<10)
	var partial []byte
	for {
		n, rerr := f.ReadAt(buf, st.off)
		chunk := buf[:n]
		for len(chunk) > 0 {
			i := bytes.IndexByte(chunk, '\n')
			if i < 0 { // no newline in this chunk
				st.off += int64(len(chunk))
				if !st.skipping {
					partial = append(partial, chunk...)
					if len(partial) > keylog.MaxLineLen {
						partial = partial[:0] // oversized: drop and skip to next '\n'
						st.skipping = true
					}
				}
				break
			}
			st.off += int64(i + 1)
			if st.skipping {
				st.skipping = false // this newline ends the garbage line
			} else {
				line := append(partial, chunk[:i]...)
				if keylog.Valid(line) {
					key := string(bytes.TrimSpace(line))
					if _, ok := seen[key]; !ok {
						seen[key] = struct{}{}
						if _, werr := out.WriteString(key + "\n"); werr != nil {
							return
						}
					}
				}
				partial = partial[:0]
			}
			chunk = chunk[i+1:]
		}
		if rerr != nil || n == 0 {
			break
		}
	}
	st.off -= int64(len(partial)) // re-read the unterminated tail next tick
}

// loadSeen primes the dedupe set from the VALID lines already in the relay file,
// streaming and skipping over-long lines so a previously-bloated relay can never
// exhaust memory.
func loadSeen(path string) map[string]struct{} {
	seen := map[string]struct{}{}
	f, err := os.Open(path)
	if err != nil {
		return seen
	}
	defer f.Close()
	br := bufio.NewReader(f)
	for {
		line, rerr := br.ReadSlice('\n')
		if keylog.Valid(line) {
			seen[string(bytes.TrimSpace(line))] = struct{}{}
		}
		if rerr != nil {
			if rerr == bufio.ErrBufferFull {
				for {
					if _, e := br.ReadSlice('\n'); e != bufio.ErrBufferFull {
						break
					}
				}
				continue
			}
			break
		}
	}
	return seen
}

func sanitizeKey(key string) string {
	return strings.NewReplacer("/", "_", ":", "_", " ", "_").Replace(key)
}
