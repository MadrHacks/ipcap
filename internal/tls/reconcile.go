package tls

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
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
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.mergeOnce(out, seen)
		}
	}
}

func (r *Reconciler) mergeOnce(out *os.File, seen map[string]struct{}) {
	files, _ := filepath.Glob(filepath.Join(r.KeylogDir, "*.log"))
	for _, fp := range files {
		b, err := os.ReadFile(fp)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if _, ok := seen[line]; ok {
				continue
			}
			seen[line] = struct{}{}
			if _, err := out.WriteString(line + "\n"); err != nil {
				return
			}
		}
	}
}

func loadSeen(path string) map[string]struct{} {
	seen := map[string]struct{}{}
	b, err := os.ReadFile(path)
	if err != nil {
		return seen
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			seen[line] = struct{}{}
		}
	}
	return seen
}

func sanitizeKey(key string) string {
	return strings.NewReplacer("/", "_", ":", "_", " ", "_").Replace(key)
}
