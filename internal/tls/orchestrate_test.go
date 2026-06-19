package tls

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEcaptureArgs(t *testing.T) {
	cases := []struct {
		tgt  Target
		want []string
	}{
		{Target{Key: "k", Library: LibOpenSSL, LibPath: "/p/libssl.so", CGroupPath: "/cg"},
			[]string{"tls", "-m", "keylog", "-k", "out", "--libssl", "/p/libssl.so", "--cgroup_path", "/cg"}},
		{Target{Key: "k", Library: LibGnuTLS, LibPath: "/p/libgnutls.so"},
			[]string{"gnutls", "-m", "keylog", "-k", "out", "--gnutls", "/p/libgnutls.so"}},
		{Target{Key: "k", Library: LibGoTLS, LibPath: "/app/server", CGroupPath: "/cg"},
			[]string{"gotls", "-m", "keylog", "-k", "out", "--elfpath", "/app/server", "--cgroup_path", "/cg"}},
	}
	for _, c := range cases {
		got, err := ecaptureArgs(c.tgt, "out")
		if err != nil {
			t.Fatalf("%s: %v", c.tgt.Library, err)
		}
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Fatalf("%s args = %v, want %v", c.tgt.Library, got, c.want)
		}
	}
	if _, err := ecaptureArgs(Target{Key: "k", Library: LibGoTLS}, "out"); err == nil {
		t.Fatal("gotls without elf path should error")
	}
}

func TestConfigPlanMergeAndExclude(t *testing.T) {
	auto := []Target{
		{Key: "aaaaaaaaaaaa/openssl", Container: "aaaaaaaaaaaa", Library: LibOpenSSL, Source: "auto"},
		{Key: "bbbbbbbbbbbb/openssl", Container: "bbbbbbbbbbbb", Library: LibOpenSSL, Source: "auto"},
	}
	tru := true
	cfg := Config{
		Auto:    &tru,
		Exclude: []string{"bbbbbbbbbbbb"}, // exclude one auto target
		Targets: []OverrideTarget{
			{Container: "mygo", Library: "gotls", Path: "/app/srv"}, // manual addition
		},
	}
	plan := cfg.Plan(auto)
	keys := map[string]Target{}
	for _, tg := range plan {
		keys[tg.Key] = tg
	}
	if _, ok := keys["aaaaaaaaaaaa/openssl"]; !ok {
		t.Fatal("auto target a should be present")
	}
	if _, ok := keys["bbbbbbbbbbbb/openssl"]; ok {
		t.Fatal("excluded target b should be absent")
	}
	if _, ok := keys["mygo/gotls//app/srv"]; !ok {
		t.Fatalf("manual gotls target should be present; have %v", keys)
	}
}

// mockHooker records starts and blocks (like a live hook) until cancelled,
// writing a keylog line so the merger has something to relay.
type mockHooker struct {
	mu     sync.Mutex
	starts map[string]int
	active map[string]bool
}

func newMockHooker() *mockHooker {
	return &mockHooker{starts: map[string]int{}, active: map[string]bool{}}
}

func (h *mockHooker) Start(ctx context.Context, t Target, keylogFile string) error {
	h.mu.Lock()
	h.starts[t.Key]++
	h.active[t.Key] = true
	h.mu.Unlock()
	_ = os.WriteFile(keylogFile, []byte("CLIENT_RANDOM "+t.Container+"\n"), 0o644)
	<-ctx.Done()
	h.mu.Lock()
	h.active[t.Key] = false
	h.mu.Unlock()
	return ctx.Err()
}

func (h *mockHooker) isActive(substr string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for k, on := range h.active {
		if on && strings.Contains(k, substr) {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for: %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestReconcileLifecycle drives the reconciler with config-only targets and a
// mock hooker, verifying hooks start, keys are merged+deduped into the relay
// file, and a live config edit removing a target stops exactly that hook.
func TestReconcileLifecycle(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "tls.yml")
	keylogDir := filepath.Join(dir, "keylogs")
	relay := filepath.Join(dir, "ssl_keys.log")

	writeCfg := func(containers ...string) {
		var b strings.Builder
		b.WriteString("auto: false\ntargets:\n")
		for _, c := range containers {
			b.WriteString("  - container: " + c + "\n    library: openssl\n    path: /x/libssl.so\n")
		}
		if err := os.WriteFile(cfgPath, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeCfg("svc-a", "svc-b")

	mh := newMockHooker()
	r := &Reconciler{
		Disco:      NewDiscoverer(),
		Hooker:     mh,
		ConfigPath: cfgPath,
		KeylogDir:  keylogDir,
		RelayFile:  relay,
		Interval:   150 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx) }()

	// Both hooks active and both keys merged into the relay file.
	waitFor(t, "both hooks active", func() bool { return mh.isActive("svc-a") && mh.isActive("svc-b") })
	waitFor(t, "both keys relayed", func() bool {
		b, _ := os.ReadFile(relay)
		return strings.Contains(string(b), "svc-a") && strings.Contains(string(b), "svc-b")
	})

	// Live edit: drop svc-b. Only its hook must stop.
	writeCfg("svc-a")
	waitFor(t, "svc-b unhooked", func() bool { return !mh.isActive("svc-b") })
	if !mh.isActive("svc-a") {
		t.Fatal("svc-a should still be hooked")
	}

	// Dedup: the relay file must have each key exactly once despite re-merging.
	b, _ := os.ReadFile(relay)
	if n := strings.Count(string(b), "CLIENT_RANDOM svc-a"); n != 1 {
		t.Fatalf("svc-a appears %d times in relay, want 1 (dedup)", n)
	}
}
