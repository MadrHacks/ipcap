package tls

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMergeRejectsOversizedGarbage reproduces the keylog-bloat bug: a per-target
// eCapture file whose trailing line is a valid label followed by a megabyte of
// zero padding and no newline. The old merge re-emitted that growing
// unterminated tail every tick, ballooning the relay to gigabytes. The fix must
// relay only the real keys and keep the relay tiny.
func TestMergeRejectsOversizedGarbage(t *testing.T) {
	dir := t.TempDir()
	relay := filepath.Join(dir, "relay.log")
	kdir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(kdir, 0o755); err != nil {
		t.Fatal(err)
	}

	cr := strings.Repeat("a", 64)
	secret := strings.Repeat("b", 64)
	valid1 := "CLIENT_RANDOM " + cr + " " + secret
	valid2 := "SERVER_TRAFFIC_SECRET_0 " + cr + " " + secret
	// a valid prefix + 1 MiB of zero padding + NO newline: the eCapture garbage.
	garbage := "CLIENT_TRAFFIC_SECRET_0 " + cr + " " + secret + strings.Repeat("0", 1<<20)

	src := filepath.Join(kdir, "t.log")
	if err := os.WriteFile(src, []byte(valid1+"\n"+garbage), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &Reconciler{KeylogDir: kdir}
	out, err := os.OpenFile(relay, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	seen := loadSeen(relay)
	states := map[string]*mergeState{}

	// Several ticks while the garbage tail is still unterminated.
	for i := 0; i < 3; i++ {
		r.mergeOnce(out, seen, states)
	}
	// The garbage line finally terminates, and a real key follows it.
	f, err := os.OpenFile(src, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\n" + valid2 + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	for i := 0; i < 2; i++ {
		r.mergeOnce(out, seen, states)
	}
	out.Close()

	got, err := os.ReadFile(relay)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > 4096 {
		t.Fatalf("relay bloated to %d bytes; garbage leaked through", len(got))
	}
	lines := strings.Split(strings.TrimSpace(string(got)), "\n")
	want := []string{valid1, valid2}
	if len(lines) != len(want) {
		t.Fatalf("relay = %d lines, want %d: %.200q", len(lines), len(want), got)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("relay line %d = %.80q, want %.80q", i, lines[i], want[i])
		}
	}
}
