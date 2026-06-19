package tls

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func writePidFixture(t *testing.T, proc string, pid int, cgroup string, maps []string) {
	t.Helper()
	dir := filepath.Join(proc, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := ""
	for _, m := range maps {
		body += m + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "maps"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscover(t *testing.T) {
	proc := t.TempDir()
	const c1 = "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
	const c2 = "ffff1111ffff1111ffff1111ffff1111ffff1111ffff1111ffff1111ffff2222"
	const c3 = "0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000bbbb"

	// Two processes in the same OpenSSL container (must dedup to one target).
	writePidFixture(t, proc, 100, "0::/system.slice/docker-"+c1+".scope", []string{
		"7f0000000000-7f0000001000 r-xp 0 08:01 1 /usr/lib64/libssl.so.3.5.4",
		"7f0000002000-7f0000003000 r-xp 0 08:01 2 /usr/lib64/libcrypto.so.3.5.4",
	})
	writePidFixture(t, proc, 101, "0::/system.slice/docker-"+c1+".scope", []string{
		"7f0000000000-7f0000001000 r-xp 0 08:01 1 /usr/lib64/libssl.so.3.5.4",
	})
	// A gnutls container.
	writePidFixture(t, proc, 200, "0::/system.slice/docker-"+c2+".scope", []string{
		"7f0000000000-7f0000001000 r-xp 0 08:01 3 /usr/lib/x86_64-linux-gnu/libgnutls.so.30",
	})
	// A host process (not a container) — must be skipped.
	writePidFixture(t, proc, 300, "0::/init.scope", []string{
		"7f0000000000-7f0000001000 r-xp 0 08:01 1 /usr/lib/libssl.so.3",
	})
	// A container with no TLS library — must be skipped.
	writePidFixture(t, proc, 400, "0::/system.slice/docker-"+c3+".scope", []string{
		"7f0000000000-7f0000001000 r-xp 0 08:01 9 /usr/bin/redis-server",
	})

	d := &Discoverer{ProcRoot: proc, CgroupRoot: "/sys/fs/cgroup"}
	got, err := d.Discover()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d targets, want 2: %+v", len(got), got)
	}

	byKey := map[string]Target{}
	for _, tg := range got {
		byKey[tg.Key] = tg
	}
	ssl, ok := byKey[c1[:12]+"/openssl"]
	if !ok {
		t.Fatalf("missing openssl target; have %+v", got)
	}
	if ssl.Library != LibOpenSSL || ssl.CGroupPath != "/sys/fs/cgroup/system.slice/docker-"+c1+".scope" {
		t.Fatalf("openssl target wrong: %+v", ssl)
	}
	wantPath := filepath.Join(proc, "100", "root", "/usr/lib64/libssl.so.3.5.4")
	wantPath2 := filepath.Join(proc, "101", "root", "/usr/lib64/libssl.so.3.5.4")
	if ssl.LibPath != wantPath && ssl.LibPath != wantPath2 {
		t.Fatalf("openssl libpath = %q, want under pid 100/101 root", ssl.LibPath)
	}
	if g, ok := byKey[c2[:12]+"/gnutls"]; !ok || g.Library != LibGnuTLS {
		t.Fatalf("missing/wrong gnutls target: %+v", byKey)
	}
}
