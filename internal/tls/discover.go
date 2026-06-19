// Package tls auto-discovers TLS-using docker containers on the vulnbox, targets
// the right crypto library per container, and drives eCapture to extract NSS
// keylog material — surviving container restarts and tolerating live operator
// overrides when auto-detection is wrong. The keys are written to a file that
// `ipcap agent listen --keylog-file` relays as TLS_KEYLOG frames.
//
// Everything here is hook-orchestration only: it never touches the vulnservices'
// processes (eCapture uses non-invasive eBPF uprobes in a separate, crash-
// isolated subprocess), and any failure degrades to "no keys for that target",
// never to disrupted capture or a broken service.
package tls

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Library identifies which TLS library (and thus which eCapture probe) a target
// uses.
type Library string

const (
	LibOpenSSL Library = "openssl" // libssl/libcrypto (also BoringSSL)
	LibGnuTLS  Library = "gnutls"  // libgnutls
	LibGoTLS   Library = "gotls"   // statically-linked Go crypto/tls
)

// Target is one (container, library) pair to hook.
type Target struct {
	Key        string  // stable dedup/identity key
	Container  string  // short container id (best effort)
	PID        int     // a representative live pid in the container
	Library    Library //
	LibPath    string  // host-visible path to the library/binary to hook
	CGroupPath string  // host cgroup-v2 path, for eCapture --cgroup_path filtering
	Source     string  // "auto" or "override"
}

// Discoverer scans procfs for TLS-using container processes. The roots are
// overridable for testing.
type Discoverer struct {
	ProcRoot   string // default /proc
	CgroupRoot string // default /sys/fs/cgroup
}

func NewDiscoverer() *Discoverer {
	return &Discoverer{ProcRoot: "/proc", CgroupRoot: "/sys/fs/cgroup"}
}

// dockerCgroup matches a docker container's cgroup-v2 leaf (…/docker-<64hex>.scope
// or …/docker/<64hex>) and captures the container id.
var dockerCgroup = regexp.MustCompile(`docker[-/]([0-9a-f]{12,64})(?:\.scope)?`)

var (
	reLibssl    = regexp.MustCompile(`/libssl\.so`)
	reLibcrypto = regexp.MustCompile(`/libcrypto\.so`)
	reGnuTLS    = regexp.MustCompile(`/libgnutls\.so`)
)

// Discover returns the deduplicated set of container TLS targets currently
// running. A process whose cgroup is not a docker container, or that maps no
// recognised TLS library, is skipped. Errors reading any single process are
// ignored (it may have exited mid-scan); only a failure to list procfs is fatal.
func (d *Discoverer) Discover() ([]Target, error) {
	procRoot := d.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	cgroupRoot := d.CgroupRoot
	if cgroupRoot == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}

	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("tls: read %s: %w", procRoot, err)
	}

	byKey := map[string]Target{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a pid dir
		}
		container, cgPath := d.containerCgroup(procRoot, cgroupRoot, pid)
		if container == "" {
			continue // not in a docker container
		}
		for lib, libPath := range d.detectLibraries(procRoot, pid) {
			key := container[:12] + "/" + string(lib)
			if _, ok := byKey[key]; ok {
				continue // already have this container+library from another pid
			}
			byKey[key] = Target{
				Key:        key,
				Container:  container[:12],
				PID:        pid,
				Library:    lib,
				LibPath:    libPath,
				CGroupPath: cgPath,
				Source:     "auto",
			}
		}
	}

	out := make([]Target, 0, len(byKey))
	for _, t := range byKey {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// containerCgroup returns the container id and host cgroup path for a pid, or
// ("", "") if the pid is not in a docker container.
func (d *Discoverer) containerCgroup(procRoot, cgroupRoot string, pid int) (string, string) {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		// cgroup v2: "0::/system.slice/docker-<id>.scope"
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		rel := parts[2]
		m := dockerCgroup.FindStringSubmatch(rel)
		if m == nil {
			continue
		}
		return m[1], filepath.Join(cgroupRoot, rel)
	}
	return "", ""
}

// detectLibraries inspects a pid's memory maps for known TLS libraries and
// returns each library kind mapped to its host-visible path (under the pid's
// mount namespace root).
func (d *Discoverer) detectLibraries(procRoot string, pid int) map[Library]string {
	f, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "maps"))
	if err != nil {
		return nil
	}
	defer f.Close()

	root := filepath.Join(procRoot, strconv.Itoa(pid), "root")
	var libssl, libcrypto, gnutls string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, '/')
		if i < 0 {
			continue
		}
		path := line[i:]
		switch {
		case libssl == "" && reLibssl.MatchString(path):
			libssl = path
		case libcrypto == "" && reLibcrypto.MatchString(path):
			libcrypto = path
		case gnutls == "" && reGnuTLS.MatchString(path):
			gnutls = path
		}
	}

	out := map[Library]string{}
	// eCapture's openssl probe hooks libssl; fall back to libcrypto only if a
	// service maps libcrypto without a separate libssl.
	if libssl != "" {
		out[LibOpenSSL] = filepath.Join(root, libssl)
	} else if libcrypto != "" {
		out[LibOpenSSL] = filepath.Join(root, libcrypto)
	}
	if gnutls != "" {
		out[LibGnuTLS] = filepath.Join(root, gnutls)
	}
	return out
}
