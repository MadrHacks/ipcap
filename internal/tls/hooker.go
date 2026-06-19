package tls

import (
	"context"
	"fmt"
	"io"
	"os/exec"
)

// Hooker hooks a target and writes its keylog lines to keylogFile until ctx is
// cancelled, blocking until the hook exits. It is an interface so the
// reconciler is testable without eBPF.
type Hooker interface {
	Start(ctx context.Context, t Target, keylogFile string) error
}

// EcaptureHooker drives the eCapture binary as an isolated subprocess — an eBPF
// crash in eCapture cannot take down ipcap, capture, or the vulnservice.
type EcaptureHooker struct {
	Bin    string    // path to the ecapture binary
	Stderr io.Writer // eCapture diagnostics sink
}

func (h *EcaptureHooker) Start(ctx context.Context, t Target, keylogFile string) error {
	args, err := ecaptureArgs(t, keylogFile)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, h.Bin, args...)
	cmd.Stderr = h.Stderr
	return cmd.Run()
}

// ecaptureArgs builds the eCapture keylog-mode invocation for a target. All
// three probes accept --cgroup_path for container scoping, which keeps a hook
// confined to its target container.
func ecaptureArgs(t Target, keylogFile string) ([]string, error) {
	switch t.Library {
	case LibOpenSSL:
		a := []string{"tls", "-m", "keylog", "-k", keylogFile}
		if t.LibPath != "" {
			a = append(a, "--libssl", t.LibPath)
		}
		if t.CGroupPath != "" {
			a = append(a, "--cgroup_path", t.CGroupPath)
		}
		return a, nil
	case LibGnuTLS:
		a := []string{"gnutls", "-m", "keylog", "-k", keylogFile}
		if t.LibPath != "" {
			a = append(a, "--gnutls", t.LibPath)
		}
		if t.CGroupPath != "" {
			a = append(a, "--cgroup_path", t.CGroupPath)
		}
		return a, nil
	case LibGoTLS:
		if t.LibPath == "" {
			return nil, fmt.Errorf("tls: gotls target %q needs an elf path", t.Key)
		}
		a := []string{"gotls", "-m", "keylog", "-k", keylogFile, "--elfpath", t.LibPath}
		if t.CGroupPath != "" {
			a = append(a, "--cgroup_path", t.CGroupPath)
		}
		return a, nil
	default:
		return nil, fmt.Errorf("tls: unknown library %q for target %q", t.Library, t.Key)
	}
}
