package collector

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"ipcap/internal/config"
	"ipcap/internal/pcapio"
	"ipcap/internal/pcapoverip"
)

// Options configures a single-source collector.
type Options struct {
	ConfigDir     string
	MirrorDir     string
	SrcID         uint16
	SrcName       string
	ListenAddr    string // local PCAP-over-IP re-serve, e.g. ":4242"
	Snaplen       uint32
	AgentBin      string // remote ipcap binary
	AgentSpoolDir string // remote spool directory
	BufSize       int

	// Spawn overrides how the agent serve process is launched (tests inject a
	// local exec). When nil, an SSH command is built from the vulnbox config.
	Spawn func(ctx context.Context, vb config.Vulnbox, resume uint64) (*exec.Cmd, error)
}

// Run holds the mirror lock, starts the re-serve listener, and supervises the
// SSH drain: connect, demux+commit, and on any failure reconnect from the last
// durable commit point with backoff and config reload.
func Run(ctx context.Context, opts Options) error {
	if opts.Snaplen == 0 {
		opts.Snaplen = 65536
	}
	if opts.SrcName == "" {
		opts.SrcName = fmt.Sprintf("ipcap-src%d", opts.SrcID)
	}
	if err := os.MkdirAll(opts.MirrorDir, 0o755); err != nil {
		return err
	}
	unlock, err := flockDir(opts.MirrorDir)
	if err != nil {
		return err
	}
	defer unlock()

	gh := pcapio.GlobalHeader{Snaplen: opts.Snaplen, LinkType: 1} // Ethernet until preamble
	mirror, err := OpenMirror(opts.MirrorDir, opts.SrcID, gh)
	if err != nil {
		return err
	}
	defer mirror.Close()

	server := pcapoverip.NewServer(mirror.Header(), opts.BufSize)
	if opts.ListenAddr != "" {
		go func() {
			if err := server.Listen(ctx, opts.ListenAddr); err != nil {
				log.Printf("collector: listener: %v", err)
			}
		}()
	}

	spawn := opts.Spawn
	if spawn == nil {
		spawn = sshSpawner(opts)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		vb, _, cerr := config.Load(opts.ConfigDir)
		if cerr != nil {
			log.Printf("collector: config load: %v", cerr)
		}
		if vb.IP == "" {
			log.Printf("collector: vulnbox IP not configured yet; waiting")
			if sleepCtx(ctx, 5*time.Second) {
				return nil
			}
			continue
		}

		resume := mirror.Committed()
		if err := runOnce(ctx, opts, vb, mirror, server, spawn, resume); err != nil {
			log.Printf("collector: src%d session ended: %v", opts.SrcID, err)
		}
		if sleepCtx(ctx, 2*time.Second) {
			return nil
		}
	}
}

// runOnce spawns one agent serve, drains it, and returns when it ends.
func runOnce(ctx context.Context, opts Options, vb config.Vulnbox, mirror *Mirror, server *pcapoverip.Server, spawn func(context.Context, config.Vulnbox, uint64) (*exec.Cmd, error), resume uint64) error {
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd, err := spawn(sessCtx, vb, resume)
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	log.Printf("collector: src%d connected, resume from gpidx %d", opts.SrcID, resume)

	demux := NewDemux(opts.SrcID, opts.SrcName, mirror, server, stdin)
	runErr := demux.Run(sessCtx, stdout)

	cancel()
	stdin.Close()
	_ = cmd.Wait()
	return runErr
}

// sshSpawner builds the default SSH command, reusing trafficsync/sync.py's
// option set plus keepalives, and running the remote agent serve.
func sshSpawner(opts Options) func(context.Context, config.Vulnbox, uint64) (*exec.Cmd, error) {
	agentBin := opts.AgentBin
	if agentBin == "" {
		agentBin = "ipcap"
	}
	return func(ctx context.Context, vb config.Vulnbox, resume uint64) (*exec.Cmd, error) {
		remote := []string{
			agentBin, "agent", "serve",
			"--src-id", fmt.Sprintf("%d", opts.SrcID),
			"--src-name", opts.SrcName,
			"--spool-dir", opts.AgentSpoolDir,
			"--resume", fmt.Sprintf("%d", resume),
		}
		// ssh options must precede the destination; anything after it is the
		// remote command.
		args := []string{
			"-o", "StrictHostKeyChecking=accept-new",
			"-o", "ServerAliveInterval=5",
			"-o", "ServerAliveCountMax=2",
			"-o", "Compression=no",
			"-p", fmt.Sprintf("%d", vb.Port()),
			fmt.Sprintf("%s@%s", vb.User(), vb.IP),
			"--",
		}
		args = append(args, remote...)

		name := "ssh"
		env := os.Environ()
		if vb.SSHPassword != "" {
			name = "sshpass"
			args = append([]string{"-e", "ssh"}, args...)
			env = append(env, "SSHPASS="+vb.SSHPassword)
		}
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = env
		return cmd, nil
	}
}

// flockDir takes an exclusive, non-blocking lock so two collectors can never
// corrupt the same mirror.
func flockDir(dir string) (func(), error) {
	lockPath := filepath.Join(dir, ".collector.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("mirror dir %s is locked by another collector: %w", dir, err)
	}
	return func() {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}, nil
}

func sleepCtx(ctx context.Context, d time.Duration) (cancelled bool) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-t.C:
		return false
	}
}
