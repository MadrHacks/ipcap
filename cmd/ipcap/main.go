// Command ipcap is a durable, SSH-drained PCAP-over-IP transport for the
// MadrHacks A/D infra: a persistent capture agent on the vulnbox and a collector
// on the tulip host, with exactly-once delivery within the spool retention
// window. See DESIGN.md.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"ipcap/internal/agent"
	"ipcap/internal/collector"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(os.Stderr)

	root := &cobra.Command{
		Use:           "ipcap",
		Short:         "Durable SSH-drained PCAP-over-IP transport",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(os.Stderr)
	root.AddCommand(agentCmd(), collectorCmd(), recoverCmd(), versionCmd())

	if err := root.Execute(); err != nil {
		log.Fatalf("ipcap: %v", err)
	}
}

// signalContext cancels on SIGINT/SIGTERM for graceful shutdown.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func agentCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "agent", Short: "Vulnbox-side capture and serve"}
	cmd.AddCommand(agentCaptureCmd(), agentServeCmd())
	return cmd
}

func agentCaptureCmd() *cobra.Command {
	var opts agent.CaptureOptions
	cmd := &cobra.Command{
		Use:   "capture",
		Short: "Persistently capture to the durable spool",
		RunE: func(c *cobra.Command, _ []string) error {
			ctx, cancel := signalContext()
			defer cancel()
			return agent.RunCapture(ctx, opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.SpoolDir, "spool-dir", "/var/lib/ipcap/spool", "durable spool directory")
	f.Uint16Var(&opts.SrcID, "src-id", 1, "source id")
	f.StringVar(&opts.Iface, "iface", "", "capture interface (AF_PACKET)")
	f.StringVar(&opts.PcapFile, "pcap-file", "", "replay a pcap file instead of live capture")
	f.IntVar(&opts.Snaplen, "snaplen", 65536, "capture snap length")
	f.IntVar(&opts.RingMiB, "ring-mib", 256, "AF_PACKET ring size (MiB)")
	f.IntVar(&opts.SSHPort, "ssh-port", 22, "SSH port to exclude from capture")
	f.StringSliceVar(&opts.Mgmt, "mgmt", nil, "management IPs/CIDRs to exclude")
	f.Int64Var(&opts.RetentionBytes, "retention-bytes", 48<<30, "spool byte cap")
	f.Int64Var(&opts.RotateBytes, "rotate-bytes", 64<<20, "segment rotation size")
	return cmd
}

func agentServeCmd() *cobra.Command {
	var opts agent.ServeOptions
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Stream the spool to a connected collector (stdin/stdout)",
		RunE: func(c *cobra.Command, _ []string) error {
			ctx, cancel := signalContext()
			defer cancel()
			opts.In = os.Stdin
			opts.Out = os.Stdout
			return agent.RunServe(ctx, opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.SpoolDir, "spool-dir", "/var/lib/ipcap/spool", "durable spool directory")
	f.Uint16Var(&opts.SrcID, "src-id", 1, "source id")
	f.StringVar(&opts.SrcName, "src-name", "", "source name")
	f.Uint64Var(&opts.Resume, "resume", 0, "resume from this gpidx (next needed)")
	return cmd
}

func collectorCmd() *cobra.Command {
	var opts collector.Options
	cmd := &cobra.Command{
		Use:   "collector",
		Short: "Tulip-host-side SSH drain, mirror, and PCAP-over-IP re-serve",
		RunE: func(c *cobra.Command, _ []string) error {
			ctx, cancel := signalContext()
			defer cancel()
			return collector.Run(ctx, opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.ConfigDir, "config-dir", "/config", "AD infra config dir (vulnbox.yml/infra.yml)")
	f.StringVar(&opts.MirrorDir, "mirror-dir", "/traffic", "durable mirror + resume directory")
	f.Uint16Var(&opts.SrcID, "src-id", 1, "source id")
	f.StringVar(&opts.SrcName, "src-name", "", "source name")
	f.StringVar(&opts.ListenAddr, "listen", ":4242", "local PCAP-over-IP re-serve address")
	f.Uint32Var(&opts.Snaplen, "snaplen", 65536, "snap length")
	f.StringVar(&opts.AgentBin, "agent-bin", "ipcap", "remote ipcap binary path")
	f.StringVar(&opts.AgentSpoolDir, "agent-spool-dir", "/var/lib/ipcap/spool", "remote spool directory")
	f.IntVar(&opts.BufSize, "buf-size", 1<<16, "per-client fan-out buffer (records)")
	return cmd
}

func recoverCmd() *cobra.Command {
	var spoolDir string
	var srcID uint16
	var snaplen, linkType uint32
	cmd := &cobra.Command{
		Use:   "recover",
		Short: "Repair a spool (truncate torn tail) and report the head",
		RunE: func(c *cobra.Command, _ []string) error {
			return agent.RecoverReport(spoolDir, srcID, snaplen, linkType, os.Stdout)
		},
	}
	f := cmd.Flags()
	f.StringVar(&spoolDir, "spool-dir", "/var/lib/ipcap/spool", "durable spool directory")
	f.Uint16Var(&srcID, "src-id", 1, "source id")
	f.Uint32Var(&snaplen, "snaplen", 65536, "snap length")
	f.Uint32Var(&linkType, "link-type", 1, "link type (1=Ethernet)")
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(c *cobra.Command, _ []string) {
			fmt.Fprintln(os.Stdout, "ipcap", version)
		},
	}
}
