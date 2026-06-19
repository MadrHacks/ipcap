// Command ipcap is a durable, Noise-secured PCAP-over-IP transport for the
// MadrHacks A/D infra: a persistent capture+listen agent on the vulnbox and a
// collector on the tulip host, with exactly-once delivery within the spool
// retention window. See DESIGN.md.
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
	"ipcap/internal/transport"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(os.Stderr)

	root := &cobra.Command{
		Use:           "ipcap",
		Short:         "Durable Noise-secured PCAP-over-IP transport",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(os.Stderr)
	root.AddCommand(agentCmd(), collectorCmd(), recoverCmd(), keygenCmd(), versionCmd())

	if err := root.Execute(); err != nil {
		log.Fatalf("ipcap: %v", err)
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func agentCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "agent", Short: "Vulnbox-side capture and Noise listener"}
	cmd.AddCommand(agentCaptureCmd(), agentListenCmd())
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
	f.IntSliceVar(&opts.ExcludePorts, "exclude-port", []int{7878}, "TCP ports to exclude from capture; MUST include the Noise drain port")
	f.StringSliceVar(&opts.Mgmt, "mgmt", nil, "management IPs/CIDRs to exclude")
	f.Int64Var(&opts.RetentionBytes, "retention-bytes", 48<<30, "spool byte cap")
	f.Int64Var(&opts.RotateBytes, "rotate-bytes", 64<<20, "segment rotation size")
	return cmd
}

func agentListenCmd() *cobra.Command {
	var (
		opts     agent.ListenOptions
		keyFile  string
		peerB64s []string
	)
	cmd := &cobra.Command{
		Use:   "listen",
		Short: "Serve the spool to authenticated collectors over Noise",
		RunE: func(c *cobra.Command, _ []string) error {
			key, err := transport.LoadPrivateKeyFile(keyFile)
			if err != nil {
				return fmt.Errorf("load --key: %w", err)
			}
			peers, err := transport.ParsePublicKeys(peerB64s)
			if err != nil {
				return fmt.Errorf("parse --peer: %w", err)
			}
			opts.Key = key
			opts.AllowedPeers = peers
			ctx, cancel := signalContext()
			defer cancel()
			return agent.RunListen(ctx, opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.SpoolDir, "spool-dir", "/var/lib/ipcap/spool", "durable spool directory")
	f.Uint16Var(&opts.SrcID, "src-id", 1, "source id")
	f.StringVar(&opts.SrcName, "src-name", "", "source name")
	f.StringVar(&opts.ListenAddr, "listen", ":7878", "Noise listen address")
	f.BoolVar(&opts.Compress, "compress", true, "zstd-compress packet batches on the link")
	f.StringVar(&keyFile, "key", "/etc/ipcap/agent.key", "this agent's private key file (base64)")
	f.StringSliceVar(&peerB64s, "peer", nil, "authorized collector public key (base64; repeatable)")
	return cmd
}

func collectorCmd() *cobra.Command {
	var (
		opts    collector.Options
		keyFile string
	)
	cmd := &cobra.Command{
		Use:   "collector",
		Short: "Tulip-host-side Noise drain, mirror, and PCAP-over-IP re-serve",
		RunE: func(c *cobra.Command, _ []string) error {
			key, err := transport.LoadPrivateKeyFile(keyFile)
			if err != nil {
				return fmt.Errorf("load --key: %w", err)
			}
			opts.Key = key
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
	f.StringVar(&keyFile, "key", "/etc/ipcap/collector.key", "this collector's private key file (base64)")
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

func keygenCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a Noise static keypair",
		RunE: func(c *cobra.Command, _ []string) error {
			k, err := transport.Generate()
			if err != nil {
				return err
			}
			if out != "" {
				if err := os.WriteFile(out, []byte(k.PrivateB64()+"\n"), 0o600); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "wrote private key to %s\n", out)
				fmt.Fprintf(os.Stdout, "public key: %s\n", k.PublicB64())
				return nil
			}
			fmt.Fprintf(os.Stdout, "private: %s\npublic:  %s\n", k.PrivateB64(), k.PublicB64())
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "write the private key to this file (0600); print public to stdout")
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
