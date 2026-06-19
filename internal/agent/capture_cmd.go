// Package agent implements the two crash-isolated vulnbox-side processes: the
// persistent capture writer and the short-lived, read-only serve streamer.
package agent

import (
	"context"
	"errors"
	"io"
	"log"
	"time"

	"ipcap/internal/capture"
	"ipcap/internal/pcapio"
	"ipcap/internal/spool"
)

// CaptureOptions configures the persistent capture process.
type CaptureOptions struct {
	SpoolDir       string
	SrcID          uint16
	Iface          string // AF_PACKET interface (vulnbox)
	PcapFile       string // offline replay source (testing); takes precedence
	Snaplen        int
	RingMiB        int
	SSHPort        int
	Mgmt           []string
	RetentionBytes int64
	RotateBytes    int64
}

// RunCapture opens the packet source and durably spools every non-excluded
// packet, assigning each a gpidx. It is the zero-loss anchor: it never depends
// on any collector being connected. It returns when the context is cancelled
// (live capture) or the replay source reaches EOF (offline).
func RunCapture(ctx context.Context, opts CaptureOptions) error {
	if opts.Snaplen <= 0 {
		opts.Snaplen = 65536
	}

	var (
		src     capture.Source
		err     error
		offline bool
	)
	if opts.PcapFile != "" {
		src, err = capture.OpenFile(opts.PcapFile)
		offline = true
	} else {
		src, err = capture.OpenAFPacket(opts.Iface, opts.RingMiB, opts.Snaplen)
	}
	if err != nil {
		return err
	}
	defer src.Close()

	linkType := src.LinkType()
	excluder := capture.NewExcluder(linkType, opts.SSHPort, opts.Mgmt)
	// Make the self-capture exclusion visible: ssh-port MUST match the vulnbox
	// sshd port (and/or --mgmt cover the collector host) or the serve drain is
	// recaptured and re-served, amplifying without bound.
	log.Printf("capture: src=%d iface=%q spool=%q excluding ssh-port=%d mgmt=%v",
		opts.SrcID, opts.Iface, opts.SpoolDir, opts.SSHPort, opts.Mgmt)

	w, err := spool.NewWriter(spool.Config{
		Dir:         opts.SpoolDir,
		SrcID:       opts.SrcID,
		Snaplen:     uint32(opts.Snaplen),
		LinkType:    linkType,
		RotateBytes: opts.RotateBytes,
	})
	if err != nil {
		return err
	}
	defer w.Close()

	// Time-based flush, rotation and retention run independently of packet
	// arrival so idle periods still bound un-synced data and disk use.
	stop := make(chan struct{})
	defer close(stop)
	go maintenanceLoop(ctx, stop, w, opts.RetentionBytes)

	// The read loop owns the source exclusively: the live source's poll timeout
	// surfaces as ErrTimeout, an idle tick where the loop observes cancellation
	// and returns, so the source is never closed concurrently with a read.
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		ts, data, origLen, err := src.ReadPacket()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			if errors.Is(err, capture.ErrTimeout) {
				continue
			}
			if offline && errors.Is(err, io.EOF) {
				return nil
			}
			if offline {
				return err
			}
			log.Printf("capture: read error: %v", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if excluder.Exclude(data) {
			continue
		}
		rec := pcapio.Record{
			TsSec:   uint32(ts.Unix()),
			TsUsec:  uint32(ts.Nanosecond() / 1000),
			OrigLen: uint32(origLen),
			Data:    data,
		}
		if _, err := w.WritePacket(rec); err != nil {
			return err
		}
	}
}

func maintenanceLoop(ctx context.Context, stop <-chan struct{}, w *spool.Writer, retentionBytes int64) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	reapEvery := time.NewTicker(2 * time.Second)
	defer reapEvery.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
			if err := w.Tick(); err != nil {
				log.Printf("capture: tick: %v", err)
			}
		case <-reapEvery.C:
			if retentionBytes > 0 {
				if n, err := w.Reap(retentionBytes); err != nil {
					log.Printf("capture: reap: %v", err)
				} else if n > 0 {
					log.Printf("capture: reaped %d segment(s); oldest gpidx now %d", n, w.OldestGpidx())
				}
			}
		}
	}
}
