package collector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"ipcap/internal/pcapio"
	"ipcap/internal/proto"
)

// isCorruptErr reports whether a frame read failed due to corruption rather
// than a clean disconnect, so the collector can count it.
func isCorruptErr(err error) bool {
	return errors.Is(err, proto.ErrPayCRC) || errors.Is(err, proto.ErrHdrCRC) ||
		errors.Is(err, proto.ErrBadMagic) || errors.Is(err, proto.ErrBadVersion) ||
		errors.Is(err, proto.ErrPayloadHuge)
}

// Demux decodes one agent connection's frame stream, dedupes by gpidx, and
// commits surviving packets to the mirror in strict order; the PCAP-over-IP
// fan-out tails the mirror independently. It also feeds ACKs back to the agent.
type Demux struct {
	srcID  uint16
	name   string
	mirror *Mirror
	ackOut io.Writer
	m      *Metrics

	lastAckAt   time.Time
	committedAt uint64
	headGpidx   uint64
}

// NewDemux builds a demux for one source. m may be nil.
func NewDemux(srcID uint16, name string, mirror *Mirror, ackOut io.Writer, m *Metrics) *Demux {
	return &Demux{srcID: srcID, name: name, mirror: mirror, ackOut: ackOut, m: m}
}

// Run reads the preamble then frames until the connection ends or ctx cancels.
// A returned error is a connection-level failure; the supervisor reconnects.
func (d *Demux) Run(ctx context.Context, in io.Reader) error {
	pre, err := proto.ReadPreamble(in)
	if err != nil {
		return err
	}
	for _, s := range pre.Sources {
		if s.ID == d.srcID {
			gh := pcapio.GlobalHeader{Snaplen: s.Snaplen, LinkType: uint32(s.Linktype)}
			if err := d.mirror.SetHeader(gh); err != nil {
				return err
			}
		}
	}
	d.committedAt = d.mirror.Committed()
	d.lastAckAt = time.Now()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		f, err := proto.ReadFrame(in)
		if err != nil {
			if isCorruptErr(err) {
				d.m.onCorrupt()
			}
			return err
		}
		if f.SourceID != d.srcID && f.SourceID != 0 && f.Type != proto.FrameHeartbeat {
			continue // single-source: ignore other sources
		}
		switch f.Type {
		case proto.FramePktBatch:
			payload := f.Payload
			if f.Flags&proto.FlagCompressed != 0 {
				dec, derr := proto.DecompressBatch(payload)
				if derr != nil {
					return derr
				}
				payload = dec
			}
			recs, derr := proto.DecodePktBatch(payload)
			if derr != nil {
				return derr
			}
			if err := d.commit(f.BaseGpidx, recs, f.Seq); err != nil {
				return err
			}
		case proto.FrameGap:
			if err := d.handleGap(f.Payload); err != nil {
				return err
			}
		case proto.FrameHeartbeat:
			if hb, derr := proto.DecodeHeartbeat(f.Payload); derr == nil {
				d.headGpidx = hb.HeadGpidx
				d.m.onLag(hb.HeadGpidx, d.mirror.Committed())
			}
		case proto.FrameStats:
			if st, derr := proto.DecodeStats(f.Payload); derr == nil {
				d.m.onStats(st)
			}
		case proto.FrameSrcInfo:
			// informational
		default:
			if !f.Type.Skippable() {
				return errUnknownFrame(f.Type)
			}
		}
		d.maybeAck(false)
	}
}

// commit dedupes a contiguous batch against the commit point, durably appends
// the survivors, fans them out, and advances the commit point.
func (d *Demux) commit(base uint64, recs []proto.PktRecord, seq uint64) error {
	committed := d.mirror.Committed()
	keep := make([]pcapio.Record, 0, len(recs))
	for i, pr := range recs {
		gp := base + uint64(i)
		if gp < committed {
			continue // duplicate already committed
		}
		if gp > committed+uint64(len(keep)) {
			// Forward hole with no preceding GAP frame: a protocol violation
			// (correct serve always precedes a discontinuity with a GAP). Fail
			// closed — abandon the connection so the supervisor reconnects from
			// the durable commit point — rather than silently skip into a live
			// stream.
			return fmt.Errorf("collector: src%d unexpected forward jump gp=%d expected=%d", d.srcID, gp, committed+uint64(len(keep)))
		}
		keep = append(keep, protoToPcap(pr))
	}
	if len(keep) == 0 {
		return nil
	}
	if err := d.mirror.Append(keep, seq); err != nil {
		return err
	}
	bytes := 0
	for i := range keep {
		bytes += pcapio.RecordHeaderLen + len(keep[i].Data)
	}
	d.m.onCommit(d.mirror.Committed(), bytes)
	return nil
}

// handleGap records a bounded loss, advances the commit point past it, and
// rotates the mirror + clients so the lost range is never a silent in-stream
// discontinuity for a live consumer.
func (d *Demux) handleGap(payload []byte) error {
	gap, err := proto.DecodeGap(payload)
	if err != nil {
		return err
	}
	committed := d.mirror.Committed()
	if gap.ToGpidx <= committed {
		return nil // already past it
	}
	log.Printf("collector: src%d GAP: lost gpidx [%d,%d) (%d packets)", d.srcID, committed, gap.ToGpidx, gap.ToGpidx-committed)
	d.m.onGap()
	if err := d.mirror.NewSession(gap.ToGpidx); err != nil {
		return err
	}
	// The fan-out detects the session change via Snapshot and recycles its
	// clients with a fresh global header, so the gap is never a silent
	// in-stream discontinuity for a live consumer.
	return nil
}

// maybeAck sends a coalesced ACK at most every second or every 256 commits.
func (d *Demux) maybeAck(force bool) {
	committed := d.mirror.Committed()
	if !force && committed-d.committedAt < 256 && time.Since(d.lastAckAt) < time.Second {
		return
	}
	if d.ackOut == nil {
		return
	}
	ack := proto.Frame{
		Type:     proto.FrameAck,
		SourceID: d.srcID,
		Payload:  proto.Ack{SrcID: d.srcID, AckedGpidx: committed, LastSeq: d.mirror.state.LastSeq}.Encode(),
	}
	if _, err := ack.WriteTo(d.ackOut); err != nil {
		return // agent stdin closed; connection ending
	}
	d.committedAt = committed
	d.lastAckAt = time.Now()
}

// Lag returns how far the collector trails the agent's reported head.
func (d *Demux) Lag() uint64 {
	if d.headGpidx > d.mirror.Committed() {
		return d.headGpidx - d.mirror.Committed()
	}
	return 0
}

func protoToPcap(pr proto.PktRecord) pcapio.Record {
	return pcapio.Record{
		TsSec:   uint32(pr.TsSec),
		TsUsec:  pr.TsNsec / 1000,
		OrigLen: pr.OrigLen,
		Data:    pr.Data,
	}
}

type errUnknownFrame proto.FrameType

func (e errUnknownFrame) Error() string {
	return "collector: unknown non-skippable frame type " + proto.FrameType(e).String()
}
