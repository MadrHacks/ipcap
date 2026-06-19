package agent

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"time"

	"ipcap/internal/pcapio"
	"ipcap/internal/proto"
	"ipcap/internal/spool"
)

// ServeOptions configures the short-lived, read-only serve streamer that is
// invoked per Noise connection by the listener.
type ServeOptions struct {
	SpoolDir        string
	SrcID           uint16
	SrcName         string
	Resume          uint64 // next gpidx the collector needs (half-open)
	Compress        bool   // zstd-compress PKT_BATCH payloads on the link
	KeylogFile      string // NSS keylog file to relay as TLS_KEYLOG frames ("" disables)
	BatchMaxPackets int
	BatchMaxBytes   int
	PollInterval    time.Duration
	In              io.Reader // ACK frames from the collector
	Out             io.Writer // frame stream to the collector
}

// RunServe streams frames for a single source from the durable spool, starting
// at the resume gpidx, tailing live, never reading past the durable head. It
// runs as a goroutine per Noise connection in the listener process, holds no
// durable state, and exits when the collector disconnects (input EOF), the
// output breaks, or the context is cancelled — it is independent of the capture
// process, so its lifetime never touches the capturer.
func RunServe(ctx context.Context, opts ServeOptions) error {
	if opts.BatchMaxPackets <= 0 {
		opts.BatchMaxPackets = 256
	}
	if opts.BatchMaxBytes <= 0 {
		opts.BatchMaxBytes = 1 << 20
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 50 * time.Millisecond
	}

	gh, err := spool.SourceHeader(opts.SpoolDir, opts.SrcID)
	if err != nil {
		return err
	}
	epoch, err := spool.Epoch(opts.SpoolDir)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go readAcks(ctx, cancel, opts.In)
	// Unblock readAcks's blocking ReadFull on shutdown so it cannot leak past
	// RunServe when the collector dies without closing its end of the connection.
	go func() {
		<-ctx.Done()
		if d, ok := opts.In.(interface{ SetReadDeadline(time.Time) error }); ok {
			d.SetReadDeadline(time.Now())
		} else if c, ok := opts.In.(io.Closer); ok {
			c.Close()
		}
	}()

	r, from, reaped, err := spool.OpenReader(opts.SpoolDir, opts.SrcID, gh.Snaplen, opts.Resume)
	if err != nil {
		return err
	}
	defer r.Close()

	out := bufio.NewWriterSize(opts.Out, 256<<10)
	s := &streamer{out: out, srcID: opts.SrcID, seq: map[proto.FrameType]uint64{}, compress: opts.Compress}
	keylog := newKeylogTailer(opts.KeylogFile)
	defer keylog.Close()

	compression := proto.CompressionNone
	if opts.Compress {
		compression = proto.CompressionZstd
	}
	if err := proto.WritePreamble(out, proto.PreambleHeader{
		Compression: compression,
		Sources: []proto.SrcInfo{{
			ID:       opts.SrcID,
			Name:     opts.SrcName,
			Linktype: uint16(gh.LinkType),
			Snaplen:  gh.Snaplen,
			Kind:     "afpacket",
			Epoch:    epoch,
		}},
		ResumeAck: map[uint16]uint64{opts.SrcID: from},
	}); err != nil {
		return err
	}
	if reaped {
		if err := s.sendGap(opts.Resume, from); err != nil {
			return err
		}
	}

	batch := make([]proto.PktRecord, 0, opts.BatchMaxPackets)
	var batchBytes int
	var baseGpidx uint64
	lastBeat := time.Now()

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := s.sendBatch(baseGpidx, batch); err != nil {
			return err
		}
		batch = batch[:0]
		batchBytes = 0
		return nil
	}

	beat := func() error {
		if err := keylog.emitNew(s); err != nil {
			return err
		}
		if err := out.Flush(); err != nil {
			return err
		}
		lastBeat = time.Now()
		if st, ok := readStats(opts.SpoolDir); ok {
			if err := s.sendStats(st); err != nil {
				return err
			}
		}
		return s.sendHeartbeat(r.Head())
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		rec, gp, err := r.Next()
		switch {
		case err == nil:
			if len(batch) == 0 {
				baseGpidx = gp
			}
			batch = append(batch, pcapToProto(rec))
			batchBytes += pcapio.RecordHeaderLen + len(rec.Data)
			if len(batch) >= opts.BatchMaxPackets || batchBytes >= opts.BatchMaxBytes {
				if err := flush(); err != nil {
					return err
				}
			}
			if time.Since(lastBeat) >= time.Second {
				if err := beat(); err != nil {
					return err
				}
			}

		case errors.Is(err, spool.ErrNoData):
			if err := flush(); err != nil {
				return err
			}
			if err := beat(); err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(opts.PollInterval):
			}

		case errors.Is(err, spool.ErrReaped):
			if err := flush(); err != nil {
				return err
			}
			lostFrom := r.Pos()
			r.Close()
			r, from, _, err = spool.OpenReader(opts.SpoolDir, opts.SrcID, gh.Snaplen, lostFrom)
			if err != nil {
				return err
			}
			log.Printf("serve: src %d resume %d reaped; gap [%d,%d)", opts.SrcID, lostFrom, lostFrom, from)
			if err := s.sendGap(lostFrom, from); err != nil {
				return err
			}

		default:
			return err
		}
	}
}

// readAcks consumes ACK frames from the collector and cancels the stream when
// the collector disconnects (input EOF/error).
func readAcks(ctx context.Context, cancel context.CancelFunc, in io.Reader) {
	defer cancel()
	if in == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// ACKs are advisory; retention is byte-cap enforced by the capture
		// janitor. We only read frames to detect the collector disconnecting.
		if _, err := proto.ReadFrame(in); err != nil {
			return
		}
	}
}

func pcapToProto(rec pcapio.Record) proto.PktRecord {
	return proto.PktRecord{
		TsSec:   uint64(rec.TsSec),
		TsNsec:  rec.TsUsec * 1000,
		OrigLen: rec.OrigLen,
		CapLen:  uint32(len(rec.Data)),
		Data:    rec.Data,
	}
}

// streamer frames and writes to the collector, tracking per-type sequence.
type streamer struct {
	out      io.Writer
	srcID    uint16
	seq      map[proto.FrameType]uint64
	compress bool
}

func (s *streamer) next(t proto.FrameType) uint64 {
	v := s.seq[t]
	s.seq[t] = v + 1
	return v
}

func (s *streamer) sendBatch(baseGpidx uint64, recs []proto.PktRecord) error {
	payload := proto.EncodePktBatch(recs)
	var flags proto.Flags
	if s.compress {
		payload = proto.CompressBatch(payload)
		flags |= proto.FlagCompressed
	}
	f := proto.Frame{
		Type:      proto.FramePktBatch,
		Flags:     flags,
		SourceID:  s.srcID,
		BaseGpidx: baseGpidx,
		Seq:       s.next(proto.FramePktBatch),
		Payload:   payload,
	}
	_, err := f.WriteTo(s.out)
	return err
}

func (s *streamer) sendHeartbeat(head uint64) error {
	f := proto.Frame{
		Type:     proto.FrameHeartbeat,
		SourceID: s.srcID,
		Seq:      s.next(proto.FrameHeartbeat),
		Payload:  proto.Heartbeat{TsNsec: uint64(time.Now().UnixNano()), HeadGpidx: head}.Encode(),
	}
	_, err := f.WriteTo(s.out)
	return err
}

func (s *streamer) sendKeylog(line []byte) error {
	f := proto.Frame{
		Type:     proto.FrameTLSKeylog,
		SourceID: s.srcID,
		Seq:      s.next(proto.FrameTLSKeylog),
		Payload:  line,
	}
	_, err := f.WriteTo(s.out)
	return err
}

func (s *streamer) sendStats(st proto.Stats) error {
	payload, err := proto.EncodeStats(st)
	if err != nil {
		return err
	}
	f := proto.Frame{
		Type:     proto.FrameStats,
		SourceID: s.srcID,
		Seq:      s.next(proto.FrameStats),
		Payload:  payload,
	}
	_, err = f.WriteTo(s.out)
	return err
}

func (s *streamer) sendGap(from, to uint64) error {
	f := proto.Frame{
		Type:     proto.FrameGap,
		Flags:    proto.FlagGap,
		SourceID: s.srcID,
		Seq:      s.next(proto.FrameGap),
		Payload:  proto.Gap{SrcID: s.srcID, FromGpidx: from, ToGpidx: to}.Encode(),
	}
	_, err := f.WriteTo(s.out)
	return err
}
