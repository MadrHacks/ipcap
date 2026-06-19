package proto

import "encoding/binary"

// Protocol-wide constants. All multi-byte integers on the wire are big-endian.
const (
	PreambleMagic   = "PMX1"
	ProtocolVersion = 1

	FrameMagic     uint16 = 0xD0CA
	FrameHeaderLen        = 32
	FrameCRCLen           = 4
	// FrameOverhead is the non-payload byte count of a framed message:
	// 32-byte header + 4-byte trailing payload CRC.
	FrameOverhead = FrameHeaderLen + FrameCRCLen
	// MaxPayloadLen caps a single frame payload so a corrupt length field
	// cannot drive an unbounded allocation (HdrCRC is checked first regardless).
	MaxPayloadLen = 8 << 20 // 8 MiB
)

// FrameType discriminates the multiplexed channels on the stream.
type FrameType uint8

const (
	FramePkt       FrameType = 0x01 // one packet (PktRecord)
	FramePktBatch  FrameType = 0x02 // u16 count + N PktRecord bodies
	FrameAck       FrameType = 0x03 // collector -> agent commit point
	FrameSrcInfo   FrameType = 0x10 // announce/update a source (CBOR)
	FrameHeartbeat FrameType = 0x11 // liveness + lag, every 1s even idle
	FrameStats     FrameType = 0x12 // capture stats (CBOR)
	FrameGap       FrameType = 0x13 // bounded, logged loss marker

	// Reserved, forward-compatible (realised in milestone 5). These sit in the
	// high-bit "skippable" range so an un-upgraded collector silently discards
	// them (PayloadLen-delimited) instead of hard-erroring the connection.
	FrameTLSKeylog    FrameType = 0xA0
	FrameTLSPlaintext FrameType = 0xA1
	FrameTLSMeta      FrameType = 0xA2
)

// Skippable reports whether an unknown frame of this type may be silently
// skipped (high bit set) rather than treated as a fatal protocol error.
func (t FrameType) Skippable() bool { return t&0x80 != 0 }

func (t FrameType) String() string {
	switch t {
	case FramePkt:
		return "PKT"
	case FramePktBatch:
		return "PKT_BATCH"
	case FrameAck:
		return "ACK"
	case FrameSrcInfo:
		return "SRCINFO"
	case FrameHeartbeat:
		return "HEARTBEAT"
	case FrameStats:
		return "STATS"
	case FrameGap:
		return "GAP"
	case FrameTLSKeylog:
		return "TLS_KEYLOG"
	case FrameTLSPlaintext:
		return "TLS_PLAINTEXT"
	case FrameTLSMeta:
		return "TLS_META"
	default:
		return "UNKNOWN"
	}
}

// Flags is the per-frame bitfield at header offset 4.
type Flags uint16

const (
	FlagCompressed Flags = 1 << 0 // payload is a single self-contained zstd frame
	FlagKeyframe   Flags = 1 << 1 // safe resync point
	FlagGap        Flags = 1 << 2 // companions a GAP frame
)

// PktRecord is one captured packet as carried in PKT / PKT_BATCH payloads:
// [TsSec u64 | TsNsec u32 | OrigLen u32 | CapLen u32 | bytes[CapLen]].
type PktRecord struct {
	TsSec   uint64
	TsNsec  uint32
	OrigLen uint32
	CapLen  uint32
	Data    []byte
}

// pktFixedLen is the size of a PktRecord header preceding Data.
const pktFixedLen = 8 + 4 + 4 + 4

// AppendTo serialises the record (header + body) onto dst and returns it.
func (p PktRecord) AppendTo(dst []byte) []byte {
	var hdr [pktFixedLen]byte
	binary.BigEndian.PutUint64(hdr[0:], p.TsSec)
	binary.BigEndian.PutUint32(hdr[8:], p.TsNsec)
	binary.BigEndian.PutUint32(hdr[12:], p.OrigLen)
	binary.BigEndian.PutUint32(hdr[16:], p.CapLen)
	dst = append(dst, hdr[:]...)
	dst = append(dst, p.Data...)
	return dst
}

// parsePktRecord decodes one PktRecord from the front of b, returning the
// record and the number of bytes consumed. ok is false if b is truncated or
// declares an implausible CapLen.
func parsePktRecord(b []byte) (rec PktRecord, n int, ok bool) {
	if len(b) < pktFixedLen {
		return rec, 0, false
	}
	rec.TsSec = binary.BigEndian.Uint64(b[0:])
	rec.TsNsec = binary.BigEndian.Uint32(b[8:])
	rec.OrigLen = binary.BigEndian.Uint32(b[12:])
	rec.CapLen = binary.BigEndian.Uint32(b[16:])
	if rec.CapLen > MaxPayloadLen {
		return rec, 0, false
	}
	end := pktFixedLen + int(rec.CapLen)
	if len(b) < end {
		return rec, 0, false
	}
	rec.Data = b[pktFixedLen:end]
	return rec, end, true
}

// EncodePktBatch serialises a batch payload: u16 count followed by records.
func EncodePktBatch(recs []PktRecord) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, uint16(len(recs)))
	for _, r := range recs {
		out = r.AppendTo(out)
	}
	return out
}

// DecodePktBatch parses a PKT_BATCH payload into its records. The returned
// records' Data fields alias payload; copy if retained past payload's lifetime.
func DecodePktBatch(payload []byte) ([]PktRecord, error) {
	if len(payload) < 2 {
		return nil, errTruncated
	}
	count := int(binary.BigEndian.Uint16(payload))
	recs := make([]PktRecord, 0, count)
	b := payload[2:]
	for i := 0; i < count; i++ {
		rec, n, ok := parsePktRecord(b)
		if !ok {
			return nil, errTruncated
		}
		recs = append(recs, rec)
		b = b[n:]
	}
	return recs, nil
}

// Ack is the collector's durable commit point for a source (FrameAck payload).
//
// AckedGpidx is an exclusive upper bound: the collector has durably committed
// every packet with gpidx < AckedGpidx, equivalently the next gpidx it needs.
// All gpidx bounds in the protocol are half-open, eliminating off-by-one
// hazards at resume and gap boundaries.
type Ack struct {
	SrcID      uint16
	AckedGpidx uint64
	LastSeq    uint64
}

func (a Ack) Encode() []byte {
	b := make([]byte, 2+8+8)
	binary.BigEndian.PutUint16(b[0:], a.SrcID)
	binary.BigEndian.PutUint64(b[2:], a.AckedGpidx)
	binary.BigEndian.PutUint64(b[10:], a.LastSeq)
	return b
}

func DecodeAck(b []byte) (Ack, error) {
	if len(b) < 18 {
		return Ack{}, errTruncated
	}
	return Ack{
		SrcID:      binary.BigEndian.Uint16(b[0:]),
		AckedGpidx: binary.BigEndian.Uint64(b[2:]),
		LastSeq:    binary.BigEndian.Uint64(b[10:]),
	}, nil
}

// Gap marks a bounded, logged loss of [FromGpidx, ToGpidx) for a source.
type Gap struct {
	SrcID     uint16
	FromGpidx uint64
	ToGpidx   uint64
}

func (g Gap) Encode() []byte {
	b := make([]byte, 2+8+8)
	binary.BigEndian.PutUint16(b[0:], g.SrcID)
	binary.BigEndian.PutUint64(b[2:], g.FromGpidx)
	binary.BigEndian.PutUint64(b[10:], g.ToGpidx)
	return b
}

func DecodeGap(b []byte) (Gap, error) {
	if len(b) < 18 {
		return Gap{}, errTruncated
	}
	return Gap{
		SrcID:     binary.BigEndian.Uint16(b[0:]),
		FromGpidx: binary.BigEndian.Uint64(b[2:]),
		ToGpidx:   binary.BigEndian.Uint64(b[10:]),
	}, nil
}

// Heartbeat is emitted at least every second per source (FrameHeartbeat).
type Heartbeat struct {
	TsNsec    uint64
	HeadGpidx uint64
}

func (h Heartbeat) Encode() []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[0:], h.TsNsec)
	binary.BigEndian.PutUint64(b[8:], h.HeadGpidx)
	return b
}

func DecodeHeartbeat(b []byte) (Heartbeat, error) {
	if len(b) < 16 {
		return Heartbeat{}, errTruncated
	}
	return Heartbeat{
		TsNsec:    binary.BigEndian.Uint64(b[0:]),
		HeadGpidx: binary.BigEndian.Uint64(b[8:]),
	}, nil
}

// SrcInfo announces or updates a capture source (FrameSrcInfo, CBOR-encoded).
type SrcInfo struct {
	ID       uint16 `cbor:"id"`
	Name     string `cbor:"name"`
	Linktype uint16 `cbor:"linktype"`
	Snaplen  uint32 `cbor:"snaplen"`
	Kind     string `cbor:"kind"`
	// Epoch identifies the agent's spool instance (gpidx space). A change
	// between connections means the spool was wiped/redeployed, so the collector
	// realigns its commit point instead of stalling on a gpidx the fresh spool
	// will never reach. Empty for agents predating epochs.
	Epoch string `cbor:"epoch,omitempty"`
}

// Stats is a capture statistics snapshot (FrameStats, CBOR-encoded).
type Stats struct {
	Captured    uint64 `cbor:"captured"`
	DroppedKern uint64 `cbor:"dropped_kernel"`
	IfDrop      uint64 `cbor:"ifdrop"`
	SpoolBytes  uint64 `cbor:"spool_bytes"`
	OldestGpidx uint64 `cbor:"oldest_gpidx"`
	HeadGpidx   uint64 `cbor:"head_gpidx"`
}
