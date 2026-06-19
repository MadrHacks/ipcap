package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

var (
	errTruncated   = errors.New("proto: truncated payload")
	ErrBadMagic    = errors.New("proto: bad frame magic")
	ErrBadVersion  = errors.New("proto: unsupported frame version")
	ErrHdrCRC      = errors.New("proto: frame header CRC mismatch")
	ErrPayCRC      = errors.New("proto: frame payload CRC mismatch")
	ErrPayloadHuge = errors.New("proto: frame payload exceeds cap")
)

// castagnoli is the CRC32C table used for both header and payload checks.
var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// CRC32C returns the Castagnoli CRC of b.
func CRC32C(b []byte) uint32 { return crc32.Checksum(b, castagnoli) }

// Frame is one decoded protocol frame. Payload aliases the read buffer for
// frames returned by ReadFrame; copy it if it must outlive the next read.
type Frame struct {
	Type      FrameType
	Flags     Flags
	SourceID  uint16
	BaseGpidx uint64
	Seq       uint64
	Payload   []byte
}

// MarshalHeader writes the 32-byte header for the given payload length into dst
// (which must be at least FrameHeaderLen long) and fills in HdrCRC.
func (f Frame) marshalHeader(dst []byte, payloadLen int) {
	binary.BigEndian.PutUint16(dst[0:], FrameMagic)
	dst[2] = ProtocolVersion
	dst[3] = byte(f.Type)
	binary.BigEndian.PutUint16(dst[4:], uint16(f.Flags))
	binary.BigEndian.PutUint16(dst[6:], f.SourceID)
	binary.BigEndian.PutUint64(dst[8:], f.BaseGpidx)
	binary.BigEndian.PutUint64(dst[16:], f.Seq)
	binary.BigEndian.PutUint32(dst[24:], uint32(payloadLen))
	binary.BigEndian.PutUint32(dst[28:], CRC32C(dst[0:28]))
}

// AppendTo serialises the whole frame (header + payload + payload CRC) onto dst.
func (f Frame) AppendTo(dst []byte) []byte {
	var hdr [FrameHeaderLen]byte
	f.marshalHeader(hdr[:], len(f.Payload))
	dst = append(dst, hdr[:]...)
	dst = append(dst, f.Payload...)
	var crc [4]byte
	binary.BigEndian.PutUint32(crc[:], CRC32C(f.Payload))
	return append(dst, crc[:]...)
}

// WriteTo serialises the frame to w in a single buffered call.
func (f Frame) WriteTo(w io.Writer) (int64, error) {
	buf := f.AppendTo(make([]byte, 0, FrameOverhead+len(f.Payload)))
	n, err := w.Write(buf)
	return int64(n), err
}

// ReadFrame reads and validates one frame from r. On any framing or CRC error
// it returns a non-nil error; the caller must then abandon the connection
// (partial bytes are never carried across connections — see the resync rule).
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [FrameHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	if binary.BigEndian.Uint16(hdr[0:]) != FrameMagic {
		return Frame{}, ErrBadMagic
	}
	if hdr[2] != ProtocolVersion {
		return Frame{}, ErrBadVersion
	}
	if CRC32C(hdr[0:28]) != binary.BigEndian.Uint32(hdr[28:]) {
		return Frame{}, ErrHdrCRC
	}
	payloadLen := binary.BigEndian.Uint32(hdr[24:])
	if payloadLen > MaxPayloadLen {
		return Frame{}, fmt.Errorf("%w: %d", ErrPayloadHuge, payloadLen)
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, err
	}
	var crc [4]byte
	if _, err := io.ReadFull(r, crc[:]); err != nil {
		return Frame{}, err
	}
	if CRC32C(payload) != binary.BigEndian.Uint32(crc[:]) {
		return Frame{}, ErrPayCRC
	}
	return Frame{
		Type:      FrameType(hdr[3]),
		Flags:     Flags(binary.BigEndian.Uint16(hdr[4:])),
		SourceID:  binary.BigEndian.Uint16(hdr[6:]),
		BaseGpidx: binary.BigEndian.Uint64(hdr[8:]),
		Seq:       binary.BigEndian.Uint64(hdr[16:]),
		Payload:   payload,
	}, nil
}
