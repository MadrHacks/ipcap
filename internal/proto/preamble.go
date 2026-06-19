package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

// Compression identifiers carried in the preamble header.
const (
	CompressionNone = "none"
	CompressionZstd = "zstd"
)

// PreambleHeader is the CBOR body of the stream preamble. It announces the
// sources on the connection and echoes the resume point the agent honoured.
type PreambleHeader struct {
	Compression string            `cbor:"compression"`
	Sources     []SrcInfo         `cbor:"sources"`
	ResumeAck   map[uint16]uint64 `cbor:"resumeAck"`
}

// maxPreambleHeader bounds the CBOR header so a corrupt length cannot drive an
// unbounded allocation before the CRC is checked.
const maxPreambleHeader = 1 << 16

// WritePreamble emits the once-per-connection stream preamble:
//
//	"PMX1" | Version u16 | HdrCRC u32 | HeaderLen u16 | CBOR(header)
func WritePreamble(w io.Writer, h PreambleHeader) error {
	body, err := cbor.Marshal(h)
	if err != nil {
		return fmt.Errorf("marshal preamble: %w", err)
	}
	if len(body) > maxPreambleHeader {
		return fmt.Errorf("preamble header too large: %d", len(body))
	}
	buf := make([]byte, 0, len(PreambleMagic)+2+4+2+len(body))
	buf = append(buf, PreambleMagic...)
	buf = binary.BigEndian.AppendUint16(buf, ProtocolVersion)
	buf = binary.BigEndian.AppendUint32(buf, CRC32C(body))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(body)))
	buf = append(buf, body...)
	_, err = w.Write(buf)
	return err
}

var ErrBadPreamble = errors.New("proto: bad preamble")

// ReadPreamble reads and validates the stream preamble from r.
func ReadPreamble(r io.Reader) (PreambleHeader, error) {
	var fixed [len(PreambleMagic) + 2 + 4 + 2]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return PreambleHeader{}, err
	}
	if string(fixed[:4]) != PreambleMagic {
		return PreambleHeader{}, fmt.Errorf("%w: magic", ErrBadPreamble)
	}
	if binary.BigEndian.Uint16(fixed[4:]) != ProtocolVersion {
		return PreambleHeader{}, ErrBadVersion
	}
	wantCRC := binary.BigEndian.Uint32(fixed[6:])
	hdrLen := binary.BigEndian.Uint16(fixed[10:])
	if int(hdrLen) > maxPreambleHeader {
		return PreambleHeader{}, fmt.Errorf("%w: header len %d", ErrBadPreamble, hdrLen)
	}
	body := make([]byte, hdrLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return PreambleHeader{}, err
	}
	if CRC32C(body) != wantCRC {
		return PreambleHeader{}, fmt.Errorf("%w: header CRC", ErrBadPreamble)
	}
	var h PreambleHeader
	if err := cbor.Unmarshal(body, &h); err != nil {
		return PreambleHeader{}, fmt.Errorf("unmarshal preamble: %w", err)
	}
	return h, nil
}

// EncodeSrcInfo / DecodeSrcInfo carry a SrcInfo as a SRCINFO frame payload.
func EncodeSrcInfo(s SrcInfo) ([]byte, error) { return cbor.Marshal(s) }

func DecodeSrcInfo(b []byte) (SrcInfo, error) {
	var s SrcInfo
	err := cbor.Unmarshal(b, &s)
	return s, err
}

// EncodeStats / DecodeStats carry a Stats snapshot as a STATS frame payload.
func EncodeStats(s Stats) ([]byte, error) { return cbor.Marshal(s) }

func DecodeStats(b []byte) (Stats, error) {
	var s Stats
	err := cbor.Unmarshal(b, &s)
	return s, err
}
