package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	f := Frame{
		Type:      FramePktBatch,
		Flags:     FlagCompressed | FlagKeyframe,
		SourceID:  7,
		BaseGpidx: 0xDEADBEEF12345678,
		Seq:       42,
		Payload:   []byte("hello batch payload"),
	}
	buf := f.AppendTo(nil)
	got, err := ReadFrame(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != f.Type || got.Flags != f.Flags || got.SourceID != f.SourceID ||
		got.BaseGpidx != f.BaseGpidx || got.Seq != f.Seq || !bytes.Equal(got.Payload, f.Payload) {
		t.Fatalf("round-trip mismatch: %+v vs %+v", got, f)
	}
}

func TestFrameRejectsCorruptPayload(t *testing.T) {
	buf := Frame{Type: FramePkt, Payload: []byte("0123456789")}.AppendTo(nil)
	buf[FrameHeaderLen+3] ^= 0xFF // flip a payload byte
	if _, err := ReadFrame(bytes.NewReader(buf)); !errors.Is(err, ErrPayCRC) {
		t.Fatalf("want ErrPayCRC, got %v", err)
	}
}

func TestFrameRejectsCorruptHeader(t *testing.T) {
	buf := Frame{Type: FramePkt, Payload: []byte("x")}.AppendTo(nil)
	buf[8] ^= 0xFF // flip a BaseGpidx byte, leaving HdrCRC stale
	if _, err := ReadFrame(bytes.NewReader(buf)); !errors.Is(err, ErrHdrCRC) {
		t.Fatalf("want ErrHdrCRC, got %v", err)
	}
}

func TestFrameRejectsBadMagic(t *testing.T) {
	buf := Frame{Type: FramePkt, Payload: []byte("x")}.AppendTo(nil)
	buf[0] = 0x00
	if _, err := ReadFrame(bytes.NewReader(buf)); !errors.Is(err, ErrBadMagic) {
		t.Fatalf("want ErrBadMagic, got %v", err)
	}
}

// TestFrameRejectsHugePayload crafts a header with a valid HdrCRC but an absurd
// PayloadLen; ReadFrame must reject it before allocating.
func TestFrameRejectsHugePayload(t *testing.T) {
	var hdr [FrameHeaderLen]byte
	binary.BigEndian.PutUint16(hdr[0:], FrameMagic)
	hdr[2] = ProtocolVersion
	hdr[3] = byte(FramePkt)
	binary.BigEndian.PutUint32(hdr[24:], MaxPayloadLen+1)
	binary.BigEndian.PutUint32(hdr[28:], CRC32C(hdr[0:28]))
	if _, err := ReadFrame(bytes.NewReader(hdr[:])); !errors.Is(err, ErrPayloadHuge) {
		t.Fatalf("want ErrPayloadHuge, got %v", err)
	}
}

func TestPreambleRoundTrip(t *testing.T) {
	h := PreambleHeader{
		Compression: CompressionZstd,
		Sources:     []SrcInfo{{ID: 1, Name: "eth0", Linktype: 1, Snaplen: 65536, Kind: "afpacket"}},
		ResumeAck:   map[uint16]uint64{1: 9001},
	}
	var buf bytes.Buffer
	if err := WritePreamble(&buf, h); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPreamble(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Compression != h.Compression || len(got.Sources) != 1 ||
		got.Sources[0] != h.Sources[0] || got.ResumeAck[1] != 9001 {
		t.Fatalf("preamble round-trip mismatch: %+v", got)
	}
}

func TestPreambleRejectsCorruptCRC(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePreamble(&buf, PreambleHeader{Compression: CompressionNone}); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	b[len(b)-1] ^= 0xFF // corrupt the CBOR body
	if _, err := ReadPreamble(bytes.NewReader(b)); err == nil {
		t.Fatal("expected error on corrupt preamble")
	}
}

func TestPayloadStructsRoundTrip(t *testing.T) {
	ack, _ := DecodeAck(Ack{SrcID: 3, AckedGpidx: 100, LastSeq: 9}.Encode())
	if ack.SrcID != 3 || ack.AckedGpidx != 100 || ack.LastSeq != 9 {
		t.Fatalf("ack round-trip: %+v", ack)
	}
	gap, _ := DecodeGap(Gap{SrcID: 3, FromGpidx: 10, ToGpidx: 20}.Encode())
	if gap.FromGpidx != 10 || gap.ToGpidx != 20 {
		t.Fatalf("gap round-trip: %+v", gap)
	}
	hb, _ := DecodeHeartbeat(Heartbeat{TsNsec: 123, HeadGpidx: 456}.Encode())
	if hb.TsNsec != 123 || hb.HeadGpidx != 456 {
		t.Fatalf("heartbeat round-trip: %+v", hb)
	}
}

func TestPktBatchRoundTrip(t *testing.T) {
	in := []PktRecord{
		{TsSec: 1, TsNsec: 2, OrigLen: 3, CapLen: 3, Data: []byte("abc")},
		{TsSec: 4, TsNsec: 5, OrigLen: 2, CapLen: 2, Data: []byte("de")},
	}
	out, err := DecodePktBatch(EncodePktBatch(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || string(out[0].Data) != "abc" || string(out[1].Data) != "de" {
		t.Fatalf("batch round-trip mismatch: %+v", out)
	}
}
