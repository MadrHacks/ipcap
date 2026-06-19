package proto

import (
	"bytes"
	"testing"
)

func TestCompressRoundTrip(t *testing.T) {
	recs := make([]PktRecord, 0, 64)
	for i := 0; i < 64; i++ {
		data := bytes.Repeat([]byte{byte(i)}, 200) // compressible
		recs = append(recs, PktRecord{TsSec: uint64(i), CapLen: uint32(len(data)), Data: data})
	}
	raw := EncodePktBatch(recs)
	comp := CompressBatch(raw)
	if len(comp) >= len(raw) {
		t.Fatalf("expected compression to shrink (%d -> %d)", len(raw), len(comp))
	}
	got, err := DecompressBatch(comp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("decompressed payload mismatch")
	}
	out, err := DecodePktBatch(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(recs) {
		t.Fatalf("got %d records, want %d", len(out), len(recs))
	}
}

func TestDecompressRejectsGarbage(t *testing.T) {
	if _, err := DecompressBatch([]byte("not a zstd frame at all")); err == nil {
		t.Fatal("expected error decompressing garbage")
	}
}
