package proto

import (
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Compression is applied ONLY to PKT_BATCH payloads on the link, gated by the
// COMPRESSED flag bit. Each batch is a self-contained zstd frame (EncodeAll), so
// resume needs no decoder replay and the collector decompresses before any
// durable write — spool files, the mirror, and the re-served stream are always
// raw libpcap.

// maxDecompressed bounds a single decompressed batch (a batch holds at most a
// few hundred snaplen-capped packets), defending against decompression bombs.
const maxDecompressed = 32 << 20

var (
	zstdEncOnce sync.Once
	zstdEnc     *zstd.Encoder
	zstdDecOnce sync.Once
	zstdDec     *zstd.Decoder
)

func encoder() *zstd.Encoder {
	zstdEncOnce.Do(func() {
		// SpeedFastest keeps CPU off the (possibly-under-attack) vulnbox; the
		// encoder's EncodeAll is safe for concurrent use.
		e, err := zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstd.SpeedFastest),
			zstd.WithEncoderConcurrency(1),
		)
		if err != nil {
			panic(err) // only fails on an invalid static option
		}
		zstdEnc = e
	})
	return zstdEnc
}

func decoder() *zstd.Decoder {
	zstdDecOnce.Do(func() {
		d, err := zstd.NewReader(nil,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxMemory(maxDecompressed),
		)
		if err != nil {
			panic(err)
		}
		zstdDec = d
	})
	return zstdDec
}

// CompressBatch returns a self-contained zstd frame for a PKT_BATCH payload.
func CompressBatch(payload []byte) []byte {
	return encoder().EncodeAll(payload, make([]byte, 0, len(payload)/2))
}

// DecompressBatch inflates a compressed PKT_BATCH payload, bounded by
// maxDecompressed.
func DecompressBatch(payload []byte) ([]byte, error) {
	out, err := decoder().DecodeAll(payload, nil)
	if err != nil {
		return nil, fmt.Errorf("proto: zstd decode: %w", err)
	}
	return out, nil
}
