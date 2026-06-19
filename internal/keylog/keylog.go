// Package keylog validates NSS SSLKEYLOGFILE lines so malformed key material
// never reaches the keylog a TLS-decrypting consumer reads. Some eCapture builds
// emit an oversized, zero-padded pseudo-key (a valid label followed by a
// never-terminating run of zero bytes); relayed verbatim it bloats the keylog to
// gigabytes and breaks every downstream consumer. Rejecting non-conforming lines
// keeps the keylog bounded and clean. Missing or dropped keys only cost the
// decryptability of individual flows — they never affect packet capture.
package keylog

import "bytes"

// MaxLineLen bounds a well-formed NSS keylog line: the longest label (31 bytes)
// + a space + a 64-hex client random + a space + a secret of at most 96 hex (a
// 48-byte master secret) is ~193 bytes. 256 leaves generous slack; anything
// longer is not a key.
const MaxLineLen = 256

// labels is the set of NSS keylog labels emitted across TLS 1.2/1.3 by NSS,
// OpenSSL, BoringSSL, GnuTLS and the eCapture hooks.
var labels = map[string]struct{}{
	"CLIENT_RANDOM":                   {},
	"CLIENT_EARLY_TRAFFIC_SECRET":     {},
	"CLIENT_HANDSHAKE_TRAFFIC_SECRET": {},
	"SERVER_HANDSHAKE_TRAFFIC_SECRET": {},
	"CLIENT_TRAFFIC_SECRET_0":         {},
	"SERVER_TRAFFIC_SECRET_0":         {},
	"EARLY_EXPORTER_SECRET":           {},
	"EXPORTER_SECRET":                 {},
}

// Valid reports whether line is a well-formed NSS keylog entry of the form
// "<LABEL> <client_random_hex> <secret_hex>": a known label and two bounded hex
// fields, the whole line within MaxLineLen. Surrounding whitespace is tolerated.
// This is the single check that stops the oversized, zero-padded pseudo-keys
// some eCapture builds emit from being relayed or stored.
func Valid(line []byte) bool {
	line = bytes.TrimSpace(line)
	if len(line) == 0 || len(line) > MaxLineLen {
		return false
	}
	fields := bytes.Fields(line)
	if len(fields) != 3 {
		return false
	}
	if _, ok := labels[string(fields[0])]; !ok {
		return false
	}
	// client random is a 32-byte value (64 hex); a secret is at most 48 bytes
	// (96 hex). Bound both and require pure hex.
	return isHex(fields[1]) && len(fields[1]) <= 64 &&
		isHex(fields[2]) && len(fields[2]) <= 96
}

func isHex(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
