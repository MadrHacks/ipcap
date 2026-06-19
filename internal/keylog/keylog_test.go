package keylog

import (
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	cr := strings.Repeat("a", 64)  // 32-byte client random
	s32 := strings.Repeat("b", 64) // 32-byte secret
	s48 := strings.Repeat("c", 96) // 48-byte master secret

	good := []string{
		"CLIENT_RANDOM " + cr + " " + s48,
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET " + cr + " " + s32,
		"SERVER_HANDSHAKE_TRAFFIC_SECRET " + cr + " " + s48,
		"CLIENT_TRAFFIC_SECRET_0 " + cr + " " + s32,
		"SERVER_TRAFFIC_SECRET_0 " + cr + " " + s32,
		"EXPORTER_SECRET " + cr + " " + s32,
		"  CLIENT_RANDOM " + cr + " " + s48 + "  ", // surrounding whitespace tolerated
		"CLIENT_RANDOM " + strings.ToUpper(cr) + " " + s32, // uppercase hex
	}
	for _, g := range good {
		if !Valid([]byte(g)) {
			t.Errorf("expected valid: %.60q", g)
		}
	}

	bad := map[string]string{
		"empty":                "",
		"blank":                "   ",
		"unknown label":        "HELLO_SECRET " + cr + " " + s32,
		"two fields":           "CLIENT_RANDOM " + cr,
		"four fields":          "CLIENT_RANDOM " + cr + " " + s32 + " extra",
		"non-hex random":       "CLIENT_RANDOM " + strings.Repeat("z", 64) + " " + s32,
		"non-hex secret":       "CLIENT_RANDOM " + cr + " " + strings.Repeat("g", 64),
		"random too long":      "CLIENT_RANDOM " + strings.Repeat("a", 65) + " " + s32,
		"secret too long":      "CLIENT_RANDOM " + cr + " " + strings.Repeat("b", 97),
		"oversized garbage":    "CLIENT_TRAFFIC_SECRET_0 " + cr + " " + s48 + strings.Repeat("0", 5000),
		"label only":           "CLIENT_RANDOM",
	}
	for name, b := range bad {
		if Valid([]byte(b)) {
			t.Errorf("expected invalid (%s): %.60q", name, b)
		}
	}
}
