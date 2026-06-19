//go:build !linux

package capture

import "errors"

// OpenAFPacket is unavailable off Linux; the agent runs on the Linux vulnbox.
func OpenAFPacket(iface string, ringMiB, snaplen int) (Source, error) {
	return nil, errors.New("afpacket capture is only supported on linux")
}
