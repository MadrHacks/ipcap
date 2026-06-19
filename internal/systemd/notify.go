// Package systemd implements the minimal sd_notify protocol (no dependency) so
// the capture agent can run as a Type=notify unit with a watchdog: it signals
// READY once capturing, and pings the watchdog only from the capture loop, so a
// silently-wedged capture (loop stalled while the process lives) is detected and
// restarted instead of going unnoticed.
package systemd

import (
	"net"
	"os"
	"strconv"
	"time"
)

// Notifier sends sd_notify messages to systemd, if running under it.
type Notifier struct {
	conn *net.UnixConn
}

// New connects to the NOTIFY_SOCKET if present. When not run under systemd it
// returns a no-op notifier, so callers need no conditional logic.
func New() *Notifier {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return &Notifier{}
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return &Notifier{}
	}
	return &Notifier{conn: conn}
}

func (n *Notifier) send(state string) {
	if n.conn == nil {
		return
	}
	_, _ = n.conn.Write([]byte(state))
}

// Ready signals that startup is complete and the unit is operational.
func (n *Notifier) Ready() { n.send("READY=1") }

// Watchdog pings the systemd watchdog timer.
func (n *Notifier) Watchdog() { n.send("WATCHDOG=1") }

// Status sets the human-readable unit status string.
func (n *Notifier) Status(s string) { n.send("STATUS=" + s) }

// WatchdogInterval returns a safe ping interval (half of WatchdogSec) when the
// watchdog is enabled, else 0.
func WatchdogInterval() time.Duration {
	usecStr := os.Getenv("WATCHDOG_USEC")
	if usecStr == "" {
		return 0
	}
	usec, err := strconv.ParseInt(usecStr, 10, 64)
	if err != nil || usec <= 0 {
		return 0
	}
	// Ping at half the timeout, per systemd recommendation.
	return time.Duration(usec) * time.Microsecond / 2
}
