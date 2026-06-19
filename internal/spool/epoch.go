package spool

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"ipcap/internal/pcapio"
)

// epochName holds a spool directory's instance id. The epoch identifies one
// spool instance — one gpidx space. It is created once when the directory is
// fresh and persists across restarts, so a normal agent restart keeps the same
// epoch (the collector resumes from its commit point), while a wiped or
// redeployed spool gets a new epoch. The collector compares the advertised
// epoch to the one it last saw: if it changed, the agent's gpidx space restarted
// and the collector realigns instead of stalling forever on a commit point the
// fresh spool will never reach.
const epochName = "epoch"

// Epoch returns the spool directory's instance id, creating it atomically if
// absent. Concurrent creators (capture and the per-connection serve share the
// directory) race on O_EXCL; the loser re-reads the winner's value, so all
// readers agree on one epoch per directory instance.
func Epoch(dir string) (string, error) {
	path := filepath.Join(dir, epochName)
	if id, err := readEpoch(path); err != nil {
		return "", err
	} else if id != "" {
		return id, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(raw[:])

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return readEpoch(path) // a concurrent creator won the race
		}
		return "", err
	}
	if _, werr := f.WriteString(id + "\n"); werr != nil {
		f.Close()
		return "", werr
	}
	if serr := pcapio.Fdatasync(f); serr != nil {
		f.Close()
		return "", serr
	}
	if cerr := f.Close(); cerr != nil {
		return "", cerr
	}
	if err := pcapio.SyncDir(dir); err != nil {
		return "", err
	}
	return id, nil
}

func readEpoch(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
