package pcapio

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Fdatasync flushes a file's data to stable storage (data + size, not mtime).
func Fdatasync(f *os.File) error { return unix.Fdatasync(int(f.Fd())) }

// SyncDir fsyncs a directory so newly created files' directory entries (names)
// are durable. fdatasync of a file flushes its contents but NOT its dirent, so
// without this a hard power cut could lose a just-created file's name while
// keeping its bytes — regressing the durable head and reissuing gpidx.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// WriteFileAtomic writes b to path atomically via a temp file and rename,
// finally fsyncing the containing directory so the rename is durable. When
// durable is true the temp file's bytes are fdatasync'd before the rename, so a
// crash can never expose the new name pointing at unflushed contents.
func WriteFileAtomic(path string, b []byte, durable bool) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if durable {
		if err := Fdatasync(f); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}
