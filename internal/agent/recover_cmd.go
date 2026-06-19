package agent

import (
	"fmt"
	"io"

	"ipcap/internal/spool"
)

// RecoverReport opens the spool (which runs crash recovery: forward-scan and
// truncate any torn tail) and reports the recovered head, oldest gpidx, and
// size. It is the offline spool-repair entry point.
func RecoverReport(spoolDir string, srcID uint16, snaplen, linkType uint32, out io.Writer) error {
	w, err := spool.NewWriter(spool.Config{
		Dir:      spoolDir,
		SrcID:    srcID,
		Snaplen:  snaplen,
		LinkType: linkType,
	})
	if err != nil {
		return err
	}
	defer w.Close()
	fmt.Fprintf(out, "src%d: head=%d oldest=%d spool_bytes=%d\n",
		srcID, w.Head(), w.OldestGpidx(), w.SpoolBytes())
	return nil
}
