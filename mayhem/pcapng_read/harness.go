package pcapng_read

import (
	"bytes"
	"io"

	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/parser"
	"github.com/mozillazg/ptcpdump/internal/types"
	"github.com/mozillazg/ptcpdump/internal/writer"
	"github.com/x-way/pktdump"
)

// Fuzz drives the `ptcpdump -r file.pcapng` path: pcapng parsing, per-packet
// process/container context comments, and the tcpdump-style packet printer.
func Fuzz(data []byte) int {
	pcache := metadata.NewProcessCache()
	p, err := parser.NewPcapNGParser(bytes.NewReader(data), pcache)
	if err != nil {
		return -1
	}

	normal := writer.NewStdoutWriter(io.Discard, pcache)
	normal.Init()

	verbose := writer.NewStdoutWriter(io.Discard, pcache).
		WithEnhancedContext(types.EnhancedContextProcess | types.EnhancedContextParentProc |
			types.EnhancedContextContainer | types.EnhancedContextPod |
			types.EnhancedContextThread | types.EnhancedContextUser)
	verbose.FormatStyle = pktdump.FormatStyleVerbose
	verbose.DataStyle = pktdump.ContentStyleHexWithLinkASCII
	verbose.PrintNumber = true
	verbose.TimestampN = 4
	verbose.Init()

	n := 0
	for n < 1024 {
		e, err := p.Parse()
		if err != nil {
			break
		}
		if err := normal.Write(e); err != nil {
			break
		}
		if err := verbose.Write(e); err != nil {
			break
		}
		n++
	}
	if n == 0 {
		return 0
	}
	return 1
}
