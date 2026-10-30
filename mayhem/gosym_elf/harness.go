package gosym_elf

import (
	"bytes"
	"debug/elf"
	"os"

	"github.com/mozillazg/ptcpdump/internal/gosym"
)

// Fuzz drives the Go TLS uprobe offset discovery (`--gotls` hooks): ELF symbol-table
// lookup + machine-code RET scanning, and the GoReSym pclntab parser.
func Fuzz(data []byte) int {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return -1
	}
	defer f.Close()

	const hooked = "crypto/tls.(*Config).writeKeyLog"
	name := hooked
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			if elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Name != "" {
				name = s.Name
				break
			}
		}
	}
	_, _ = gosym.GetFuncRetOffsetsViaSymbolTable(f, name)
	_, _ = gosym.GetFuncRetOffsetsViaSymbolTable(f, hooked)

	tmp, err := os.CreateTemp(os.Getenv("TMPDIR"), "gosym-*.elf")
	if err != nil {
		return 0
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(data)
	tmp.Close()
	if werr != nil {
		return 0
	}
	_, _, _ = gosym.GetFuncRetOffsetsViaPclntab(tmp.Name(), f, "runtime.main")
	_, _, _ = gosym.GetFuncRetOffsetsViaPclntab(tmp.Name(), f, hooked)
	return 1
}
