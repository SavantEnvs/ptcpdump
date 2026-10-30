#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's go-fuzz harness(es) as sanitized libFuzzer
# binaries (OSS-Fuzz Go path: go-fuzz-build -libfuzzer + clang link). EDIT per repo.
#
# Runs inside the commit image (GO mayhem/Dockerfile) as `mayhem` in /mayhem.
# GOROOT/GOPATH/GOMODCACHE are pinned by the Dockerfile ENV (under /opt/toolchains —
# absolute, $HOME-independent).
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs THIS script OFFLINE.
#   - This FIRST build (in CI, online) populates the module cache under $GOMODCACHE.
#   - The module cache doubles as a FILE PROXY at $GOMODCACHE/cache/download. We set
#     GOPROXY to that file proxy FIRST, network LAST: the offline re-run resolves
#     entirely from the cache, and the network fallback only fills cache-misses on
#     this first online build. -mod=mod lets go-fuzz-build's `go get` of go-fuzz-dep
#     update go.mod from the cache. (GOPROXY=off is NOT enough — it blocks reading
#     the version list from the cache, which `go get` needs.)
#   - For a FULLY self-contained tree instead: `go mod vendor` and build -mod=vendor.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
# OSS-Fuzz Go path is ASan-only for the libFuzzer link (keep ASan regardless of base default).
: "${SANITIZER_FLAGS=-fsanitize=address}"
: "${MAYHEM_JOBS:=$(nproc)}"
export CC CXX LIB_FUZZING_ENGINE SANITIZER_FLAGS MAYHEM_JOBS
# DWARF < 4 (SPEC §6.2 item 10): -gdwarf-3 on cgo C, the shim and lsan_off; Go's own CUs are DWARF 5 (no 3 option).
: "${GO_DEBUG_FLAGS:=-g -gdwarf-3}"

# Resolve modules offline-first from the in-image cache; network only as a fallback.
# $(go env GOMODCACHE) reads the pinned ENV, so it is correct under ANY $HOME.
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOPROXY="${GOPROXY:-file://$(go env GOMODCACHE)/cache/download,https://proxy.golang.org,direct}"

cd "$SRC"
go version

# go-fuzz-build needs the go-fuzz-dep package on the module graph. With -mod=mod +
# the file-proxy GOPROXY this resolves from the cache offline (no-op if already present).
go get github.com/dvyukov/go-fuzz/go-fuzz-dep

# One go-fuzz harness package per target; the output binary name is the Mayhemfile `target:`.
TARGETS="pcapng_read:ptcpdump_read_pcapng gosym_elf:ptcpdump_gosym_elf filter_expr:ptcpdump_filter_expr"

WORK="${TMPDIR:-/tmp}/ptcpdump-fuzz-build"
mkdir -p "$WORK" "$SRC/mayhem-build"

# Init-ordering shim (go_runtime_ready.c), linked first into targets whose archive lacks the symbol.
SHIM_O="$WORK/go_runtime_ready.o"
$CC $GO_DEBUG_FLAGS -c "$SRC/mayhem/go_runtime_ready.c" -o "$SHIM_O"

# LeakSanitizer off at build time (fleet policy); also a -gdwarf-3 CU that heads .debug_info.
LSAN_O="$WORK/lsan_off.o"
$CXX $SANITIZER_FLAGS $GO_DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$LSAN_O"

for spec in $TARGETS; do
  HARNESS_DIR="mayhem/${spec%%:*}"
  TARGET="${spec##*:}"
  echo "=== building $TARGET (go-fuzz-build -libfuzzer) ==="
  (
    cd "$SRC/$HARNESS_DIR"
    CGO_CFLAGS="${CGO_CFLAGS:-} $GO_DEBUG_FLAGS" go-fuzz-build -libfuzzer -o "$WORK/$TARGET.a"
  )
  # When the target's package graph includes cgo (here: gopacket/pcap), go-fuzz-build's archive already
  # defines LLVMFuzzerInitialize via a cgo export wrapper that waits for the Go runtime; the shim would
  # then be a duplicate definition, so link it only when the archive lacks one.
  SHIM=""
  if ! nm "$WORK/$TARGET.a" 2>/dev/null | grep ' T LLVMFuzzerInitialize$' >/dev/null; then SHIM="$SHIM_O"; fi
  # Link go-fuzz archive into a libFuzzer binary with clang (ASan). -lpcap: gopacket's cgo pcap binding.
  $CXX $SANITIZER_FLAGS $LIB_FUZZING_ENGINE $GO_DEBUG_FLAGS $LSAN_O $SHIM \
      "$WORK/$TARGET.a" -lpcap -o "/mayhem/$TARGET"
  # No `grep -q`: under pipefail nm would die of SIGPIPE.
  nm "/mayhem/$TARGET" | grep ' T LLVMFuzzerInitialize$' >/dev/null \
    || { echo "build.sh: LLVMFuzzerInitialize init-ordering shim missing from /mayhem/$TARGET" >&2; exit 1; }
  echo "built /mayhem/$TARGET"
done

# Test binaries with the project's NORMAL flags (no sanitizers); mayhem/test.sh only runs them.
# The packages below are the ones whose tests need no root/eBPF.
echo "=== building test binaries ==="
for pkg in cmd internal/types internal/utils internal/event; do
  (
    unset CGO_CFLAGS CGO_LDFLAGS
    go test -c -tags dynamic -buildmode=pie -o "$SRC/mayhem-build/test-$(echo "$pkg" | tr / _).test" "./$pkg"
  )
done
echo "build.sh complete"
