#!/usr/bin/env bash
# Prove the emitted binary64 complex helper ABI without ambient target code.
set -euo pipefail
readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly TOOLCHAIN="$(python3 "$ROOT_DIR/scripts/rust_toolchain.py")"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly FIXTURES="$ROOT_DIR/builtins/fixtures"
readonly work="${1:-$ROOT_DIR/.work/x86_64/compilercomplex-division}"
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ]
case "$work" in "$ROOT_DIR"/.work/x86_64/*) ;; *) exit 2 ;; esac
python3 - "$ROOT_DIR" "$work" <<'BOUNDARY'
from pathlib import Path
import sys
root = Path(sys.argv[1]).resolve()
boundary = root / '.work' / 'x86_64'
work = Path(sys.argv[2])
assert boundary.resolve() == boundary and '..' not in work.parts
assert work.resolve() == work
work.relative_to(boundary)
BOUNDARY
[ ! -e "$work" ]
mkdir -p "$work/tmp"
export TMPDIR="$work/tmp"
cd "$work"
(cd "$FIXTURES/llvm22_divdc3" && sha256sum -c SHA256SUMS) > oracle-inputs.log
rustup run "$TOOLCHAIN" rustc --crate-name crabc_builtins_x86_64 --crate-type=lib --edition=2021 \
    --target x86_64-unknown-linux-musl --emit=obj -C panic=abort -C force-unwind-tables=no \
    -C overflow-checks=off -C opt-level=2 -C codegen-units=1 -C debuginfo=0 \
    -C relocation-model=pic -C embed-bitcode=no "$ROOT_DIR/builtins/src/lib.rs" -o candidate.o
clang -std=c11 -O2 -ffp-contract=off -fno-stack-protector -fno-asynchronous-unwind-tables \
    -c "$FIXTURES/x86_64_divdc3_probe.c" -o probe.o
clang -c "$FIXTURES/x86_64_divdc3_start.S" -o start.o
nm --undefined-only probe.o > emitted-imports.txt
python3 - emitted-imports.txt <<'CHECK'
from pathlib import Path
import sys
names={line.split()[-1] for line in Path(sys.argv[1]).read_text().splitlines() if line.strip()}
assert names == {'__divdc3'}, names
CHECK
linker="$(rustup run "$TOOLCHAIN" rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-musl/bin/rust-lld"
if "$linker" -flavor gnu -static --gc-sections -e _start start.o probe.o -o without-helper > without-helper.log 2>&1; then
    echo 'emitted division linked without its helper' >&2
    exit 1
fi
grep -Fq '__divdc3' without-helper.log
"$linker" -flavor gnu -static --gc-sections --trace -Map=candidate.map -e _start \
    start.o probe.o candidate.o -o candidate > candidate.trace
nm --undefined-only candidate > candidate-undefined.txt
[ ! -s candidate-undefined.txt ]
if readelf -l candidate | grep -q INTERP; then exit 1; fi
objdump -d candidate > candidate-disassembly.txt
grep -Eq '(call|jmp).*<__divdc3>' candidate-disassembly.txt
./candidate
"$ORACLE_CC" -std=c11 -O2 -ffp-contract=off -frounding-math \
    -D__divdc3=crabc_reference_divdc3 -c "$FIXTURES/llvm22_divdc3/divdc3.c" -o oracle.o
nm --undefined-only oracle.o > oracle-undefined.txt
[ ! -s oracle-undefined.txt ]
"$ORACLE_CC" -std=c11 -O2 -ffp-contract=off -frounding-math \
    "$FIXTURES/x86_64_divdc3_differential.c" candidate.o oracle.o -lm -o differential
./differential | tee differential.log
printf 'compiler-emitted double complex division: PASS (closed freestanding link)\n'
