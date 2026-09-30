#!/usr/bin/env bash
set -euo pipefail
readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly TOOLCHAIN="$(python3 "$ROOT_DIR/scripts/rust_toolchain.py")"
readonly work="${1:-$ROOT_DIR/.work/x86_64/binary32-casts}"
readonly replay="${2:-}"
case "$work" in "$ROOT_DIR"/.work/x86_64/*) ;; *) exit 2 ;; esac
python3 - "$ROOT_DIR" "$work" <<'BOUNDARY'
from pathlib import Path
import sys
root=Path(sys.argv[1]).resolve();work=Path(sys.argv[2])
assert work.resolve()==work and '..' not in work.parts
work.relative_to(root/'.work/x86_64')
BOUNDARY
if [ "$replay" != --replay ]; then
[ -z "$replay" ]
[ ! -e "$work" ]
mkdir -p "$work/tmp"
export TMPDIR="$work/tmp"
cd "$work"
out="$work"
rustup run "$TOOLCHAIN" rustc --crate-name crabc_builtins_x86_64 --crate-type=lib --edition=2021 \
    --target x86_64-unknown-linux-musl --emit=obj -C panic=abort -C force-unwind-tables=no \
    -C overflow-checks=off -C opt-level=2 -C codegen-units=1 -C debuginfo=0 \
    -C relocation-model=pic -C embed-bitcode=no "$ROOT_DIR/builtins/src/lib.rs" -o candidate.o
cp candidate.o crabc-builtins.o
ar rcsD libcrabc-builtins.a crabc-builtins.o
/usr/local/bin/crabc-x86_64-musl-gcc -dM -E -x c /dev/null > compiler-default-macros.txt
/usr/local/bin/crabc-x86_64-musl-gcc -O2 -ffreestanding -fno-builtin -fno-stack-protector \
    -fno-asynchronous-unwind-tables -fno-unwind-tables -ffp-contract=off -frounding-math \
    -c "$ROOT_DIR/builtins/fixtures/x86_64_binary32_casts_probe.c" -o probe.o
/usr/local/bin/crabc-x86_64-musl-gcc -c "$ROOT_DIR/builtins/fixtures/x86_64_binary32_casts_start.S" -o start.o
nm --undefined-only probe.o > emitted-imports.txt
python3 - emitted-imports.txt <<'IMPORTS'
from pathlib import Path
import sys
names={line.split()[-1] for line in Path(sys.argv[1]).read_text().splitlines() if line.strip()}
assert names=={'__fixsfti','__fixunssfti','__floattisf','__floatuntisf'},names
IMPORTS
readonly linker="$(rustup run "$TOOLCHAIN" rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-musl/bin/rust-lld"
for mode in static pie; do
    flags=(-static --no-dynamic-linker)
    if [ "$mode" = pie ]; then flags+=(-pie); fi
    "$linker" -flavor gnu "${flags[@]}" --no-undefined --gc-sections --trace -Map="$mode.map" \
        -e _start "$work/start.o" "$work/probe.o" "$work/libcrabc-builtins.a" -o "$mode" > "$mode.trace" 2> "$mode.stderr"
done
readonly upstream="$(rustup run "$TOOLCHAIN" rustc --print sysroot)/lib/rustlib/src/rust/library/compiler-builtins"
mkdir -p oracle-source/compiler-builtins oracle-source/libm
cp -a "$upstream/compiler-builtins/src" oracle-source/compiler-builtins/
cp -a "$upstream/libm/src" oracle-source/libm/
cp -a "$upstream/LICENSE.txt" oracle-source/
printf '%s  %s\n' 1ec3627f95be4a4e6b0e25c0ecaff9040e4ef68222a4df7398a422fb55a61ac8 \
    oracle-source/compiler-builtins/src/float/conv.rs | sha256sum -c - > oracle-inputs.log
find oracle-source -type f -print0 | sort -z | xargs -0 sha256sum > oracle-source-sha256.txt
rustup run "$TOOLCHAIN" rustc --crate-name binary32_source_oracle --crate-type=rlib --edition=2024 \
    --target x86_64-unknown-linux-musl -C opt-level=2 -C overflow-checks=off -C panic=abort \
    -C codegen-units=1 -C embed-bitcode=yes oracle-source/compiler-builtins/src/lib.rs \
    -o libbinary32_source_oracle.rlib
rustup run "$TOOLCHAIN" rustc --crate-name binary32_reference --crate-type=lib --edition=2021 \
    --target x86_64-unknown-linux-musl --emit=obj -C opt-level=2 -C overflow-checks=off \
    -C panic=abort -C lto=fat -C embed-bitcode=yes \
    --extern binary32_source_oracle=libbinary32_source_oracle.rlib \
    "$ROOT_DIR/builtins/fixtures/x86_64_binary32_casts_oracle.rs" -o oracle.o
nm --undefined-only oracle.o > oracle-imports.txt
if grep -Eq ' U (__fixsfti|__fixunssfti|__floattisf|__floatuntisf)$' oracle-imports.txt; then exit 1; fi
/usr/local/bin/crabc-x86_64-musl-gcc -std=c11 -O2 -ffreestanding -fno-builtin -fno-stack-protector \
    -fno-asynchronous-unwind-tables -fno-unwind-tables -ffp-contract=off -frounding-math \
    -c "$ROOT_DIR/builtins/fixtures/x86_64_binary32_casts_differential.c" -o differential.o
/usr/local/bin/crabc-x86_64-musl-gcc -c "$ROOT_DIR/builtins/fixtures/x86_64_divdc3_start.S" -o differential-start.o
"$linker" -flavor gnu -static --no-undefined --gc-sections --trace -Map=differential.map -e _start \
    differential-start.o differential.o libcrabc-builtins.a oracle.o libbinary32_source_oracle.rlib \
    -o differential > differential.trace
else
[ -d "$work" ]
cd "$work"
mkdir -p "$ROOT_DIR/.work/x86_64/tmp"
out="$(mktemp -d "$ROOT_DIR/.work/x86_64/tmp/binary32-replay.XXXXXX")"
fi
sha256sum -c oracle-source-sha256.txt > "$out/oracle-replay.log"
for mode in static pie differential; do
    nm --undefined-only "$mode" > "$out/$mode.undefined"
    [ ! -s "$out/$mode.undefined" ]
    if readelf -l "$mode" | grep -q INTERP; then exit 1; fi
    objdump -d "$mode" > "$out/$mode.disassembly"
    for name in __fixsfti __fixunssfti __floattisf __floatuntisf; do
        grep -Eq "(call|jmp).*<$name>" "$out/$mode.disassembly"
    done
    "./$mode"
done
python3 - "$ROOT_DIR" "$work" <<'TRANSFERS'
from pathlib import Path
import sys
root=Path(sys.argv[1]);work=Path(sys.argv[2])
sys.path.insert(0,str(root/'compat/x86_64'))
import compiler_helper_evidence as reader
member=reader.Elf(work/'crabc-builtins.o')
for mode in ('static','pie'):
    final=reader.Elf(work/mode)
    lines=(work/(mode+'.map')).read_text().splitlines()
    trace=(work/(mode+'.trace')).read_text().splitlines()
    archive=str(work/'libcrabc-builtins.a')
    workload=str(work/'probe.o')
    assert trace.count(archive+'(crabc-builtins.o)')==1
    assert trace.count(workload)==1
    for name in ('__fixsfti','__fixunssfti','__floattisf','__floatuntisf'):
        original=member.symbol(name,dynamic=False)
        provider=reader._final_symbol(final,name,'GLOBAL')
        reader._owned_helper_provider_closure(member,final,lines,archive,original,provider)
        calls=reader._direct_source_calls((work/'probe.o').read_bytes(),name,root,allow_tail_calls=True)
        addresses={}
        for section in {row['section'] for row in calls}:
            rows=[line for line in lines if line.rstrip().endswith(workload+':('+section+')')]
            assert len(rows)==1
            fields=rows[0].split();addresses[section]=(int(fields[0],16),int(fields[2],16))
        reader._final_direct_calls(final,calls,addresses,provider['value'])
print('binary32 calls and complete owned provider bytes: PASS')
TRANSFERS
printf 'binary32 compiler-emitted casts: PASS\n'
printf 'verification scratch: %s\n' "$out"
