#!/usr/bin/env bash
# Compare pinned-musl temporary-object calls with the freestanding static C ABI.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() { printf 'ERROR: x86 temporary objects: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
for tool in nm readelf strace timeout; do command -v "$tool" >/dev/null || fail "requires $tool"; done
[ -x "$ORACLE_CC" ] || fail 'missing pinned musl compiler'
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

mkdir -p "$ROOT_DIR/.work/x86_64/reports"
work_dir="$(mktemp -d "$ROOT_DIR/.work/x86_64/reports/libc-temporary-objects.XXXXXX")"
mkdir "$work_dir/musl-root" "$work_dir/candidate-root"
probe="$ROOT_DIR/compat/x86_64/libc_temporary_objects_probe.c"
start="$ROOT_DIR/compat/x86_64/libc_temporary_objects_start.S"
reference="$work_dir/reference"
candidate="$work_dir/candidate"
archive="$work_dir/libc.a"
builtins_archive="$work_dir/libcrabc-builtins.a"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    "-DFIXTURE_ROOT=\"$work_dir/musl-root\"" \
    "$probe" -o "$reference"
build_source_runtime_libc "$archive" --features x86-owned-static-runtime-core
python3 "$ROOT_DIR/builtins/build_x86_64.py" --output "$builtins_archive" \
    >"$work_dir/builtins-build.log"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_TEMPORARY_OBJECTS_FREESTANDING \
    "-DFIXTURE_ROOT=\"$work_dir/candidate-root\"" -I "$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    "$probe" "$start" "$archive" "$builtins_archive" -o "$candidate"

nm --defined-only "$candidate" >"$work_dir/candidate-defined-symbols"
for symbol in mkstemp mkstemps mkostemp __mkostemps mkdtemp __errno_location; do
    grep -Eq "[[:space:]][TW][[:space:]]$symbol$" "$work_dir/candidate-defined-symbols" ||
        fail "candidate lacks $symbol"
done
readelf -lW "$candidate" >"$work_dir/candidate-program-headers"
readelf -Ws "$candidate" >"$work_dir/candidate-symbols"
if grep -Eq 'INTERP|Requesting program interpreter' "$work_dir/candidate-program-headers"; then
    fail 'candidate has a dynamic interpreter'
fi
awk '$7 == "UND" && NF >= 8 { print }' "$work_dir/candidate-symbols" \
    >"$work_dir/candidate-unresolved"
if [ -s "$work_dir/candidate-unresolved" ]; then
    fail 'candidate has unresolved symbols'
fi

for product in "$reference" "$candidate"; do
    label="${product##*/}"
    output="$(timeout 20s "$product")" || fail "$label normal case exited $?"
    [ "$output" = 'temporary-objects:PASS' ] || fail "$label normal output: $output"
    for operation in open mkdir; do
        trace="$work_dir/$label-$operation.trace"
        output="$(timeout 20s strace -qq -e "trace=$operation" \
            -e "inject=$operation:error=EEXIST:when=1" -o "$trace" "$product")" ||
            fail "$label injected $operation collision exited $?"
        [ "$output" = 'temporary-objects:PASS' ] ||
            fail "$label injected $operation output: $output"
        if [ "$operation" = open ]; then collision_stem=plain; else collision_stem=dir; fi
        grep -Eq "/${collision_stem}-[A-Pa-p]{6}.*EEXIST \(File exists\) \(INJECTED\)" "$trace" ||
            fail "$label $operation injection was not observed"
    done
done

printf 'x86 pinned-musl/static temporary objects: PASS\n'
printf 'raw evidence: %s\n' "$work_dir"
