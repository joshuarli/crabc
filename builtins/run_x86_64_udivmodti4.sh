#!/usr/bin/env bash
# Native Linux/x86-64 proof for the unsigned 128-bit compiler-helper ABI.
#
# A pinned-musl C reference uses ordinary unsigned division and remainder. The
# candidate is a fresh Rust-only archive linked to a freestanding C object that
# directly calls __udivti3, __umodti3, and __udivmodti4. The archive-free link
# must fail; the archive-backed image must be static, closed, and execute the
# same nonzero-divisor cases as the pinned compiler reference.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly BUILDER="${ROOT_DIR}/builtins/build_x86_64.py"
readonly PROBE="${ROOT_DIR}/builtins/fixtures/x86_64_udivmodti4_probe.c"
readonly START="${ROOT_DIR}/builtins/fixtures/x86_64_udivmodti4_start.S"

fail() {
    printf 'ERROR: private x86 udivmodti4 builtins proof: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

oracle_cc() {
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u COMPILER_PATH \
        "$ORACLE_CC" "$@"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac

for tool in cmp grep mktemp nm objdump python3 readelf sha256sum wc; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned x86 musl compiler wrapper"
[ -f "$BUILDER" ] || fail "missing bounded x86 archive builder"
[ -f "$PROBE" ] || fail "missing udivmodti4 C fixture"
[ -f "$START" ] || fail "missing freestanding x86 start fixture"

bash "${ROOT_DIR}/compat/x86_64/run_musl_oracle.sh" >/dev/null

report_root="${ROOT_DIR}/.work/x86_64/builtins-udivmodti4"
mkdir -p "$report_root"
work_dir="$(mktemp -d "${report_root}/run.XXXXXX")"
chmod 755 "$work_dir"
printf 'raw unsigned compiler-helper evidence: %s\n' "$work_dir"
archive="${work_dir}/libcrabc-builtins.a"
provenance="${work_dir}/libcrabc-builtins.a.provenance.json"
object="${work_dir}/udivmodti4.o"
start_object="${work_dir}/udivmodti4-start.o"
without_archive="${work_dir}/without-builtins"
without_archive_log="${work_dir}/without-builtins.log"
candidate="${work_dir}/with-builtins"
candidate_link_log="${work_dir}/with-builtins-link.log"
reference="${work_dir}/pinned-musl-reference"
reference_object="${work_dir}/reference.o"
reference_link_log="${work_dir}/reference-link.log"
candidate_output="${work_dir}/candidate-results.bin"
reference_output="${work_dir}/reference-results.bin"
symbols="${work_dir}/object-undefined.txt"
candidate_symbols="${work_dir}/candidate-defined-symbols.txt"
candidate_undefined="${work_dir}/candidate-undefined-symbols.txt"
disassembly="${work_dir}/candidate-disassembly.txt"
header="${work_dir}/candidate-header.txt"
program_headers="${work_dir}/candidate-program-headers.txt"
dynamic="${work_dir}/candidate-dynamic.txt"
relocations="${work_dir}/candidate-relocations.txt"
link_map="${work_dir}/candidate-link.map"

python3 "$BUILDER" --output "$archive" --provenance "$provenance" --verify-reproducible >/dev/null
python3 - "$provenance" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
archive = record.get("archive")
if record.get("target") != "x86_64-unknown-linux-musl":
    raise SystemExit("archive provenance target drifted")
if record.get("scope") != "bounded private x86 static consumers only; not a complete compiler runtime or public sysroot":
    raise SystemExit("archive provenance scope drifted")
if not isinstance(archive, dict):
    raise SystemExit("archive provenance is missing archive metadata")
if archive.get("members") != ["crabc-builtins.o"]:
    raise SystemExit("archive membership drifted")
if not {"__udivti3", "__umodti3", "__udivmodti4"} <= set(archive.get("defined_symbols", [])):
    raise SystemExit("archive lacks an unsigned division helper")
if record.get("reproducible") is not True:
    raise SystemExit("archive reproducibility proof did not pass")
PY

oracle_cc \
    -std=c11 -O2 -fno-builtin -fno-stack-protector \
    -fno-asynchronous-unwind-tables -fno-unwind-tables \
    -ffreestanding -fno-pic -fno-pie \
    -DCRABC_BUILTINS_FREESTANDING \
    -c "$PROBE" -o "$object"
oracle_cc -c "$START" -o "$start_object"

nm --undefined-only "$object" >"$symbols"
for symbol in __udivti3 __umodti3 __udivmodti4; do
    grep -Eq "[[:space:]]${symbol}$" "$symbols" || {
        fail "native C object did not require ${symbol}"
    }
done
if grep -Evq '[[:space:]](__udivti3|__umodti3|__udivmodti4)$' "$symbols"; then
    fail "native C object admitted an unexpected helper boundary"
fi

if oracle_cc \
    -nostdlib -static -no-pie \
    -Wl,--build-id=none -Wl,--no-undefined -Wl,-e,_start \
    "$start_object" "$object" -o "$without_archive" >"$without_archive_log" 2>&1; then
    fail "freestanding udivmodti4 link unexpectedly succeeded without the bounded archive"
fi
for symbol in __udivti3 __umodti3 __udivmodti4; do
    grep -Fq "$symbol" "$without_archive_log" || {
        fail "archive-free link failure did not name ${symbol}"
    }
done

oracle_cc \
    -nostdlib -static -no-pie \
    -Wl,--build-id=none -Wl,--no-undefined -Wl,-e,_start -Wl,-t \
    -Wl,-Map,"$link_map" \
    -Wl,--trace-symbol=__udivti3 -Wl,--trace-symbol=__umodti3 \
    -Wl,--trace-symbol=__udivmodti4 \
    "$start_object" "$object" "$archive" -o "$candidate" >"$candidate_link_log" 2>&1
if grep -Eq 'libgcc|compiler-rt|libc\.a|/crt[^[:space:]]*\.o' "$candidate_link_log"; then
    fail "candidate link admitted an ambient CRT or compiler runtime"
fi

readelf --file-header --wide "$candidate" >"$header"
grep -Fq 'Type:                              EXEC (Executable file)' "$header" || {
    fail "candidate is not a static ET_EXEC image"
}
grep -Fq 'Machine:                           Advanced Micro Devices X86-64' "$header" || {
    fail "candidate is not x86-64 ELF"
}
readelf --program-headers --wide "$candidate" >"$program_headers"
if grep -Eq 'INTERP|DYNAMIC| TLS ' "$program_headers"; then
    fail "candidate unexpectedly needs an interpreter or dynamic runtime state"
fi
if grep -Eq 'GNU_STACK.*RWE' "$program_headers"; then
    fail "candidate has an executable stack"
fi
readelf --dynamic --wide "$candidate" >"$dynamic"
if grep -Eq '\((NEEDED|JMPREL|PLTGOT)\)' "$dynamic"; then
    fail "candidate unexpectedly records a dynamic runtime dependency"
fi
nm --undefined-only "$candidate" >"$candidate_undefined"
if grep -q . "$candidate_undefined"; then
    fail "candidate retains unresolved symbols"
fi
readelf --relocs --wide "$candidate" >"$relocations"
if grep -q 'R_X86_64_' "$relocations"; then
    fail "candidate has runtime relocations"
fi
nm --defined-only "$candidate" >"$candidate_symbols"
objdump --disassemble "$candidate" >"$disassembly"
for symbol in __udivti3 __umodti3 __udivmodti4; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" || {
        fail "candidate did not retain ${symbol}"
    }
    grep -Eq "(call[a-z]*|jmp[a-z]*)[[:space:]].*<${symbol}>" "$disassembly" || {
        fail "candidate code does not transfer control to ${symbol}"
    }
    grep -Fq "$archive" "$candidate_link_log" || {
        fail "candidate link did not trace the owned archive"
    }
    grep -Fq "$object: reference to $symbol" "$candidate_link_log" || {
        fail "candidate link did not trace the ${symbol} reference"
    }
    grep -Fq "$archive(crabc-builtins.o): definition of $symbol" "$candidate_link_log" || {
        fail "candidate link did not attribute ${symbol} to the owned archive member"
    }
    grep -Fq " .text.${symbol}" "$link_map" || {
        fail "candidate map did not retain the ${symbol} text section"
    }
done

libgcc="$(oracle_cc -print-libgcc-file-name)"
[ -f "$libgcc" ] || fail "pinned compiler cannot identify its reference arithmetic archive"
oracle_cc --version >"${work_dir}/oracle-compiler-version.txt"
oracle_cc \
    -std=c11 -O2 -fno-builtin -fno-stack-protector \
    -fno-asynchronous-unwind-tables -fno-unwind-tables \
    -ffreestanding -fno-pic -fno-pie \
    -DCRABC_BUILTINS_FREESTANDING -DCRABC_BUILTINS_REFERENCE \
    -c "$PROBE" -o "$reference_object"
oracle_cc -nostdlib -static -no-pie \
    -Wl,--build-id=none -Wl,--no-undefined -Wl,-e,_start -Wl,-t \
    "$start_object" "$reference_object" -lgcc -o "$reference" >"$reference_link_log" 2>&1

"$reference" >"$reference_output" || fail "pinned compiler reference failed"
"$candidate" >"$candidate_output" || fail "owned compiler-helper candidate failed"
if ! cmp -s "$reference_output" "$candidate_output"; then
    cmp "$reference_output" "$candidate_output" >&2 || true
    fail "unsigned compiler-helper differential differs"
fi
case_count=$((14 * 13 + 128 * 4 + 256))
expected_bytes=$((case_count * 4 * 16))
[ "$(wc -c <"$candidate_output")" -eq "$expected_bytes" ] || {
    fail "result stream length differs from the selected case matrix"
}
sha256sum "$ORACLE_CC" "${ROOT_DIR}/builtins/src/lib.rs" "$PROBE" "$START" \
    "$archive" "$candidate" "$reference" \
    "$candidate_output" "$reference_output" "$libgcc" >"${work_dir}/sha256sums.txt"
printf 'private x86 unsigned 128-bit compiler-helper ABI: PASS (%s cases)\n' "$case_count"
