#!/usr/bin/env bash
# Native Linux/x86-64 proof for the private signed __int128 helper pair.
#
# The candidate is a fresh Rust-only bounded archive.  A pinned-musl C
# program first establishes the ordinary C quotient/remainder results, then a
# freestanding C object is shown to require exactly __divti3 and __modti3.  A
# link without that archive must fail, while the archive-backed static image
# must retain both definitions and emit the same result bits for every case.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly BUILDER="${ROOT_DIR}/builtins/build_x86_64.py"
readonly PROBE="${ROOT_DIR}/builtins/fixtures/x86_64_signed_int128_probe.c"
readonly START="${ROOT_DIR}/builtins/fixtures/x86_64_signed_int128_start.S"

fail() {
    printf 'ERROR: private x86 signed-int128 builtins proof: %s\n' "$*" >&2
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

for tool in chmod cmp grep mktemp nm objdump python3 readelf; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned x86 musl compiler wrapper"
[ -f "$BUILDER" ] || fail "missing bounded x86 archive builder"
[ -f "$PROBE" ] || fail "missing signed-int128 C fixture"
[ -f "$START" ] || fail "missing freestanding x86 start fixture"

bash "${ROOT_DIR}/compat/x86_64/run_musl_oracle.sh" >/dev/null

mkdir -p "${ROOT_DIR}/.work/x86_64/reports"
work_dir="$(mktemp -d "${ROOT_DIR}/.work/x86_64/reports/signed-int128.XXXXXX")"
chmod 755 "$work_dir"
archive="${work_dir}/libcrabc-builtins.a"
provenance="${work_dir}/libcrabc-builtins.a.provenance.json"
object="${work_dir}/signed-int128.o"
start_object="${work_dir}/signed-int128-start.o"
without_archive="${work_dir}/without-builtins"
without_archive_log="${work_dir}/without-builtins.log"
candidate="${work_dir}/with-builtins"
candidate_link_log="${work_dir}/with-builtins-link.log"
candidate_map="${work_dir}/with-builtins.map"
reference="${work_dir}/pinned-musl-reference"
reference_link_log="${work_dir}/pinned-musl-reference-link.log"
reference_symbols="${work_dir}/pinned-musl-reference-symbols.txt"
reference_stream="${work_dir}/pinned-musl-reference.stdout"
candidate_stream="${work_dir}/with-builtins.stdout"
symbols="${work_dir}/object-undefined.txt"
candidate_symbols="${work_dir}/candidate-defined-symbols.txt"
candidate_undefined="${work_dir}/candidate-undefined-symbols.txt"
disassembly="${work_dir}/candidate-disassembly.txt"
header="${work_dir}/candidate-header.txt"
program_headers="${work_dir}/candidate-program-headers.txt"
dynamic="${work_dir}/candidate-dynamic.txt"

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
defined = set(archive.get("defined_symbols", []))
missing = {"__divti3", "__modti3"}.difference(defined)
if missing:
    raise SystemExit(f"archive lacks signed helper definitions: {sorted(missing)}")
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
for symbol in __divti3 __modti3; do
    grep -Eq "[[:space:]]${symbol}$" "$symbols" || {
        fail "native C object did not require ${symbol}"
    }
done
if grep -Evq '[[:space:]](__divti3|__modti3)$' "$symbols"; then
    fail "native C object admitted an unexpected helper boundary"
fi

if oracle_cc \
    -nostdlib -static -no-pie \
    -Wl,--build-id=none -Wl,--no-undefined -Wl,-e,_start \
    "$start_object" "$object" -o "$without_archive" >"$without_archive_log" 2>&1; then
    fail "freestanding signed-int128 link unexpectedly succeeded without the bounded archive"
fi
for symbol in __divti3 __modti3; do
    grep -Fq "$symbol" "$without_archive_log" || {
        fail "archive-free link failure did not name ${symbol}"
    }
done

oracle_cc \
    -nostdlib -static -no-pie \
    -Wl,--build-id=none -Wl,--no-undefined -Wl,-e,_start -Wl,-t \
    -Wl,-Map,"$candidate_map" \
    "$start_object" "$object" "$archive" -o "$candidate" >"$candidate_link_log" 2>&1
if grep -Eq 'libgcc|compiler-rt|libc\.a|/crt[^[:space:]]*\.o' "$candidate_link_log"; then
    fail "candidate link admitted an ambient CRT or compiler runtime"
fi
grep -Fxq "$archive" "$candidate_link_log" || {
    fail "candidate link trace did not name the owned archive"
}
grep -Fq "$archive(crabc-builtins.o)" "$candidate_map" || {
    fail "candidate map did not attribute the extracted member to the owned archive"
}

readelf --file-header --wide "$candidate" >"$header"
grep -Fq 'Type:                              EXEC (Executable file)' "$header" || {
    fail "candidate is not a static ET_EXEC image"
}
grep -Fq 'Machine:                           Advanced Micro Devices X86-64' "$header" || {
    fail "candidate is not x86-64 ELF"
}
readelf --program-headers --wide "$candidate" >"$program_headers"
if grep -Eq 'INTERP| TLS ' "$program_headers"; then
    fail "candidate unexpectedly needs an interpreter or TLS runtime state"
fi
readelf --dynamic --wide "$candidate" >"$dynamic"
if grep -Eq '\((NEEDED|JMPREL|PLTGOT)\)' "$dynamic"; then
    fail "candidate unexpectedly records a dynamic runtime dependency"
fi
nm --undefined-only "$candidate" >"$candidate_undefined"
if grep -q . "$candidate_undefined"; then
    fail "candidate retains unresolved symbols"
fi
nm --defined-only "$candidate" >"$candidate_symbols"
for symbol in __divti3 __modti3; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" || {
        fail "candidate did not retain ${symbol}"
    }
done
objdump --disassemble "$candidate" >"$disassembly"
for symbol in __divti3 __modti3; do
    grep -Eq "call[a-z]*[[:space:]].*<${symbol}>" "$disassembly" || {
        fail "candidate code does not call ${symbol}"
    }
done

oracle_cc -std=c11 -O2 -fno-builtin -fno-stack-protector -fno-pie -no-pie \
    -static -Wl,-t "$PROBE" -o "$reference" >"$reference_link_log" 2>&1
grep -Eq 'libgcc\.a' "$reference_link_log" || {
    fail "reference link trace did not name pinned compiler helper archive"
}
nm --defined-only "$reference" >"$reference_symbols"
for symbol in __divti3 __modti3; do
    grep -Eq "[[:space:]]${symbol}$" "$reference_symbols" || {
        fail "reference ELF did not retain pinned ${symbol}"
    }
done
"$reference" >"$reference_stream"
"$candidate" >"$candidate_stream"
[ -s "$reference_stream" ] || fail "reference emitted no result stream"
if ! cmp -s "$reference_stream" "$candidate_stream"; then
    fail "candidate result stream differs from pinned reference: $reference_stream $candidate_stream"
fi

printf 'private x86 signed __int128 compiler-helper ABI: PASS (%s)\n' "$work_dir"
