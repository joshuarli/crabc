#!/usr/bin/env bash
# Native same-object differential for one selected x86 static C ABI boundary.
#
# The workload is compiled exactly once with the pinned musl 1.2.6 headers.
# That immutable object is then linked once through the pinned musl runtime and
# once through an explicitly supplied crabc-libc archive plus the test-only
# Static Initial TLS entry shim.  The candidate link is freestanding and is
# rejected if it acquires an interpreter, DT_NEEDED entry, unresolved symbol,
# or dynamic-TLS resolver.  This is a bounded static admission artifact, not a
# dynamic-runtime, ABI-inventory, symbol-parity, sysroot, or promotion gate.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly MUSL_LOADER="$MUSL_ROOT/lib/ld-musl-x86_64.so.1"
readonly FIXTURE="$ROOT_DIR/compat/x86_64/static_c_abi_differential_memfd_probe.c"
readonly START="$ROOT_DIR/compat/x86_64/static_c_abi_differential_start.S"
readonly PROBE_SYMBOL=crabc_x86_64_static_c_abi_differential_probe
readonly EXPECTED_OUTPUT=$'memfd.success=1\nmemfd.stale_errno=1\nmemfd.invalid_flags_errno=22\nmemfd.bad_pointer_errno=14\n'
readonly EXECUTION_TIMEOUT=10s

fail() {
    printf 'ERROR: x86 same-object static C ABI differential: %s\n' "$*" >&2
    exit 1
}

usage() {
    printf 'usage: %s --archive PATH\n' "${0##*/}" >&2
    exit 2
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

normalize_output() {
    local input="$1"
    local output="$2"

    # The workload emits stable semantic values.  Only transport-level CRLF
    # canonicalization is admitted; no status, errno, or whitespace filtering
    # can turn a semantic difference into a match.
    tr -d '\r' <"$input" >"$output"
    cmp -s <(printf '%s' "$EXPECTED_OUTPUT") "$output" || {
        diff -u <(printf '%s' "$EXPECTED_OUTPUT") "$output" >&2 || true
        fail "workload output escaped the canonical observable contract"
    }
}

archive=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --archive)
            [ "$#" -ge 2 ] || usage
            archive="$2"
            shift 2
            ;;
        --help|-h) usage ;;
        *) usage ;;
    esac
done
[ -n "$archive" ] || usage
[ -f "$archive" ] || fail "candidate archive is not a file: $archive"

require_native_linux_x86_64
for tool in cmp diff gcc grep mktemp readelf sha256sum timeout tr; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl headers"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
# The same-object lane intentionally uses pinned headers.  Retain the separate
# project-header declaration gate in the same transaction so this ABI proof
# cannot be mistaken for candidate-header closure.
bash "$ROOT_DIR/compat/x86_64/run_memfd_create_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-same-object-static-c-abi.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
workload_object="$work_dir/workload.o"
start_object="$work_dir/start.o"
reference="$work_dir/musl-reference"
candidate="$work_dir/crabc-static-candidate"
reference_stdout="$work_dir/reference.stdout"
reference_stderr="$work_dir/reference.stderr"
candidate_stdout="$work_dir/candidate.stdout"
candidate_stderr="$work_dir/candidate.stderr"
reference_normalized="$work_dir/reference.normalized"
candidate_normalized="$work_dir/candidate.normalized"
reference_headers="$work_dir/reference-headers"
reference_dynamic="$work_dir/reference-dynamic"
candidate_headers="$work_dir/candidate-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_symbols="$work_dir/candidate-symbols"
workload_symbols="$work_dir/workload-symbols"
candidate_builtin_include="$(gcc -print-file-name=include)"
[ -d "$candidate_builtin_include" ] || fail "raw GCC builtin include directory missing"

# This is the durable same-object contract: there is exactly one C compilation
# of the workload, against only pinned-musl plus compiler-builtin headers.  Both
# final links below consume this path, and its hash is checked after linking.
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -nostdinc \
    -isystem "$MUSL_ROOT/include" -isystem "$candidate_builtin_include" \
    -fno-builtin -fno-stack-protector -c "$FIXTURE" -o "$workload_object"
workload_hash="$(sha256sum "$workload_object" | awk '{print $1}')"
readelf --symbols --wide "$workload_object" >"$workload_symbols"
for symbol in main "$PROBE_SYMBOL"; do
    grep -Eq "[[:space:]]${symbol}$" "$workload_symbols" ||
        fail "shared workload object lacks ${symbol}"
done

env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" "$workload_object" -o "$reference"
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -c -fno-pie -ffreestanding -fno-stack-protector \
    "$START" -o "$start_object"
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    gcc -nostdlib -static -fno-pie -no-pie -Wl,-e,_start -Wl,--no-undefined \
    "$workload_object" "$start_object" "$archive" -o "$candidate"
[ "$(sha256sum "$workload_object" | awk '{print $1}')" = "$workload_hash" ] ||
    fail "shared workload object changed between reference and candidate links"

readelf --program-headers --wide "$reference" >"$reference_headers"
readelf --dynamic --wide "$reference" >"$reference_dynamic"
grep -Fq "Requesting program interpreter: $MUSL_LOADER" "$reference_headers" ||
    fail "reference does not select the pinned musl interpreter"
grep -Fq 'Shared library: [libc.so]' "$reference_dynamic" ||
    fail "reference does not select the pinned musl libc soname"
if grep -Eq 'libc\.so\.6|ld-linux|libgcc_s|\((RPATH|RUNPATH)\)' \
    "$reference_dynamic"; then
    fail "reference selected an ambient glibc or search-path runtime"
fi

readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_headers" ||
    grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic or ambient runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers" ||
    fail "candidate is not a selected initial-TLS static artifact"
for symbol in "$PROBE_SYMBOL" __crabc_x86_static_tls_bootstrap \
    __errno_location memfd_create; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate lacks selected ${symbol} boundary"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols"; then
    fail "candidate selected a dynamic TLS resolver"
fi

run_controlled() {
    local executable="$1"
    local stdout="$2"
    local stderr="$3"
    local status

    if env -i PATH=/usr/bin:/bin LC_ALL=C LANG=C TZ=UTC \
        timeout "$EXECUTION_TIMEOUT" "$executable" >"$stdout" 2>"$stderr"; then
        :
    else
        status=$?
        fail "$(basename "$executable") exited ${status} in controlled environment"
    fi
    [ ! -s "$stderr" ] || {
        sed -n '1,80p' "$stderr" >&2
        fail "$(basename "$executable") wrote stderr"
    }
}

run_controlled "$reference" "$reference_stdout" "$reference_stderr"
run_controlled "$candidate" "$candidate_stdout" "$candidate_stderr"
normalize_output "$reference_stdout" "$reference_normalized"
normalize_output "$candidate_stdout" "$candidate_normalized"
cmp -s "$reference_normalized" "$candidate_normalized" || {
    diff -u "$reference_normalized" "$candidate_normalized" >&2 || true
    fail "pinned-musl and candidate observables differ"
}

printf 'x86 static C ABI same-object differential: PASS (%s; pinned musl 1.2.6)\n' \
    "$(basename "$archive")"
