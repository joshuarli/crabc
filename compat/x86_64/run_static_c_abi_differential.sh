#!/usr/bin/env bash
# Deterministic private x86 selected-static-C-ABI musl differential bootstrap.
#
# The caller supplies the candidate archive explicitly. This runner compiles
# the same bounded C workload once against pinned musl headers/runtime and
# once against project headers plus that archive. It runs both with a minimal
# environment, requires empty stderr and equal successful status, then checks
# the fixture's canonical observable record. It is a reusable harness shape,
# not an aggregate ABI inventory, dynamic-runtime test, or promotion gate.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly FIXTURE="$ROOT_DIR/compat/x86_64/static_c_abi_differential_memfd_probe.c"
readonly START="$ROOT_DIR/compat/x86_64/static_c_abi_differential_start.S"
readonly PROBE_SYMBOL=crabc_x86_64_static_c_abi_differential_probe
readonly EXPECTED_OUTPUT=$'memfd.success=1\nmemfd.stale_errno=1\nmemfd.invalid_flags_errno=22\nmemfd.bad_pointer_errno=14\n'
readonly EXECUTION_TIMEOUT=10s

fail() {
    printf 'ERROR: x86 static C ABI differential: %s\n' "$*" >&2
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

    # Workloads must report semantic observables themselves. Normalization is
    # intentionally only CRLF-to-LF canonicalization; it must not hide values.
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
for tool in cmp diff gcc mktemp readelf timeout tr; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl headers"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-static-c-abi-differential.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
reference="$work_dir/musl-reference"
candidate="$work_dir/static-candidate"
reference_stdout="$work_dir/reference.stdout"
reference_stderr="$work_dir/reference.stderr"
candidate_stdout="$work_dir/candidate.stdout"
candidate_stderr="$work_dir/candidate.stderr"
reference_normalized="$work_dir/reference.normalized"
candidate_normalized="$work_dir/candidate.normalized"
candidate_headers="$work_dir/candidate-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_symbols="$work_dir/candidate-symbols"
candidate_builtin_include="$(gcc -print-file-name=include)"
[ -d "$candidate_builtin_include" ] || fail "raw GCC builtin include directory missing"

# The reference gets only the pinned musl include tree and GCC builtins. The
# candidate gets only project headers and the same GCC builtins; neither lane
# can silently inherit host or the other lane's C headers.
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -nostdinc \
    -isystem "$MUSL_ROOT/include" -isystem "$candidate_builtin_include" \
    -fno-builtin -fno-stack-protector "$FIXTURE" -o "$reference"
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    gcc -std=c11 -D_GNU_SOURCE -DCRABC_STATIC_C_ABI_DIFFERENTIAL_FREESTANDING \
    -nostdinc -isystem "$ROOT_DIR/include" -isystem "$candidate_builtin_include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined "$FIXTURE" "$START" \
    "$archive" -o "$candidate"

readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --symbols --wide "$candidate" >"$candidate_symbols"
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_headers" ||
    grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers" ||
    fail "candidate is not a selected initial-TLS static artifact"
for symbol in "$PROBE_SYMBOL" __crabc_x86_static_tls_bootstrap \
    __errno_location memfd_create; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate lacks selected ${symbol} boundary"
done

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

printf 'x86 static C ABI differential bootstrap: PASS (%s; pinned musl 1.2.6)\n' \
    "$(basename "$archive")"
