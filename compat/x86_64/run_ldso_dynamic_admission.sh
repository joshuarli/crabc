#!/usr/bin/env bash
# Native admission inventory for the staged x86 loader graphs.
#
# This is a gate, not a generated report: it executes the existing fixtures that
# build and inspect their candidate ELF objects, then requires each accepted and
# rejected admission boundary to remain part of that executable evidence.  The
# graph runners own the byte-level mutations because only they know their
# ephemeral fixture paths; keeping this aggregate here prevents a later loader
# slice from treating their independent successes as a general loader claim.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly GRAPH_RUNNER="$ROOT_DIR/compat/x86_64/run_ldso_initial_graph.sh"
readonly TLS_RUNNER="$ROOT_DIR/compat/x86_64/run_ldso_initial_tls.sh"
readonly HANDOFF_RUNNER="$ROOT_DIR/compat/x86_64/run_ldso_owned_crt_handoff.sh"
readonly INTROSPECTION_RUNNER="$ROOT_DIR/compat/x86_64/run_ldso_fixed_graph_introspection.sh"
readonly DLFCN_RUNNER="$ROOT_DIR/compat/x86_64/run_ldso_fixed_graph_dlfcn.sh"
readonly PUBLIC_DLFCN_RUNNER="$ROOT_DIR/compat/x86_64/run_ldso_public_dlfcn.sh"
readonly BOUNDED_DLOPEN_RUNNER="$ROOT_DIR/compat/x86_64/run_ldso_bounded_dlopen.sh"

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    printf '%s\n' 'ERROR: dynamic-admission inventory requires native Linux/x86-64' >&2
    exit 2
fi

for runner in "$GRAPH_RUNNER" "$TLS_RUNNER" "$HANDOFF_RUNNER" "$INTROSPECTION_RUNNER" "$DLFCN_RUNNER" "$PUBLIC_DLFCN_RUNNER" "$BOUNDED_DLOPEN_RUNNER"; do
    if [ ! -f "$runner" ]; then
        printf '%s\n' "ERROR: required loader fixture is missing: $runner" >&2
        exit 2
    fi
done

require_runner_contract() {
    local runner="$1"
    shift
    local phrase
    for phrase in "$@"; do
        if ! grep -Fq "$phrase" "$runner"; then
            printf '%s\n' "ERROR: loader fixture no longer owns admission boundary '$phrase': $runner" >&2
            exit 1
        fi
    done
}

# The accepted inventory is intentionally only the graphs constructed by these
# runners.  They inspect the actual fresh ET_DYN/PIE objects with readelf before
# launching them, and mutate those same objects before every negative launch.
require_runner_contract "$GRAPH_RUNNER" \
    'readelf -dW' \
    'readelf -rW' \
    'R_X86_64_RELATIVE' \
    'R_X86_64_GLOB_DAT' \
    'R_X86_64_JUMP_SLOT' \
    'DT_RELA' \
    'DT_RELR' \
    'PT_GNU_RELRO' \
    'PT_TLS' \
    'R_X86_64_COPY' \
    'DT_TEXTREL' \
    'STATIC_TLS' \
    'main DT_INIT mutation'
require_runner_contract "$TLS_RUNNER" \
    'readelf -dW' \
    'readelf -rW' \
    'R_X86_64_DTPMOD64' \
    'R_X86_64_DTPOFF64' \
    'R_X86_64_TPOFF64' \
    '__tls_get_addr' \
    'PT_TLS' \
    'STATIC_TLS' \
    'env -i PATH=/usr/bin:/bin'
require_runner_contract "$HANDOFF_RUNNER" \
    'readelf -dW' \
    'R_X86_64_GLOB_DAT' \
    '__crabc_x86_64_owned_crt_handoff' \
    'GNU_RELRO' \
    'env -i PATH=/usr/bin:/bin'
require_runner_contract "$INTROSPECTION_RUNNER" \
    'readelf -dW' \
    'readelf -rW' \
    '__crabc_x86_64_fixed_graph_introspection_v1' \
    'R_X86_64_GLOB_DAT' \
    'GNU_RELRO' \
    'PT_TLS' \
    'env -i PATH=/usr/bin:/bin'
require_runner_contract "$DLFCN_RUNNER" \
    'readelf -dW' \
    'readelf -rW' \
    '__crabc_x86_64_fixed_graph_dlfcn_v1' \
    'R_X86_64_GLOB_DAT' \
    'GNU_RELRO' \
    'PT_TLS' \
    'strong-import' \
    'dso-import' \
    'env -i PATH=/usr/bin:/bin'
require_runner_contract "$PUBLIC_DLFCN_RUNNER" \
    'static_c_abi_exports.txt' \
    '__crabc_x86_64_fixed_graph_dlfcn_v1' \
    'R_X86_64_GLOB_DAT' \
    'PT_TLS' \
    'main-musl-public-dlfcn' \
    'main-crabc-public-dlfcn-malformed' \
    'main-crabc-public-dlfcn-absent' \
    'env -i PATH=/usr/bin:/bin'
require_runner_contract "$BOUNDED_DLOPEN_RUNNER" \
    'crabc_bounded_runtime_dlopen' \
    '__crabc_x86_64_fixed_graph_dlfcn_v1' \
    'R_X86_64_GLOB_DAT' \
    'libbounded-plugin.so' \
    'libbounded-tls.so' \
    'RTLD_NOLOAD' \
    'RTLD_NODELETE' \
    'PT_TLS' \
    'main-musl-bounded-dlopen' \
    'env -i PATH=/usr/bin:/bin'

run_fixture() {
    local label="$1"
    local expected="$2"
    local runner="$3"
    local output
    output="$(bash "$runner" 2>&1)"
    if ! grep -Fq "$expected" <<<"$output"; then
        printf '%s\n' "ERROR: $label fixture did not report its completed admission proof" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
}

# These are not mere smoke runs.  Each child gate constructs fresh candidate
# and pinned-musl objects, validates their dynamic/relocation shape, executes
# the accepted graph, and proves its listed malformed images terminate at 127.
run_fixture \
    'no-TLS graph' \
    'x86 ET_DYN initial graph negative file-range/PT_TLS/RELA/RELR-cap/tag/flags/table/main-init: PASS' \
    "$GRAPH_RUNNER"
run_fixture \
    'GNU-Dynamic TLS graph' \
    'x86 initial-TLS loader graph PT_TLS/DTPMOD/DTPOFF/TPOFF/static-TLS boundary: PASS' \
    "$TLS_RUNNER"
run_fixture \
    'owned-CRT handoff graph' \
    'x86 owned ldso-to-Scrt1 CRT handoff: PASS' \
    "$HANDOFF_RUNNER"
run_fixture \
    'fixed-graph introspection graph' \
    'x86 fixed-graph loader introspection snapshot/address/information: PASS' \
    "$INTROSPECTION_RUNNER"
run_fixture \
    'fixed-graph dlfcn graph' \
    'x86 fixed-graph loader handles/symbols/address/snapshot/information: PASS' \
    "$DLFCN_RUNNER"
run_fixture \
    'public fixed-graph dlfcn bridge' \
    'x86 public C fixed-graph dlfcn ABI/diagnostics/introspection: PASS' \
    "$PUBLIC_DLFCN_RUNNER"
run_fixture \
    'bounded runtime dlopen graph' \
    'x86 bounded runtime dlopen search/mapping/concurrency: PASS' \
    "$BOUNDED_DLOPEN_RUNNER"

printf '%s\n' 'x86 dynamic-loader staged admission inventory: PASS'
