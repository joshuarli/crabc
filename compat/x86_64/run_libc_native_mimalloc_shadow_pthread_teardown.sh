#!/usr/bin/env bash
# Native Linux/x86-64 selected-native allocator worker-teardown evidence.
#
# This uses a real owned-static process startup and its ordinary pthread
# create/exit/join/cancellation path. It is intentionally feature-gated:
# default x86 remains C mimalloc. The selected archive still has an incidental
# C mimalloc build dependency through the owned-static aggregate, so this is
# neither a C-free graph claim nor promotion evidence.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly EXECUTION_TIMEOUT=20s

fail() {
    printf 'ERROR: x86 selected native-mimalloc pthread teardown: %s\n' "$*" >&2
    exit 1
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

require_native_linux_x86_64
for tool in cargo grep mkdir mkfifo mktemp nm readelf rm sleep timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

work_parent="$ROOT_DIR/.work/x86_64/native-mimalloc-shadow-pthread-teardown"
mkdir -p "$work_parent"
work_dir="$(mktemp -d "$work_parent/run.XXXXXX")"
mkdir -p "$work_dir/tmp"
export TMPDIR="$work_dir/tmp"
export CARGO_HOME="$ROOT_DIR/.work/x86_64/cargo"
mkdir -p "$CARGO_HOME"
cleanup() {
    status=$?
    if [ "$status" -eq 0 ]; then
        rm -rf -- "$work_dir"
    else
        printf 'x86 selected native-mimalloc pthread teardown retained failed evidence: %s\n' \
            "$work_dir" >&2
    fi
    exit "$status"
}
trap cleanup EXIT

# The fixture's final worker must not return until the bootstrapped task has
# actually become a zombie. An in-process release flag would race the selected
# pthread list transition and could make the main task the ordinary-exit
# allocator caller instead. This adopts the existing last-thread evidence
# handshake while keeping the exercised candidate static and native-selected.
run_final_worker_atexit_probe() {
    local executable="$1"
    local label="$2"
    local release="$3"
    local fifo="$work_dir/final-worker-release"
    local release_fd
    local process
    local status
    local attempt

    mkfifo "$fifo" || return 1
    # Keep one read/write endpoint open before the child starts, so neither
    # side blocks opening the FIFO before the runner observes the zombie.
    exec {release_fd}<>"$fifo"
    "$executable" <"$fifo" &
    process=$!
    for ((attempt = 0; attempt != 2000; ++attempt)); do
        if grep -Eq '^State:[[:space:]]+Z' "/proc/$process/task/$process/status" 2>/dev/null; then
            printf '%s' "$release" >&"$release_fd"
            wait "$process"
            status=$?
            exec {release_fd}>&-
            rm -f -- "$fifo"
            if [ "$status" -ne 0 ]; then
                printf '%s final-worker atexit status: %s\n' "$label" "$status" >&2
            fi
            return "$status"
        fi
        if ! kill -0 "$process" 2>/dev/null; then
            wait "$process"
            status=$?
            exec {release_fd}>&-
            rm -f -- "$fifo"
            printf '%s ended before the bootstrapped task became a zombie (status %s)\n' \
                "$label" "$status" >&2
            return "$status"
        fi
        sleep 0.01
    done
    kill "$process" 2>/dev/null || true
    wait "$process" || true
    exec {release_fd}>&-
    rm -f -- "$fifo"
    printf '%s did not expose a zombie bootstrapped task before timeout\n' "$label" >&2
    return 1
}

cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-reference"
candidate="$work_dir/native-shadow-candidate"
internal_allocator_override_candidate="$work_dir/native-shadow-internal-allocator-override-candidate"
archive_symbols="$work_dir/archive-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_relocations="$work_dir/candidate-relocations"

# `cargo rustc -- -Ztls-model=initial-exec` would reach only crabc-libc, while
# this selected archive also links crabc-mimalloc. Keep the model target-wide
# for this static candidate so the audit bridge cannot hide a TLSGD dependency
# in that dependency's object code. Cargo's encoded setting takes precedence
# over RUSTFLAGS, including an empty encoded value, so set its one exact flag.
readonly NATIVE_ENCODED_RUSTFLAGS='-Ztls-model=initial-exec'

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin \
    -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_probe.c \
    -o "$reference"
if ! run_final_worker_atexit_probe "$reference" "pinned-musl reference normal-return" R; then
    fail "pinned-musl reference execution failed"
fi
if ! run_final_worker_atexit_probe "$reference" "pinned-musl reference explicit-exit" E; then
    fail "pinned-musl reference execution failed"
fi

CARGO_ENCODED_RUSTFLAGS="$NATIVE_ENCODED_RUSTFLAGS" CARGO_TARGET_DIR="$cargo_target" \
    cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl \
    --features x86-owned-static-runtime,native-mimalloc-shadow,native-mimalloc-shadow-test-audit -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the selected static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
for symbol in __crabc_x86_native_mimalloc_shadow_v1 \
    __crabc_x86_native_mimalloc_active_later_thread_count_test_audit \
    __crabc_x86_static_tls_bootstrap __libc_start_main \
    pthread_create pthread_exit pthread_join pthread_cancel pthread_testcancel \
    pthread_key_create pthread_key_delete pthread_getspecific pthread_setspecific \
    malloc free calloc realloc; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "selected archive does not define ${symbol}"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT \
    -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
    -Wl,-u,__crabc_x86_native_mimalloc_shadow_v1 \
    compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_probe.c \
    compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_start.S \
    "$archive" -o "$candidate"

# A caller-owned strong malloc returns null. `pthread_atfork` is an existing
# private allocator client, so successful registration proves its node uses
# the native internal seam rather than the weak public symbol.
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_NATIVE_INTERNAL_MALLOC_OVERRIDE \
    -DCRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--no-undefined -Wl,--gc-sections \
    -Wl,-u,__crabc_x86_native_mimalloc_shadow_v1 \
    compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_probe.c \
    compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_start.S \
    "$archive" -o "$internal_allocator_override_candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
for symbol in __crabc_x86_native_mimalloc_shadow_v1 \
    __crabc_x86_native_mimalloc_active_later_thread_count_test_audit \
    __crabc_x86_static_tls_bootstrap __libc_start_main \
    pthread_create pthread_exit pthread_join pthread_cancel pthread_testcancel \
    pthread_key_create pthread_key_delete pthread_getspecific pthread_setspecific \
    malloc free; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
[ -z "$unresolved_symbols" ] || {
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
}
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" ||
    grep -Eq 'NEEDED|JMPREL|PLTGOT' "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks initial TLS"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols"; then
    fail "candidate retains a dynamic TLS route"
fi
# A native-selected public allocation call must not extract the bundled C
# mimalloc wrappers. The aggregate's retained C build dependency is checked
# separately in documentation and does not make these selected pointers C.
if grep -Eq '[[:space:]](mi_(malloc|free|calloc|realloc)|_mi_malloc_generic)$' \
    "$candidate_symbols"; then
    fail "candidate extracted a C mimalloc allocation entry"
fi

if ! run_final_worker_atexit_probe "$candidate" "selected native candidate normal-return" R; then
    fail "selected native candidate execution failed"
fi
if ! run_final_worker_atexit_probe "$candidate" "selected native candidate explicit-exit" E; then
    fail "selected native candidate execution failed"
fi
if ! timeout "$EXECUTION_TIMEOUT" "$internal_allocator_override_candidate"; then
    fail "native internal allocation selected a strong public malloc replacement"
fi

printf 'x86 selected native-mimalloc pthread teardown: PASS\n'
