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
# The focused runner regression overrides only this private bound so its
# deliberate post-release stall completes quickly. Production evidence keeps
# the existing twenty-second budget.
readonly EXECUTION_TIMEOUT="${CRABC_NATIVE_MIMALLOC_SHADOW_PROBE_TIMEOUT:-20s}"

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
for tool in cargo chmod cmp grep mkdir mkfifo mktemp nm objcopy python3 readelf rm rustup sleep timeout; do
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
run_final_worker_atexit_probe_inner() {
    local executable="$1"
    local label="$2"
    local release="$3"
    local probe_work_dir="$4"
    local fifo="$probe_work_dir/final-worker-release"
    local release_fd
    local process
    local status
    local final_worker_present
    local task

    rm -f -- "$fifo"
    mkfifo "$fifo" || return 1
    # Keep one read/write endpoint open before the child starts, so neither
    # side blocks opening the FIFO before the runner observes the zombie.
    exec {release_fd}<>"$fifo"
    "$executable" <"$fifo" &
    process=$!
    while :; do
        if grep -Eq '^State:[[:space:]]+Z' "/proc/$process/task/$process/status" 2>/dev/null; then
            # A process leader can be a zombie only because the initial task
            # called pthread_exit while another task remains. A whole process
            # that simply exited must not be accepted as that observation.
            final_worker_present=0
            for task in "/proc/$process/task/"*; do
                [ -e "$task/status" ] || continue
                if [ "${task##*/}" != "$process" ]; then
                    final_worker_present=1
                    break
                fi
            done
            if [ "$final_worker_present" -eq 0 ]; then
                if wait "$process"; then
                    status=0
                else
                    status=$?
                fi
                exec {release_fd}>&-
                rm -f -- "$fifo"
                printf '%s ended after its initial task retired without a final worker (status %s)\n' \
                    "$label" "$status" >&2
                return 1
            fi
            printf '%s' "$release" >&"$release_fd"
            if wait "$process"; then
                status=0
            else
                status=$?
            fi
            exec {release_fd}>&-
            rm -f -- "$fifo"
            if [ "$status" -ne 0 ]; then
                printf '%s final-worker atexit status: %s\n' "$label" "$status" >&2
            fi
            return "$status"
        fi
        if ! kill -0 "$process" 2>/dev/null; then
            if wait "$process"; then
                status=0
            else
                status=$?
            fi
            exec {release_fd}>&-
            rm -f -- "$fifo"
            printf '%s ended before the bootstrapped task became a zombie (status %s)\n' \
                "$label" "$status" >&2
            return 1
        fi
        sleep 0.01
    done
}

export -f run_final_worker_atexit_probe_inner

run_final_worker_atexit_probe() {
    # `timeout` owns the whole parent/child handshake, including the wait after
    # FIFO release. It signals the inner process group, so it never races a
    # later PID reuse by separately killing a raw child PID.
    timeout "$EXECUTION_TIMEOUT" bash -c \
        'run_final_worker_atexit_probe_inner "$@"' \
        run_final_worker_atexit_probe_inner "$1" "$2" "$3" "$work_dir"
}

run_normal_main_return_process_done_probe() {
    local executable="$1"
    local label="$2"
    local expected_trace="$3"
    local stderr_log="$4"
    local expected_log="$stderr_log.expected"
    local status

    if timeout "$EXECUTION_TIMEOUT" "$executable" 2>"$stderr_log"; then
        status=0
    else
        status=$?
    fi
    if [ "$status" -ne 0 ]; then
        printf '%s normal-main-return status: %s\n' "$label" "$status" >&2
        return "$status"
    fi
    printf '%s' "$expected_trace" >"$expected_log"
    if ! cmp -s "$expected_log" "$stderr_log"; then
        printf '%s normal-main-return trace mismatch (expected %s)\n' \
            "$label" "$expected_trace" >&2
        return 1
    fi
}

run_final_worker_atexit_probe_regressions() {
    local early_zero="$work_dir/final-worker-early-zero"
    local post_release_stall="$work_dir/final-worker-post-release-stall"
    local status

    cat >"$early_zero" <<'EOF'
#!/bin/sh
exit 0
EOF
    chmod 700 "$early_zero"
    if run_final_worker_atexit_probe "$early_zero" "early-zero regression" R; then
        printf 'early-zero regression unexpectedly passed\n' >&2
        return 1
    else
        status=$?
    fi
    if [ "$status" -ne 1 ]; then
        printf 'early-zero regression returned %s, expected handshake rejection 1\n' \
            "$status" >&2
        return 1
    fi

    cat >"$work_dir/final-worker-post-release-stall.c" <<'EOF'
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

static void *worker(void *opaque)
{
    char release;

    (void)opaque;
    if (read(STDIN_FILENO, &release, 1) != 1)
        _Exit(61);
    for (;;)
        pause();
}

int main(void)
{
    pthread_t thread;

    if (pthread_create(&thread, 0, worker, 0) != 0)
        return 62;
    pthread_exit(0);
}
EOF
    "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread \
        "$work_dir/final-worker-post-release-stall.c" -o "$post_release_stall"
    if run_final_worker_atexit_probe "$post_release_stall" "post-release-stall regression" R; then
        printf 'post-release-stall regression unexpectedly passed\n' >&2
        return 1
    else
        status=$?
    fi
    if [ "$status" -ne 124 ]; then
        printf 'post-release-stall regression returned %s, expected timeout 124\n' \
            "$status" >&2
        return 1
    fi
    printf 'x86 selected native-mimalloc pthread teardown probe regressions: PASS\n'
}

if [ "${1:-}" = "--probe-regressions" ]; then
    [ "$#" -eq 1 ] || fail "--probe-regressions takes no additional arguments"
    run_final_worker_atexit_probe_regressions
    exit 0
fi
[ "$#" -eq 0 ] || fail "run_libc_native_mimalloc_shadow_pthread_teardown.sh takes no arguments"

cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-reference"
candidate="$work_dir/native-shadow-candidate"
internal_allocator_override_candidate="$work_dir/native-shadow-internal-allocator-override-candidate"
normal_main_reference="$work_dir/musl-normal-main-return-reference"
normal_main_candidate="$work_dir/native-shadow-normal-main-return-candidate"
archive_symbols="$work_dir/archive-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_relocations="$work_dir/candidate-relocations"
normal_main_archive_symbols="$work_dir/normal-main-archive-symbols"
crt_output="$work_dir/owned-crt"
fixture_crt1="$work_dir/fixture-crt1.o"

# `cargo rustc -- -Ztls-model=initial-exec` would reach only crabc-libc, while
# this selected archive also links crabc-mimalloc. Keep the model target-wide
# for this static candidate so the audit bridge cannot hide a TLSGD dependency
# in that dependency's object code. Cargo's encoded setting takes precedence
# over RUSTFLAGS, including an empty encoded value, so set its one exact flag.
readonly NATIVE_ENCODED_RUSTFLAGS='-Ztls-model=initial-exec'

cd "$ROOT_DIR"
# The native Docker image need not expose LLVM utilities globally. Use the
# pinned Rust toolchain component selected by the ordinary CRT evidence lane,
# so this fixture verifies the same owned executable init/fini bridge.
if command -v llvm-objdump >/dev/null 2>&1; then
    crt_llvm_objdump="$(command -v llvm-objdump)"
else
    crt_rust_sysroot="$(rustup run nightly-2026-07-24 rustc --print sysroot)"
    crt_llvm_objdump="$crt_rust_sysroot/lib/rustlib/x86_64-unknown-linux-musl/bin/llvm-objdump"
fi
[ -x "$crt_llvm_objdump" ] || fail "requires the pinned Rust llvm-objdump component"
python3 crt/build_x86_64.py --out-dir "$crt_output" --llvm-objdump "$crt_llvm_objdump"
[ -f "$crt_output/crt1.o" ] && [ -f "$crt_output/crti.o" ] && [ -f "$crt_output/crtn.o" ] ||
    fail "owned CRT builder did not emit the executable lifecycle bridge"
# Keep the fixture's pre-start rejection `_start`, but link the actual owned
# CRT's init/fini array walkers. Renaming only the CRT entry leaves its
# executable lifecycle symbols and linker-boundary adapters unchanged.
objcopy --redefine-sym _start=__crabc_x86_fixture_unused_owned_crt_start \
    "$crt_output/crt1.o" "$fixture_crt1"

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
    --features x86-owned-static-native-shadow,native-mimalloc-shadow-test-audit -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the selected static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
for symbol in __crabc_x86_native_mimalloc_shadow_v1 \
    __crabc_x86_native_mimalloc_active_later_thread_count_test_audit \
    __crabc_x86_native_mimalloc_process_done_test_audit \
    __crabc_x86_native_mimalloc_process_done_retained_worker_matches_current_thread_test_audit \
    __crabc_x86_native_mimalloc_process_done_retained_local_preflight_test_audit \
    __crabc_x86_native_mimalloc_current_local_page_test_audit \
    __crabc_x86_native_mimalloc_current_local_page_same_test_audit \
    __crabc_x86_native_mimalloc_process_done_retained_local_page_test_audit \
    __crabc_x86_native_mimalloc_process_done_retained_page_retired_test_audit \
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
    "$fixture_crt1" "$crt_output/crti.o" \
    compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_probe.c \
    compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_start.S \
    "$archive" "$crt_output/crtn.o" -o "$candidate"

# A caller-owned strong malloc returns null. `pthread_atfork` is an existing
# private allocator client, so successful registration proves its node uses
# the native internal seam rather than the weak public symbol.
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_NATIVE_INTERNAL_MALLOC_OVERRIDE \
    -DCRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--no-undefined -Wl,--gc-sections \
    -Wl,-u,__crabc_x86_native_mimalloc_shadow_v1 \
    "$fixture_crt1" "$crt_output/crti.o" \
    compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_probe.c \
    compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_start.S \
    "$archive" "$crt_output/crtn.o" -o "$internal_allocator_override_candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
for symbol in __crabc_x86_native_mimalloc_shadow_v1 \
    __crabc_x86_native_mimalloc_active_later_thread_count_test_audit \
    __crabc_x86_native_mimalloc_process_done_test_audit \
    __crabc_x86_native_mimalloc_process_done_retained_worker_matches_current_thread_test_audit \
    __crabc_x86_native_mimalloc_process_done_retained_local_preflight_test_audit \
    __crabc_x86_native_mimalloc_current_local_page_test_audit \
    __crabc_x86_native_mimalloc_current_local_page_same_test_audit \
    __crabc_x86_native_mimalloc_process_done_retained_local_page_test_audit \
    __crabc_x86_native_mimalloc_process_done_retained_page_retired_test_audit \
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

# `main` return takes static_startup::exit rather than the final-worker path.
# The reference records application `atexit` then application fini (`AD`). The
# selected candidate inserts the suppressed pinned process destructor in the
# same CRT-owned fini-array walk, so its feature-only receipt is `AMD`: user
# atexit, native logical process-done bridge, then a later app destructor. All
# three callbacks allocate and free; the initial task's fatal TSD destructor
# remains uncalled on ordinary process exit.
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE \
    -DCRABC_NATIVE_MIMALLOC_SHADOW_NORMAL_MAIN_RETURN_PROBE \
    -pthread -fno-builtin -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_probe.c \
    -o "$normal_main_reference"
if ! run_normal_main_return_process_done_probe "$normal_main_reference" \
    "pinned-musl normal-main-return reference" AD \
    "$work_dir/normal-main-reference.stderr"; then
    fail "pinned-musl normal-main-return execution failed"
fi

CARGO_ENCODED_RUSTFLAGS="$NATIVE_ENCODED_RUSTFLAGS" CARGO_TARGET_DIR="$cargo_target" \
    cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl \
    --features x86-owned-static-native-shadow,native-mimalloc-shadow-process-done-exit-test-audit -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the normal-main selected static libc archive"
nm -A --defined-only "$archive" >"$normal_main_archive_symbols"
grep -Eq "[[:space:]][TW][[:space:]]__crabc_x86_native_mimalloc_process_done_fini_array_test_audit$" \
    "$normal_main_archive_symbols" ||
    fail "normal-main selected archive lacks its fini-array receipt"
grep -Eq "[[:space:]][TW][[:space:]]__crabc_x86_native_mimalloc_process_done_terminal_purge_test_audit$" \
    "$normal_main_archive_symbols" ||
    fail "normal-main selected archive lacks its terminal-purge receipt"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE \
    -DCRABC_NATIVE_MIMALLOC_SHADOW_NORMAL_MAIN_RETURN_PROBE \
    -DCRABC_NATIVE_MIMALLOC_SHADOW_PROCESS_DONE_EXIT_TEST_AUDIT \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--no-undefined -Wl,--gc-sections \
    -Wl,-u,__crabc_x86_native_mimalloc_shadow_v1 \
    "$fixture_crt1" "$crt_output/crti.o" \
    compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_probe.c \
    compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_start.S \
    "$archive" "$crt_output/crtn.o" -o "$normal_main_candidate"
if ! run_normal_main_return_process_done_probe "$normal_main_candidate" \
    "selected native normal-main-return candidate" AMD \
    "$work_dir/normal-main-candidate.stderr"; then
    fail "selected native normal-main-return execution failed"
fi

printf 'x86 selected native-mimalloc pthread teardown: PASS\n'
