#!/usr/bin/env bash
# Native Linux/x86-64 selected-native allocator worker-teardown evidence.
#
# This uses a real owned-static process startup and its ordinary pthread
# create/exit/join/cancellation path. It is intentionally feature-gated:
# default x86 remains C mimalloc. The selected archive still has an incidental
# C mimalloc build dependency through the owned-static aggregate, so this is
# neither a C-free graph claim nor promotion evidence.
#
# Every run publishes a revision-bound receipt through
# `native_shadow_receipt.py` under `.work/x86_64/reports/native-shadow/
# libc-native-mimalloc-shadow-pthread-teardown/latest`: the source seal,
# digests of every executed candidate, reference, and source-runtime receipt,
# each recorded case exit with the runner transcript, and a final `runner`
# case carrying the script's own exit status. The previous receipt is
# withdrawn first, so a failed or interrupted run leaves a failing receipt or
# none. Overriding the probe timeout makes the run non-canonical.
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
case_exit_dir="$work_dir/case-exits"
mkdir -p "$case_exit_dir"
readonly receipt_runner=libc-native-mimalloc-shadow-pthread-teardown
receipt_canonical=yes
[ -z "${CRABC_NATIVE_MIMALLOC_SHADOW_PROBE_TIMEOUT+x}" ] || receipt_canonical=no
rm -rf "$ROOT_DIR/.work/x86_64/reports/native-shadow/$receipt_runner/latest"
# The runner transcript is the raw log every receipt case cites.
exec > >(tee -a "$work_dir/runner.log") 2> >(tee -a "$work_dir/runner.log" >&2)

publish_receipt() {
    local status="$1"
    local -a arguments=(--runner "$receipt_runner" --work "$work_dir" --canonical "$receipt_canonical"
        --parameter "EXECUTION_TIMEOUT=$EXECUTION_TIMEOUT")
    local path name
    for path in "$case_exit_dir"/*.exit; do
        [ -f "$path" ] || continue
        name="$(basename "$path" .exit)"
        arguments+=(--case "$name=$(cat "$path"):case-exits/$name.exit,runner.log")
    done
    printf '%s\n' "$status" >"$work_dir/runner.status"
    arguments+=(--case "runner=$status:runner.status,runner.log")
    for path in "$work_dir"/musl-*reference "$work_dir"/native-shadow-*candidate \
        "$work_dir"/source-runtime-*/receipt.json; do
        [ -f "$path" ] || continue
        name="${path#"$work_dir"/}"
        arguments+=(--product "${name//\//-}=$path")
    done
    python3 -B "$ROOT_DIR/compat/x86_64/native_shadow_receipt.py" write "${arguments[@]}" >&2
}

cleanup() {
    status=$?
    # The normal raw-copy cohort needs its source-runtime receipts, final-link
    # maps/traces, and individual execution exits after a successful run. The
    # focused physical-destroy lane already has the same provenance need.
    printf 'x86 selected native-mimalloc pthread teardown retained evidence: %s\n' \
        "$work_dir" >&2
    publish_receipt "$status" || status=1
    exit "$status"
}
trap cleanup EXIT

record_case_exit() {
    local case_name="$1"
    local status="$2"

    printf '%s\n' "$status" >"$case_exit_dir/$case_name.exit"
}

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
    local status

    if timeout "$EXECUTION_TIMEOUT" bash -c \
        'run_final_worker_atexit_probe_inner "$@"' \
        run_final_worker_atexit_probe_inner "$1" "$2" "$3" "$work_dir"; then
        status=0
    else
        status=$?
    fi
    record_case_exit "$4" "$status"
    return "$status"
}

run_normal_main_return_process_done_probe() {
    local executable="$1"
    local label="$2"
    local expected_trace="$3"
    local stderr_log="$4"
    local expected_log="$stderr_log.expected"
    local status
    local case_name="$5"

    if timeout "$EXECUTION_TIMEOUT" "$executable" 2>"$stderr_log"; then
        status=0
    else
        status=$?
    fi
    if [ "$status" -ne 0 ]; then
        printf '%s normal-main-return status: %s\n' "$label" "$status" >&2
        record_case_exit "$case_name" "$status"
        return "$status"
    fi
    printf '%s' "$expected_trace" >"$expected_log"
    if ! cmp -s "$expected_log" "$stderr_log"; then
        printf '%s normal-main-return trace mismatch (expected %s)\n' \
            "$label" "$expected_trace" >&2
        record_case_exit "$case_name" 1
        return 1
    fi
    record_case_exit "$case_name" 0
}

run_recorded_timeout_case() {
    local case_name="$1"
    local executable="$2"
    local status

    if timeout "$EXECUTION_TIMEOUT" "$executable"; then
        status=0
    else
        status=$?
    fi
    record_case_exit "$case_name" "$status"
    return "$status"
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
    if run_final_worker_atexit_probe "$early_zero" "early-zero regression" R \
        "probe-regression-early-zero"; then
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
    if run_final_worker_atexit_probe "$post_release_stall" "post-release-stall regression" R \
        "probe-regression-post-release-stall"; then
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

physical_process_destroy_only=0
if [ "${1:-}" = "--probe-regressions" ]; then
    [ "$#" -eq 1 ] || fail "--probe-regressions takes no additional arguments"
    run_final_worker_atexit_probe_regressions
    exit 0
elif [ "${1:-}" = "--physical-process-destroy" ]; then
    [ "$#" -eq 1 ] || fail "--physical-process-destroy takes no additional arguments"
    # Build one owned-static source-runtime closure and execute only the
    # explicit-destroy audit. This is intentionally narrower than
    # the normal worker-teardown and normal-main evidence family.
    physical_process_destroy_only=1
elif [ "$#" -ne 0 ]; then
    fail "run_libc_native_mimalloc_shadow_pthread_teardown.sh takes no arguments"
fi

work_relative="${work_dir#"$ROOT_DIR/.work/x86_64/"}"
[ "$work_relative" != "$work_dir" ] || fail "private work directory escapes .work/x86_64"
source_runtime_helper="$ROOT_DIR/compat/x86_64/native_static_source_runtime_closure.py"
source_runtime_primary_work="$work_relative/source-runtime-primary"
source_runtime_normal_work="$work_relative/source-runtime-normal-main"
source_runtime_primary_receipt="$work_dir/source-runtime-primary/receipt.json"
source_runtime_normal_receipt="$work_dir/source-runtime-normal-main/receipt.json"
archive=""
reference="$work_dir/musl-reference"
candidate="$work_dir/native-shadow-candidate"
internal_allocator_override_candidate="$work_dir/native-shadow-internal-allocator-override-candidate"
physical_process_destroy_candidate="$work_dir/native-shadow-physical-process-destroy-candidate"
physical_process_destroy_link_map="$work_dir/physical-process-destroy-link.map"
physical_process_destroy_link_trace="$work_dir/physical-process-destroy-link.trace"
normal_main_reference="$work_dir/musl-normal-main-return-reference"
normal_main_candidate="$work_dir/native-shadow-normal-main-return-candidate"
auto_process_done_candidate="$work_dir/native-shadow-auto-process-done-candidate"
archive_symbols="$work_dir/archive-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_relocations="$work_dir/candidate-relocations"
candidate_link_map="$work_dir/candidate-link.map"
candidate_link_trace="$work_dir/candidate-link.trace"
normal_main_archive_symbols="$work_dir/normal-main-archive-symbols"
normal_main_link_map="$work_dir/normal-main-link.map"
normal_main_link_trace="$work_dir/normal-main-link.trace"
crt_output="$work_dir/owned-crt"
fixture_crt1="$work_dir/fixture-crt1.o"

# The source-runtime producer applies this profile to the complete target
# graph, including crabc-mimalloc and source-built core/alloc/compiler_builtins.
# It replaces only the fixture's prebuilt target-runtime input; product builders
# retain their own reviewed profiles. `panic=immediate-abort` is development-only
# because it bypasses the static C root's nonreturning spin panic handler.
readonly NATIVE_SOURCE_RUNTIME_PROFILE='-Ztls-model=initial-exec -Zunstable-options -Cpanic=immediate-abort -Cforce-unwind-tables=no -Crelocation-model=static -Ccode-model=small'

cd "$ROOT_DIR"
printf 'x86 selected native-mimalloc source-runtime profile: %s\n' "$NATIVE_SOURCE_RUNTIME_PROFILE"
printf '%s\n' 'x86 selected native-mimalloc final link: -nostdlib -static -Wl,--no-undefined -Wl,--gc-sections -Wl,-Map -Wl,--trace-symbol=rust_eh_personality'
# The native Docker image need not expose LLVM utilities globally. Use the
# pinned Rust toolchain component selected by the ordinary CRT evidence lane,
# so this fixture verifies the same owned executable init/fini bridge.
if command -v llvm-objdump >/dev/null 2>&1; then
    crt_llvm_objdump="$(command -v llvm-objdump)"
else
    crt_rust_sysroot="$(rustup run "$(python3 "$ROOT_DIR/scripts/rust_toolchain.py")" rustc --print sysroot)"
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

if [ "$physical_process_destroy_only" -eq 0 ]; then
    "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin \
        -fno-stack-protector -I"$ROOT_DIR/include" \
        compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_probe.c \
        -o "$reference"
    if ! run_final_worker_atexit_probe "$reference" "pinned-musl reference normal-return" R \
        "musl-worker-normal-return"; then
        fail "pinned-musl reference execution failed"
    fi
    if ! run_final_worker_atexit_probe "$reference" "pinned-musl reference explicit-exit" E \
        "musl-worker-explicit-exit"; then
        fail "pinned-musl reference execution failed"
    fi
fi

[ -x "$source_runtime_helper" ] || fail "missing native static source-runtime producer"
archive="$(python3 "$source_runtime_helper" build \
    --work "$source_runtime_primary_work" \
    --features x86-owned-static-native-shadow,native-mimalloc-shadow-test-audit \
    --print-archive)" || fail "source-built native static runtime production failed"
[ -f "$archive" ] || fail "source-built native static runtime did not emit the selected archive"
[ -f "$source_runtime_primary_receipt" ] ||
    fail "source-built native static runtime did not retain its receipt"

nm -A --defined-only "$archive" >"$archive_symbols"
for symbol in __crabc_x86_native_mimalloc_shadow_v1 \
    __crabc_x86_native_mimalloc_active_later_thread_count_test_audit \
    __crabc_x86_native_mimalloc_registered_thread_descriptor_count_test_audit \
    __crabc_x86_native_mimalloc_reclaimed_worker_descriptor_count_test_audit \
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

# This focused private program calls the dedicated explicit physical-destroy
# audit only after normal selected startup. Each fresh process supplies one signed
# source option value: `1` and `2` distinguish explicit from automatic
# dispatch, and `-1` confirms that nonzero is not flattened to a bool. The
# audit returns from the pinned descriptor transfer before the allocator's
# physical Heap/metadata/arena/PageMap successor runs; it then observes the
# source once no-op and exits without walking the automatic finalizer.
if [ "$physical_process_destroy_only" -eq 1 ]; then
    grep -Eq "[[:space:]][TW][[:space:]]__crabc_x86_native_mimalloc_process_destroy_test_audit$" \
        "$archive_symbols" ||
        fail "selected physical process-destroy archive does not define __crabc_x86_native_mimalloc_process_destroy_test_audit"
    "$ORACLE_CC" -std=c11 -D_GNU_SOURCE \
        -DCRABC_NATIVE_MIMALLOC_SHADOW_PHYSICAL_PROCESS_DESTROY_PROBE \
        -DCRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT \
        -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
        -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
        -Wl,--no-undefined -Wl,--gc-sections \
        -Wl,-Map,"$physical_process_destroy_link_map" -Wl,--trace-symbol=rust_eh_personality \
        -Wl,-u,__crabc_x86_native_mimalloc_shadow_v1 \
        "$fixture_crt1" "$crt_output/crti.o" \
        compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_probe.c \
        compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_start.S \
        "$archive" "$crt_output/crtn.o" -o "$physical_process_destroy_candidate" >"$physical_process_destroy_link_trace" 2>&1
    python3 "$source_runtime_helper" audit-final-link \
        --receipt "$source_runtime_primary_receipt" --candidate "$physical_process_destroy_candidate" \
        --link-map "$physical_process_destroy_link_map" --trace "$physical_process_destroy_link_trace" \
        --label selected-native-explicit-process-destroy ||
        fail "source-built native static runtime physical process-destroy final link audit failed"
    for destroy_on_exit in 1 2 -1; do
        if ! env "mimalloc_destroy_on_exit=$destroy_on_exit" \
            timeout "$EXECUTION_TIMEOUT" "$physical_process_destroy_candidate"; then
            fail "selected native explicit process-destroy candidate failed for destroy_on_exit=$destroy_on_exit"
        fi
    done
    printf 'x86 selected native-mimalloc explicit process-destroy fixture: PASS\n'
    exit 0
fi

if [ "$physical_process_destroy_only" -eq 0 ]; then
    "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT \
        -I"$ROOT_DIR/include" \
        -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
        -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
        -Wl,-Map,"$candidate_link_map" -Wl,--trace-symbol=rust_eh_personality \
        -Wl,-u,__crabc_x86_native_mimalloc_shadow_v1 \
        "$fixture_crt1" "$crt_output/crti.o" \
        compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_probe.c \
        compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_start.S \
        "$archive" "$crt_output/crtn.o" -o "$candidate" >"$candidate_link_trace" 2>&1
    python3 "$source_runtime_helper" audit-final-link \
        --receipt "$source_runtime_primary_receipt" --candidate "$candidate" \
        --link-map "$candidate_link_map" --trace "$candidate_link_trace" \
        --label selected-native-pthread-teardown ||
        fail "source-built native static runtime final link audit failed"

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
fi

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
for symbol in __crabc_x86_native_mimalloc_shadow_v1 \
    __crabc_x86_native_mimalloc_active_later_thread_count_test_audit \
    __crabc_x86_native_mimalloc_registered_thread_descriptor_count_test_audit \
    __crabc_x86_native_mimalloc_reclaimed_worker_descriptor_count_test_audit \
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

if ! run_final_worker_atexit_probe "$candidate" "selected native candidate normal-return" R \
    "native-worker-normal-return"; then
    fail "selected native candidate execution failed"
fi
if ! run_final_worker_atexit_probe "$candidate" "selected native candidate explicit-exit" E \
    "native-worker-explicit-exit"; then
    fail "selected native candidate execution failed"
fi
if ! run_recorded_timeout_case "native-internal-allocator-override" \
    "$internal_allocator_override_candidate"; then
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
    "$work_dir/normal-main-reference.stderr" "musl-normal-main-return"; then
    fail "pinned-musl normal-main-return execution failed"
fi

archive="$(python3 "$source_runtime_helper" build \
    --work "$source_runtime_normal_work" \
    --features x86-owned-static-native-shadow,native-mimalloc-shadow-process-done-exit-test-audit \
    --print-archive)" || fail "normal-main source-built native static runtime production failed"
[ -f "$archive" ] || fail "normal-main source-built native static runtime did not emit the selected archive"
[ -f "$source_runtime_normal_receipt" ] ||
    fail "normal-main source-built native static runtime did not retain its receipt"
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
    -Wl,--no-undefined -Wl,--gc-sections -Wl,-Map,"$normal_main_link_map" \
    -Wl,--trace-symbol=rust_eh_personality \
    -Wl,-u,__crabc_x86_native_mimalloc_shadow_v1 \
    "$fixture_crt1" "$crt_output/crti.o" \
    compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_probe.c \
    compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_start.S \
    "$archive" "$crt_output/crtn.o" -o "$normal_main_candidate" >"$normal_main_link_trace" 2>&1
python3 "$source_runtime_helper" audit-final-link \
    --receipt "$source_runtime_normal_receipt" --candidate "$normal_main_candidate" \
    --link-map "$normal_main_link_map" --trace "$normal_main_link_trace" \
    --label selected-native-normal-main-return ||
    fail "normal-main source-built native static runtime final link audit failed"
if ! run_normal_main_return_process_done_probe "$normal_main_candidate" \
    "selected native normal-main-return candidate" AMD \
    "$work_dir/normal-main-candidate.stderr" "native-normal-main-return"; then
    fail "selected native normal-main-return execution failed"
fi

# The same installed finalizer runs from ordinary main return with the signed
# automatic option. Value 1 physically destroys process backing after user
# atexit; value 2 suppresses process-done and leaves later allocation valid.
auto_process_done_link_map="$work_dir/auto-process-done-link.map"
auto_process_done_link_trace="$work_dir/auto-process-done-link.trace"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--no-undefined -Wl,--gc-sections -Wl,-Map,"$auto_process_done_link_map" \
    -Wl,--trace-symbol=rust_eh_personality \
    -Wl,-u,__crabc_x86_native_mimalloc_shadow_v1 \
    "$fixture_crt1" "$crt_output/crti.o" \
    compat/x86_64/native_mimalloc_auto_process_done_probe.c \
    compat/x86_64/libc_native_mimalloc_shadow_pthread_teardown_start.S \
    "$archive" "$crt_output/crtn.o" -o "$auto_process_done_candidate" \
    >"$auto_process_done_link_trace" 2>&1
python3 "$source_runtime_helper" audit-final-link \
    --receipt "$source_runtime_normal_receipt" --candidate "$auto_process_done_candidate" \
    --link-map "$auto_process_done_link_map" --trace "$auto_process_done_link_trace" \
    --label selected-native-auto-process-done ||
    fail "source-built native automatic process-done final link audit failed"
for destroy_on_exit in 1 2; do
    case_name="native-auto-process-done-$destroy_on_exit"
    stderr_log="$work_dir/$case_name.stderr"
    if env "mimalloc_destroy_on_exit=$destroy_on_exit" timeout "$EXECUTION_TIMEOUT" \
        "$auto_process_done_candidate" 2>"$stderr_log"; then
        status=0
    else
        status=$?
    fi
    if [ "$status" -ne 0 ]; then
        record_case_exit "$case_name" "$status"
        fail "selected native automatic process-done failed for destroy_on_exit=$destroy_on_exit"
    fi
    if [ "$destroy_on_exit" -eq 1 ]; then expected_trace=AMD; else expected_trace=AD; fi
    printf '%s' "$expected_trace" >"$stderr_log.expected"
    if ! cmp -s "$stderr_log.expected" "$stderr_log"; then
        record_case_exit "$case_name" 1
        fail "selected native automatic process-done trace differed for destroy_on_exit=$destroy_on_exit"
    fi
    record_case_exit "$case_name" 0
done

printf 'x86 selected native-mimalloc pthread teardown: PASS\n'
