#!/usr/bin/env bash
# Native SCHED_FIFO progress reproducer for the selected pthread-key lock.
#
#   compat/pthread-stress/run_tsd_fifo_progress.sh --sysroot HOST_SYSROOT [--repeat N] [--include-registry] [--include-signal]
#
# HOST_SYSROOT is an installed owned static product below this checkout's .work,
# built in the pinned image with
#   scripts/build_x86_64_owned_sysroot.py --output /workspace/.work/x86_64/NAME
# The fixture is compiled with that installed crabc-cc and linked against its
# installed libc, then run beside a pinned-musl control build. The container has
# no network and only CAP_SYS_NICE added. Each trial pins the SCHED_FIFO tasks to
# one CPU and runs under compat/pthread-stress/tsd_fifo_watchdog.py on another
# CPU, with a stall limit, a total deadline, a kernel RLIMIT_RTTIME backstop, and
# an outer hard kill of the whole container.
#
# The default scenarios (getset, delete) keep the lock owner on a task whose key
# lookup takes only the selected pthread-key lock. --include-registry adds the
# worker-to-worker scenario, whose lookups also take the selected-worker registry
# spin lock owned by pthread_create_join.rs.
#
# --include-signal adds signal handlers that call pthread_getspecific on a thread
# interrupted inside its own TSD operations, with no real-time policy.
#
# Exit status: 0 every crabc trial made progress; 1 a crabc trial made no
# progress (or its control did); 77 SCHED_FIFO or CAP_SYS_NICE is unavailable.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly HERE=compat/pthread-stress
readonly CONTAINER_TIMEOUT=240

fail() {
    printf 'ERROR: tsd fifo progress: %s\n' "$*" >&2
    exit 2
}

if [ "${1:-}" != --in-container ]; then
    sysroot=""
    repeat=3
    include_registry=0
    include_signal=0
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --sysroot) [ "$#" -ge 2 ] || fail "--sysroot needs a path"; sysroot="$2"; shift 2 ;;
            --repeat) [ "$#" -ge 2 ] || fail "--repeat needs a count"; repeat="$2"; shift 2 ;;
            --include-registry) include_registry=1; shift ;;
            --include-signal) include_signal=1; shift ;;
            *) fail "usage: $0 --sysroot HOST_SYSROOT [--repeat N] [--include-registry] [--include-signal]" ;;
        esac
    done
    [ -n "$sysroot" ] || fail "--sysroot is required"
    sysroot="$(cd -P -- "$sysroot" 2>/dev/null && pwd -P)" || fail "cannot resolve sysroot"
    case "$sysroot" in
        "$ROOT_DIR"/.work/*) ;;
        *) fail "sysroot must be below $ROOT_DIR/.work" ;;
    esac
    [[ "$repeat" =~ ^[1-9][0-9]?$ ]] || fail "--repeat must be 1 through 99"
    eval "$(python3 -B "$ROOT_DIR/compat/x86_64/native_arch.py" x86_64)"
    docker image inspect "$image" >/dev/null || fail "pinned image $image is unavailable"
    mkdir -p "$ROOT_DIR/.work/x86_64/tmp"
    name="crabc-tsd-fifo-$$"
    trap 'docker kill "$name" >/dev/null 2>&1 || true' EXIT
    timeout -s KILL "$CONTAINER_TIMEOUT" docker run --rm --init --name "$name" \
        --platform "$platform" --cap-add SYS_NICE --network none \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --env TMPDIR=/workspace/.work/x86_64/tmp \
        --volume "$ROOT_DIR:/workspace" --workdir /workspace \
        "$image" bash "/workspace/$HERE/run_tsd_fifo_progress.sh" \
        --in-container "/workspace/${sysroot#"$ROOT_DIR"/}" "$repeat" "$include_registry" "$include_signal"
    exit
fi

sysroot="$2"
repeat="$3"
include_registry="$4"
include_signal="$5"
cd /workspace
work="$(mktemp -d "$TMPDIR/tsd-fifo.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
oracle=/usr/local/bin/crabc-x86_64-musl-gcc
source_file="$HERE/tsd_fifo_progress.c"

(
    cd "$work"
    "$sysroot/bin/crabc-cc" -static -std=c11 -D_GNU_SOURCE -O1 \
        -fno-stack-protector -c "/workspace/$source_file" -o fixture.o
    "$sysroot/bin/crabc-cc" -static --link-receipt fixture.receipt.json fixture.o -o crabc-fixture
)
"$oracle" -std=c11 -D_GNU_SOURCE -O1 -pthread -fno-stack-protector \
    -I/workspace/include "$source_file" -o "$work/musl-fixture"

lock_arguments=()
for symbol in SELECTED_TSD_LOCK SELECTED_WORKER_REGISTRY_LOCK; do
    read -r address size < <(nm -S "$work/crabc-fixture" | awk -v symbol="$symbol" 'index($4, symbol) { print $1, $2 + 0; exit }')
    [ -n "${address:-}" ] && [ -n "${size:-}" ] || fail "$symbol is absent from the installed product, so lock state cannot be attributed"
    lock_arguments+=(--lock "$symbol:$address:$((10#$size))")
done

nproc_allowed="$(python3 -c 'import os; print(len(os.sched_getaffinity(0)))')"
[ "$nproc_allowed" -ge 2 ] || fail "needs at least two allowed CPUs"

crabc_failed=0
control_failed=0
unavailable=0
run_trial() {
    local label="$1" binary="$2" scenario="$3" status=0
    shift 3
    printf '%s ' "$label"
    python3 -B "$HERE/tsd_fifo_watchdog.py" --binary "$binary" --scenario "$scenario" "$@" || status=$?
    return "$status"
}

scenarios=(getset delete)
[ "$include_registry" -eq 0 ] || scenarios+=(registry)
[ "$include_signal" -eq 0 ] || scenarios+=(signal signal-worker)
for scenario in "${scenarios[@]}"; do
    for attempt in $(seq "$repeat"); do
        status=0
        run_trial "control[musl]" "$work/musl-fixture" "$scenario" || status=$?
        case "$status" in
            0) ;;
            77) unavailable=1 ;;
            *) control_failed=1 ;;
        esac
        status=0
        run_trial "crabc[installed]" "$work/crabc-fixture" "$scenario" "${lock_arguments[@]}" || status=$?
        case "$status" in
            0) ;;
            77) unavailable=1 ;;
            *) crabc_failed=1 ;;
        esac
    done
done

if [ "$unavailable" -ne 0 ]; then
    printf 'tsd fifo progress: UNAVAILABLE (SCHED_FIFO or CAP_SYS_NICE denied)\n'
    exit 77
fi
if [ "$control_failed" -ne 0 ]; then
    printf 'tsd fifo progress: INVALID (the pinned-musl control did not complete)\n'
    exit 1
fi
if [ "$crabc_failed" -ne 0 ]; then
    printf 'tsd fifo progress: FAIL (installed crabc made no progress under SCHED_FIFO)\n'
    exit 1
fi
printf 'tsd fifo progress: PASS\n'
