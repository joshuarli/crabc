#!/usr/bin/env bash
# Native owned-product replay of the frozen signal/process source.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly EVIDENCE="$ROOT/compat/x86_64/owned_signal_process_evidence.py"
readonly SOURCE="$ROOT/compat/signal-process/tests/signal_process.c"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly SUBCASES=(
    siginfo nodefer mask-pending sa-restart altstack thread-mask sigwait timer
    wait-signal wait-nohang atfork fork-worker-exec
)
readonly TIMEOUT="${CRABC_SIGNAL_PROCESS_TIMEOUT:-10}"

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
}

if [ "$#" -eq 1 ]; then
    static_input=''
    dynamic_input="$1"
elif [ "$#" -eq 3 ] && [ "$1" = --static-sysroot ]; then
    static_input="$2"
    dynamic_input="$3"
else
    usage
fi
case "$dynamic_input" in ''|-*) usage ;; esac
case "$static_input" in -*) usage ;; esac

# Product selection comes before mutable evidence.  This component neither
# builds nor alters a product: callers copy a reviewed product into this
# worktree's ignored .work tree before invoking it.
mapfile -t product_paths < <(python3 -B - "$ROOT" "${TMPDIR:-}" "$dynamic_input" "$static_input" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
dynamic, static = sys.argv[3:]
sys.path.insert(0, str(root / "compat/x86_64"))
import owned_signal_process_evidence as evidence

try:
    temporary = evidence.physical(temporary, "signal-process TMPDIR", directory=True)
    if not temporary.is_relative_to(root / ".work"):
        raise evidence.SignalProcessEvidenceError(
            "signal-process TMPDIR must be a physical checkout .work directory"
        )
    dynamic_product = evidence.supplied_product(root, Path(dynamic), "dynamic")
    print(dynamic_product)
    if static:
        static_product = evidence.supplied_product(root, Path(static), "static")
        if static_product == dynamic_product:
            raise evidence.SignalProcessEvidenceError("signal-process static and dynamic products must differ")
        print(static_product)
except (OSError, evidence.SignalProcessEvidenceError) as error:
    raise SystemExit(str(error))
PY
)
readonly dynamic_sysroot="${product_paths[0]:-}"
readonly static_sysroot="${product_paths[1]:-}"
[ -n "$dynamic_sysroot" ] || exit 1

readonly work="$(mktemp -d "$TMPDIR/owned-signal-process.XXXXXX")"
readonly execution_root="$work/execution-root"
chmod a+rx "$work"
printf 'owned signal-process evidence: %s\n' "$work"
trap 'printf "owned signal-process failed near %s; evidence: %s\\n" "${step:-setup}" "$work" >&2' ERR

# `capture` starts every invocation in a new session.  On a timeout its helper
# kills that whole process group, covering the fixture's child and worker cases.
# The four dynamic labels are pie-kernel, pie-direct, non-pie-kernel, and
# non-pie-direct; each retains raw status, stdout, and stderr for all 12 cases.
capture_case() {
    local label="$1"
    shift
    python3 -B "$EVIDENCE" capture --timeout "$TIMEOUT" --cwd "$work" \
        --output-base "$work/$label" -- "$@"
    [ "$(cat "$work/$label.status")" = 0 ] || {
        printf 'signal-process %s did not succeed; retained raw triplet at %s.{status,stdout,stderr}\n' \
            "$label" "$work/$label" >&2
        return 1
    }
}

compare_case() {
    local reference="$1" candidate="$2" stream
    for stream in status stdout stderr; do
        cmp "$work/$reference.$stream" "$work/$candidate.$stream"
    done
}

validate_link() {
    local product="$1" executable="$2" receipt="$3" linkage="$4" record="$5"
    python3 -B "$EVIDENCE" validate-link "$product" "$work/workload.o" \
        "$executable" "$receipt" "$linkage" "$record"
}

step=compile
# This is the sole source translation.  No candidate-specific preprocessor
# spelling crosses into the frozen source; installed headers are selected only
# by the supplied dynamic product's sealed driver.
"$dynamic_sysroot/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$SOURCE" -o "$work/workload.o" \
    >"$work/driver-compile.stdout" 2>"$work/driver-compile.stderr"
python3 -B "$EVIDENCE" record-compile "$dynamic_sysroot" "$SOURCE" \
    "$work/workload.o" "$work/compile.json"
python3 -B "$EVIDENCE" validate-compile "$dynamic_sysroot" "$SOURCE" \
    "$work/workload.o" "$work/compile.json" >"$work/compile-identity.json"

step=oracle-link
"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"
python3 -B "$EVIDENCE" record-oracle "$ORACLE_CC" "$work/workload.o" \
    "$work/oracle" "$work/oracle.json"

step=oracle-observations
for subcase in "${SUBCASES[@]}"; do
    capture_case "oracle-$subcase" "$work/oracle" "$subcase"
done

if [ -n "$static_sysroot" ]; then
    for mode in static static-pie; do
        step="static-$mode-link"
        (
            cd "$work"
            "$static_sysroot/bin/crabc-cc" "-$mode" --link-receipt "$mode.receipt.json" \
                "$work/workload.o" -o "$work/$mode"
        )
        validate_link "$static_sysroot" "$work/$mode" "$work/$mode.receipt.json" \
            "$mode" "$work/$mode.link.json"
        for subcase in "${SUBCASES[@]}"; do
            step="static-$mode-$subcase"
            capture_case "$mode-$subcase" "$work/$mode" "$subcase"
            compare_case "oracle-$subcase" "$mode-$subcase"
        done
    done
fi

step=dynamic-root
# The source does not inspect /proc; no proc mount is required.  The copied
# product keeps each dynamic entry's loader, libc, and application payload
# disposable while fork-worker-exec still resolves argv[0] inside the chroot.
cp -a "$dynamic_sysroot" "$execution_root"
for mode in pie non-pie; do
    step="dynamic-$mode-link"
    "$dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" \
        -o "$work/dynamic-$mode"
    validate_link "$dynamic_sysroot" "$work/dynamic-$mode" \
        "$work/dynamic-$mode.crabc-link.json" "$mode" "$work/dynamic-$mode.link.json"
    cp "$work/dynamic-$mode" "$execution_root/consumer-$mode"
    for subcase in "${SUBCASES[@]}"; do
        step="dynamic-$mode-kernel-$subcase"
        capture_case "$mode-kernel-$subcase" /usr/sbin/chroot "$execution_root" \
            "/consumer-$mode" "$subcase"
        compare_case "oracle-$subcase" "$mode-kernel-$subcase"
        step="dynamic-$mode-direct-$subcase"
        capture_case "$mode-direct-$subcase" /usr/sbin/chroot "$execution_root" \
            /lib/ld-crabc-x86_64.so.1 "/consumer-$mode" "$subcase"
        compare_case "oracle-$subcase" "$mode-direct-$subcase"
    done
done

step=seal
seal=(python3 -B "$EVIDENCE" seal --dynamic-product "$dynamic_sysroot" --source "$SOURCE" \
    --object "$work/workload.o" --compile-audit "$work/compile.json" \
    --oracle-compiler "$ORACLE_CC" --oracle-binary "$work/oracle" \
    --oracle-record "$work/oracle.json")
if [ -n "$static_sysroot" ]; then
    seal+=(--static-product "$static_sysroot")
fi
seal+=("$work")
"${seal[@]}"

printf 'owned signal-process: PASS (one unchanged frozen workload object through pinned musl and supplied owned products; 12 fresh-process-group signal/process scenarios with raw status/stdout/stderr); evidence: %s\n' "$work"
