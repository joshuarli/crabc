#!/usr/bin/env bash
# Installed native-shadow libc malloc-family policy against pinned musl.
#
# Three unmodified C programs define the `memory.allocator-basic` and
# `memory.allocator-observability` policy: the allocator-basic runtime probe
# (zero size, natural and explicit alignment, calloc overflow, realloc
# failure and realloc(p, 0), posix_memalign output preservation, errno,
# threads, fork/atfork, atexit allocation), the observability fixture
# (malloc_usable_size), and the size-class policy probe (the same rules
# across small through huge blocks). Each runs through pinned musl and then
# through the native-shadow static, static-PIE and dynamic PIE/non-PIE
# (kernel and direct loader) products, which must reproduce musl's exit
# status and transcript. Without supplied products the runner builds both
# native-shadow sysroots.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly programs=(basic observability policy)

program_source() {
    case "$1" in
        basic) printf '%s\n' "$ROOT/compat/x86_64/libc_allocator_basic_runtime_v1_probe.c" ;;
        observability) printf '%s\n' "$ROOT/tests/fixtures/allocator_observability_test.c" ;;
        policy) printf '%s\n' "$ROOT/compat/x86_64/owned_native_allocator_policy_probe.c" ;;
    esac
}

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

static_sysroot=''
dynamic_sysroot=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] && [ -z "$static_sysroot" ] && [ -n "$2" ] || usage
            static_sysroot="$(realpath -e "$2")"
            shift 2
            ;;
        -*|'') usage ;;
        *)
            [ -z "$dynamic_sysroot" ] || usage
            dynamic_sysroot="$(realpath -e "$1")"
            shift
            ;;
    esac
done

python3 -B - "$ROOT" "${TMPDIR:-}" "$static_sysroot" "$dynamic_sysroot" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('native-allocator-policy TMPDIR must be a physical checkout .work directory')
for argument in sys.argv[3:]:
    if argument and not Path(argument).is_relative_to(root / '.work'):
        raise SystemExit('native-allocator-policy products must be checkout .work directories')
PY

work="$(mktemp -d "$TMPDIR/owned-native-allocator-policy.XXXXXX")"
readonly work
chmod a+rx "$work"
printf 'native-allocator-policy evidence: %s\n' "$work"

if [ -z "$static_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --allocator-backend native-shadow \
        --output "$work/static-sysroot" >"$work/static-build.json"
    static_sysroot="$work/static-sysroot"
fi
if [ -z "$dynamic_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --allocator-backend native-shadow \
        --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    dynamic_sysroot="$work/dynamic-sysroot"
fi
python3 -B - "$static_sysroot/share/crabc/manifest.json" \
    "$dynamic_sysroot/share/crabc/libc-shared.provenance.json" <<'PY'
import json
import sys
for path in sys.argv[1:]:
    with open(path, encoding='utf-8') as stream:
        backend = json.load(stream).get('allocator_backend')
    if backend != 'native-shadow':
        raise SystemExit(f'{path}: allocator_backend is {backend!r}, not native-shadow')
PY

# The allocator-basic probe builds a small symlink graph below the relative
# directory `.work/x86_64` and compares realpath results with getcwd, so
# every mode runs from a non-root directory that provides it.
mkdir -p "$work/host-cwd/.work/x86_64"
cp -a "$dynamic_sysroot" "$work/execution-root"
mkdir -p "$work/execution-root/run/.work/x86_64"
# chroot(1) always enters `/`; this enters the execution root at /run.
readonly enter_root=(python3 -B -c 'import os, sys; os.chroot(sys.argv[1]); os.chdir("/run"); os.execv(sys.argv[2], sys.argv[2:])'
    "$work/execution-root")

# Run one program in one mode; retain stdout, stderr and status, then compare
# status and stdout with the oracle's for the same program.
run_case() {
    local mode="$1"
    local program="$2"
    local name="$mode-$program"
    shift 2
    local status=0
    (cd "$work/host-cwd" && timeout 120 env -i PATH="$PATH" "$@") \
        >"$work/$name.stdout" 2>"$work/$name.stderr" || status=$?
    printf '%s\n' "$status" >"$work/$name.status"
    if [ "$status" -ne 0 ] || [ -s "$work/$name.stderr" ]; then
        printf 'native-allocator-policy: %s exited %s\n' "$name" "$status" >&2
        cat "$work/$name.stderr" >&2
        return 1
    fi
    [ "$mode" != oracle ] || return 0
    cmp "$work/oracle-$program.stdout" "$work/$name.stdout" || {
        printf 'native-allocator-policy: %s transcript differs from musl\n' "$name" >&2
        return 1
    }
}

readonly common_flags=(-std=c11 -D_GNU_SOURCE -pthread -fno-builtin)
for program in "${programs[@]}"; do
    source="$(program_source "$program")"
    "$oracle_cc" -static -fno-pie -no-pie "${common_flags[@]}" "$source" -o "$work/oracle-$program.exe"
    run_case oracle "$program" "$work/oracle-$program.exe"
    for mode in static static-pie; do
        "$static_sysroot/bin/crabc-cc" "-$mode" "${common_flags[@]}" "$source" -o "$work/$mode-$program.exe"
        run_case "$mode" "$program" "$work/$mode-$program.exe"
    done
    for mode in pie non-pie; do
        "$dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" "${common_flags[@]}" "$source" \
            -o "$work/dynamic-$mode-$program.exe"
        cp "$work/dynamic-$mode-$program.exe" "$work/execution-root/consumer-$mode-$program"
        run_case "kernel-$mode" "$program" "${enter_root[@]}" "/consumer-$mode-$program"
        run_case "direct-$mode" "$program" "${enter_root[@]}" /lib/ld-crabc-x86_64.so.1 \
            "/consumer-$mode-$program"
    done
done
printf 'owned native-allocator policy: PASS (musl + native-shadow static/static-PIE/dynamic PIE/non-PIE kernel/direct; allocator-basic, observability and size-class policy programs); evidence: %s\n' "$work"
