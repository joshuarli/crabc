#!/usr/bin/env bash
# Installed static/dynamic pthread_getcpuclockid live-worker evidence.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_pthread_cpuclock_probe.c"

[ "$#" -eq 0 ] || [ "$#" -eq 1 ] || {
    printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}
provided_dynamic_sysroot="${1:-}"
if [ -n "$provided_dynamic_sysroot" ]; then
    provided_dynamic_sysroot="$(realpath -e "$provided_dynamic_sysroot")"
fi

python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic_sysroot" <<'PY'
from pathlib import Path
import sys

root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('pthread-cpuclock TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3])
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('pthread-cpuclock product must be a checkout .work directory')
PY

work="$(mktemp -d "$TMPDIR/owned-pthread-cpuclock.XXXXXX")"
readonly work
printf 'pthread-cpuclock evidence: %s\n' "$work"

"$oracle_cc" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector \
    -I"$ROOT/include" "$probe" -o "$work/oracle"
timeout 20 env -i "$work/oracle" >"$work/oracle.stdout"

if [ -z "$provided_dynamic_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-sysroot" >"$work/static-build.json"
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" -std=c11 \
            -D_GNU_SOURCE -fno-builtin -fno-stack-protector "$probe" \
            -o "$work/$mode"
        timeout 20 env -i "$work/$mode" >"$work/$mode.stdout"
        cmp "$work/oracle.stdout" "$work/$mode.stdout"
    done
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic_sysroot="$work/dynamic-sysroot"
fi

cp -a "$provided_dynamic_sysroot" "$work/execution-root"
for mode in pie non-pie; do
    "$provided_dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector "$probe" \
        -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    for entry in kernel direct; do
        if [ "$entry" = direct ]; then
            command=(/lib/ld-crabc-x86_64.so.1 "/consumer-$mode")
        else
            command=("/consumer-$mode")
        fi
        timeout 20 chroot "$work/execution-root" "${command[@]}" \
            >"$work/dynamic-$mode-$entry.stdout"
        cmp "$work/oracle.stdout" "$work/dynamic-$mode-$entry.stdout"
    done
done

printf '%s\n' \
    'owned pthread CPU clock: PASS (pinned musl + installed static ET_EXEC/static-PIE and dynamic PIE/non-PIE kernel/direct entries; worker self and parent-to-live-worker CPU-clock IDs, clock_gettime acceptance, and errno preservation); evidence:' "$work"
