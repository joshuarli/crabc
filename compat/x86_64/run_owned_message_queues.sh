#!/usr/bin/env bash
# Same-object installed POSIX message-queue transfer and notification lifecycle.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly witness="$ROOT/compat/x86_64/run_pthread_wait_witness.py"
[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
provided_dynamic="${1:-}"
provided_dynamic="$(python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('message queues TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3]).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('message queues product must be a physical checkout .work directory')
    print(product)
PY
)"
# Docker supplies the private IPC namespace. Queue operations use mq syscalls
# directly, so no mqueuefs mount or chroot /dev/mqueue directory is required.
readonly work="$(mktemp -d "$TMPDIR/owned-message-queues.XXXXXX")"
chmod a+rx "$work"
printf 'message queues evidence: %s\n' "$work"
if [ -z "$provided_dynamic" ]; then
    provided_dynamic="$work/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
python3 -B "$ROOT/compat/x86_64/compile_owned_message_queues.py" "$provided_dynamic" "$work"
sha256sum "$work/probe.o" >"$work/probe.sha256"
"$oracle_cc" -static -no-pie -pthread "$work/probe.o" -o "$work/oracle"
mkdir -p "$work/oracle-root"
cp "$work/oracle" "$work/oracle-root/consumer"
timeout 35 python3 -B "$witness" "$work/oracle-root" /consumer >"$work/oracle.stdout"
grep -qx owned-message-queues-ok "$work/oracle.stdout"
if [ "$#" -eq 0 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-product" >"$work/static-build.json"
    for mode in static static-pie; do
        "$work/static-product/bin/crabc-cc" "-$mode" "$work/probe.o" -o "$work/$mode"
        mkdir -p "$work/$mode-root"
        cp "$work/$mode" "$work/$mode-root/consumer"
        timeout 35 python3 -B "$witness" "$work/$mode-root" /consumer >"$work/$mode.stdout"
        cmp "$work/oracle.stdout" "$work/$mode.stdout"
    done
fi
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/probe.o" -o "$work/dynamic-$mode"
    cp -a "$provided_dynamic" "$work/$mode-root"
    cp "$work/dynamic-$mode" "$work/$mode-root/consumer"
    for entry in kernel direct; do
        command=(/consumer)
        if [ "$entry" = direct ]; then command=(/lib/ld-crabc-x86_64.so.1 /consumer); fi
        timeout 35 python3 -B "$witness" "$work/$mode-root" "${command[@]}" >"$work/$mode-$entry.stdout"
        cmp "$work/oracle.stdout" "$work/$mode-$entry.stdout"
    done
done
printf 'owned message queues: PASS (same object, musl + installed static/dynamic entries, POSIX message queues); evidence: %s\n' "$work"
