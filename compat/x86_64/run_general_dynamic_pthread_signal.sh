#!/usr/bin/env bash
# Reuse ordinary pthread/C11 signal behavior through both installed entries.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || exit 2
readonly installed="$1"
readonly driver="$installed/bin/crabc-cc-dynamic"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('pthread-signal TMPDIR must be a physical checkout .work directory')
PY
readonly work="$(mktemp -d "$TMPDIR/general-dynamic-pthread-signal.XXXXXX")"
readonly consumer="$ROOT/compat/x86_64/owned_pthread_signal_probe.c"
cp -a "$installed" "$work/execution-root"
mkdir -p "$work/execution-root/proc"
mounted=0
cleanup() {
    local status=$?
    trap - EXIT
    if [ "$mounted" -eq 1 ]; then
        umount "$work/execution-root/proc" || status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mount -t proc -o ro,nosuid,nodev,noexec proc "$work/execution-root/proc" || {
    printf 'pthread signal evidence requires the dedicated mount-capable dynamic container\n' >&2
    exit 1
}
mounted=1
for mode in pie non-pie; do
    oracle_entry=(-fPIE -pie)
    [ "$mode" = pie ] || oracle_entry=(-fno-pie -no-pie)
    "$oracle_cc" -std=c11 -pthread "${oracle_entry[@]}" -I"$ROOT/include" \
        "$consumer" -o "$work/oracle-$mode"
    timeout 20 "$work/oracle-$mode" >"$work/oracle-$mode.stdout"
    "$driver" "--dynamic-$mode" -std=c11 "$consumer" -o "$work/consumer-$mode"
    cp "$work/consumer-$mode" "$work/execution-root/consumer-$mode"
    timeout 20 chroot "$work/execution-root" "/consumer-$mode" >"$work/candidate-$mode.stdout"
    cmp "$work/oracle-$mode.stdout" "$work/candidate-$mode.stdout"
done
printf 'general dynamic pthread signal delivery: PASS; evidence: %s\n' "$work"
