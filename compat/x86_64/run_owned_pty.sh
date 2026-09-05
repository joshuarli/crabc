#!/usr/bin/env bash
# Pinned-musl and installed PTY consumers share one object and isolated devpts.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
provided_dynamic="${1:-}"
if [ -n "$provided_dynamic" ]; then provided_dynamic="$(realpath -e "$provided_dynamic")"; fi
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('PTY TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3])
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('PTY product must be a checkout .work directory')
PY
readonly work="$(mktemp -d "$TMPDIR/owned-pty.XXXXXX")"
chmod a+rx "$work"
printf 'PTY evidence: %s\n' "$work"
readonly execution_root="$work/execution-root"
readonly probe="$ROOT/compat/x86_64/owned_pty_probe.c"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly cases=(naming openpty no-controlling-terminal optional-errors master-failure unlock-failure number-failure slave-failure login login-failures forkpty pipe-failure fork-failure child-login-failure cancellation)
# The public naming entry is musl's weak alias of a hidden internal provider;
# ptsname must keep calling that internal body if the application overrides it.
assert_ptsname_binding() {
    local binary="$1" table="$2" output="$3"
    readelf --wide "$table" "$binary" >"$output"
    python3 -B - "$output" "$table" <<'PYTHON'
from pathlib import Path
import sys
symbols = {}
for line in Path(sys.argv[1]).read_text().splitlines():
    fields = line.split()
    if len(fields) == 8 and fields[7] in ('ptsname_r', '__ptsname_r'):
        symbols[fields[7]] = fields
alias = symbols['ptsname_r']
assert alias[3:6] == ['FUNC', 'WEAK', 'DEFAULT'] and alias[6] != 'UND', alias
if sys.argv[2] == '--dyn-syms':
    assert '__ptsname_r' not in symbols, symbols
else:
    internal = symbols['__ptsname_r']
    assert internal[3] == 'FUNC' and internal[5] == 'HIDDEN', internal
    assert internal[1:3] == alias[1:3] and internal[6] == alias[6], (internal, alias)
PYTHON
}
# A private devpts instance prevents tests from acquiring any host/container
# terminal. Procfs resolves only the executing consumer's descriptor names.
# The surrounding Docker mount/PID namespaces contain every mount and child.
mkdir -p "$execution_root/dev/pts" "$execution_root/proc"
mounted_devpts=0
mounted_proc=0
cleanup() {
    local status="$?"
    trap - EXIT
    if [ "$mounted_proc" = 1 ]; then umount "$execution_root/proc" || status=1; fi
    if [ "$mounted_devpts" = 1 ]; then umount "$execution_root/dev/pts" || status=1; fi
    exit "$status"
}
trap cleanup EXIT
mount -t devpts -o newinstance,ptmxmode=0666,mode=0620 devpts "$execution_root/dev/pts"
mounted_devpts=1
mount -t proc -o ro,nosuid,nodev,noexec proc "$execution_root/proc"
mounted_proc=1
ln -s pts/ptmx "$execution_root/dev/ptmx"
mknod -m 666 "$execution_root/dev/null" c 1 3
if [ -z "$provided_dynamic" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    "$work/static-sysroot/bin/crabc-cc" -static-pie -std=c11 -fno-builtin -c "$probe" -o "$work/workload.o"
else
    "$provided_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin -c "$probe" -o "$work/workload.o"
fi
"$oracle_cc" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"
assert_ptsname_binding "$work/oracle" --syms "$work/oracle-symbols.txt"
cp "$work/oracle" "$execution_root/oracle"
for scenario in "${cases[@]}"; do
    timeout 20 chroot "$execution_root" /oracle "$scenario" >"$work/oracle-$scenario.stdout" 2>"$work/oracle-$scenario.stderr"
done
if [ -z "$provided_dynamic" ]; then
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$work/$mode"
        assert_ptsname_binding "$work/$mode" --syms "$work/$mode-symbols.txt"
        cp "$work/$mode" "$execution_root/consumer-$mode"
        for scenario in "${cases[@]}"; do
            timeout 20 chroot "$execution_root" "/consumer-$mode" "$scenario" >"$work/$mode-$scenario.stdout" 2>"$work/$mode-$scenario.stderr"
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$scenario.stdout"
            cmp "$work/oracle-$scenario.stderr" "$work/$mode-$scenario.stderr"
        done
    done
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi
assert_ptsname_binding "$provided_dynamic/usr/lib/libc.so" --dyn-syms "$work/dynamic-provider-symbols.txt"
cp -a "$provided_dynamic/." "$execution_root/"
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$execution_root/consumer-$mode"
    for scenario in "${cases[@]}"; do
        for entry in kernel direct; do
            command=("/consumer-$mode")
            if [ "$entry" = direct ]; then command=(/lib/ld-crabc-x86_64.so.1 "/consumer-$mode"); fi
            timeout 20 chroot "$execution_root" "${command[@]}" "$scenario" >"$work/$mode-$entry-$scenario.stdout" 2>"$work/$mode-$entry-$scenario.stderr"
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$entry-$scenario.stdout"
            cmp "$work/oracle-$scenario.stderr" "$work/$mode-$entry-$scenario.stderr"
        done
    done
done
printf 'owned PTY lifecycle: PASS (same object, musl + installed entries, private devpts, naming, descriptor/session ownership, cancellation/mask/error handshakes); evidence: %s\n' "$work"
