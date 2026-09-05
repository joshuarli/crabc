#!/usr/bin/env bash
# Source-bound installed Linux/filesystem/terminal mechanism evidence.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_unix_mechanisms_probe.c"

[ "$#" -le 1 ] || {
    printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

provided_dynamic="${1:-}"
if [ -n "$provided_dynamic" ]; then
    provided_dynamic="$(realpath "$provided_dynamic")"
fi

# Check supplied products before creating any mutable output. This lets the
# dynamic qualification receipt safely distinguish its installed/extracted
# product input from this runner's contained evidence directory.
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
product_argument = sys.argv[3]
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / ".work"):
    raise SystemExit("owned unix mechanisms TMPDIR must be a physical checkout .work directory")
if product_argument:
    product = Path(product_argument)
    if not product.is_dir() or not product.is_relative_to(root / ".work"):
        raise SystemExit("owned unix mechanisms product must be a checkout .work directory")
PY

readonly work="$(mktemp -d "$TMPDIR/owned-unix-mechanisms.XXXXXX")"
chmod a+rx "$work"
printf 'owned unix mechanisms evidence: %s\n' "$work"
readonly execution_root="$work/execution-root"
readonly cases=(cwd privileged-errors terminal terminal-cancel vmsplice streams)

# The source has no public aliases among these eight strong providers. Check
# archive, final static links, and the shared provider independently.
assert_mechanism_symbols() {
    local binary="$1"
    local table="$2"
    local output="$3"

    readelf --wide "$table" "$binary" >"$output"
    python3 -B - "$output" <<'PYTHON'
from pathlib import Path
import sys

names = {
    "get_current_dir_name", "isastream", "mount", "tcdrain", "umount",
    "umount2", "vhangup", "vmsplice",
}
records = {}
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    fields = line.split()
    if len(fields) == 8 and fields[7] in names:
        records.setdefault(fields[7], []).append(fields)

assert set(records) == names, records
for name, entries in records.items():
    assert len(entries) == 1, (name, entries)
    fields = entries[0]
    assert fields[3:6] == ["FUNC", "GLOBAL", "DEFAULT"], fields
    assert fields[6] != "UND", fields
PYTHON
}

# Open a pseudo-terminal only in the surrounding private container namespace,
# preserve it across chroot/exec as fd 3, and let the workload observe it.
# No mount, umount, or vhangup request reaches the host: those API checks are
# separately denied by the workload's child-local seccomp filter.
run_in_root() {
    local root="$1"
    local output="$2"
    shift 2
    timeout 30 python3 -B - "$root" "$@" >"$output" 2>"${output%.stdout}.stderr" <<'PY'
import os
import sys

root = sys.argv[1]
command = sys.argv[2:]
pty = os.open("/dev/ptmx", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
if pty != 3:
    os.dup2(pty, 3)
    os.close(pty)
os.set_inheritable(3, True)
os.chroot(root)
os.chdir("/")
os.execve(command[0], command, {"PATH": os.environ.get("PATH", "")})
PY
}

mkdir -p "$execution_root"

# Build the dynamic product first so one installed dynamic driver compiles the
# one workload object consumed by musl, both static modes, and both dynamic
# modes. A caller-provided installed or extracted product is validated above.
if [ -z "$provided_dynamic" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi
"$provided_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"

"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"
assert_mechanism_symbols "$work/oracle" --syms "$work/oracle-symbols.txt"
cp "$work/oracle" "$execution_root/oracle"
for scenario in "${cases[@]}"; do
    run_in_root "$execution_root" "$work/oracle-$scenario.stdout" \
        /oracle "$scenario"
done

if [ "${1:-}" = "" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-sysroot" >"$work/static-build.json"
    assert_mechanism_symbols "$work/static-sysroot/usr/lib/libc.a" --syms \
        "$work/static-archive-symbols.txt"
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$work/$mode"
        assert_mechanism_symbols "$work/$mode" --syms "$work/$mode-symbols.txt"
        cp "$work/$mode" "$execution_root/consumer-$mode"
        for scenario in "${cases[@]}"; do
            run_in_root "$execution_root" "$work/$mode-$scenario.stdout" \
                "/consumer-$mode" "$scenario"
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$scenario.stdout"
            cmp "$work/oracle-$scenario.stderr" "$work/$mode-$scenario.stderr"
        done
    done
fi

assert_mechanism_symbols "$provided_dynamic/usr/lib/libc.so" --dyn-syms \
    "$work/dynamic-provider-symbols.txt"
cp -a "$provided_dynamic/." "$execution_root/"
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" \
        -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$execution_root/consumer-$mode"
    for scenario in "${cases[@]}"; do
        for entry in kernel direct; do
            if [ "$entry" = direct ]; then
                command=(/lib/ld-crabc-x86_64.so.1 "/consumer-$mode" "$scenario")
            else
                command=("/consumer-$mode" "$scenario")
            fi
            run_in_root "$execution_root" "$work/$mode-$entry-$scenario.stdout" "${command[@]}"
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$entry-$scenario.stdout"
            cmp "$work/oracle-$scenario.stderr" "$work/$mode-$entry-$scenario.stderr"
        done
    done
done

printf 'owned unix mechanisms: PASS (same installed object, musl, static/static-PIE, dynamic PIE/non-PIE, kernel/direct, logical cwd, seccomp-contained privileged errors, tty drain cancellation, vmsplice pipe, and STREAMS probes); evidence: %s\n' "$work"
