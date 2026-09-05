#!/usr/bin/env bash
# One installed-header pthread signal workload across sealed runtime products.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_pthread_signal_probe.c"

if ! { [ "$#" -eq 1 ] || { [ "$#" -eq 3 ] && [ "$1" = --static-sysroot ]; }; }; then
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
fi

if [ "$#" -eq 1 ]; then
    static_input=''
    dynamic_input="$1"
else
    static_input="$2"
    dynamic_input="$3"
fi

# Resolve neither supplied tree through a symlink.  The dynamic product owns
# the sole compilation, while an explicitly selected static product is only a
# linker/CRT provider for the same resulting object.
supplied_product_paths="$(python3 -B - "$ROOT" "${TMPDIR:-}" "$dynamic_input" "$static_input" <<'PY'
from pathlib import Path
import os
import stat
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
dynamic_input, static_input = sys.argv[3:]

if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('pthread-signal TMPDIR must be a physical checkout .work directory')

def supplied_tree(argument: str, label: str) -> Path:
    raw = Path(argument)
    if '..' in raw.parts:
        raise SystemExit(f'pthread-signal {label} product must be a physical checkout .work directory')
    absolute = Path(os.path.abspath(raw))
    current = Path(absolute.anchor)
    try:
        for component in absolute.parts[1:]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                raise SystemExit(f'pthread-signal {label} product must be a physical checkout .work directory')
        if not stat.S_ISDIR(absolute.lstat().st_mode) or not absolute.is_relative_to(root / '.work'):
            raise SystemExit(f'pthread-signal {label} product must be a physical checkout .work directory')
    except OSError:
        raise SystemExit(f'pthread-signal {label} product must be a physical checkout .work directory')
    return absolute

print(supplied_tree(dynamic_input, 'dynamic'))
if static_input:
    print(supplied_tree(static_input, 'static'))
PY
 )"
readonly supplied_product_paths
mapfile -t supplied_products <<<"$supplied_product_paths"
readonly dynamic_sysroot="${supplied_products[0]}"
readonly static_sysroot="${supplied_products[1]:-}"

readonly work="$(mktemp -d "$TMPDIR/owned-pthread-signal.XXXXXX")"
readonly execution_root="$work/execution-root"
chmod a+rx "$work"
printf 'owned pthread signal evidence: %s\n' "$work"

# Each command retains its untouched result.  The empty success transcript is
# still behavior evidence because the probe's task-retirement checks execute
# before it returns; a failed assertion is preserved on stderr with its exit.
run_host() {
    local output="$1"
    shift
    local status=0
    timeout 20 env -i "$@" >"$output" 2>"${output%.stdout}.stderr" || status=$?
    printf '%s\n' "$status" >"${output%.stdout}.status"
    [ "$status" -eq 0 ]
}

run_in_root() {
    local root="$1" output="$2"
    shift 2
    local status=0
    timeout 20 env -i PATH="$PATH" chroot "$root" "$@" >"$output" 2>"${output%.stdout}.stderr" || status=$?
    printf '%s\n' "$status" >"${output%.stdout}.status"
    [ "$status" -eq 0 ]
}

compare_observation() {
    local label="$1" suffix
    for suffix in stdout stderr status; do
        cmp "$work/oracle.$suffix" "$work/$label.$suffix"
    done
}

audit_link() {
    local product="$1" candidate="$2" receipt="$3" linkage="$4"
    readelf -hW "$candidate" >"$candidate.header"
    readelf -lW "$candidate" >"$candidate.segments"
    readelf -dW "$candidate" >"$candidate.dynamic"
    python3 -B - "$ROOT" "$product" "$work/workload.o" "$candidate" "$receipt" "$linkage" <<'PY'
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(sys.argv[1]) / 'compat/x86_64'))
from owned_posix_product_evidence import validate_link

product, workload, executable, receipt = map(Path, sys.argv[2:6])
identity = validate_link(product, workload, executable, receipt, sys.argv[6])
Path(str(executable) + '.evidence.json').write_text(
    json.dumps(identity, indent=2, sort_keys=True) + '\n'
)
PY
}

# The dynamic driver chooses the installed header tree.  The dependency record
# repeats only preprocessing using that driver's declared compiler policy; it
# does not make a second object that could escape the product binding.
"$dynamic_sysroot/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin -c "$probe" -o "$work/workload.o"
python3 -B - "$dynamic_sysroot" "$work" "$probe" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

product, work, source = map(Path, sys.argv[1:])
sys.path.insert(0, str(product / 'share/crabc'))
import crabc_cc_static as compiler_contract

dependency_command = [
    compiler_contract.compiler(), '-nostdinc', '-isystem', str(product / 'usr/include'),
    '-std=c11', '-ffreestanding', '-fno-builtin', '-fstack-protector-strong', '-fPIE',
    '-M', str(source),
]
with (work / 'workload.d').open('wb') as output:
    subprocess.run(dependency_command, stdout=output, check=True,
                   env=compiler_contract.clean_environment())
dependencies = (work / 'workload.d').read_text().replace('\\\n', ' ').split(':', 1)[1].split()
headers = product / 'usr/include'
assert dependencies and str(source) in dependencies
for name in dependencies:
    path = Path(name).resolve(strict=True)
    assert path == source or path.is_relative_to(headers), path

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

record = {
    'schema': 'crabc.pthread-signal-compile/v1',
    'driver_sha256': digest(product / 'bin/crabc-cc-dynamic'),
    'manifest_sha256': digest(product / 'share/crabc/manifest.json'),
    'source_sha256': digest(source),
    'object_sha256': digest(work / 'workload.o'),
    'dependency_audit_command': dependency_command,
    'dependencies': {name: digest(Path(name)) for name in dependencies},
}
(work / 'compile.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
PY

"$oracle_cc" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"
run_host "$work/oracle.stdout" "$work/oracle"

if [ -n "$static_sysroot" ]; then
    for mode in static static-pie; do
        (
            cd "$work"
            "$static_sysroot/bin/crabc-cc" "-$mode" --link-receipt "$mode.receipt.json" \
                "$work/workload.o" -o "$work/$mode"
        )
        audit_link "$static_sysroot" "$work/$mode" "$work/$mode.receipt.json" "$mode"
        run_host "$work/$mode.stdout" "$work/$mode"
        compare_observation "$mode"
    done
fi

# This copy is the disposable chroot used by both PT_INTERP and direct loader
# entries.  Keep the original read-only proc mount and exit-trap ownership: the
# shared probe needs /proc to witness each worker TID disappear before join.
cp -a "$dynamic_sysroot" "$execution_root"
mkdir -p "$execution_root/proc"
mounted=0
cleanup() {
    local status=$?
    trap - EXIT
    if [ "$mounted" -eq 1 ]; then
        umount "$execution_root/proc" || status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mount -t proc -o ro,nosuid,nodev,noexec proc "$execution_root/proc" || {
    printf 'pthread signal evidence requires the dedicated mount-capable dynamic container\n' >&2
    exit 1
}
mounted=1

for mode in pie non-pie; do
    "$dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" \
        -o "$work/dynamic-$mode"
    audit_link "$dynamic_sysroot" "$work/dynamic-$mode" \
        "$work/dynamic-$mode.crabc-link.json" "$mode"
    cp "$work/dynamic-$mode" "$execution_root/consumer-$mode"
    for entry in kernel direct; do
        if [ "$entry" = direct ]; then
            command=(/lib/ld-crabc-x86_64.so.1 "/consumer-$mode")
        else
            command=("/consumer-$mode")
        fi
        run_in_root "$execution_root" "$work/$mode-$entry.stdout" "${command[@]}"
        compare_observation "$mode-$entry"
    done
done

printf 'owned pthread signal: PASS; evidence: %s\n' "$work"
