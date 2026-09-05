#!/usr/bin/env bash
# Joint environment, signal, FILE, syslog, fork/exec/spawn and cancellation evidence.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_posix_composition_probe.c"

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
    raise SystemExit("owned POSIX composition TMPDIR must be a physical checkout .work directory")
if product_argument:
    product = Path(product_argument)
    if not product.is_dir() or not product.is_relative_to(root / ".work"):
        raise SystemExit("owned POSIX composition product must be a checkout .work directory")
PY

readonly work="$(mktemp -d "$TMPDIR/owned-posix-composition.XXXXXX")"
chmod a+rx "$work"
printf 'owned POSIX composition evidence: %s\n' "$work"
readonly execution_root="$work/execution-root"
# Each run owns its logger pathname, stream and full raw transcript.
run_in_root() {
    local root="$1" output="$2"
    shift 2
    mkdir -p "$root/dev"
    : >"$root/log-wire"
    local status=0
    timeout 30 env -i PATH="$PATH" chroot "$root" "$@" >"$output" 2>"${output%.stdout}.stderr" || status=$?
    printf '%s\n' "$status" >"${output%.stdout}.status"
    cp "$root/log-wire" "${output%.stdout}.log-wire"
    [ "$status" -eq 0 ]
}

compare_run() {
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
Path(str(executable) + '.evidence.json').write_text(json.dumps(identity, indent=2, sort_keys=True) + '\n')
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
python3 -B - "$provided_dynamic" "$work" "$PROBE" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

product, work, source = map(Path, sys.argv[1:])
# Repeat only preprocessing using the installed driver's exact compiler and
# header policy. The linked object remains the one produced by that driver.
sys.path.insert(0, str(product / 'share/crabc'))
import crabc_cc_static as compiler_contract
dependency_command = [compiler_contract.compiler(), '-nostdinc', '-isystem', str(product / 'usr/include'),
    '-std=c11', '-ffreestanding', '-fno-builtin', '-fstack-protector-strong', '-fPIE', '-M', str(source)]
with (work / 'workload.d').open('wb') as output:
    subprocess.run(dependency_command, stdout=output, check=True, env=compiler_contract.clean_environment())
dependencies = (work / 'workload.d').read_text().replace('\\\n', ' ').split(':', 1)[1].split()
headers = product / 'usr/include'
assert dependencies and str(source) in dependencies
for name in dependencies:
    path = Path(name).resolve(strict=True)
    assert path == source or path.is_relative_to(headers), path
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
record = {
    'schema': 'crabc.posix-composition-compile/v1',
    'driver_sha256': digest(product / 'bin/crabc-cc-dynamic'),
    'manifest_sha256': digest(product / 'share/crabc/manifest.json'),
    'source_sha256': digest(source), 'object_sha256': digest(work / 'workload.o'),
    'dependency_audit_command': dependency_command,
    'dependencies': {name: digest(Path(name)) for name in dependencies},
}
(work / 'compile.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
PY

"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"
cp "$work/oracle" "$execution_root/oracle"
run_in_root "$execution_root" "$work/oracle.stdout" /oracle

if [ "${1:-}" = "" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-sysroot" >"$work/static-build.json"
    for mode in static static-pie; do
        (
            cd "$work"
            "$work/static-sysroot/bin/crabc-cc" "-$mode" --link-receipt "$mode.receipt.json" \
                "$work/workload.o" -o "$work/$mode"
        )
        audit_link "$work/static-sysroot" "$work/$mode" "$work/$mode.receipt.json" "$mode"
        cp "$work/$mode" "$execution_root/consumer-$mode"
        run_in_root "$execution_root" "$work/$mode.stdout" "/consumer-$mode"
        compare_run "$mode"
    done
fi

cp -a "$provided_dynamic/." "$execution_root/"
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" \
        -o "$work/dynamic-$mode"
    audit_link "$provided_dynamic" "$work/dynamic-$mode" "$work/dynamic-$mode.crabc-link.json" "$mode"
    cp "$work/dynamic-$mode" "$execution_root/consumer-$mode"
    for entry in kernel direct; do
        if [ "$entry" = direct ]; then
            command=(/lib/ld-crabc-x86_64.so.1 "/consumer-$mode")
        else
            command=("/consumer-$mode")
        fi
        run_in_root "$execution_root" "$work/$mode-$entry.stdout" "${command[@]}"
        compare_run "$mode-$entry"
    done
done

printf 'owned POSIX composition: PASS; evidence: %s\n' "$work"
