#!/usr/bin/env bash
# One ordinary application object through pinned musl and owned linkage modes.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}
provided_static=''
provided_dynamic=''
if [ "${1:-}" = --static-sysroot ]; then
    [ "$#" -ge 2 ] && [ -n "$2" ] && [[ "$2" != -* ]] || usage
    provided_static="$2"
    shift 2
fi
[ "$#" -le 1 ] || usage
if [ "$#" -eq 1 ]; then
    [ -n "$1" ] && [[ "$1" != -* ]] || usage
    provided_dynamic="$1"
fi
build_static=0
if [ -z "$provided_static" ] && [ -z "$provided_dynamic" ]; then build_static=1; fi
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_static" "$provided_dynamic" <<'PY_INPUTS'
from pathlib import Path
import sys
root = Path(sys.argv[1])
sys.path.insert(0, str(root / 'compat/x86_64'))
import owned_posix_product_evidence as evidence

def physical(value, label):
    path = Path(value).absolute()
    if not value or '..' in Path(value).parts or path.resolve(strict=True) != path or not path.is_dir() or not path.is_relative_to(root / '.work'):
        raise ValueError(f'signal helpers {label} must be a physical checkout .work directory')
    return path

try:
    physical(sys.argv[2], 'TMPDIR')
    if sys.argv[3]: evidence._validate_static_product(physical(sys.argv[3], 'static product'))
    if sys.argv[4]: evidence._validate_dynamic_product(physical(sys.argv[4], 'dynamic product'))
except (OSError, ValueError, evidence.ProductEvidenceError) as error:
    raise SystemExit(str(error))
PY_INPUTS
if [ -n "$provided_static" ]; then provided_static="$(realpath "$provided_static")"; fi
if [ -n "$provided_dynamic" ]; then provided_dynamic="$(realpath "$provided_dynamic")"; fi
readonly work="$(mktemp -d "$TMPDIR/owned-signal-helpers.XXXXXX")"
chmod a+rx "$work"
printf 'signal helpers evidence: %s\n' "$work"
readonly probe="$ROOT/compat/x86_64/owned_signal_helpers_probe.c"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly cases=(actions interrupt failed-interrupt restart partial-action cancellation reporting partial-reporting)
# Musl's historical entry points are overridable weak aliases, not merely
# functions that happen to forward to signal. Retain binding/address evidence.
assert_signal_aliases() {
    local binary="$1" table="$2" output="$3"
    readelf --wide "$table" "$binary" >"$output"
    python3 -B - "$output" <<'PYTHON'
from pathlib import Path
import sys
symbols = {}
for line in Path(sys.argv[1]).read_text().splitlines():
    fields = line.split()
    if len(fields) == 8 and fields[7] in ('signal', 'bsd_signal', '__sysv_signal'):
        symbols[fields[7]] = fields
assert set(symbols) == {'signal', 'bsd_signal', '__sysv_signal'}, symbols
signal = symbols['signal']
assert signal[3:6] == ['FUNC', 'GLOBAL', 'DEFAULT'] and signal[6] != 'UND', signal
for name in ('bsd_signal', '__sysv_signal'):
    alias = symbols[name]
    assert alias[3:6] == ['FUNC', 'WEAK', 'DEFAULT'], alias
    assert alias[1:3] == signal[1:3] and alias[6] == signal[6], (signal, alias)
PYTHON
}
# The installed dynamic driver owns the one immutable application object in
# every invocation mode. Its strong stack protection is retained for all links.
if [ -z "$provided_dynamic" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi
python3 -B - "$provided_dynamic" "$work" "$probe" <<'PY_COMPILE'
import hashlib
import json
from pathlib import Path
import subprocess
import sys
product, work, source = map(Path, sys.argv[1:])
sys.path.insert(0, str(product / 'share/crabc'))
import crabc_cc_static as compiler_contract

def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

driver = product / 'bin/crabc-cc-dynamic'
manifest = product / 'share/crabc/manifest.json'
inputs = {str(path): digest(path) for path in (source, driver, manifest, product / 'share/crabc/crabc_cc_static.py')}
arguments = [str(driver), '--dynamic-pie', '-std=c11', '-fno-builtin', '-c', str(source), '-o', str(work / 'workload.o')]
with (work / 'compile.stdout').open('wb') as stdout, (work / 'compile.stderr').open('wb') as stderr:
    subprocess.run(arguments, check=True, stdout=stdout, stderr=stderr)
# Preprocessing repeats the installed driver's actual header/code-generation
# policy; it never creates a replacement object for any consumer.
command = [compiler_contract.compiler(), '-nostdinc', '-isystem', str(product / 'usr/include'),
           '-ffreestanding', '-fno-builtin', '-fstack-protector-strong', '-std=c11', '-fno-builtin', '-fPIE', '-M', str(source)]
with (work / 'workload.d').open('wb') as stdout:
    subprocess.run(command, check=True, stdout=stdout, env=compiler_contract.clean_environment())
paths = (work / 'workload.d').read_text().replace('\\\n', ' ').split(':', 1)[1].split()
headers = {}
for name in paths:
    path = Path(name).resolve(strict=True)
    if path == source: continue
    if not path.is_relative_to(product / 'usr/include'):
        raise SystemExit(f'unowned signal-helper header: {path}')
    headers[str(path.relative_to(product))] = digest(path)
for required in ('signal.h', 'pthread.h', 'stdio.h', 'locale.h', 'errno.h'):
    if 'usr/include/' + required not in headers: raise SystemExit(f'missing installed header {required}')
if any(digest(path) != identity for path, identity in inputs.items()):
    raise SystemExit('signal-helper compile input changed')
record = {'schema': 'crabc.x86_64-owned-signal-helpers-compile/v1', 'command': arguments,
          'dependency_audit_command': command, 'inputs': inputs, 'headers': headers,
          'compiler_sha256': digest(compiler_contract.compiler()), 'object_sha256': digest(work / 'workload.o')}
(work / 'compile.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
PY_COMPILE

# Keep the original host execution for oracle/static and disposable chroot for
# dynamic entries. Retain raw status alongside both streams, including failure.
observe() {
    local output="$1" status=0
    shift
    timeout 20 "$@" >"$output.stdout" 2>"$output.stderr" || status=$?
    printf '%s\n' "$status" >"$output.status"
    [ "$status" -eq 0 ]
}
compare() {
    local reference="$1" candidate="$2" suffix
    for suffix in status stdout stderr; do cmp "$reference.$suffix" "$candidate.$suffix"; done
}
audit_link() {
    python3 -B - "$ROOT" "$work" "$1" "$2" "$3" "$4" <<'PY_LINK'
import hashlib
import json
from pathlib import Path
import sys
root, work, product, executable, receipt = map(Path, sys.argv[1:6])
sys.path.insert(0, str(root / 'compat/x86_64'))
from owned_posix_product_evidence import validate_link
compiled = json.loads((work / 'compile.json').read_text())
if hashlib.sha256((work / 'workload.o').read_bytes()).hexdigest() != compiled['object_sha256']:
    raise SystemExit('signal-helper workload changed after compilation')
identity = validate_link(product, work / 'workload.o', executable, receipt, sys.argv[6])
Path(str(executable) + '.audit.json').write_text(json.dumps(identity, indent=2, sort_keys=True) + '\n')
PY_LINK
}

"$oracle_cc" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"
assert_signal_aliases "$work/oracle" --syms "$work/oracle-symbols.txt"
for scenario in "${cases[@]}"; do observe "$work/oracle-$scenario" "$work/oracle" "$scenario"; done
if [ "$build_static" -eq 1 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    provided_static="$work/static-sysroot"
fi
if [ -n "$provided_static" ]; then
    for mode in static static-pie; do
        (cd "$work" && "$provided_static/bin/crabc-cc" "-$mode" --link-receipt "$mode.crabc-link.json" "$work/workload.o" -o "$work/$mode")
        audit_link "$provided_static" "$work/$mode" "$work/$mode.crabc-link.json" "$mode"
        assert_signal_aliases "$work/$mode" --syms "$work/$mode-symbols.txt"
        for scenario in "${cases[@]}"; do
            observe "$work/$mode-$scenario" "$work/$mode" "$scenario"
            compare "$work/oracle-$scenario" "$work/$mode-$scenario"
        done
    done
fi
assert_signal_aliases "$provided_dynamic/usr/lib/libc.so" --dyn-syms "$work/dynamic-provider-symbols.txt"
cp -a "$provided_dynamic" "$work/execution-root"
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$work/dynamic-$mode"
    audit_link "$provided_dynamic" "$work/dynamic-$mode" "$work/dynamic-$mode.crabc-link.json" "$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    for scenario in "${cases[@]}"; do
        for entry in kernel direct; do
            command=("/consumer-$mode")
            if [ "$entry" = direct ]; then command=(/lib/ld-crabc-x86_64.so.1 "/consumer-$mode"); fi
            observe "$work/$mode-$entry-$scenario" chroot "$work/execution-root" "${command[@]}" "$scenario"
            compare "$work/oracle-$scenario" "$work/$mode-$entry-$scenario"
        done
    done
done
python3 -B - "$work" "$provided_static" "$provided_dynamic" "${cases[@]}" <<'PY_RECORD'
import hashlib
import json
from pathlib import Path
import sys
work, static, dynamic = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
scenarios = sys.argv[4:]
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
compiled = json.loads((work / 'compile.json').read_text())
if digest(work / 'workload.o') != compiled['object_sha256']:
    raise SystemExit('signal-helper workload changed during replay')
if any(digest(path) != identity for path, identity in compiled['inputs'].items()):
    raise SystemExit('signal-helper compile input changed during replay')
if any(digest(dynamic / path) != identity for path, identity in compiled['headers'].items()):
    raise SystemExit('signal-helper installed header changed during replay')
links = [json.loads(path.read_text()) for path in sorted(work.glob('*.audit.json'))]
expected_links = ['non-pie', 'pie', 'static', 'static-pie'] if static else ['non-pie', 'pie']
if sorted(link['linkage'] for link in links) != expected_links or any(link['workload_sha256'] != compiled['object_sha256'] for link in links):
    raise SystemExit('signal-helper link/object roster differs')
modes = (['static', 'static-pie'] if static else []) + ['pie-kernel', 'pie-direct', 'non-pie-kernel', 'non-pie-direct']
comparisons = []
for mode in modes:
    for scenario in scenarios:
        artifacts = {}
        for suffix in ('status', 'stdout', 'stderr'):
            reference, candidate = work / f'oracle-{scenario}.{suffix}', work / f'{mode}-{scenario}.{suffix}'
            if reference.read_bytes() != candidate.read_bytes(): raise SystemExit('signal-helper observation changed')
            artifacts[suffix] = {'reference_sha256': digest(reference), 'candidate_sha256': digest(candidate)}
        comparisons.append({'mode': mode, 'scenario': scenario, 'artifacts': artifacts})
record = {'schema': 'crabc.x86_64-owned-signal-helpers/v1', 'workload_object_sha256': compiled['object_sha256'],
          'compile_receipt_sha256': digest(work / 'compile.json'), 'links': links, 'comparisons': comparisons,
          'oracle_link_command': ['/usr/local/bin/crabc-x86_64-musl-gcc', '-static', '-fno-pie', '-no-pie', '-pthread', str(work / 'workload.o'), '-o', str(work / 'oracle')],
          'oracle': {str(path): digest(path) for path in (Path('/usr/local/bin/crabc-x86_64-musl-gcc'), Path('/opt/musl-1.2.6/lib/libc.a'), work / 'oracle')},
          'static_product_manifest_sha256': digest(Path(static) / 'share/crabc/manifest.json') if static else None,
          'dynamic_product_manifest_sha256': digest(dynamic / 'share/crabc/manifest.json')}
(work / 'signal-helpers.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
PY_RECORD
printf 'owned signal helpers: PASS (same object, musl + installed entries, aliases/actions/masks, EINTR and cancellation bookkeeping, reporting locale/orientation/error state); evidence: %s\n' "$work"
