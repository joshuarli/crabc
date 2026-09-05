#!/usr/bin/env bash
# The existing spawn workload through installed dynamic entry and optional static replay.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly CHROOT="$(command -v chroot)"
usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}
provided_static=''
provided_dynamic=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] || usage
            [ -z "$provided_static" ] || usage
            [ -n "$2" ] && [[ "$2" != -* ]] || usage
            provided_static="$2"
            shift 2
            ;;
        -*)
            usage
            ;;
        *)
            [ -z "$provided_dynamic" ] && [ -n "$1" ] || usage
            provided_dynamic="$1"
            shift
            ;;
    esac
done
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" "$provided_static" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('dynamic spawn TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3]).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('dynamic spawn product must be a checkout .work directory')
if sys.argv[4]:
    product = Path(sys.argv[4]).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('static spawn product must be a checkout .work directory')
    sys.path.insert(0, str(root / 'compat/x86_64'))
    from owned_static_sysroot_package import source_entries, validate_installed_tree
    validate_installed_tree(product, source_entries(product))
PY
if [ -n "$provided_static" ]; then
    provided_static="$(realpath "$provided_static")"
fi
readonly work="$(mktemp -d "$TMPDIR/owned-dynamic-spawn.XXXXXX")"
chmod a+rx "$work"
printf 'dynamic spawn evidence: %s\n' "$work"
readonly probe="$ROOT/compat/x86_64/owned_spawn_probe.c"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc

run_in_root() {
    local root="$1" output="$2" status=0
    shift 2
    timeout 40 env -i PATH="$PATH" "$CHROOT" "$root" "$@" \
        >"$output" 2>"${output%.stdout}.stderr" || status=$?
    printf '%s\n' "$status" >"${output%.stdout}.status"
    return "$status"
}

compare_oracle() {
    local label="$1" suffix
    for suffix in stdout stderr status; do
        cmp "$work/oracle.$suffix" "$work/$label.$suffix"
    done
}

# The common validator owns both sealed receipt schemas and actual ELF checks.
# Preserve its exact returned product/object/output identity for each linkage.
validate_sealed_link() {
    local product="$1" consumer="$2" receipt="$3" linkage="$4"
    python3 -B - "$ROOT" "$product" "$work/workload.o" "$consumer" "$receipt" "$linkage" \
        >"$work/$linkage.link-identity.json" <<'PY_LINK'
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(sys.argv[1]) / 'compat/x86_64'))
from owned_posix_product_evidence import validate_link
identity = validate_link(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), sys.argv[6])
json.dump(identity, sys.stdout, sort_keys=True, separators=(',', ':'))
sys.stdout.write('\n')
PY_LINK
}

if [ -z "$provided_dynamic" ]; then
    provided_dynamic="$work/product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$provided_dynamic" >"$work/build.json"
fi
readonly installed="$(realpath "$provided_dynamic")"
assert_compile_receipt() {
    python3 -B - "$installed" "$work" "$probe" <<'PY_RECEIPT'
import hashlib
import json
from pathlib import Path
import sys

product, work, source = map(Path, sys.argv[1:])
source_path = source.resolve(strict=True)
workload = work / 'workload.o'
driver = product / 'bin/crabc-cc-dynamic'
helper = product / 'share/crabc/crabc_cc_static.py'
manifest = product / 'share/crabc/manifest.json'
headers_root = (product / 'usr/include').resolve(strict=True)
record_path = work / 'compile.json'

sys.path.insert(0, str(product / 'share/crabc'))
import crabc_cc_static as compiler_contract
if Path(compiler_contract.__file__).resolve() != helper.resolve():
    raise SystemExit('spawn compile helper did not come from the installed product')

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

try:
    record = json.loads(record_path.read_text(encoding='utf-8'))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f'spawn compile receipt is unreadable: {error}') from error
expected_fields = {
    'schema', 'actual_command', 'dependency_audit_command', 'dependency_audit_sha256',
    'clean_environment', 'source', 'installed_driver', 'installed_helper', 'compiler',
    'manifest', 'headers', 'object_sha256',
}
if not isinstance(record, dict) or set(record) != expected_fields:
    raise SystemExit('spawn compile receipt fields drifted')
if record['schema'] != 'crabc.x86_64-owned-dynamic-spawn-compile/v1':
    raise SystemExit('spawn compile receipt schema drifted')

def assert_binding(name, expected):
    value = record[name]
    if not isinstance(value, dict) or set(value) != {'path', 'sha256'}:
        raise SystemExit(f'spawn compile {name} binding drifted')
    if value['path'] != str(expected) or not isinstance(value['sha256'], str):
        raise SystemExit(f'spawn compile {name} path drifted')
    if digest(expected) != value['sha256']:
        raise SystemExit(f'spawn compile {name} changed after compilation')

compiler = Path(compiler_contract.compiler())
environment = compiler_contract.clean_environment()
for name, path in (
    ('source', source_path), ('installed_driver', driver), ('installed_helper', helper),
    ('compiler', compiler), ('manifest', manifest),
):
    assert_binding(name, path)
macro = '-DCRABC_SPAWN_EXECUTABLE="/consumer"'
actual_command = [str(driver), '--dynamic-pie', '-std=c11', '-fno-builtin', macro,
                  '-c', str(source_path), '-o', str(workload)]
dependency_audit_command = [str(compiler), '-nostdinc', '-isystem', str(headers_root),
    '-ffreestanding', '-fno-builtin', '-fstack-protector-strong', '-std=c11',
    '-fno-builtin', macro, '-fPIE', '-M', str(source_path)]
if record['actual_command'] != actual_command:
    raise SystemExit('spawn actual compile command drifted')
if record['dependency_audit_command'] != dependency_audit_command:
    raise SystemExit('spawn dependency audit command drifted')
if record['clean_environment'] != environment:
    raise SystemExit('spawn compiler environment drifted')
if record['dependency_audit_sha256'] != digest(work / 'workload.d'):
    raise SystemExit('spawn dependency audit changed after compilation')
if not isinstance(record['headers'], dict) or not record['headers']:
    raise SystemExit('spawn installed header receipt is empty')
required_headers = (
    'spawn.h', 'features.h', 'bits/alltypes.h', 'stdio.h', 'stdlib.h', 'string.h',
    'errno.h', 'fcntl.h', 'signal.h', 'unistd.h', 'sys/stat.h', 'sys/wait.h',
    'sys/resource.h', 'pthread.h',
)
for relative, identity in record['headers'].items():
    if not isinstance(relative, str) or not isinstance(identity, str):
        raise SystemExit('spawn installed header receipt path drifted')
    relative_path = Path(relative)
    if (relative_path.is_absolute() or '..' in relative_path.parts
            or relative_path.parts[:2] != ('usr', 'include') or len(relative_path.parts) == 2):
        raise SystemExit('spawn installed header receipt path drifted')
    path = (product / relative_path).resolve(strict=True)
    if not path.is_relative_to(headers_root):
        raise SystemExit(f'spawn installed header escaped the product: {relative}')
    if digest(path) != identity:
        raise SystemExit(f'spawn installed header changed after compilation: {relative}')
for header in required_headers:
    if 'usr/include/' + header not in record['headers']:
        raise SystemExit(f'spawn installed header receipt omitted {header}')
if not isinstance(record['object_sha256'], str) or digest(workload) != record['object_sha256']:
    raise SystemExit('spawn workload changed after compilation')
PY_RECEIPT
}

mkdir "$work/oracle-root"
# One application object is linked by the pinned oracle and each installed
# entry. A fixed owned path permits exec from chdir actions without mounting
# host procfs inside the isolated execution roots.
python3 -B - "$installed" "$work" "$probe" <<'PY_COMPILE'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

product, work, source = map(Path, sys.argv[1:])
source_path = source.resolve(strict=True)
workload = work / 'workload.o'
driver = product / 'bin/crabc-cc-dynamic'
helper = product / 'share/crabc/crabc_cc_static.py'
manifest = product / 'share/crabc/manifest.json'
headers_root = (product / 'usr/include').resolve(strict=True)
sys.path.insert(0, str(product / 'share/crabc'))
import crabc_cc_static as compiler_contract
if Path(compiler_contract.__file__).resolve() != helper.resolve():
    raise SystemExit('spawn compile helper did not come from the installed product')

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def binding(path):
    path = Path(path)
    return {'path': str(path), 'sha256': digest(path)}

compiler = Path(compiler_contract.compiler())
environment = compiler_contract.clean_environment()
macro = '-DCRABC_SPAWN_EXECUTABLE="/consumer"'
actual_command = [str(driver), '--dynamic-pie', '-std=c11', '-fno-builtin', macro,
                  '-c', str(source_path), '-o', str(workload)]
before = {
    'source': binding(source_path),
    'installed_driver': binding(driver),
    'installed_helper': binding(helper),
    'compiler': binding(compiler),
    'manifest': binding(manifest),
}
with (work / 'compile.stdout').open('xb') as stdout, (work / 'compile.stderr').open('xb') as stderr:
    subprocess.run(actual_command, check=True, env=environment, stdin=subprocess.DEVNULL,
                   stdout=stdout, stderr=stderr)
# This is a dependency-only replay of the installed dynamic driver's source
# translation: the emitted workload object above remains the only link input.
dependency_audit_command = [str(compiler), '-nostdinc', '-isystem', str(headers_root),
    '-ffreestanding', '-fno-builtin', '-fstack-protector-strong', '-std=c11',
    '-fno-builtin', macro, '-fPIE', '-M', str(source_path)]
dependency_file = work / 'workload.d'
with dependency_file.open('xb') as output:
    subprocess.run(dependency_audit_command, check=True, env=environment,
                   stdin=subprocess.DEVNULL, stdout=output)
try:
    dependencies = dependency_file.read_text(encoding='utf-8').replace('\\\n', ' ').split(':', 1)[1].split()
except (IndexError, UnicodeDecodeError) as error:
    raise SystemExit(f'spawn installed-header dependency audit is invalid: {error}') from error
if not dependencies:
    raise SystemExit('spawn installed-header dependency audit is empty')
dependency_paths = []
for name in dependencies:
    path = Path(name).resolve(strict=True)
    if path != source_path and not path.is_relative_to(headers_root):
        raise SystemExit(f'spawn dependency escaped the installed headers: {path}')
    if path in dependency_paths:
        raise SystemExit(f'spawn dependency audit repeated {path}')
    dependency_paths.append(path)
if source_path not in dependency_paths:
    raise SystemExit('spawn dependency audit omitted the workload source')
required_headers = (
    'spawn.h', 'features.h', 'bits/alltypes.h', 'stdio.h', 'stdlib.h', 'string.h',
    'errno.h', 'fcntl.h', 'signal.h', 'unistd.h', 'sys/stat.h', 'sys/wait.h',
    'sys/resource.h', 'pthread.h',
)
headers = {}
for path in dependency_paths:
    if path == source_path:
        continue
    headers[str(path.relative_to(product))] = digest(path)
for header in required_headers:
    if 'usr/include/' + header not in headers:
        raise SystemExit(f'spawn installed-header dependency audit omitted {header}')
for name, identity in before.items():
    if binding(identity['path']) != identity:
        raise SystemExit(f'spawn compile {name} changed during compilation')
record = {
    'schema': 'crabc.x86_64-owned-dynamic-spawn-compile/v1',
    'actual_command': actual_command,
    'dependency_audit_command': dependency_audit_command,
    'dependency_audit_sha256': digest(dependency_file),
    'clean_environment': environment,
    **before,
    'headers': headers,
    'object_sha256': digest(workload),
}
(work / 'compile.json').write_text(
    json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8'
)
PY_COMPILE
assert_compile_receipt
"$oracle_cc" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle-root/consumer"
assert_compile_receipt
run_in_root "$work/oracle-root" "$work/oracle.stdout" /consumer /spawn-state
grep -qx owned-spawn-ok "$work/oracle.stdout"

# Static replay is opt-in: no static producer is selected by this leaf.
if [ -n "$provided_static" ]; then
    for mode in static static-pie; do
        consumer="$work/consumer-$mode"
        receipt="$work/consumer-$mode.receipt.json"
        assert_compile_receipt
        (
            cd "$work"
            "$provided_static/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$receipt")" \
                "$work/workload.o" -o "$consumer"
        )
        assert_compile_receipt
        validate_sealed_link "$provided_static" "$consumer" "$receipt" "$mode"
        mkdir "$work/$mode-root"
        cp "$consumer" "$work/$mode-root/consumer"
        run_in_root "$work/$mode-root" "$work/$mode.stdout" /consumer /spawn-state
        compare_oracle "$mode"
    done
fi
for mode in pie non-pie; do
    assert_compile_receipt
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$work/consumer-$mode"
    assert_compile_receipt
    validate_sealed_link "$installed" "$work/consumer-$mode" "$work/consumer-$mode.crabc-link.json" "$mode"
    readelf -hW "$work/consumer-$mode" >"$work/consumer-$mode.header"
    readelf -lW "$work/consumer-$mode" >"$work/consumer-$mode.segments"
    readelf -dW "$work/consumer-$mode" >"$work/consumer-$mode.dynamic"
    cp -a "$installed" "$work/$mode-root"
    cp "$work/consumer-$mode" "$work/$mode-root/consumer"
    for entry in kernel direct; do
        command=(/consumer)
        if [ "$entry" = direct ]; then command=(/lib/ld-crabc-x86_64.so.1 /consumer); fi
        run_in_root "$work/$mode-root" "$work/$mode-$entry.stdout" "${command[@]}" /spawn-state
        compare_oracle "$mode-$entry"
    done
done
assert_compile_receipt
printf 'owned dynamic spawn: PASS (same workload object, musl, optional supplied static/static-PIE, PIE/non-PIE kernel/direct entry, sealed link identities and raw status/stdout/stderr, attributes, file actions, PATH, worker spawn and failure rollback); evidence: %s\n' "$work"
