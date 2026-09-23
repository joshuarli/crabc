#!/usr/bin/env bash
# Execute one C11/TLS/synchronization object through supplied installed products.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly SOURCE="$ROOT/compat/x86_64/owned_pthread_family_composition.c"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1

usage() {
    printf 'usage: %s --static-sysroot STATIC_SYSROOT DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
}

[ "$#" -eq 3 ] && [ "$1" = --static-sysroot ] || usage
[ -n "$2" ] && [ -n "$3" ] || usage
readonly STATIC_PRODUCT="$(realpath -e "$2")"
readonly DYNAMIC_PRODUCT="$(realpath -e "$3")"

python3 -B - "$ROOT" "${TMPDIR:-}" "$STATIC_PRODUCT" "$DYNAMIC_PRODUCT" <<'PY'
from pathlib import Path
import sys
root, temporary, static, dynamic = map(Path, sys.argv[1:])
for path, description in ((root, 'checkout'), (temporary, 'TMPDIR'),
                          (static, 'static product'), (dynamic, 'dynamic product')):
    if not path.is_dir() or path.resolve() != path:
        raise SystemExit(f'{description} must be a physical directory')
if not temporary.is_relative_to(root / '.work'):
    raise SystemExit('pthread family composition TMPDIR must be under checkout .work')
for path, description in ((static, 'static product'), (dynamic, 'dynamic product')):
    if not path.is_relative_to(root / '.work'):
        raise SystemExit(f'pthread family composition {description} must be under checkout .work')
PY

[ -x "$ORACLE_CC" ] || { printf 'pthread family composition: missing pinned oracle compiler\n' >&2; exit 1; }
[ -x "$STATIC_PRODUCT/bin/crabc-cc" ] || { printf 'pthread family composition: missing static driver\n' >&2; exit 1; }
[ -x "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" ] || { printf 'pthread family composition: missing dynamic driver\n' >&2; exit 1; }
[ -f "$SOURCE" ] || { printf 'pthread family composition: missing source\n' >&2; exit 1; }

readonly WORK="$(mktemp -d "$TMPDIR/owned-pthread-family-composition.XXXXXX")"
finish() {
    chmod -R a+rX "$WORK"
}
trap finish EXIT
printf 'evidence: %s\n' "$WORK"

fail() {
    printf 'pthread family composition: %s\n' "$*" >&2
    exit 1
}

run_capture() {
    local stem="$1"
    shift
    python3 -B - "$WORK/$stem.argv.json" "$@" <<'PY'
import json
from pathlib import Path
import sys

Path(sys.argv[1]).write_text(
    json.dumps(sys.argv[2:], separators=(',', ':')) + '\n', encoding='utf-8'
)
PY
    local status
    set +e
    timeout 45 "$@" >"$WORK/$stem.stdout" 2>"$WORK/$stem.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$WORK/$stem.status"
    [ "$status" -eq 0 ] || fail "$stem failed with status $status"
}

capture_tools() {
    local output="$1"
    python3 -B - "$STATIC_PRODUCT" "$DYNAMIC_PRODUCT" "$ORACLE_CC" "$output" <<'PY'
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys

static, dynamic, oracle, output = map(Path, sys.argv[1:])

def identity(path):
    path = path.resolve(strict=True)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise SystemExit(f'pthread family composition tool is not a physical file: {path}')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'path': str(path), 'sha256': digest, 'size': path.stat().st_size}

helper = dynamic / 'share/crabc/crabc_cc_static.py'
if helper.is_symlink() or not helper.is_file():
    raise SystemExit('pthread family composition dynamic compiler helper is not physical')
spec = importlib.util.spec_from_file_location('pthread_family_composition_tools', helper)
if spec is None or spec.loader is None:
    raise SystemExit('pthread family composition cannot load dynamic compiler helper')
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
try:
    spec.loader.exec_module(module)
    record = {
        'oracle': identity(oracle),
        'static_driver': identity(static / 'bin/crabc-cc'),
        'dynamic_driver': identity(dynamic / 'bin/crabc-cc-dynamic'),
        'compiler': identity(Path(module.compiler())),
        'linker': identity(Path(module.linker(dynamic))),
    }
finally:
    sys.modules.pop(spec.name, None)
Path(output).write_text(json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
PY
}

compare_oracle() {
    local stem="$1"
    cmp "$WORK/oracle.stdout" "$WORK/$stem.stdout" || fail "$stem stdout differs from pinned musl"
    cmp "$WORK/oracle.stderr" "$WORK/$stem.stderr" || fail "$stem stderr differs from pinned musl"
    cmp "$WORK/oracle.status" "$WORK/$stem.status" || fail "$stem status differs from pinned musl"
}

validate_link() {
    local stem="$1" product="$2" workload="$3" executable="$4" receipt="$5" linkage="$6"
    run_capture "$stem-validate" python3 -B - "$ROOT" "$product" "$workload" "$executable" "$receipt" "$linkage" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
sys.path.insert(0, str(root / 'compat' / 'x86_64'))
from owned_posix_product_evidence import validate_link
identity = validate_link(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), sys.argv[6])
print(json.dumps(identity, sort_keys=True, separators=(',', ':')))
PY
    cp "$WORK/$stem-validate.stdout" "$WORK/$stem.link.json"
}

capture_tools "$WORK/tools-before.json"
run_capture compile "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -D_GNU_SOURCE \
    -fno-builtin -c "$SOURCE" -o "$WORK/workload.o"
run_capture oracle-link "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread "$WORK/workload.o" -o "$WORK/oracle"
run_capture oracle env -i "$WORK/oracle"
[ "$(cat "$WORK/oracle.stdout")" = 'pthread-family-composition-ok' ] || fail 'pinned musl composition output differs'
[ ! -s "$WORK/oracle.stderr" ] || fail 'pinned musl composition emitted stderr'

for linkage in static static-pie; do
    executable="$WORK/$linkage"
    receipt="$WORK/$linkage.crabc-link.json"
    (
        cd "$WORK"
        run_capture "$linkage-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$linkage" \
            --link-receipt "$linkage.crabc-link.json" "$WORK/workload.o" -o "$executable"
    )
    validate_link "$linkage" "$STATIC_PRODUCT" "$WORK/workload.o" "$executable" "$receipt" "$linkage"
    run_capture "$linkage-run" env -i "$executable"
    compare_oracle "$linkage-run"
done

mkdir "$WORK/dynamic-root"
cp -a "$DYNAMIC_PRODUCT/." "$WORK/dynamic-root"
for linkage in pie non-pie; do
    executable="$WORK/dynamic-$linkage"
    run_capture "dynamic-$linkage-link" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "--dynamic-$linkage" \
        -std=c11 "$WORK/workload.o" -o "$executable"
    validate_link "dynamic-$linkage" "$DYNAMIC_PRODUCT" "$WORK/workload.o" "$executable" \
        "$executable.crabc-link.json" "$linkage"
    cp "$executable" "$WORK/dynamic-root/consumer-$linkage"
    run_capture "dynamic-$linkage-kernel" chroot "$WORK/dynamic-root" "/consumer-$linkage"
    compare_oracle "dynamic-$linkage-kernel"
    run_capture "dynamic-$linkage-direct" chroot "$WORK/dynamic-root" "$INTERPRETER" "/consumer-$linkage"
    compare_oracle "dynamic-$linkage-direct"
done

capture_tools "$WORK/tools-after.json"
cmp "$WORK/tools-before.json" "$WORK/tools-after.json" || fail 'native compiler/linker tool roster changed during composition'

python3 -B - "$ROOT" "$WORK" "$STATIC_PRODUCT" "$DYNAMIC_PRODUCT" "$SOURCE" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
root, work, static, dynamic, source = map(Path, sys.argv[1:])

def identity(path):
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f'missing physical evidence: {path}')
    data = path.read_bytes()
    try:
        name = path.relative_to(root).as_posix()
    except ValueError:
        name = str(path)
    return {'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}

def product(path):
    manifest = path / 'share/crabc/manifest.json'
    return {'path': path.relative_to(root).as_posix(), 'manifest': identity(manifest)}

raw = {}
for stem in ('oracle', 'static-run', 'static-pie-run', 'dynamic-pie-kernel',
             'dynamic-pie-direct', 'dynamic-non-pie-kernel', 'dynamic-non-pie-direct'):
    raw[stem] = {suffix: identity(work / f'{stem}.{suffix}') for suffix in ('stdout', 'stderr', 'status')}
links = {
    'static': {'linkage': 'static', 'executable': identity(work / 'static'),
               'receipt': identity(work / 'static.crabc-link.json'), 'validated': identity(work / 'static.link.json')},
    'static-pie': {'linkage': 'static-pie', 'executable': identity(work / 'static-pie'),
                   'receipt': identity(work / 'static-pie.crabc-link.json'), 'validated': identity(work / 'static-pie.link.json')},
    'dynamic-pie': {'linkage': 'pie', 'executable': identity(work / 'dynamic-pie'),
                    'receipt': identity(work / 'dynamic-pie.crabc-link.json'), 'validated': identity(work / 'dynamic-pie.link.json')},
    'dynamic-non-pie': {'linkage': 'non-pie', 'executable': identity(work / 'dynamic-non-pie'),
                        'receipt': identity(work / 'dynamic-non-pie.crabc-link.json'), 'validated': identity(work / 'dynamic-non-pie.link.json')},
}
command_names = (
    'compile', 'oracle-link', 'oracle', 'static-link', 'static-validate', 'static-run',
    'static-pie-link', 'static-pie-validate', 'static-pie-run', 'dynamic-pie-link', 'dynamic-pie-validate',
    'dynamic-pie-kernel', 'dynamic-pie-direct', 'dynamic-non-pie-link', 'dynamic-non-pie-validate',
    'dynamic-non-pie-kernel', 'dynamic-non-pie-direct',
)
commands = {name: {suffix: identity(work / f'{name}.{suffix}')
                   for suffix in ('argv.json', 'stdout', 'stderr', 'status')}
            for name in command_names}
commands = {name: {'argv': value['argv.json'], 'stdout': value['stdout'],
                   'stderr': value['stderr'], 'status': value['status']}
            for name, value in commands.items()}
record = {
    'schema': 'crabc.x86_64-owned-pthread-family-composition/v1',
    'source': identity(source), 'workload': identity(work / 'workload.o'),
    'products': {'static': product(static), 'dynamic': product(dynamic)},
    'tools': {'before': identity(work / 'tools-before.json'),
              'after': identity(work / 'tools-after.json')},
    'oracle': {'compiler': identity(Path('/usr/local/bin/crabc-x86_64-musl-gcc')),
               'runtime': identity(Path('/opt/musl-1.2.6/lib/libc.so')),
               'pin': identity(Path('/opt/musl-1.2.6/.crabc-oracle'))},
    'commands': commands, 'links': links, 'raw': raw,
}
(work / 'composition.json').write_text(json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
PY
printf 'owned pthread family composition: PASS (one installed-header C11 object through supplied static ET_EXEC/static-PIE and dynamic PIE/non-PIE kernel/direct products; TLS, once, TSD, barrier, rwlock, and spin handshakes)\n'
