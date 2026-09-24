#!/usr/bin/env bash
# One installed-header regex object through pinned musl and owned products.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_regex_probe.c"
readonly RUNNER="$ROOT/compat/x86_64/run_owned_regex.sh"
readonly RECEIPT_READER="$ROOT/compat/x86_64/owned_regex_component_receipt.py"
readonly COPIES="$ROOT/compat/x86_64/owned_crypt_runtime_evidence.py"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned regex products: %s\n' "$*" >&2
    exit 1
}

provided_static=''
provided_dynamic=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] && [ -z "$provided_static" ] && [ -n "$2" ] || usage
            provided_static="$2"
            shift 2
            ;;
        -*) usage ;;
        *)
            [ -z "$provided_dynamic" ] && [ -n "$1" ] || usage
            provided_dynamic="$1"
            shift
            ;;
    esac
done
[ -z "$provided_static" ] || [ -n "$provided_dynamic" ] || usage

[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -n "${TMPDIR:-}" ] || fail 'requires checkout-local TMPDIR'

python3 -B - "$ROOT" "$TMPDIR" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import os, stat, sys

root, temporary, static, dynamic = map(Path, sys.argv[1:])
root = root.resolve(strict=True)
items = [(temporary, 'TMPDIR')]
if str(static) != '.':
    items.append((static, 'static product'))
if str(dynamic) != '.':
    items.append((dynamic, 'dynamic product'))
for path, description in items:
    path = path.absolute()
    if '..' in path.parts or not path.is_relative_to(root / '.work'):
        raise SystemExit(f'owned regex products {description} must stay below checkout .work')
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.exists() and stat.S_ISLNK(current.lstat().st_mode):
            raise SystemExit(f'owned regex products {description} traverses a symlink')
    if not path.is_dir():
        raise SystemExit(f'owned regex products {description} is not a directory')
PY

if [ -n "$provided_static" ]; then provided_static="$(realpath -e "$provided_static")"; fi
if [ -n "$provided_dynamic" ]; then provided_dynamic="$(realpath -e "$provided_dynamic")"; fi
[ -x "$ORACLE_CC" ] || fail 'missing pinned musl compiler'
[ -x /usr/bin/nm ] && [ -x /usr/bin/readelf ] || fail 'missing pinned symbol readers'
[ -f "$PROBE" ] && [ -f "$RUNNER" ] && [ -f "$RECEIPT_READER" ] && [ -f "$COPIES" ] ||
    fail 'missing owned regex source, runner, receipt reader, or payload auditor'
command -v chroot >/dev/null || fail 'missing chroot'
command -v timeout >/dev/null || fail 'missing timeout'

readonly WORK="$(mktemp -d "$TMPDIR/owned-regex-products.XXXXXX")"
chmod a+rx "$WORK"
trap 'chmod -R a+rX "$WORK"' EXIT
printf 'owned regex products evidence: %s\n' "$WORK"

if [ -z "$provided_dynamic" ]; then
    provided_static="$WORK/static-product"
    provided_dynamic="$WORK/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$provided_static" \
        >"$WORK/static-build.json"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$provided_dynamic" \
        >"$WORK/dynamic-build.json"
fi
readonly STATIC_PRODUCT="$provided_static"
readonly DYNAMIC_PRODUCT="$provided_dynamic"
[ -x "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" ] || fail 'missing installed dynamic driver'
if [ -n "$STATIC_PRODUCT" ]; then
    [ -x "$STATIC_PRODUCT/bin/crabc-cc" ] || fail 'missing supplied static driver'
fi

capture() {
    local stem="$1"
    shift
    python3 -B - "$WORK/$stem.argv.json" "$@" <<'PY'
import json
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:], separators=(',', ':')) + '\n', encoding='utf-8')
PY
    local status
    set +e
    # The differential corpus executes millions of regexec calls per run;
    # keep generous headroom for a contended native host.
    timeout 300 "$@" >"$WORK/$stem.stdout" 2>"$WORK/$stem.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$WORK/$stem.status"
    [ "$status" -eq 0 ] || fail "$stem exited $status"
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

static_text, dynamic_text, oracle_text, output_text = sys.argv[1:]
static = Path(static_text) if static_text else None
dynamic, oracle, output = Path(dynamic_text), Path(oracle_text), Path(output_text)

def identity(path):
    path = path.resolve(strict=True)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise SystemExit(f'owned regex tool is not a physical regular file: {path}')
    data = path.read_bytes()
    return {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}

helper = dynamic / 'share/crabc/crabc_cc_static.py'
if helper.is_symlink() or not helper.is_file():
    raise SystemExit('owned regex dynamic compiler helper is not physical')
spec = importlib.util.spec_from_file_location('owned_regex_tools', helper)
if spec is None or spec.loader is None:
    raise SystemExit('owned regex cannot load dynamic compiler helper')
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
try:
    spec.loader.exec_module(module)
    record = {'oracle': identity(oracle), 'dynamic_driver': identity(dynamic / 'bin/crabc-cc-dynamic'),
              'compiler': identity(Path(module.compiler())), 'linker': identity(Path(module.linker(dynamic))),
              'nm': identity(Path('/usr/bin/nm')), 'readelf': identity(Path('/usr/bin/readelf')),
              'env': identity(Path('/usr/bin/env'))}
    if static is not None:
        record['static_driver'] = identity(static / 'bin/crabc-cc')
finally:
    sys.modules.pop(spec.name, None)
output.write_text(json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
PY
}

capture_seal() {
    local point="$1"
    python3 -B - "$ROOT" "$PROBE" "$RUNNER" "$RECEIPT_READER" "$STATIC_PRODUCT" "$DYNAMIC_PRODUCT" "$WORK/$point.json" <<'PY'
import json
from pathlib import Path
import stat
import sys

root, source, runner, reader, static_text, dynamic, output = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / 'compat/x86_64'))
import owned_posix_family_execution as family
import owned_posix_product_evidence as products

def source_identity(path):
    path = path.resolve(strict=True)
    if path.is_symlink() or not path.is_file():
        raise SystemExit('owned regex source is not physical')
    return {'path': path.relative_to(root).as_posix(), 'sha256': family.digest(path),
            'size': path.stat().st_size, 'mode': stat.S_IMODE(path.stat().st_mode)}

def product_identity(path, kind):
    path = path.resolve(strict=True)
    manifest, _ = (products._validate_static_product(path) if kind == 'static'
                   else products._validate_dynamic_product(path))
    return {'path': path.relative_to(root).as_posix(),
            'manifest': family.file_identity(root, manifest), 'tree': family.snapshot(path)}

record = {'sources': {'probe': source_identity(source), 'runner': source_identity(runner),
                      'reader': source_identity(reader)},
          'dynamic': product_identity(dynamic, 'dynamic')}
if str(static_text) != '.':
    record['static'] = product_identity(static_text, 'static')
output.write_text(json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
PY
}

validate_link() {
    local stem="$1" product="$2" workload="$3" executable="$4" receipt="$5" linkage="$6"
    capture "$stem-validate" python3 -B - "$ROOT" "$product" "$workload" "$executable" "$receipt" "$linkage" <<'PY'
import json
from pathlib import Path
import sys
root, product, workload, executable, receipt, linkage = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / 'compat/x86_64'))
from owned_posix_product_evidence import validate_link
print(json.dumps(validate_link(product, workload, executable, receipt, str(linkage)),
                 sort_keys=True, separators=(',', ':')))
PY
    cp "$WORK/$stem-validate.stdout" "$WORK/$stem.product-link.json"
}

resolve_compiler() {
    python3 -B - "$DYNAMIC_PRODUCT" <<'PY'
import importlib.util
from pathlib import Path
import sys
product = Path(sys.argv[1])
helper = product / 'share/crabc/crabc_cc_static.py'
spec = importlib.util.spec_from_file_location('owned_regex_compiler', helper)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
try:
    spec.loader.exec_module(module)
    print(Path(module.compiler()).resolve(strict=True))
finally:
    sys.modules.pop(spec.name, None)
PY
}

compare_oracle() {
    local stem="$1"
    cmp "$WORK/oracle-run.stdout" "$WORK/$stem.stdout" || fail "$stem stdout differs from pinned musl"
    cmp "$WORK/oracle-run.stderr" "$WORK/$stem.stderr" || fail "$stem stderr differs from pinned musl"
    cmp "$WORK/oracle-run.status" "$WORK/$stem.status" || fail "$stem status differs from pinned musl"
}

check_nm_api_rows() {
    local report="$1" kind="$2" description="$3"
    python3 -B - "$report" "$kind" "$description" <<'PY'
from pathlib import Path
import sys

report, kind, description = map(str, sys.argv[1:])
rows = [line.split() for line in Path(report).read_text(encoding='utf-8').splitlines()]
for name in ('regcomp', 'regexec', 'regerror', 'regfree'):
    matches = [row for row in rows if len(row) >= 2 and row[0] == name and row[1] == kind]
    if len(matches) != 1:
        raise SystemExit(f'{description} does not contain exactly one {kind} {name} row')
PY
}

check_dynamic_api_rows() {
    local report="$1"
    python3 -B - "$report" <<'PY'
from pathlib import Path
import sys

rows = [line.split() for line in Path(sys.argv[1]).read_text(encoding='utf-8').splitlines()]
for name in ('regcomp', 'regexec', 'regerror', 'regfree'):
    matches = [row for row in rows if len(row) == 8 and row[3:6] == ['FUNC', 'GLOBAL', 'DEFAULT'] and
               row[6] != 'UND' and row[7] == name]
    if len(matches) != 1:
        raise SystemExit(f'dynamic regex provider does not contain exactly one public {name} row')
PY
}

capture_tools "$WORK/tools-before.json"
capture_seal source-product-before
readonly COMPILER="$(resolve_compiler)"
capture header-trace "$COMPILER" -nostdinc -isystem "$DYNAMIC_PRODUCT/usr/include" \
    -ffreestanding -fno-builtin -std=c11 -fPIE -E -H "$PROBE"
for header in locale.h regex.h stddef.h stdio.h stdlib.h string.h features.h bits/alltypes.h; do
    grep -Fq "$DYNAMIC_PRODUCT/usr/include/$header" "$WORK/header-trace.stderr" ||
        fail "installed header trace omitted $header"
done
capture compile "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 \
    -fno-builtin -c "$PROBE" -o "$WORK/workload.o"
capture object-imports /usr/bin/env -i LC_ALL=C LANG=C TZ=UTC PATH=/usr/bin:/bin \
    /usr/bin/nm -g --undefined-only --format=posix "$WORK/workload.o"
check_nm_api_rows "$WORK/object-imports.stdout" U 'installed-header object imports'
sha256sum "$PROBE" "$RUNNER" "$RECEIPT_READER" "$WORK/workload.o" >"$WORK/source-object-before.sha256"

capture oracle-link "$ORACLE_CC" -static -fno-pie -no-pie "$WORK/workload.o" -o "$WORK/oracle"
capture oracle-providers /usr/bin/env -i LC_ALL=C LANG=C TZ=UTC PATH=/usr/bin:/bin \
    /usr/bin/nm -g --defined-only --format=posix "$WORK/oracle"
check_nm_api_rows "$WORK/oracle-providers.stdout" T 'pinned musl provider'
capture oracle-run env -i LC_ALL=C LANG=C TZ=UTC "$WORK/oracle"
# The probe checks its directed contracts itself and prints the completion
# line last; the differential corpus is judged by the byte comparisons below.
[ "$(tail -n 1 "$WORK/oracle-run.stdout")" = owned-regex-installed-header-ok ] ||
    fail 'pinned musl transcript is incomplete'
[ ! -s "$WORK/oracle-run.stderr" ] || fail 'pinned musl emitted stderr'

if [ -n "$STATIC_PRODUCT" ]; then
    capture static-archive-providers /usr/bin/env -i LC_ALL=C LANG=C TZ=UTC PATH=/usr/bin:/bin \
        /usr/bin/nm -g --defined-only --format=posix "$STATIC_PRODUCT/usr/lib/libc.a"
    check_nm_api_rows "$WORK/static-archive-providers.stdout" T 'static archive provider'
    for mode in static static-pie; do
        receipt="$WORK/$mode.crabc-link.json"
        (
            cd "$WORK"
            capture "$mode-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$mode" --link-receipt \
                "$(basename "$receipt")" "$WORK/workload.o" -o "$WORK/$mode"
        )
        validate_link "$mode" "$STATIC_PRODUCT" "$WORK/workload.o" "$WORK/$mode" "$receipt" "$mode"
        capture "$mode-run" env -i LC_ALL=C LANG=C TZ=UTC "$WORK/$mode"
        compare_oracle "$mode-run"
        capture "$mode-providers" /usr/bin/env -i LC_ALL=C LANG=C TZ=UTC PATH=/usr/bin:/bin \
            /usr/bin/nm -g --defined-only --format=posix "$WORK/$mode"
        check_nm_api_rows "$WORK/$mode-providers.stdout" T "$mode provider"
    done
fi

capture dynamic-providers /usr/bin/env -i LC_ALL=C LANG=C TZ=UTC PATH=/usr/bin:/bin \
    /usr/bin/readelf --dyn-syms --wide "$DYNAMIC_PRODUCT/usr/lib/libc.so"
check_dynamic_api_rows "$WORK/dynamic-providers.stdout"
for mode in pie non-pie; do
    executable="$WORK/dynamic-$mode"
    capture "dynamic-$mode-link" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        "$WORK/workload.o" -o "$executable"
    validate_link "dynamic-$mode" "$DYNAMIC_PRODUCT" "$WORK/workload.o" "$executable" \
        "$executable.crabc-link.json" "$mode"
    root="$WORK/dynamic-$mode-root"
    mkdir "$root"
    cp -a "$DYNAMIC_PRODUCT/." "$root"
    cp "$executable" "$root/consumer"
    capture "dynamic-$mode-copy-before" python3 -B "$COPIES" record \
        --product "$DYNAMIC_PRODUCT" --execution-root "$root" \
        --source-consumer "$executable" --execution-consumer "$root/consumer" \
        --record "$WORK/dynamic-$mode-execution-payload.json"
    capture "dynamic-$mode-copy-audit-before" python3 -B "$COPIES" audit \
        --product "$DYNAMIC_PRODUCT" --execution-root "$root" \
        --source-consumer "$executable" --execution-consumer "$root/consumer" \
        --record "$WORK/dynamic-$mode-execution-payload.json"
    capture "dynamic-$mode-kernel" chroot "$root" /consumer
    compare_oracle "dynamic-$mode-kernel"
    capture "dynamic-$mode-direct" chroot "$root" "$INTERPRETER" /consumer
    compare_oracle "dynamic-$mode-direct"
    capture "dynamic-$mode-copy-audit-after" python3 -B "$COPIES" audit \
        --product "$DYNAMIC_PRODUCT" --execution-root "$root" \
        --source-consumer "$executable" --execution-consumer "$root/consumer" \
        --record "$WORK/dynamic-$mode-execution-payload.json"
done

capture_tools "$WORK/tools-after.json"
cmp "$WORK/tools-before.json" "$WORK/tools-after.json" || fail 'compiler/linker tool roster changed'
capture_seal source-product-after
cmp "$WORK/source-product-before.json" "$WORK/source-product-after.json" ||
    fail 'source or supplied product changed during execution'
sha256sum -c "$WORK/source-object-before.sha256" >"$WORK/source-object-after.txt" ||
    fail 'source or installed-header object changed during execution'

python3 -B - "$ROOT" "$WORK" "$STATIC_PRODUCT" "$DYNAMIC_PRODUCT" "$PROBE" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

root, work, static_text, dynamic, source = map(Path, sys.argv[1:])

def identity(path):
    data = path.read_bytes()
    try:
        name = path.relative_to(root).as_posix()
    except ValueError:
        name = str(path)
    return {'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}

commands = {}
for path in sorted(work.glob('*.argv.json')):
    stem = path.name.removesuffix('.argv.json')
    commands[stem] = {name: identity(work / f'{stem}.{suffix}')
                      for name, suffix in (('argv', 'argv.json'), ('stdout', 'stdout'),
                                           ('stderr', 'stderr'), ('status', 'status'))}
links = {name: identity(work / f'{name}.product-link.json') for name in
         ('static', 'static-pie', 'dynamic-pie', 'dynamic-non-pie')
         if (work / f'{name}.product-link.json').is_file()}
payloads = {name: {
    'record': identity(work / f'dynamic-{name}-execution-payload.json'),
    'before': identity(work / f'dynamic-{name}-copy-audit-before.stdout'),
    'after': identity(work / f'dynamic-{name}-copy-audit-after.stdout'),
} for name in ('pie', 'non-pie')}
record = {
    'schema': 'crabc.x86_64-owned-regex-products/v2',
    'source_mount': '/workspace',
    'execution_mode': ('full-six-mode' if str(static_text) != '.' else
                       'dynamic-only-four-cell-development'),
    'scope': ['pattern.regex'],
    'sources': json.loads((work / 'source-product-before.json').read_text(encoding='utf-8'))['sources'],
    'workload': identity(work / 'workload.o'),
    'products': {'dynamic': dynamic.relative_to(root).as_posix()},
    'seals': {name: identity(work / f'{name}.json') for name in
              ('source-product-before', 'source-product-after', 'tools-before', 'tools-after')},
    'commands': commands, 'links': links, 'execution_payloads': payloads,
    'source_object_checks': {'before': identity(work / 'source-object-before.sha256'),
                             'after': identity(work / 'source-object-after.txt')},
    'family_completion': False, 'promotion_ready': False, 'public_support': False,
}
if str(static_text) != '.':
    record['products']['static'] = static_text.relative_to(root).as_posix()
(work / 'owned-regex-products.json').write_text(
    json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
PY

python3 -B "$RECEIPT_READER" validate-report --root "$ROOT" \
    --report "$WORK/owned-regex-products.json"

if [ -n "$STATIC_PRODUCT" ]; then
    printf 'owned regex products: PASS (one selected-header object; pinned musl, static/static-PIE, dynamic PIE/non-PIE kernel/direct; selected installed regex interface and behavior only); evidence: %s\n' "$WORK"
else
    printf 'owned regex products: PASS (development-only dynamic replay; one selected-header object; pinned musl and supplied dynamic PIE/non-PIE kernel/direct; selected installed regex interface and behavior only); evidence: %s\n' "$WORK"
fi
