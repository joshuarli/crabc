#!/usr/bin/env bash
# Installed C ABI differential for four complete, fixed math/fenv surfaces.
#
# This runner deliberately reuses the existing musl-backed probe observations.
# Its contribution is one ordered installed-header object set, retained links,
# and the six supplied-product entry modes. It does not claim general libm or
# family-90 completion.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1
readonly COPIES="$ROOT/compat/x86_64/owned_crypt_runtime_evidence.py"
readonly VALIDATOR="$ROOT/compat/x86_64/validate_owned_math_fenv_all_entry.py"
readonly CONTRACT="$ROOT/compat/x86_64/owned_math_fenv_all_entry_contract.py"
readonly PROVIDER_EVIDENCE="$ROOT/compat/x86_64/owned_math_fenv_all_entry_evidence.py"
readonly COVERAGE="$ROOT/compat/crabc-rs/coverage.toml"
readonly COMPLEX_BASELINE="$ROOT/compat/x86_64/validate_parity_ledger.py"
readonly RUNNER="$ROOT/compat/x86_64/run_owned_math_fenv_all_entry.sh"
readonly DRIVER="$ROOT/compat/x86_64/owned_math_fenv_all_entry_driver.c"

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned math/fenv all-entry: %s\n' "$*" >&2
    exit 1
}

provided_static=''
provided_dynamic=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] && [ -z "$provided_static" ] && [ -n "$2" ] && [[ "$2" != -* ]] || usage
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
[ -n "$provided_dynamic" ] || usage

[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] || fail 'requires checkout-local TMPDIR'

# Reject lexical parent traversal and symlink hops before creating evidence.
python3 -B - "$ROOT" "$TMPDIR" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import stat
import sys

root, temporary, static, dynamic = map(Path, sys.argv[1:])
root = root.resolve(strict=True)
items = [(temporary, 'TMPDIR'), (dynamic, 'dynamic product')]
if str(static) != '.':
    items.append((static, 'static product'))
for path, description in items:
    path = path.absolute()
    if '..' in path.parts or not path.is_relative_to(root / '.work'):
        raise SystemExit(f'owned math/fenv all-entry {description} must stay below checkout .work')
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.exists() and stat.S_ISLNK(current.lstat().st_mode):
            raise SystemExit(f'owned math/fenv all-entry {description} traverses a symlink')
    if not path.is_dir():
        raise SystemExit(f'owned math/fenv all-entry {description} is not a directory')
PY

provided_dynamic="$(realpath -e -- "$provided_dynamic")"
if [ -n "$provided_static" ]; then
    provided_static="$(realpath -e -- "$provided_static")"
fi

for tool in cmp cp mkdir mktemp nm python3 readelf realpath sha256sum timeout chroot; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail 'missing pinned musl oracle compiler'
for path in "$COPIES" "$VALIDATOR" "$CONTRACT" "$PROVIDER_EVIDENCE" "$COVERAGE" \
    "$COMPLEX_BASELINE" "$RUNNER" "$DRIVER"; do
    [ -f "$path" ] || fail "missing retained component input: $path"
done

readonly STATIC_PRODUCT="$provided_static"
readonly DYNAMIC_PRODUCT="$provided_dynamic"
[ -x "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" ] || fail 'missing supplied dynamic driver'
if [ -n "$STATIC_PRODUCT" ]; then
    [ -x "$STATIC_PRODUCT/bin/crabc-cc" ] || fail 'missing supplied static driver'
fi

readonly WORK="$(mktemp -d "$TMPDIR/owned-math-fenv-all-entry.XXXXXX")"
chmod a+rx "$WORK"
trap 'chmod -R a+rX "$WORK"' EXIT
printf 'owned math/fenv all-entry evidence: %s\n' "$WORK"

readonly -a ROLE_SOURCES=(
    'driver|compat/x86_64/owned_math_fenv_all_entry_driver.c|'
    'elementary-long-double|compat/x86_64/libc_math_elementary_long_double_probe.c|CRABC_MATH_ELEMENTARY_LONG_DOUBLE_FREESTANDING'
    'fenv-sensitive-aggregate|compat/x86_64/libc_math_elementary_fenv_sensitive_aggregate_probe.c|'
    'fenv-rounding|compat/x86_64/libc_fenv_rounding_probe.c|CRABC_FENV_ROUNDING_FREESTANDING'
    'fdim|compat/x86_64/libc_fdim_probe.c|CRABC_FDIM_FREESTANDING'
    'exp10|compat/x86_64/libc_math_exp10_probe.c|CRABC_MATH_EXP10_FREESTANDING'
    'exp10f|compat/x86_64/libc_math_exp10f_probe.c|CRABC_MATH_EXP10F_FREESTANDING'
    'long-double-completion|compat/x86_64/libc_math_long_double_completion_probe.c|CRABC_MATH_LONG_DOUBLE_COMPLETION_FREESTANDING'
    'special|compat/x86_64/libc_math_special_probe.c|CRABC_MATH_SPECIAL_FREESTANDING'
    'complex|compat/x86_64/libc_math_complex_complete_probe.c|CRABC_MATH_COMPLEX_COMPLETE_FREESTANDING'
)

declare -a SOURCES=() OBJECTS=()
for entry in "${ROLE_SOURCES[@]}"; do
    IFS='|' read -r role relative define <<<"$entry"
    SOURCES+=("$ROOT/$relative")
    OBJECTS+=("$WORK/$role.o")
done
SOURCES+=("$RUNNER" "$VALIDATOR" "$CONTRACT" "$PROVIDER_EVIDENCE" "$COPIES" "$COVERAGE" \
    "$COMPLEX_BASELINE")

capture() {
    local stem="$1" status=0
    shift
    python3 -B - "$WORK/$stem.argv.json" "$@" <<'PY'
import json
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:], separators=(',', ':')) + '\n', encoding='utf-8')
PY
    set +e
    timeout 120 "$@" >"$WORK/$stem.stdout" 2>"$WORK/$stem.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$WORK/$stem.status"
    [ "$status" -eq 0 ] || fail "$stem exited $status"
}

resolve_tool() {
    local attribute="$1"
    python3 -B - "$DYNAMIC_PRODUCT" "$attribute" <<'PY'
import importlib.util
from pathlib import Path
import sys
product, attribute = map(Path, sys.argv[1:])
helper = product / 'share/crabc/crabc_cc_static.py'
spec = importlib.util.spec_from_file_location('owned_math_fenv_all_entry_tool', helper)
if spec is None or spec.loader is None:
    raise SystemExit('cannot load supplied compiler helper')
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
try:
    spec.loader.exec_module(module)
    print(Path(getattr(module, str(attribute))()).resolve(strict=True))
finally:
    sys.modules.pop(spec.name, None)
PY
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
    if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
        raise SystemExit(f'owned math/fenv all-entry tool is not physical: {path}')
    data = path.read_bytes()
    return {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}

helper = dynamic / 'share/crabc/crabc_cc_static.py'
spec = importlib.util.spec_from_file_location('owned_math_fenv_all_entry_tools', helper)
if spec is None or spec.loader is None:
    raise SystemExit('cannot load supplied compiler helper')
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
try:
    spec.loader.exec_module(module)
    record = {'oracle': identity(oracle), 'dynamic_driver': identity(dynamic / 'bin/crabc-cc-dynamic'),
              'compiler': identity(Path(module.compiler())), 'linker': identity(Path(module.linker(dynamic)))}
    if static is not None:
        record['static_driver'] = identity(static / 'bin/crabc-cc')
finally:
    sys.modules.pop(spec.name, None)
output.write_text(json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
PY
}

capture_seal() {
    local point="$1"
    python3 -B - "$ROOT" "$STATIC_PRODUCT" "$DYNAMIC_PRODUCT" "$WORK/$point.json" "${SOURCES[@]}" <<'PY'
import json
from pathlib import Path
import stat
import sys

root, static_text, dynamic_text, output_text, *sources = sys.argv[1:]
root, dynamic, output = map(Path, (root, dynamic_text, output_text))
static = Path(static_text) if static_text else None
sys.path.insert(0, str(root / 'compat/x86_64'))
import owned_posix_family_execution as family
import owned_posix_product_evidence as products

def identity(path):
    path = path.resolve(strict=True)
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f'owned math/fenv all-entry source is not physical: {path}')
    return {'path': path.relative_to(root).as_posix(), 'sha256': family.digest(path),
            'mode': stat.S_IMODE(path.stat().st_mode)}

def product_identity(path, kind):
    path = path.resolve(strict=True)
    manifest, _ = (products._validate_static_product(path) if kind == 'static'
                   else products._validate_dynamic_product(path))
    return {'path': path.relative_to(root).as_posix(),
            'manifest': family.file_identity(root, manifest), 'tree': family.snapshot(path)}

record = {'sources': {Path(path).name: identity(Path(path)) for path in sources},
          'dynamic': product_identity(dynamic, 'dynamic')}
if static is not None:
    record['static'] = product_identity(static, 'static')
output.write_text(json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
PY
}

validate_link() {
    local stem="$1" product="$2" executable="$3" receipt="$4" linkage="$5"
    capture "$stem-validate" python3 -B - "$ROOT" "$product" "$WORK/workload.o" \
        "$executable" "$receipt" "$linkage" <<'PY'
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

validate_records() {
    local stem="$1"
    python3 -B "$VALIDATOR" "$WORK/$stem.stdout" || fail "$stem emitted an invalid framed record stream"
    [ ! -s "$WORK/$stem.stderr" ] || fail "$stem wrote stderr"
}

compare_oracle() {
    local stem="$1"
    validate_records "$stem"
    cmp "$WORK/oracle-run.stdout" "$WORK/$stem.stdout" || fail "$stem stdout differs from pinned musl"
    cmp "$WORK/oracle-run.stderr" "$WORK/$stem.stderr" || fail "$stem stderr differs from pinned musl"
    cmp "$WORK/oracle-run.status" "$WORK/$stem.status" || fail "$stem status differs from pinned musl"
}

capture_tools "$WORK/tools-before.json"
capture_seal source-product-before
readonly COMPILER="$(resolve_tool compiler)"
readonly LINKER="$(resolve_tool linker)"

for entry in "${ROLE_SOURCES[@]}"; do
    IFS='|' read -r role relative define <<<"$entry"
    # The sealed application driver deliberately admits translation but not
    # ``-E``. Replay its compiler invocation directly only for the retained
    # header trace, with the same clean environment, installed include root,
    # translation flags, and dynamic-PIE mode that ``crabc-cc-dynamic`` uses.
    # ``tools-before.json`` binds this resolved fixed-image compiler.
    arguments=(env -i LC_ALL=C PATH=/usr/bin:/bin SOURCE_DATE_EPOCH=1 TZ=UTC "$COMPILER"
        -nostdinc -isystem "$DYNAMIC_PRODUCT/usr/include" -ffreestanding -fno-builtin
        -fstack-protector-strong -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector)
    if [ -n "$define" ]; then arguments+=("-D$define"); fi
    arguments+=(-frounding-math -fPIE -E -H "$ROOT/$relative")
    capture "header-$role" "${arguments[@]}"
done
for header in complex.h fenv.h float.h math.h stddef.h stdint.h unistd.h features.h bits/alltypes.h; do
    grep -Fq "$DYNAMIC_PRODUCT/usr/include/$header" "$WORK"/header-*.stderr ||
        fail "installed header traces omitted $header"
done

for entry in "${ROLE_SOURCES[@]}"; do
    IFS='|' read -r role relative define <<<"$entry"
    arguments=(--dynamic-pie -std=c11 -D_GNU_SOURCE -fno-builtin -frounding-math -fno-stack-protector)
    if [ -n "$define" ]; then arguments+=("-D$define"); fi
    arguments+=(-c "$ROOT/$relative" -o "$WORK/$role.o")
    capture "compile-$role" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "${arguments[@]}"
done
capture combine "$LINKER" -r -o "$WORK/workload.o" "${OBJECTS[@]}"
sha256sum "${SOURCES[@]}" "${OBJECTS[@]}" "$WORK/workload.o" >"$WORK/source-objects-before.sha256"

capture workload-imports nm --undefined-only --format=posix "$WORK/workload.o"
capture dynamic-provider-symbols readelf --dyn-syms -W "$DYNAMIC_PRODUCT/usr/lib/libc.so"
provider_arguments=(python3 -B "$PROVIDER_EVIDENCE" --root "$ROOT" --work "$WORK" \
    --dynamic-product "$DYNAMIC_PRODUCT" --imports "$WORK/workload-imports.stdout" \
    --dynamic-definitions "$WORK/dynamic-provider-symbols.stdout")
if [ -n "$STATIC_PRODUCT" ]; then
    capture static-provider-symbols nm -A -g --defined-only --format=posix \
        "$STATIC_PRODUCT/usr/lib/libc.a"
    provider_arguments+=(--static-definitions "$WORK/static-provider-symbols.stdout")
fi
capture component-preflight "${provider_arguments[@]}"

capture oracle-link "$ORACLE_CC" -std=c11 -static -fno-pie -no-pie "$WORK/workload.o" -lm -o "$WORK/oracle"
capture oracle-run env -i LC_ALL=C LANG=C TZ=UTC "$WORK/oracle"
validate_records oracle-run

if [ -n "$STATIC_PRODUCT" ]; then
    for mode in static static-pie; do
        receipt="$WORK/$mode.crabc-link.json"
        (
            cd "$WORK"
            capture "$mode-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$mode" --link-receipt \
                "$(basename "$receipt")" "$WORK/workload.o" -o "$WORK/$mode"
        )
        validate_link "$mode" "$STATIC_PRODUCT" "$WORK/$mode" "$receipt" "$mode"
        capture "$mode-run" env -i LC_ALL=C LANG=C TZ=UTC "$WORK/$mode"
        compare_oracle "$mode-run"
    done
fi

for mode in pie non-pie; do
    executable="$WORK/dynamic-$mode"
    capture "dynamic-$mode-link" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        "$WORK/workload.o" -o "$executable"
    validate_link "dynamic-$mode" "$DYNAMIC_PRODUCT" "$executable" \
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
sha256sum -c "$WORK/source-objects-before.sha256" >"$WORK/source-objects-after.txt" ||
    fail 'source or installed-header objects changed during execution'
capture component-collector "${provider_arguments[@]}"
cmp "$WORK/component-preflight.stdout" "$WORK/component-collector.stdout" ||
    fail 'component provider/import collector changed during execution'

python3 -B - "$ROOT" "$WORK" "$STATIC_PRODUCT" "$DYNAMIC_PRODUCT" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

root, work, static_text, dynamic = map(Path, sys.argv[1:])

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
objects = {path.stem: identity(path) for path in sorted(work.glob('*.o'))}
record = {
    'schema': 'crabc.x86_64-owned-math-fenv-all-entry/v1',
    'scope': ['math.elementary-long-double', 'math.elementary-fenv-sensitive',
              'math.special', 'math.complex'],
    'source_objects': objects,
    'products': {'dynamic': dynamic.relative_to(root).as_posix()},
    'seals': {name: identity(work / f'{name}.json') for name in
              ('source-product-before', 'source-product-after', 'tools-before', 'tools-after')},
    'provider_evidence': identity(work / 'component-collector.stdout'),
    'commands': commands, 'links': links, 'execution_payloads': payloads,
    'family_completion': False, 'promotion_ready': False, 'public_support': False,
}
if str(static_text) != '.':
    record['products']['static'] = static_text.relative_to(root).as_posix()
(work / 'owned-math-fenv-all-entry.json').write_text(
    json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
PY

if [ -n "$STATIC_PRODUCT" ]; then
    printf 'owned math/fenv all-entry: PASS (206 selected C ABI entries; pinned musl; static/static-PIE; dynamic PIE/non-PIE kernel/direct; bounded installed-product component only) evidence: %s\n' "$WORK"
else
    printf 'owned math/fenv all-entry: PASS (206 selected C ABI entries; pinned musl; dynamic PIE/non-PIE kernel/direct; bounded installed-product component only) evidence: %s\n' "$WORK"
fi
