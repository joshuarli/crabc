#!/usr/bin/env bash
# One installed-header stdio composition object through pinned musl and owned products.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_stdio_probe.c"
readonly FOPEN64_C_PROBE="$ROOT/compat/x86_64/fopen64_header_abi_probe.c"
readonly FOPEN64_CXX_PROBE="$ROOT/compat/x86_64/fopen64_header_abi_probe.cpp"
readonly RUNNER="$ROOT/compat/x86_64/run_owned_stdio.sh"
readonly COPIES="$ROOT/compat/x86_64/owned_crypt_runtime_evidence.py"
readonly RECEIPT_READER="$ROOT/compat/x86_64/owned_stdio_component_receipt.py"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned stdio products: %s\n' "$*" >&2
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

# A component reader may live in an isolated worktree below the primary
# checkout's ignored .work tree.  Admit frozen sibling products only below
# that shared boundary; inspect every lexical component before realpath later
# resolves the product root.
def project_worktree(root):
    for ancestor in (root, *root.parents):
        if ancestor.name == '.work':
            return ancestor.parent / '.work'
    return root / '.work'

worktree = project_worktree(root)
items = [(temporary, 'TMPDIR')]
if str(static) != '.':
    items.append((static, 'static product'))
if str(dynamic) != '.':
    items.append((dynamic, 'dynamic product'))
for path, description in items:
    path = path.absolute()
    if '..' in path.parts or not path.is_relative_to(worktree):
        raise SystemExit(f'owned stdio products {description} must stay below checkout .work')
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.exists() and stat.S_ISLNK(current.lstat().st_mode):
            raise SystemExit(f'owned stdio products {description} traverses a symlink')
    if not path.is_dir():
        raise SystemExit(f'owned stdio products {description} is not a directory')
    if (path / '.git').exists():
        raise SystemExit(f'owned stdio products {description} must not name a checkout worktree')
PY

if [ -n "$provided_static" ]; then provided_static="$(realpath -e "$provided_static")"; fi
if [ -n "$provided_dynamic" ]; then provided_dynamic="$(realpath -e "$provided_dynamic")"; fi
[ -x "$ORACLE_CC" ] || fail 'missing pinned musl compiler'
[ -f "$PROBE" ] && [ -f "$FOPEN64_C_PROBE" ] && [ -f "$FOPEN64_CXX_PROBE" ] && [ -f "$RUNNER" ] &&
    [ -f "$COPIES" ] && [ -f "$RECEIPT_READER" ] ||
    fail 'missing owned stdio source, fopen64 header probes, runner, payload auditor, or receipt reader'
command -v chroot >/dev/null || fail 'missing chroot'
command -v timeout >/dev/null || fail 'missing timeout'

readonly WORK="$(mktemp -d "$TMPDIR/owned-stdio-products.XXXXXX")"
chmod a+rx "$WORK"
trap 'chmod -R a+rX "$WORK"' EXIT
printf 'owned stdio products evidence: %s\n' "$WORK"

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
    timeout 45 "$@" >"$WORK/$stem.stdout" 2>"$WORK/$stem.stderr"
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
        raise SystemExit(f'owned stdio tool is not a physical regular file: {path}')
    data = path.read_bytes()
    return {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data),
            'mode': stat.S_IMODE(path.stat().st_mode)}

helper = dynamic / 'share/crabc/crabc_cc_static.py'
if helper.is_symlink() or not helper.is_file():
    raise SystemExit('owned stdio dynamic compiler helper is not physical')
spec = importlib.util.spec_from_file_location('owned_stdio_tools', helper)
if spec is None or spec.loader is None:
    raise SystemExit('owned stdio cannot load dynamic compiler helper')
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
try:
    spec.loader.exec_module(module)
    record = {'oracle': identity(oracle), 'dynamic_driver': identity(dynamic / 'bin/crabc-cc-dynamic'),
              'compiler': identity(Path(module.compiler())), 'linker': identity(Path(module.linker()))}
    if static is not None:
        record['static_driver'] = identity(static / 'bin/crabc-cc')
finally:
    sys.modules.pop(spec.name, None)
output.write_text(json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
PY
}

capture_seal() {
    local point="$1"
    python3 -B - "$ROOT" "$PROBE" "$FOPEN64_C_PROBE" "$FOPEN64_CXX_PROBE" "$RUNNER" "$RECEIPT_READER" "$STATIC_PRODUCT" "$DYNAMIC_PRODUCT" "$WORK/$point.json" <<'PY'
import json
from pathlib import Path
import stat
import sys

root, source, fopen64_c, fopen64_cxx, runner, reader, static_text, dynamic, output = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / 'compat/x86_64'))
import owned_posix_family_execution as family
import owned_posix_product_evidence as products

def source_identity(path):
    path = path.resolve(strict=True)
    if path.is_symlink() or not path.is_file():
        raise SystemExit('owned stdio source is not physical')
    return {'path': path.relative_to(root).as_posix(), 'sha256': family.digest(path),
            'mode': stat.S_IMODE(path.stat().st_mode)}

def product_identity(path, kind):
    path = path.resolve(strict=True)
    manifest, _ = (products._validate_static_product(path) if kind == 'static'
                   else products._validate_dynamic_product(path))
    metadata = manifest.stat()
    return {'path': str(path),
            'manifest': {'path': str(manifest), 'sha256': family.digest(manifest), 'size': metadata.st_size},
            'tree': family.snapshot(path)}

record = {'sources': {'probe': source_identity(source), 'fopen64_c': source_identity(fopen64_c),
                      'fopen64_cxx': source_identity(fopen64_cxx), 'runner': source_identity(runner),
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
spec = importlib.util.spec_from_file_location('owned_stdio_compiler', helper)
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

fopen64_profile_arguments() {
    case "$1" in
        c11-base)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_FILE_OFFSET_BITS -U_LARGEFILE_SOURCE -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -DCRABC_FOPEN64_HEADER_C11_BASE
            ;;
        c11-gnu)
            printf '%s\0' -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_FILE_OFFSET_BITS \
                -U_LARGEFILE_SOURCE -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE -D_GNU_SOURCE \
                -DCRABC_FOPEN64_HEADER_C11_GNU
            ;;
        c11-file-offset-bits-64)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_LARGEFILE_SOURCE -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE -D_FILE_OFFSET_BITS=64 \
                -DCRABC_FOPEN64_HEADER_C11_FILE_OFFSET_BITS_64
            ;;
        c11-largefile-source)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_FILE_OFFSET_BITS -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE -D_LARGEFILE_SOURCE \
                -DCRABC_FOPEN64_HEADER_C11_LARGEFILE_SOURCE
            ;;
        c11-largefile64)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_FILE_OFFSET_BITS -U_LARGEFILE_SOURCE -U_DEFAULT_SOURCE -D_LARGEFILE64_SOURCE \
                -DCRABC_FOPEN64_HEADER_C11_LARGEFILE64
            ;;
        cxx17-base)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_FILE_OFFSET_BITS -U_LARGEFILE_SOURCE -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -DCRABC_FOPEN64_HEADER_CXX17_BASE
            ;;
        cxx17-gnu)
            printf '%s\0' -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_FILE_OFFSET_BITS \
                -U_LARGEFILE_SOURCE -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE -D_GNU_SOURCE \
                -DCRABC_FOPEN64_HEADER_CXX17_GNU
            ;;
        cxx17-file-offset-bits-64)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_LARGEFILE_SOURCE -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE -D_FILE_OFFSET_BITS=64 \
                -DCRABC_FOPEN64_HEADER_CXX17_FILE_OFFSET_BITS_64
            ;;
        cxx17-largefile-source)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_FILE_OFFSET_BITS -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE -D_LARGEFILE_SOURCE \
                -DCRABC_FOPEN64_HEADER_CXX17_LARGEFILE_SOURCE
            ;;
        cxx17-largefile64)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_FILE_OFFSET_BITS -U_LARGEFILE_SOURCE -U_DEFAULT_SOURCE -D_LARGEFILE64_SOURCE \
                -DCRABC_FOPEN64_HEADER_CXX17_LARGEFILE64
            ;;
        *) fail "unknown fopen64 header profile: $1" ;;
    esac
}

capture_fopen64_header_profile() {
    local tree="$1" profile="$2" compiler="$3" include="$4"
    local source object
    local -a language feature_args common

    mapfile -d '' -t feature_args < <(fopen64_profile_arguments "$profile")
    case "$profile" in
        c11-*)
            source="$FOPEN64_C_PROBE"
            language=(-x c -std=c11 -Werror=implicit-function-declaration)
            ;;
        cxx17-*)
            source="$FOPEN64_CXX_PROBE"
            language=(-x c++ -std=c++17 -nostdinc++)
            ;;
        *) fail "unknown fopen64 header profile language: $profile" ;;
    esac
    object="$WORK/fopen64-$tree-$profile.o"
    common=("${language[@]}" -nostdinc -isystem "$include" -H -fno-builtin "${feature_args[@]}")
    capture "fopen64-$tree-$profile-preprocess" "$compiler" "${common[@]}" -E "$source"
    capture "fopen64-$tree-$profile-compile" "$compiler" "${common[@]}" -c "$source" -o "$object"
}

compare_oracle() {
    local stem="$1"
    cmp "$WORK/oracle-run.stdout" "$WORK/$stem.stdout" || fail "$stem stdout differs from pinned musl"
    cmp "$WORK/oracle-run.stderr" "$WORK/$stem.stderr" || fail "$stem stderr differs from pinned musl"
    cmp "$WORK/oracle-run.status" "$WORK/$stem.status" || fail "$stem status differs from pinned musl"
}

capture_seal source-product-before
capture_tools "$WORK/tools-before.json"
readonly COMPILER="$(resolve_compiler)"
for profile in c11-base c11-gnu c11-file-offset-bits-64 c11-largefile-source c11-largefile64 \
    cxx17-base cxx17-gnu cxx17-file-offset-bits-64 cxx17-largefile-source cxx17-largefile64; do
    capture_fopen64_header_profile reference "$profile" "$ORACLE_CC" /opt/musl-1.2.6/include
    capture_fopen64_header_profile installed "$profile" "$COMPILER" "$DYNAMIC_PRODUCT/usr/include"
done
capture header-trace "$COMPILER" -nostdinc -isystem "$DYNAMIC_PRODUCT/usr/include" -D_LARGEFILE64_SOURCE=1 \
    -ffreestanding -fno-builtin -fno-stack-protector -std=c11 -fPIE -E -H "$PROBE"
for header in errno.h fcntl.h locale.h stdio.h unistd.h wchar.h features.h bits/alltypes.h; do
    grep -Fq "$DYNAMIC_PRODUCT/usr/include/$header" "$WORK/header-trace.stderr" ||
        fail "installed header trace omitted $header"
done
capture compile "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -D_POSIX_C_SOURCE=200809L \
    -D_LARGEFILE64_SOURCE=1 -fno-builtin -fno-stack-protector -c "$PROBE" -o "$WORK/workload.o"
sha256sum "$PROBE" "$FOPEN64_C_PROBE" "$FOPEN64_CXX_PROBE" "$RUNNER" "$WORK/workload.o" \
    >"$WORK/source-object-before.sha256"

capture oracle-link "$ORACLE_CC" -std=c11 -static -fno-pie -no-pie "$WORK/workload.o" -o "$WORK/oracle"
capture oracle-run env -i LC_ALL=C LANG=C TZ=UTC "$WORK/oracle" \
    "$WORK/oracle-first" "$WORK/oracle-second" "$WORK/oracle-wide"
[ "$(cat "$WORK/oracle-run.stdout")" = 'owned-stdio-products-ok' ] || fail 'pinned musl transcript differs'
[ ! -s "$WORK/oracle-run.stderr" ] || fail 'pinned musl emitted stderr'

if [ -n "$STATIC_PRODUCT" ]; then
    for mode in static static-pie; do
        receipt="$WORK/$mode.crabc-link.json"
        (
            cd "$WORK"
            capture "$mode-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$mode" --link-receipt \
                "$(basename "$receipt")" "$WORK/workload.o" -o "$WORK/$mode"
        )
        validate_link "$mode" "$STATIC_PRODUCT" "$WORK/workload.o" "$WORK/$mode" "$receipt" "$mode"
        capture "$mode-run" env -i LC_ALL=C LANG=C TZ=UTC "$WORK/$mode" \
            "$WORK/$mode-first" "$WORK/$mode-second" "$WORK/$mode-wide"
        compare_oracle "$mode-run"
    done
fi

for mode in pie non-pie; do
    executable="$WORK/dynamic-$mode"
    capture "dynamic-$mode-link" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        -std=c11 "$WORK/workload.o" -o "$executable"
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
    mkdir "$root/scratch"
    capture "dynamic-$mode-kernel" chroot "$root" /consumer \
        /scratch/first /scratch/second /scratch/wide
    compare_oracle "dynamic-$mode-kernel"
    capture "dynamic-$mode-direct" chroot "$root" "$INTERPRETER" /consumer \
        /scratch/first /scratch/second /scratch/wide
    compare_oracle "dynamic-$mode-direct"
    rmdir "$root/scratch"
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
import stat
import sys

root, work, static_text, dynamic, source = map(Path, sys.argv[1:])

def receipt_identity(path):
    data = path.read_bytes()
    path = path.resolve(strict=True)
    if path.is_symlink() or not path.is_file() or not path.is_relative_to(work):
        raise SystemExit(f'owned stdio retained artifact is not a physical work file: {path}')
    return {'path': path.relative_to(work).as_posix(), 'sha256': hashlib.sha256(data).hexdigest(),
            'size': len(data), 'mode': stat.S_IMODE(path.stat().st_mode)}

def source_identity(path):
    data = path.read_bytes()
    path = path.resolve(strict=True)
    if path.is_symlink() or not path.is_file() or not path.is_relative_to(root):
        raise SystemExit(f'owned stdio source is not a physical checkout file: {path}')
    return {'path': path.relative_to(root).as_posix(), 'sha256': hashlib.sha256(data).hexdigest(),
            'size': len(data), 'mode': stat.S_IMODE(path.stat().st_mode)}

commands = {}
for path in sorted(work.glob('*.argv.json')):
    stem = path.name.removesuffix('.argv.json')
    commands[stem] = {name: receipt_identity(work / f'{stem}.{suffix}')
                      for name, suffix in (('argv', 'argv.json'), ('stdout', 'stdout'),
                                           ('stderr', 'stderr'), ('status', 'status'))}
links = {name: receipt_identity(work / f'{name}.product-link.json') for name in
         ('static', 'static-pie', 'dynamic-pie', 'dynamic-non-pie')
         if (work / f'{name}.product-link.json').is_file()}
payloads = {name: {
    'record': receipt_identity(work / f'dynamic-{name}-execution-payload.json'),
    'before': receipt_identity(work / f'dynamic-{name}-copy-audit-before.stdout'),
    'after': receipt_identity(work / f'dynamic-{name}-copy-audit-after.stdout'),
} for name in ('pie', 'non-pie')}
record = {
    'schema': 'crabc.x86_64-owned-stdio-products/v3',
    'scope': ['stdio.path-stream', 'stdio.stream-io', 'stdio.position-buffering', 'stdio.format-scan',
              'stdio.fopen64-alias'],
    'rows': {'stdio.fopen64-alias': {
        'feature': '_LARGEFILE64_SOURCE=1', 'macro': 'fopen64', 'target': 'fopen',
        'pointer_equality': True, 'object_import': 'fopen',
        'header_profiles': {
            'c11-base': 'hidden', 'c11-gnu': 'hidden', 'c11-file-offset-bits-64': 'hidden',
            'c11-largefile-source': 'hidden', 'c11-largefile64': 'fopen',
            'cxx17-base': 'hidden', 'cxx17-gnu': 'hidden', 'cxx17-file-offset-bits-64': 'hidden',
            'cxx17-largefile-source': 'hidden', 'cxx17-largefile64': 'fopen',
        },
        'runtime_cells': ['dynamic-pie-kernel', 'dynamic-pie-direct',
                          'dynamic-non-pie-kernel', 'dynamic-non-pie-direct'] +
                         (['static', 'static-pie'] if str(static_text) != '.' else []),
    }},
    'source': source_identity(source), 'workload': receipt_identity(work / 'workload.o'),
    'products': {'dynamic': str(dynamic)},
    'seals': {name: receipt_identity(work / f'{name}.json') for name in
              ('source-product-before', 'source-product-after', 'tools-before', 'tools-after')},
    'object_seals': {name: receipt_identity(work / f'source-object-{name}.{suffix}') for name, suffix in
                     (('before', 'sha256'), ('after', 'txt'))},
    'commands': commands, 'links': links, 'execution_payloads': payloads,
    'family_completion': False, 'promotion_ready': False, 'public_support': False,
}
if str(static_text) != '.':
    record['products']['static'] = str(static_text)
(work / 'owned-stdio-products.json').write_text(
    json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
PY

if [ -n "$STATIC_PRODUCT" ]; then
    python3 -B "$RECEIPT_READER" "$WORK/owned-stdio-products.json" --checkout "$ROOT" --require-static
else
    python3 -B "$RECEIPT_READER" "$WORK/owned-stdio-products.json" --checkout "$ROOT"
fi

if [ -n "$STATIC_PRODUCT" ]; then
    printf 'owned stdio products: PASS (one selected-header object; pinned musl, static/static-PIE, dynamic PIE/non-PIE kernel/direct; selected path/stream, byte/wide I/O, positions, and byte format/scan only); evidence: %s\n' "$WORK"
else
    printf 'owned stdio products: PASS (one selected-header object; pinned musl and supplied dynamic PIE/non-PIE kernel/direct; selected path/stream, byte/wide I/O, positions, and byte format/scan only); evidence: %s\n' "$WORK"
fi
