#!/usr/bin/env bash
# Complete installed-header utmpx behavior against pinned musl 1.2.6.
#
# One C object compiled through the installed dynamic driver is linked by the
# pinned musl oracle and every selected owned product mode. Probe output
# retains raw stdout, stderr, and process status before its
# exact stream comparison is accepted.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_utmpx_probe.c"
readonly header_c="$ROOT/compat/x86_64/owned_utmpx_header_abi_probe.c"
readonly header_cxx="$ROOT/compat/x86_64/owned_utmpx_header_abi_probe.cpp"
readonly interpreter=/lib/ld-crabc-x86_64.so.1
declare -a link_identity_records=()

# Receipt collection opts in to command retention. Ordinary focused runs keep
# their disposable evidence lifecycle unchanged; a supplied value may not
# silently widen that boundary.
retain_commands="${CRABC_X86_64_RETAIN_UTMPX_COMMANDS:-}"
case "$retain_commands" in
    ''|1) ;;
    *) printf 'owned utmpx: CRABC_X86_64_RETAIN_UTMPX_COMMANDS must be unset or 1\n' >&2; exit 2 ;;
esac
if [ "$retain_commands" = 1 ]; then
    # Collection fixes this three-entry execution environment before the
    # trusted runner starts.  The record below captures the command child
    # environment after removing every inherited variable, including a
    # caller-supplied PATH that could otherwise redirect a bare utility.
    readonly retained_command_path='/opt/cargo/bin:/opt/musl-1.2.6/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    readonly retained_command_tmpdir="$ROOT/.work/utmpx-receipt"
    if [ "${PATH:-}" != "$retained_command_path" ] || [ "${TMPDIR:-}" != "$retained_command_tmpdir" ]; then
        printf 'owned utmpx: retained command collection requires the fixed native environment\n' >&2
        exit 2
    fi
fi

run_retained_command() (
    # An exported shell function, locale variable, loader path, or tool
    # override must not reach a command just because it reached collection.
    # Bash creates the final ``_`` entry from the resolved program; the record
    # seals that deterministic entry along with this explicit environment.
    local name
    for name in $(compgen -e); do
        unset "$name" 2>/dev/null || :
    done
    export PATH="$retained_command_path"
    export TMPDIR="$retained_command_tmpdir"
    export CRABC_X86_64_RETAIN_UTMPX_COMMANDS=1
    export SHLVL=0
    "$@"
)

record_command() {
    local role="$1" status program record stdin
    shift
    if [ "$retain_commands" != 1 ]; then
        "$@"
        return
    fi
    case "$role" in *[!a-z0-9-]*|'') fail "invalid retained command role: $role" ;; esac
    record="$work/commands/$role.json"
    [ ! -e "$record" ] && [ ! -L "$record" ] || fail "duplicate retained command role: $role"
    program="$(type -P -- "$1" || true)"
    [ -n "$program" ] || fail "retained command has no external program: $1"
    if run_retained_command "$@"; then status=0; else status=$?; fi
    stdin="$work/commands/$role.stdin"
    python3 -B - "$record" "$ROOT" "$role" "$PWD" "$status" "$program" "$retained_command_path" "$retained_command_tmpdir" "$stdin" "$@" <<'PYCMD'
import hashlib
import json
from pathlib import Path
import stat
import sys

record, root, role, cwd, status, program, command_path, command_tmpdir, stdin, *argv = sys.argv[1:]
root_path = Path(root)
stdin_path = Path(stdin)
if stdin_path.exists():
    state = stdin_path.lstat()
    if not stat.S_ISREG(state.st_mode):
        raise SystemExit(f'owned-utmpx retained stdin is not a regular file: {stdin}')
    stdin_identity = {
        'path': stdin_path.relative_to(root_path).as_posix(),
        'sha256': hashlib.sha256(stdin_path.read_bytes()).hexdigest(),
        'size': state.st_size,
        'mode': stat.S_IMODE(state.st_mode),
    }
else:
    stdin_identity = None
Path(record).parent.mkdir(mode=0o755, exist_ok=True)
Path(record).write_text(json.dumps({
    'schema': 'crabc.x86_64-owned-utmpx-command/v2',
    'role': role,
    'cwd': cwd,
    'status': int(status),
    'program': program,
    'argv': argv,
    'env': {
        'PATH': command_path,
        'TMPDIR': command_tmpdir,
        'CRABC_X86_64_RETAIN_UTMPX_COMMANDS': '1',
        'SHLVL': '0',
        '_': program,
    },
    'stdin': stdin_identity,
}, indent=2, sort_keys=True) + '\n', encoding='utf-8')
PYCMD
    return "$status"
}

record_stdin_command() {
    local role="$1" stdin
    shift
    if [ "$retain_commands" != 1 ]; then
        record_command "$role" "$@"
        return
    fi
    stdin="$work/commands/$role.stdin"
    [ -d "$work/commands" ] || fail "retained command directory is missing: $role"
    [ ! -e "$stdin" ] && [ ! -L "$stdin" ] || fail "duplicate retained command stdin: $role"
    local -a lines=()
    mapfile -t lines
    ( umask 022; printf '%s\n' "${lines[@]}" >"$stdin" )
    record_command "$role" "$@" <"$stdin"
}

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned utmpx: %s\n' "$*" >&2
    exit 1
}

provided_static=''
provided_dynamic=''
static_was_supplied=0
dynamic_was_supplied=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] || usage
            [ "$static_was_supplied" -eq 0 ] || usage
            [ -n "$2" ] || usage
            case "$2" in -*) usage ;; esac
            provided_static="$2"
            static_was_supplied=1
            shift 2
            ;;
        -*|'')
            usage
            ;;
        *)
            [ "$dynamic_was_supplied" -eq 0 ] || usage
            provided_dynamic="$1"
            dynamic_was_supplied=1
            shift
            ;;
    esac
done
# Check each supplied raw path lexically before realpath can erase a symlink
# component. Relative paths are made absolute without resolving links; every
# component must remain a physical checkout path.
python3 -B - "$ROOT" "$provided_static" "$provided_dynamic" <<'PY'
import os
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
for raw, name in ((sys.argv[2], 'static'), (sys.argv[3], 'dynamic')):
    if not raw:
        continue
    lexical = Path(os.path.abspath(raw))
    if not lexical.is_relative_to(root / '.work'):
        raise SystemExit(f'owned-utmpx {name} product must be a checkout .work directory')
    cursor = root
    for component in lexical.relative_to(root).parts:
        cursor /= component
        if cursor.is_symlink():
            raise SystemExit(f'owned-utmpx {name} product must be a checkout .work directory')
PY
if [ "$static_was_supplied" -eq 1 ]; then
    provided_static="$(realpath "$provided_static")"
fi
if [ "$dynamic_was_supplied" -eq 1 ]; then
    provided_dynamic="$(realpath "$provided_dynamic")"
fi
if [ "$static_was_supplied" -eq 1 ] && [ "$dynamic_was_supplied" -eq 1 ] &&
        [ "$provided_static" = "$provided_dynamic" ]; then
    usage
fi

# Supplied paths must name contained physical products before this runner makes
# its disposable evidence directory. The shared validator below separately
# checks each product payload again while binding every output receipt.
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
temporary = Path(sys.argv[2])
static_product = Path(sys.argv[3]) if sys.argv[3] else None
dynamic_product = Path(sys.argv[4]) if sys.argv[4] else None
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned-utmpx TMPDIR must be a physical checkout .work directory')
for product, name in ((static_product, 'static'), (dynamic_product, 'dynamic')):
    if product and (not product.is_dir() or product.resolve() != product or not product.is_relative_to(root / '.work')):
        raise SystemExit(f'owned-utmpx {name} product must be a checkout .work directory')
PY

validate_product_payload() {
    local product="$1" family="$2"

    python3 -B - "$ROOT" "$product" "$family" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
product = Path(sys.argv[2])
family = sys.argv[3]
sys.path.insert(0, str(root / 'compat/x86_64'))
from owned_posix_product_evidence import (
    ProductEvidenceError,
    _validate_dynamic_product,
    _validate_static_product,
)

try:
    if family == 'static':
        _validate_static_product(product)
    elif family == 'dynamic':
        _validate_dynamic_product(product)
    else:
        raise SystemExit(f'owned-utmpx has an unknown product family: {family}')
except ProductEvidenceError as error:
    raise SystemExit(f'owned-utmpx {family} product payload is invalid: {error}') from error
PY
}

if [ "$static_was_supplied" -eq 1 ]; then
    validate_product_payload "$provided_static" static
fi
if [ "$dynamic_was_supplied" -eq 1 ]; then
    validate_product_payload "$provided_dynamic" dynamic
fi

if [ "$retain_commands" = 1 ]; then
    # A closed receipt needs stable /workspace spellings for every input that
    # a sealed link names.  This private leaf is only used by the opted-in
    # collector; ordinary runner evidence remains uniquely disposable.
    readonly work="$TMPDIR/owned-utmpx-receipt"
    [ ! -e "$work" ] && [ ! -L "$work" ] || fail "retained evidence leaf already exists"
    mkdir -m 755 "$work"
else
    readonly work="$(mktemp -d "$TMPDIR/owned-utmpx.XXXXXX")"
fi
chmod a+rx "$work"
printf 'owned utmpx evidence: %s\n' "$work"

compile_header_witnesses() {
    local tree="$1" include_root="$2"
    local -a include_args=()
    local trace="$work/$tree-header.trace"
    local c_object="$work/$tree-header-c.o"
    local cxx_object="$work/$tree-header-cxx.o"
    if [ -n "$include_root" ]; then include_args=(-I "$include_root"); fi

    record_command "header-$tree-c" "$oracle_cc" -std=c11 -D_GNU_SOURCE -fno-builtin "${include_args[@]}" \
        -H -c "$header_c" -o "$c_object" >/dev/null 2>"$trace"
    if [ "$tree" = project ]; then
        grep -Fq "$ROOT/include/utmpx.h" "$trace" || {
            printf 'owned utmpx header witness did not use project utmpx.h\n' >&2
            return 1
        }
    fi
    record_command "header-$tree-cxx" "$oracle_cc" -x c++ -std=c++17 -D_GNU_SOURCE -fno-builtin -nostdinc++ \
        "${include_args[@]}" -c "$header_cxx" -o "$cxx_object"
    record_stdin_command "header-$tree-undefined-judge" python3 -B - "$c_object" "$cxx_object" <<'PY'
from pathlib import Path
import subprocess
import sys

expected = {
    'endutxent', 'setutxent', 'getutxent', 'getutxid', 'getutxline',
    'pututxline', 'updwtmpx', 'endutent', 'setutent', 'getutent',
    'getutid', 'getutline', 'pututline', 'updwtmp', 'utmpname', 'utmpxname',
}
for filename in sys.argv[1:]:
    lines = subprocess.check_output(['nm', '--undefined-only', filename], text=True)
    names = {line.split()[-1] for line in lines.splitlines() if line.split()} & expected
    if names != expected:
        raise SystemExit(f'{filename}: header witness references {sorted(names)!r}')
PY
}

compile_header_witnesses oracle ""
compile_header_witnesses project "$ROOT/include"
sha256sum "$header_c" "$header_cxx" "$work"/*-header-*.o >"$work/header-input.sha256"

run_capture() {
    local role="$1" output="$2" status
    shift 2

    if [ "$retain_commands" = 1 ]; then
        # record_command preserves the exact timeout/env/chroot invocation and
        # its observed status; stdout/stderr remain the original raw streams.
        if record_command "$role" timeout 20 env -i PATH="$PATH" "$@" >"$output" 2>"${output%.stdout}.stderr"; then
            status=0
        else
            status=$?
        fi
    elif timeout 20 env -i PATH="$PATH" "$@" >"$output" 2>"${output%.stdout}.stderr"; then
        status=0
    else
        status=$?
    fi
    printf '%s\n' "$status" >"${output%.stdout}.status"
    [ "$status" -eq 0 ] || fail "expected success, got ${status}: $*"
}

compare_oracle() {
    local label="$1" scenario="$2"

    cmp "$work/oracle-$scenario.stdout" "$work/$label-$scenario.stdout" ||
        fail "stdout differs from pinned musl for ${label}/${scenario}"
    cmp "$work/oracle-$scenario.stderr" "$work/$label-$scenario.stderr" ||
        fail "stderr differs from pinned musl for ${label}/${scenario}"
    cmp "$work/oracle-$scenario.status" "$work/$label-$scenario.status" ||
        fail "status differs from pinned musl for ${label}/${scenario}"
}

prepare_root() {
    local root="$1"

    mkdir -p "$root/state" "$root/dev"
    [ -e "$root/dev/null" ] || mknod "$root/dev/null" c 1 3
}

assert_archive_symbols() {
    local archive="$1" symbols="$2"
    record_command archive-symbols nm -g --defined-only "$archive" >"$symbols"
    if [ "$retain_commands" = 1 ]; then
        record_command archive-symbol-bytes readelf --symbols --wide "$archive" >"$work/archive-symbol-bytes.txt"
    fi
    record_stdin_command archive-symbol-judge python3 -B - "$symbols" <<'PY'
from collections import Counter
from pathlib import Path
import sys

strong = {
    'endutxent', 'setutxent', 'getutxent', 'getutxid', 'getutxline',
    'pututxline', 'updwtmpx',
}
weak = {
    'endutent', 'setutent', 'getutent', 'getutid', 'getutline',
    'pututline', 'updwtmp', 'utmpname', 'utmpxname',
}
expected = strong | weak
definitions = Counter()
strong_seen = Counter()
weak_seen = Counter()
text = Path(sys.argv[1]).read_text()
for line in text.splitlines():
    fields = line.split()
    if len(fields) != 3:
        continue
    _, binding, name = fields
    if name not in expected:
        continue
    definitions[name] += 1
    if name in strong and binding == 'T':
        strong_seen[name] += 1
    if name in weak and binding == 'W':
        weak_seen[name] += 1
if definitions != Counter({name: 1 for name in expected}):
    raise SystemExit(f'archive provider multiplicity mismatch: {definitions!r}')
if strong_seen != Counter({name: 1 for name in strong}):
    raise SystemExit(f'archive strong providers mismatch: {strong_seen!r}')
if weak_seen != Counter({name: 1 for name in weak}):
    raise SystemExit(f'archive weak aliases mismatch: {weak_seen!r}')
if '__utmpxname' in text:
    raise SystemExit('archive leaked musl internal __utmpxname')
PY
}

assert_shared_symbols() {
    local library="$1" symbols="$2"
    record_command shared-symbols readelf --dyn-syms --wide "$library" >"$symbols"
    record_stdin_command shared-symbol-judge python3 -B - "$symbols" <<'PY'
from collections import Counter
from pathlib import Path
import sys

strong = {
    'endutxent', 'setutxent', 'getutxent', 'getutxid', 'getutxline',
    'pututxline', 'updwtmpx',
}
weak = {
    'endutent', 'setutent', 'getutent', 'getutid', 'getutline',
    'pututline', 'updwtmp', 'utmpname', 'utmpxname',
}
expected = strong | weak
definitions = Counter()
strong_seen = Counter()
weak_seen = Counter()
text = Path(sys.argv[1]).read_text()
for line in text.splitlines():
    fields = line.split()
    if len(fields) < 8:
        continue
    kind, binding, visibility, index, name = fields[3:8]
    if name not in expected or index == 'UND':
        continue
    definitions[name] += 1
    if kind != 'FUNC' or visibility != 'DEFAULT':
        continue
    if name in strong and binding == 'GLOBAL':
        strong_seen[name] += 1
    if name in weak and binding == 'WEAK':
        weak_seen[name] += 1
if definitions != Counter({name: 1 for name in expected}):
    raise SystemExit(f'shared provider multiplicity mismatch: {definitions!r}')
if strong_seen != Counter({name: 1 for name in strong}):
    raise SystemExit(f'shared strong providers mismatch: {strong_seen!r}')
if weak_seen != Counter({name: 1 for name in weak}):
    raise SystemExit(f'shared weak aliases mismatch: {weak_seen!r}')
if '__utmpxname' in text:
    raise SystemExit('shared library leaked musl internal __utmpxname')
PY
}

retain_executable_symbol_bytes() {
    local label="$1" executable="$2"
    if [ "$retain_commands" = 1 ]; then
        record_command "executable-symbol-bytes-$label" readelf --symbols --wide "$executable" >"$work/$label-symbol-bytes.txt"
    fi
}

assert_executable_symbols() {
    local label="$1" executable="$2" symbols="$3"
    record_command "executable-symbols-$label" nm -g --defined-only "$executable" >"$symbols"
    retain_executable_symbol_bytes "$label" "$executable"
    record_stdin_command "executable-symbol-judge-$label" python3 -B - "$symbols" <<'PY'
from collections import Counter
from pathlib import Path
import sys

expected = {
    'endutxent', 'setutxent', 'getutxent', 'getutxid', 'getutxline',
    'pututxline', 'updwtmpx', 'endutent', 'setutent', 'getutent',
    'getutid', 'getutline', 'pututline', 'updwtmp', 'utmpname', 'utmpxname',
}
seen = Counter()
for line in Path(sys.argv[1]).read_text().splitlines():
    fields = line.split()
    if len(fields) == 3 and fields[2] in expected and fields[1] in {'T', 'W'}:
        seen[fields[2]] += 1
if seen != Counter({name: 1 for name in expected}):
    raise SystemExit(f'executable provider multiplicity mismatch: {seen!r}')
PY
}

# The common validator owns both receipt schemas. Persisting its return value
# retains the exact product, workload, output, and receipt identities used for
# each executable; it also proves the static no-DSO boundary and the dynamic
# no-foreign-import/application-DSO boundary before a process executes.
validate_sealed_link() {
    local product="$1" workload="$2" executable="$3" receipt="$4" linkage="$5"
    local identity="$work/$linkage.link-identity.json"

    record_stdin_command "sealed-link-$linkage" python3 -B - "$ROOT" "$product" "$workload" "$executable" "$receipt" \
        "$linkage" >"$identity" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
sys.path.insert(0, str(root / 'compat/x86_64'))
from owned_posix_product_evidence import ProductEvidenceError
from owned_posix_product_evidence import validate_link

try:
    identity = validate_link(
        Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), sys.argv[6]
    )
except ProductEvidenceError as error:
    raise SystemExit(f'owned-utmpx sealed link evidence: {error}') from error
json.dump(identity, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write('\n')
PY
    link_identity_records+=("$linkage:$identity")
}

retain_link_identities() {
    record_stdin_command link-identities python3 -B - "$work/link-identities.json" "$@" -- "${link_identity_records[@]}" <<'PY'
import json
from pathlib import Path
import sys

expected_fields = {
    'linkage', 'product', 'product_format', 'product_manifest_sha256',
    'workload_sha256', 'executable_sha256', 'receipt_sha256',
}
separator = sys.argv.index('--')
expected_linkages = set(sys.argv[2:separator])
if not expected_linkages:
    raise SystemExit('retained owned-utmpx link identities have no expected modes')
records = {}
for item in sys.argv[separator + 1:]:
    linkage, raw_path = item.split(':', 1)
    if linkage in records:
        raise SystemExit(f'duplicate retained link identity: {linkage}')
    try:
        identity = json.loads(Path(raw_path).read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f'retained {linkage} link identity is unreadable: {error}') from error
    if not isinstance(identity, dict) or set(identity) != expected_fields:
        raise SystemExit(f'retained {linkage} link identity fields drifted')
    if identity['linkage'] != linkage:
        raise SystemExit(f'retained {linkage} link identity linkage drifted')
    records[linkage] = identity
if set(records) != expected_linkages:
    raise SystemExit('retained owned-utmpx link identities omit a product mode')
Path(sys.argv[1]).write_text(
    json.dumps(
        {
            'schema': 'crabc.x86_64-owned-utmpx-link-identities/v1',
            'expected_linkages': sorted(expected_linkages),
            'links': records,
        },
        indent=2,
        sort_keys=True,
    ) + '\n',
    encoding='utf-8',
)
PY
}

# Build the dynamic product first so its installed driver emits the one object
# consumed unchanged by pinned musl, static/static-PIE, and dynamic PIE/non-PIE
# links. Supplied products replace only their own product creation.
if [ "$dynamic_was_supplied" -eq 0 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi
readonly installed="$(realpath "$provided_dynamic")"
validate_product_payload "$installed" dynamic

record_command dynamic-driver-compile "$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$probe" -o "$work/workload.o"
record_stdin_command dependency-audit python3 -B - "$installed" "$work" "$probe" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

product, work, source = map(Path, sys.argv[1:])
source_path = source.resolve(strict=True)
workload = work / 'workload.o'
headers = (product / 'usr/include').resolve(strict=True)
# Repeat only preprocessing with the installed driver's source translator and
# sanitized environment. The linked workload remains the object emitted by the
# installed driver above; this checks its header boundary without replacing it.
sys.path.insert(0, str(product / 'share/crabc'))
import crabc_cc_static as compiler_contract

dependency_command = [compiler_contract.compiler(), '-nostdinc', '-isystem', str(headers),
    '-std=c11', '-ffreestanding', '-fno-builtin', '-fstack-protector-strong', '-fPIE', '-M', str(source_path)]
dependency_file = work / 'workload.d'
with dependency_file.open('xb') as output:
    subprocess.run(
        dependency_command,
        check=True,
        env=compiler_contract.clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=output,
    )
try:
    dependencies = dependency_file.read_text(encoding='utf-8').replace('\\\n', ' ').split(':', 1)[1].split()
except (IndexError, UnicodeDecodeError) as error:
    raise SystemExit(f'owned-utmpx installed-driver dependency output is invalid: {error}') from error
if not dependencies:
    raise SystemExit('owned-utmpx installed-driver dependency output is empty')
dependency_paths = []
for name in dependencies:
    path = Path(name).resolve(strict=True)
    if path != source_path and not path.is_relative_to(headers):
        raise SystemExit(f'owned-utmpx dependency escaped the installed headers: {path}')
    dependency_paths.append(path)
if source_path not in dependency_paths:
    raise SystemExit('owned-utmpx dependency output omits the workload source')

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

record = {
    'schema': 'crabc.x86_64-owned-utmpx-compile/v1',
    'driver_sha256': digest(product / 'bin/crabc-cc-dynamic'),
    'manifest_sha256': digest(product / 'share/crabc/manifest.json'),
    'source_sha256': digest(source_path),
    'object_sha256': digest(workload),
    'dependency_audit_command': dependency_command,
    'dependencies': {str(path): digest(path) for path in dependency_paths},
}
(work / 'compile.json').write_text(
    json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8'
)
PY
sha256sum "$probe" "$work/workload.o" >"$work/input.sha256"
record_command oracle-link "$oracle_cc" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"
prepare_root "$work/oracle-root"
for scenario in ordinary; do
    cp "$work/oracle" "$work/oracle-root/consumer"
    run_capture "runtime-oracle-$scenario" "$work/oracle-$scenario.stdout" \
        chroot "$work/oracle-root" /consumer "$scenario"
done

# A supplied static product retains its static/static-PIE replay even when a
# dynamic product is supplied. Dynamic-only qualification skips static product
# construction; zero arguments retain both disposable product builds.
static_product=''
if [ "$static_was_supplied" -eq 1 ]; then
    static_product="$provided_static"
elif [ "$dynamic_was_supplied" -eq 0 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-sysroot" >"$work/static-build.json"
    static_product="$work/static-sysroot"
fi
if [ -n "$static_product" ]; then
    validate_product_payload "$static_product" static
    assert_archive_symbols "$static_product/usr/lib/libc.a" "$work/archive-symbols.txt"
    for mode in static static-pie; do
        candidate="$work/static-$mode"
        receipt="$candidate.receipt.json"
        (
            cd "$work"
            record_command "static-link-$mode" "$static_product/bin/crabc-cc" "-$mode" \
                --link-receipt "$(basename "$receipt")" "$work/workload.o" -o "$candidate"
        )
        validate_sealed_link "$static_product" "$work/workload.o" "$candidate" "$receipt" "$mode"
        assert_executable_symbols "static-$mode" "$candidate" "$work/$mode-symbols.txt"
        root="$work/static-$mode-root"
        prepare_root "$root"
        cp "$candidate" "$root/consumer"
        for scenario in ordinary; do
            run_capture "runtime-static-$mode-$scenario" "$work/static-$mode-$scenario.stdout" \
                chroot "$root" /consumer "$scenario"
            compare_oracle "static-$mode" "$scenario"
        done
    done
fi

assert_shared_symbols "$installed/usr/lib/libc.so" "$work/dynamic-symbols.txt"
for mode in pie non-pie; do
    candidate="$work/dynamic-$mode"
    record_command "dynamic-link-$mode" "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$candidate"
    receipt="$candidate.crabc-link.json"
    validate_sealed_link "$installed" "$work/workload.o" "$candidate" "$receipt" "$mode"
    # Dynamic consumers import the providers from libc.so; only the opted-in
    # receipt retains their complete ELF rows.  The established provider
    # multiplicity assertion remains confined to static final executables.
    retain_executable_symbol_bytes "dynamic-$mode" "$candidate"
    root="$work/dynamic-$mode-root"
    mkdir -p "$root"
    cp -a "$installed/." "$root/"
    prepare_root "$root"
    cp "$candidate" "$root/consumer"
    for scenario in ordinary; do
        run_capture "runtime-dynamic-$mode-kernel-$scenario" "$work/dynamic-$mode-kernel-$scenario.stdout" \
            chroot "$root" /consumer "$scenario"
        compare_oracle "dynamic-$mode-kernel" "$scenario"
        run_capture "runtime-dynamic-$mode-direct-$scenario" "$work/dynamic-$mode-direct-$scenario.stdout" \
            chroot "$root" "$interpreter" /consumer "$scenario"
        compare_oracle "dynamic-$mode-direct" "$scenario"
    done
done

if [ -n "$static_product" ]; then
    retain_link_identities static static-pie pie non-pie
else
    retain_link_identities pie non-pie
fi
if [ "$static_was_supplied" -eq 1 ] && [ "$dynamic_was_supplied" -eq 1 ]; then
    matrix='provided static/static-PIE plus provided dynamic PIE/non-PIE kernel/direct'
elif [ "$static_was_supplied" -eq 1 ]; then
    matrix='provided static/static-PIE plus disposable dynamic PIE/non-PIE kernel/direct'
elif [ "$dynamic_was_supplied" -eq 1 ]; then
    matrix='provided dynamic PIE/non-PIE kernel/direct'
else
    matrix='disposable static/static-PIE plus dynamic PIE/non-PIE kernel/direct'
fi
sha256sum -c "$work/header-input.sha256" >"$work/header-input-verified.txt"
sha256sum -c "$work/input.sha256" >"$work/input-verified.txt"
printf 'owned utmpx: PASS (one installed-header object through pinned musl; %s; seven strong providers, nine weak same-address aliases, C/C++ declarations, null/unreadable ignored inputs, ENOTSUP name results, unchanged errno and caller input, raw status/stdout/stderr and sealed link identities retained); evidence: %s\n' \
    "$matrix" "$work"
