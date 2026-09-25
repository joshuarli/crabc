#!/usr/bin/env bash
# Installed rand/srand C ABI evidence against pinned musl 1.2.6.
#
# One installed-header workload object is linked unchanged by pinned musl and
# the owned static/dynamic products. The normal scenarios compare raw status,
# stdout, and stderr to musl; the concurrent transition-count scenario is
# deliberately candidate-only because musl's global source state is racy.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_rand_probe.c"
readonly HEADER_C="$ROOT/compat/x86_64/owned_rand_header_abi_probe.c"
readonly HEADER_CXX="$ROOT/compat/x86_64/owned_rand_header_abi_probe.cpp"
readonly DSO_SOURCE="$ROOT/compat/x86_64/owned_rand_dso.c"
readonly DSO_CONSUMER_SOURCE="$ROOT/compat/x86_64/owned_rand_dso_consumer.c"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1
readonly -a ORACLE_SCENARIOS=(core serialized-workers fork)
readonly -a RAND_SYMBOLS=(rand srand)
declare -a link_identity_records=()

usage() {
    printf 'usage: %s [--expect-missing] [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned rand: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -sm)" = 'Linux x86_64' ] || fail 'requires native Linux/x86-64'

expect_missing=0
provided_static=''
provided_dynamic=''
static_was_supplied=0
dynamic_was_supplied=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --expect-missing)
            [ "$expect_missing" -eq 0 ] || usage
            expect_missing=1
            shift
            ;;
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
[ "$expect_missing" -eq 0 ] || {
    [ "$static_was_supplied" -eq 0 ] && [ "$dynamic_was_supplied" -eq 0 ] || usage
}

# Reject raw caller paths before canonicalization could erase a lexical `..`
# or an ancestor symlink. Product validation below then binds physical files.
python3 -B - "$ROOT" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
for raw, name in ((sys.argv[2], 'static'), (sys.argv[3], 'dynamic')):
    if not raw:
        continue
    lexical = Path(raw)
    if any(component == '..' for component in lexical.parts):
        raise SystemExit(f'owned rand {name} product must be a checkout .work directory')
    if not lexical.is_absolute():
        lexical = Path.cwd() / lexical
    if not lexical.is_relative_to(root / '.work'):
        raise SystemExit(f'owned rand {name} product must be a checkout .work directory')
    cursor = root
    for component in lexical.relative_to(root).parts:
        cursor /= component
        if cursor.is_symlink():
            raise SystemExit(f'owned rand {name} product must be a checkout .work directory')
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

python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
temporary = Path(sys.argv[2])
static_product = Path(sys.argv[3]) if sys.argv[3] else None
dynamic_product = Path(sys.argv[4]) if sys.argv[4] else None
if (not temporary.is_dir() or temporary.resolve() != temporary
        or not temporary.is_relative_to(root / '.work')):
    raise SystemExit('owned rand TMPDIR must be a physical checkout .work directory')
for product, name in ((static_product, 'static'), (dynamic_product, 'dynamic')):
    if product and (not product.is_dir() or product.resolve() != product
                    or not product.is_relative_to(root / '.work')):
        raise SystemExit(f'owned rand {name} product must be a physical checkout .work directory')
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
        raise SystemExit(f'owned rand has an unknown product family: {family}')
except ProductEvidenceError as error:
    raise SystemExit(f'owned rand {family} product payload is invalid: {error}') from error
PY
}

if [ "$static_was_supplied" -eq 1 ]; then
    validate_product_payload "$provided_static" static
fi
if [ "$dynamic_was_supplied" -eq 1 ]; then
    validate_product_payload "$provided_dynamic" dynamic
fi

readonly work="$(mktemp -d "$TMPDIR/owned-rand.XXXXXX")"
chmod a+rx "$work"
printf 'owned rand evidence: %s\n' "$work"

run_capture() {
    local label="$1" status
    shift
    if timeout 30 env -i PATH="$PATH" TZ=UTC "$@" >"$work/$label.stdout" 2>"$work/$label.stderr"; then
        status=0
    else
        status=$?
    fi
    printf '%s\n' "$status" >"$work/$label.status"
    [ "$status" -eq 0 ] || fail "expected success, got $status: $*"
}

compare_oracle() {
    local label="$1" scenario="$2"

    cmp "$work/oracle-$scenario.stdout" "$work/$label-$scenario.stdout" ||
        fail "stdout differs from pinned musl for $label/$scenario"
    cmp "$work/oracle-$scenario.stderr" "$work/$label-$scenario.stderr" ||
        fail "stderr differs from pinned musl for $label/$scenario"
    cmp "$work/oracle-$scenario.status" "$work/$label-$scenario.status" ||
        fail "status differs from pinned musl for $label/$scenario"
}

prepare_empty_root() {
    local root="$1"

    mkdir -p "$root/dev"
    if [ ! -e "$root/dev/null" ]; then
        mknod "$root/dev/null" c 1 3
        chmod 666 "$root/dev/null"
    fi
}

assert_symbols() {
    local artifact="$1" selector="$2" report="$3"

    if [ "$selector" = nm ]; then
        nm -g --defined-only "$artifact" >"$report"
    else
        readelf --dyn-syms -W "$artifact" >"$report"
    fi
    python3 -B - "$report" "$selector" "${RAND_SYMBOLS[@]}" <<'PY'
from collections import Counter
from pathlib import Path
import sys

report = Path(sys.argv[1]).read_text(encoding='utf-8').splitlines()
selector = sys.argv[2]
expected = Counter({name: 1 for name in sys.argv[3:]})
definitions = Counter()
correct = Counter()
for name in sys.argv[3:]:
    if selector == 'nm':
        for line in report:
            fields = line.split()
            if len(fields) != 3 or fields[2] != name:
                continue
            definitions[name] += 1
            if fields[1] == 'T':
                correct[name] += 1
    else:
        for line in report:
            fields = line.split()
            if len(fields) != 8 or fields[6] == 'UND' or fields[7] != name:
                continue
            definitions[name] += 1
            if fields[3:6] == ['FUNC', 'GLOBAL', 'DEFAULT']:
                correct[name] += 1
if definitions != expected:
    raise SystemExit(f'rand provider multiplicity mismatch: {definitions!r}')
if correct != expected:
    raise SystemExit(f'rand provider binding mismatch: {correct!r}')
PY
}

# The source and oracle witnesses compile their respective header trees. The
# installed arm proves the published product header separately from the common
# installed-driver workload receipt below.
compile_header_witnesses() {
    local tree="$1" include_root="$2"
    local -a include_args=()
    local trace="$work/$tree-header.trace"
    local c_object="$work/$tree-header-c.o"
    local cxx_object="$work/$tree-header-cxx.o"

    if [ -n "$include_root" ]; then
        include_args=(-nostdinc -isystem "$include_root")
    fi
    "$ORACLE_CC" -std=c11 -fno-builtin "${include_args[@]}" -H -c "$HEADER_C" \
        -o "$c_object" >/dev/null 2>"$trace"
    if [ "$tree" = source ]; then
        grep -Fq "$ROOT/include/stdlib.h" "$trace" ||
            fail 'source C header witness did not use include/stdlib.h'
    fi
    "$ORACLE_CC" -x c++ -std=c++17 -fno-builtin -nostdinc++ "${include_args[@]}" \
        -c "$HEADER_CXX" -o "$cxx_object"
    for object in "$c_object" "$cxx_object"; do
        local undefined symbol
        undefined="$(nm --undefined-only "$object" | awk '{print $NF}')"
        for symbol in "${RAND_SYMBOLS[@]}"; do
            printf '%s\n' "$undefined" | grep -Fx "$symbol" >/dev/null ||
                fail "$tree header witness lacks unmangled $symbol: $object"
        done
    done
}

validate_sealed_link() {
    local product="$1" workload="$2" executable="$3" receipt="$4" linkage="$5"
    local identity="$work/$linkage.link-identity.json"

    python3 -B - "$ROOT" "$product" "$workload" "$executable" "$receipt" \
        "$linkage" >"$identity" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
sys.path.insert(0, str(root / 'compat/x86_64'))
from owned_posix_product_evidence import ProductEvidenceError, validate_link

try:
    identity = validate_link(
        Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), sys.argv[6]
    )
except ProductEvidenceError as error:
    raise SystemExit(f'owned rand sealed link evidence: {error}') from error
json.dump(identity, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write('\n')
PY
    link_identity_records+=("$linkage:$identity")
}

retain_link_identities() {
    python3 -B - "$work/link-identities.json" "$@" -- "${link_identity_records[@]}" <<'PY'
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
    raise SystemExit('retained rand link identities have no expected modes')
records = {}
for item in sys.argv[separator + 1:]:
    linkage, raw_path = item.split(':', 1)
    if linkage in records:
        raise SystemExit(f'duplicate retained rand link identity: {linkage}')
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
    raise SystemExit('retained rand link identities omit a product mode')
Path(sys.argv[1]).write_text(
    json.dumps({
        'schema': 'crabc.x86_64-owned-rand-link-identities/v1',
        'expected_linkages': sorted(expected_linkages),
        'links': records,
    }, indent=2, sort_keys=True) + '\n',
    encoding='utf-8',
)
PY
}

write_compile_receipt() {
    local product="$1"

    python3 -B - "$product" "$work" "$PROBE" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

product, work, source = map(Path, sys.argv[1:])
source_path = source.resolve(strict=True)
workload = work / 'workload.o'
headers = (product / 'usr/include').resolve(strict=True)
sys.path.insert(0, str(product / 'share/crabc'))
import crabc_cc_static as compiler_contract

dependency_command = [
    compiler_contract.compiler(), '-nostdinc', '-isystem', str(headers),
    '-std=c11', *compiler_contract.HOSTED_TRANSLATION_FLAGS,
    '-fPIE', '-M', str(source_path),
]
dependency_file = work / 'workload.d'
with dependency_file.open('xb') as output:
    subprocess.run(
        dependency_command, check=True, env=compiler_contract.clean_environment(),
        stdin=subprocess.DEVNULL, stdout=output,
    )
try:
    dependencies = dependency_file.read_text(encoding='utf-8').replace('\\\n', ' ').split(':', 1)[1].split()
except (IndexError, UnicodeDecodeError) as error:
    raise SystemExit(f'rand installed-driver dependency output is invalid: {error}') from error
if not dependencies:
    raise SystemExit('rand installed-driver dependency output is empty')
dependency_paths = []
for name in dependencies:
    path = Path(name).resolve(strict=True)
    if path != source_path and not path.is_relative_to(headers):
        raise SystemExit(f'rand dependency escaped installed headers: {path}')
    dependency_paths.append(path)
if source_path not in dependency_paths:
    raise SystemExit('rand dependency output omits the workload source')

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

record = {
    'schema': 'crabc.x86_64-owned-rand-compile/v1',
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
}

write_dependency_audit() {
    python3 -B - "$ROOT" "$work" <<'PY'
import hashlib
import json
from pathlib import Path
import tomllib
import sys

root, work = map(Path, sys.argv[1:])
lock = tomllib.loads((root / 'Cargo.lock').read_text(encoding='utf-8'))
packages = {item['name']: item for item in lock['package']}
expected = {
    'rand_pcg': ('0.10.2', 'caa0f4137e1c0a72f4c651489402276c8e8e1cf081f3b0ba156d2cbeef09e86a'),
    'rand_core': ('0.10.1', '63b8176103e19a2643978565ca18b50549f6101881c443590420e4dc998a3c69'),
}
for name, (version, checksum) in expected.items():
    item = packages.get(name)
    if item is None or item.get('version') != version or item.get('checksum') != checksum:
        raise SystemExit(f'owned rand lock drifted for {name}')
if packages['rand_pcg'].get('dependencies') != ['rand_core']:
    raise SystemExit('owned rand normal graph is not rand_pcg -> rand_core')
manifest = (root / 'libc/Cargo.toml').read_text(encoding='utf-8')
needle = 'rand_pcg = { version = "=0.10.2", default-features = false, optional = true }'
if needle not in manifest or '"dep:rand_pcg",' not in manifest:
    raise SystemExit('owned rand feature/dependency declaration drifted')

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

record = {
    'schema': 'crabc.x86_64-owned-rand-dependency-audit/v1',
    'normal_graph': {
        'rand_pcg': {'version': expected['rand_pcg'][0], 'checksum': expected['rand_pcg'][1], 'dependencies': ['rand_core']},
        'rand_core': {'version': expected['rand_core'][0], 'checksum': expected['rand_core'][1], 'dependencies': []},
    },
    'selection': {
        'target': 'cfg(all(target_os = "linux", target_arch = "x86_64", target_endian = "little"))',
        'feature': 'x86-owned-static-runtime',
        'default_features': False,
        'optional': True,
    },
    'source_inputs': {
        'libc/Cargo.toml': digest(root / 'libc/Cargo.toml'),
        'Cargo.lock': digest(root / 'Cargo.lock'),
        'libc/src/c_abi/x86_64/owned_rand.rs': digest(root / 'libc/src/c_abi/x86_64/owned_rand.rs'),
    },
}
(work / 'dependency-audit.json').write_text(
    json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8'
)
PY
}

# The release archive is one fat-LTO Rust CGU plus the separately attested C
# allocator member. Audit the actual member that owns both exports rather than
# mistaking unrelated allocator references elsewhere in that fused CGU for a
# rand allocation edge. The provider disassembly must have no calls or Rust
# allocation shim; the recurrence arrives only through the reviewed dependency.
audit_static_provider_artifact() {
    local archive="$1"

    python3 -B - "$archive" "$work" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

archive, work = map(Path, sys.argv[1:])
def run(arguments, *, text=True):
    return subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=text, check=False)

members = run(['ar', 't', str(archive)]).stdout.splitlines()
if not members or len(set(members)) != len(members):
    raise SystemExit('rand archive member roster is empty or duplicated')
if any('rand_pcg' in member or 'rand_core' in member for member in members):
    raise SystemExit('rand dependency escaped the selected fat-LTO CGU as a separate archive member')
owners = []
for index, member in enumerate(members):
    object_path = work / f'rand-provider-member-{index}.o'
    with object_path.open('xb') as stream:
        copied = subprocess.run(['ar', 'p', str(archive), member], stdin=subprocess.DEVNULL,
                                stdout=stream, stderr=subprocess.PIPE, check=False)
    if copied.returncode != 0:
        raise SystemExit(f'could not extract rand archive member {member}: {copied.stderr.decode(errors="replace")}')
    defined = run(['nm', '-g', '--defined-only', str(object_path)]).stdout
    types = {}
    for line in defined.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] in {'rand', 'srand'}:
            types[fields[2]] = fields[1]
    if types:
        owners.append((member, object_path, types))
if len(owners) != 1 or owners[0][2] != {'rand': 'T', 'srand': 'T'}:
    raise SystemExit(f'rand exports do not have one strong archive owner: {[(name, types) for name, _, types in owners]!r}')
member, object_path, _ = owners[0]
undefined = run(['nm', '--undefined-only', str(object_path)]).stdout
(work / 'rand-provider-undefined.txt').write_text(undefined, encoding='utf-8')
defined = run(['nm', '-g', '--defined-only', str(object_path)]).stdout
(work / 'rand-provider-defined.txt').write_text(defined, encoding='utf-8')
if re.search(r'__rust_(?:alloc|dealloc|realloc)|__rdl_', undefined + defined):
    raise SystemExit('rand provider CGU unexpectedly exposes a Rust allocation shim')
disassemblies = {}
for symbol in ('rand', 'srand'):
    full_disassembly = run(['objdump', '-dr', f'--disassemble={symbol}', str(object_path)]).stdout
    match = re.search(
        rf'(?ms)^[0-9a-f]+ <{re.escape(symbol)}>:\n(.*?)(?=^\s*$)', full_disassembly
    )
    if match is None:
        raise SystemExit(f'rand provider {symbol} is absent from the extracted object')
    disassembly = match.group(0)
    if re.search(r'\bcall(?:[qwl])?\b', disassembly):
        raise SystemExit(f'rand provider {symbol} has an unexpected call edge')
    if re.search(r'__rust_|__rdl_|rand_core|rand_pcg|alloc', disassembly):
        raise SystemExit(f'rand provider {symbol} has an unexpected helper edge')
    (work / f'rand-provider-{symbol}.objdump').write_text(disassembly, encoding='utf-8')
    disassemblies[symbol] = hashlib.sha256(disassembly.encode()).hexdigest()
if 'cmpxchg' not in (work / 'rand-provider-rand.objdump').read_text(encoding='utf-8'):
    raise SystemExit('rand provider lacks the atomic publish instruction')
relocations = run(['readelf', '-rW', str(object_path)]).stdout
(work / 'rand-provider-relocations.txt').write_text(relocations, encoding='utf-8')
record = {
    'schema': 'crabc.x86_64-owned-rand-provider-artifact/v1',
    'archive': str(archive),
    'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
    'archive_members': members,
    'provider_member': member,
    'provider_member_sha256': hashlib.sha256(object_path.read_bytes()).hexdigest(),
    'undefined_sha256': hashlib.sha256(undefined.encode()).hexdigest(),
    'disassembly_sha256': disassemblies,
    'notes': [
        'fat-LTO fused unrelated owned-runtime references remain visible in the provider CGU',
        'rand and srand themselves have no call edge or Rust allocation shim',
        'the reviewed rand_pcg recurrence is inlined by LTO rather than copied into owned source',
    ],
}
(work / 'provider-artifact.json').write_text(
    json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8'
)
PY
}

run_oracle_scenarios() {
    local scenario root
    for scenario in "${ORACLE_SCENARIOS[@]}"; do
        root="$work/oracle-$scenario-root"
        prepare_empty_root "$root"
        cp "$work/oracle" "$root/consumer"
        run_capture "oracle-$scenario" chroot "$root" /consumer "$scenario"
    done
}

run_static_scenarios() {
    local label="$1" candidate="$2" scenario root
    for scenario in "${ORACLE_SCENARIOS[@]}"; do
        root="$work/$label-$scenario-root"
        prepare_empty_root "$root"
        cp "$candidate" "$root/consumer"
        run_capture "$label-$scenario" chroot "$root" /consumer "$scenario"
        compare_oracle "$label" "$scenario"
    done
}

run_static_concurrency() {
    local label="$1" candidate="$2" root
    root="$work/$label-candidate-concurrency-root"
    prepare_empty_root "$root"
    cp "$candidate" "$root/consumer"
    run_capture "$label-candidate-concurrency" chroot "$root" /consumer candidate-concurrency
    grep -Eq '^candidate-concurrency-transitions=1024 after=[0-9]+$' \
        "$work/$label-candidate-concurrency.stdout" ||
        fail "$label did not prove the serialized candidate transition count"
}

run_dynamic_scenarios() {
    local label="$1" candidate="$2" product="$3" scenario root
    for scenario in "${ORACLE_SCENARIOS[@]}"; do
        root="$work/$label-$scenario-root"
        mkdir -p "$root"
        cp -a "$product/." "$root/"
        prepare_empty_root "$root"
        cp "$candidate" "$root/consumer"
        run_capture "$label-kernel-$scenario" chroot "$root" /consumer "$scenario"
        compare_oracle "$label-kernel" "$scenario"
        run_capture "$label-direct-$scenario" chroot "$root" "$INTERPRETER" /consumer "$scenario"
        compare_oracle "$label-direct" "$scenario"
    done
}

run_dynamic_concurrency() {
    local label="$1" candidate="$2" product="$3" root
    root="$work/$label-candidate-concurrency-root"
    mkdir -p "$root"
    cp -a "$product/." "$root/"
    prepare_empty_root "$root"
    cp "$candidate" "$root/consumer"
    for entry in kernel direct; do
        if [ "$entry" = kernel ]; then
            run_capture "$label-$entry-candidate-concurrency" \
                chroot "$root" /consumer candidate-concurrency
        else
            run_capture "$label-$entry-candidate-concurrency" \
                chroot "$root" "$INTERPRETER" /consumer candidate-concurrency
        fi
        grep -Eq '^candidate-concurrency-transitions=1024 after=[0-9]+$' \
            "$work/$label-$entry-candidate-concurrency.stdout" ||
            fail "$label/$entry did not prove the serialized candidate transition count"
    done
}

expect_missing_link() {
    local label="$1"
    shift
    if "$@" >"$work/$label.stdout" 2>"$work/$label.stderr"; then
        fail "pre-provider $label link unexpectedly succeeded"
    fi
    local symbol
    for symbol in "${RAND_SYMBOLS[@]}"; do
        grep -Eq "undefined reference to .*$symbol|undefined symbol: $symbol" \
            "$work/$label.stderr" ||
            fail "pre-provider $label link did not expose missing $symbol"
    done
}

audit_dso_link() {
    local consumer="$1" provider="$2" receipt="$3" label="$4"

    readelf -dW "$consumer" >"$work/$label-consumer.dynamic"
    readelf --dyn-syms -W "$provider" >"$work/$label-provider.symbols"
    python3 -B - "$consumer" "$provider" "$receipt" \
        "$work/$label-consumer.dynamic" "$work/$label-provider.symbols" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import sys

consumer, provider, receipt, dynamic, symbols = map(Path, sys.argv[1:])
record = json.loads(receipt.read_text(encoding='utf-8'))
provider_name = provider.name
if record.get('application_dsos') != {provider_name: hashlib.sha256(provider.read_bytes()).hexdigest()}:
    raise SystemExit('rand DSO receipt does not bind the provider')
if record.get('mode') not in {'pie', 'exec'} or record.get('binding') != 'now':
    raise SystemExit('rand DSO receipt mode or binding drifted')
text = dynamic.read_text(encoding='utf-8')
needed = re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', text)
if needed != [provider_name, 'libc.so']:
    raise SystemExit(f'rand DSO consumer needed roster drifted: {needed!r}')
if re.findall(r'\(RUNPATH\).*?\[([^\]]*)\]', text) != ['/usr/lib'] or '(RPATH)' in text:
    raise SystemExit('rand DSO consumer search path drifted')
provider_symbols = symbols.read_text(encoding='utf-8')
if re.search(r'\bFUNC\s+GLOBAL\s+DEFAULT\s+\d+\s+crabc_owned_rand_dso_next$', provider_symbols, re.M) is None:
    raise SystemExit('rand DSO does not export its test entry')
if re.search(r'\bUND\s+rand$', provider_symbols, re.M) is None:
    raise SystemExit('rand DSO does not resolve rand through process libc')
PY
}

run_dso_shared_stream() {
    local product="$1" mode label root provider consumer receipt entry
    "$product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
        -c "$DSO_SOURCE" -o "$work/rand-dso.o"
    "$product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
        -c "$DSO_CONSUMER_SOURCE" -o "$work/rand-dso-consumer.o"
    for mode in pie non-pie; do
        label="dynamic-$mode-dso"
        root="$work/$label-root"
        mkdir -p "$root"
        cp -a "$product/." "$root/"
        provider="$root/usr/lib/libowned-rand-dso.so"
        consumer="$work/$label-consumer"
        "$product/bin/crabc-cc-dynamic" --dynamic-shared-object "$work/rand-dso.o" -o "$provider"
        "$product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/rand-dso-consumer.o" \
            --application-dso "$provider" -o "$consumer"
        receipt="$consumer.crabc-link.json"
        audit_dso_link "$consumer" "$provider" "$receipt" "$label"
        cp "$consumer" "$root/consumer"
        for entry in kernel direct; do
            if [ "$entry" = kernel ]; then
                run_capture "$label-$entry" chroot "$root" /consumer
            else
                run_capture "$label-$entry" chroot "$root" "$INTERPRETER" /consumer
            fi
            grep -Eq '^main-dso=[0-9]+,[0-9]+$' "$work/$label-$entry.stdout" ||
                fail "$label/$entry did not demonstrate a main/DSO shared rand stream"
        done
    done
}

# Build the dynamic product first. Its installed driver emits the single C
# workload object consumed unchanged by the oracle and all normal product modes.
if [ "$dynamic_was_supplied" -eq 0 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi
readonly installed="$(realpath "$provided_dynamic")"
validate_product_payload "$installed" dynamic

compile_header_witnesses oracle ''
compile_header_witnesses source "$ROOT/include"
compile_header_witnesses installed "$installed/usr/include"
sha256sum "$HEADER_C" "$HEADER_CXX" "$work"/*-header-*.o >"$work/header-input.sha256"

"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"
write_compile_receipt "$installed"
write_dependency_audit
"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"

if [ "$expect_missing" -eq 1 ]; then
    # The retained red first runs this exact installed-header object through
    # pinned musl, then attributes each absent provider to the owned links.
    run_oracle_scenarios
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-sysroot" >"$work/static-build.json"
    for mode in static static-pie; do
        expect_missing_link "red-$mode" \
            "$work/static-sysroot/bin/crabc-cc" "-$mode" "$work/workload.o" \
            -o "$work/$mode"
    done
    for mode in pie non-pie; do
        expect_missing_link "red-dynamic-$mode" \
            "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" \
            -o "$work/dynamic-$mode"
    done
    printf 'owned rand: expected red PASS (one installed-header object ran through pinned musl; all four owned links expose absent rand/srand); evidence: %s\n' "$work"
    exit 0
fi

run_oracle_scenarios

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
    assert_symbols "$static_product/usr/lib/libc.a" nm "$work/static-symbols.txt"
    audit_static_provider_artifact "$static_product/usr/lib/libc.a"
    for mode in static static-pie; do
        candidate="$work/static-$mode"
        receipt="$candidate.receipt.json"
        (
            cd "$work"
            "$static_product/bin/crabc-cc" "-$mode" \
                --link-receipt "$(basename "$receipt")" "$work/workload.o" -o "$candidate"
        )
        validate_sealed_link "$static_product" "$work/workload.o" "$candidate" "$receipt" "$mode"
        run_static_scenarios "static-$mode" "$candidate"
        run_static_concurrency "static-$mode" "$candidate"
    done
fi

assert_symbols "$installed/usr/lib/libc.so" readelf "$work/dynamic-symbols.txt"
for mode in pie non-pie; do
    candidate="$work/dynamic-$mode"
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$candidate"
    receipt="$candidate.crabc-link.json"
    validate_sealed_link "$installed" "$work/workload.o" "$candidate" "$receipt" "$mode"
    run_dynamic_scenarios "dynamic-$mode" "$candidate" "$installed"
    run_dynamic_concurrency "dynamic-$mode" "$candidate" "$installed"
done
run_dso_shared_stream "$installed"

if [ -n "$static_product" ]; then
    retain_link_identities static static-pie pie non-pie
else
    retain_link_identities pie non-pie
fi
sha256sum -c "$work/header-input.sha256" >"$work/header-input-verified.txt"
sha256sum "$PROBE" "$HEADER_C" "$HEADER_CXX" "$DSO_SOURCE" "$DSO_CONSUMER_SOURCE" \
    "$ROOT/libc/src/c_abi/x86_64/owned_rand.rs" >"$work/source-input.sha256"
if [ "$static_was_supplied" -eq 1 ] && [ "$dynamic_was_supplied" -eq 1 ]; then
    matrix='provided static/static-PIE plus provided dynamic PIE/non-PIE kernel/direct'
elif [ "$static_was_supplied" -eq 1 ]; then
    matrix='provided static/static-PIE plus disposable dynamic PIE/non-PIE kernel/direct'
elif [ "$dynamic_was_supplied" -eq 1 ]; then
    matrix='provided dynamic PIE/non-PIE kernel/direct'
else
    matrix='disposable static/static-PIE plus dynamic PIE/non-PIE kernel/direct'
fi
printf 'owned rand: PASS (same installed-header object through pinned musl; %s; source/oracle/installed C/C++ headers, exact seed/reseed/default/u32-prewiden/64x128 streams, errno, constructor, serialized workers, fork, candidate-only atomic transition count, main/DSO stream, strong exports, provider artifact audit, raw status/stdout/stderr, compile receipt, and sealed normal-link identities retained); evidence: %s\n' \
    "$matrix" "$work"
