#!/usr/bin/env bash
# Installed account-file C ABI behavior against pinned musl 1.2.6.
#
# A single C object emitted by the installed dynamic driver is linked by the
# musl oracle and each owned product mode. Every workload invocation creates
# its own chroot `/etc`, so neither the probe nor its oracle can observe host
# account files. Raw status/stdout/stderr and sealed link identities remain
# alongside the product and installed-header receipts.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_account_files_probe.c"
readonly HEADER_C="$ROOT/compat/x86_64/owned_account_files_header_abi_probe.c"
readonly HEADER_CXX="$ROOT/compat/x86_64/owned_account_files_header_abi_probe.cpp"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1
readonly -a SCENARIOS=(
    symbols fields early tcb tcb-denied global stream read-error workers
    cancellation noops usershell cuserid
)
readonly -a ACCOUNT_SYMBOLS=(
    cuserid getusershell setusershell endusershell
    endspent setspent getspent fgetspent getspnam getspnam_r putspent
    lckpwdf ulckpwdf
)
declare -a link_identity_records=()

usage() {
    printf 'usage: %s [--expect-missing] [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned account files: %s\n' "$*" >&2
    exit 1
}

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
# Reject a raw path before `realpath` could hide an ancestor symlink or a
# lexical `..` component. A later physical-product validation binds receipts,
# but it must not be asked to recover this caller-input boundary.
python3 -B - "$ROOT" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
for raw, name in ((sys.argv[2], 'static'), (sys.argv[3], 'dynamic')):
    if not raw:
        continue
    lexical = Path(raw)
    if any(component == '..' for component in lexical.parts):
        raise SystemExit(f'owned account files {name} product must be a checkout .work directory')
    if not lexical.is_absolute():
        lexical = Path.cwd() / lexical
    if not lexical.is_relative_to(root / '.work'):
        raise SystemExit(f'owned account files {name} product must be a checkout .work directory')
    cursor = root
    for component in lexical.relative_to(root).parts:
        cursor /= component
        if cursor.is_symlink():
            raise SystemExit(f'owned account files {name} product must be a checkout .work directory')
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

# Supplied products are checked before allocating evidence state. The common
# validator below checks their physical payload again before every receipt is
# bound to a final executable.
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
temporary = Path(sys.argv[2])
static_product = Path(sys.argv[3]) if sys.argv[3] else None
dynamic_product = Path(sys.argv[4]) if sys.argv[4] else None
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned account files TMPDIR must be a physical checkout .work directory')
for product, name in ((static_product, 'static'), (dynamic_product, 'dynamic')):
    if product and (not product.is_dir() or product.resolve() != product or not product.is_relative_to(root / '.work')):
        raise SystemExit(f'owned account files {name} product must be a physical checkout .work directory')
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
        raise SystemExit(f'owned account files has an unknown product family: {family}')
except ProductEvidenceError as error:
    raise SystemExit(f'owned account files {family} product payload is invalid: {error}') from error
PY
}

if [ "$static_was_supplied" -eq 1 ]; then
    validate_product_payload "$provided_static" static
fi
if [ "$dynamic_was_supplied" -eq 1 ]; then
    validate_product_payload "$provided_dynamic" dynamic
fi

readonly work="$(mktemp -d "$TMPDIR/owned-account-files.XXXXXX")"
chmod a+rx "$work"
printf 'owned account files evidence: %s\n' "$work"

run_capture() {
    local output="$1" status
    shift

    if timeout 30 env -i PATH="$PATH" "$@" >"$output" 2>"${output%.stdout}.stderr"; then
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

    mkdir -p "$root/etc" "$root/dev"
    [ -e "$root/dev/null" ] || mknod "$root/dev/null" c 1 3
}

assert_symbols() {
    local artifact="$1" selector="$2" report="$3"

    if [ "$selector" = nm ]; then
        nm -g --defined-only "$artifact" >"$report"
    else
        readelf --dyn-syms -W "$artifact" >"$report"
    fi
    python3 -B - "$report" "$selector" "${ACCOUNT_SYMBOLS[@]}" <<'PY'
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
    raise SystemExit(f'account-file provider multiplicity mismatch: {definitions!r}')
if correct != expected:
    raise SystemExit(f'account-file provider binding mismatch: {correct!r}')
PY
}

# The `source` declaration witness compiles source-tree headers, `oracle`
# compiles the pinned oracle headers, and `installed` compiles installed
# product headers. The installed dynamic driver separately compiles the common
# C workload and its dependency receipt records that workload's headers.
compile_header_witnesses() {
    local tree="$1" include_root="$2"
    local -a include_args=()
    local trace="$work/$tree-header.trace"
    local c_object="$work/$tree-header-c.o"
    local cxx_object="$work/$tree-header-cxx.o"
    if [ -n "$include_root" ]; then
        include_args=(-nostdinc -isystem "$include_root")
    fi

    "$ORACLE_CC" -std=c11 -fno-builtin "${include_args[@]}" \
        -H -c "$HEADER_C" -o "$c_object" >/dev/null 2>"$trace"
    if [ "$tree" = source ]; then
        grep -Fq "$ROOT/include/shadow.h" "$trace" ||
            fail 'source C header witness did not use include/shadow.h'
    fi
    "$ORACLE_CC" -x c++ -std=c++17 -fno-builtin -nostdinc++ \
        "${include_args[@]}" -c "$HEADER_CXX" -o "$cxx_object"
    for object in "$c_object" "$cxx_object"; do
        local undefined symbol
        undefined="$(nm --undefined-only "$object" | awk '{print $NF}')"
        for symbol in "${ACCOUNT_SYMBOLS[@]}"; do
            printf '%s\n' "$undefined" | grep -Fx "$symbol" >/dev/null ||
                fail "${tree} header witness lacks unmangled ${symbol}: ${object}"
        done
    done
}

# The common validator owns both static and dynamic receipt schemas. Its
# retained identity binds the exact product, common workload object, output,
# and receipt, and checks the static no-DSO or dynamic no-foreign-import
# boundary before this runner executes an account-file fixture.
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
    raise SystemExit(f'owned account files sealed link evidence: {error}') from error
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
    raise SystemExit('retained account-file link identities have no expected modes')
records = {}
for item in sys.argv[separator + 1:]:
    linkage, raw_path = item.split(':', 1)
    if linkage in records:
        raise SystemExit(f'duplicate retained account-file link identity: {linkage}')
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
    raise SystemExit('retained account-file link identities omit a product mode')
Path(sys.argv[1]).write_text(
    json.dumps(
        {
            'schema': 'crabc.x86_64-owned-account-files-link-identities/v1',
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
    '-std=c11', '-ffreestanding', '-fno-builtin', '-fstack-protector-strong',
    '-fPIE', '-M', str(source_path),
]
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
    raise SystemExit(f'account-file installed-driver dependency output is invalid: {error}') from error
if not dependencies:
    raise SystemExit('account-file installed-driver dependency output is empty')
dependency_paths = []
for name in dependencies:
    path = Path(name).resolve(strict=True)
    if path != source_path and not path.is_relative_to(headers):
        raise SystemExit(f'account-file dependency escaped installed headers: {path}')
    dependency_paths.append(path)
if source_path not in dependency_paths:
    raise SystemExit('account-file dependency output omits the workload source')

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

record = {
    'schema': 'crabc.x86_64-owned-account-files-compile/v1',
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

run_oracle_scenarios() {
    local scenario root
    for scenario in "${SCENARIOS[@]}"; do
        root="$work/oracle-$scenario-root"
        prepare_root "$root"
        cp "$work/oracle" "$root/consumer"
        run_capture "$work/oracle-$scenario.stdout" \
            chroot "$root" /consumer "$scenario"
    done
}

run_static_scenarios() {
    local label="$1" candidate="$2" scenario root
    for scenario in "${SCENARIOS[@]}"; do
        root="$work/$label-$scenario-root"
        prepare_root "$root"
        cp "$candidate" "$root/consumer"
        run_capture "$work/$label-$scenario.stdout" \
            chroot "$root" /consumer "$scenario"
        compare_oracle "$label" "$scenario"
    done
}

run_dynamic_scenarios() {
    local label="$1" candidate="$2" product="$3" scenario root
    for scenario in "${SCENARIOS[@]}"; do
        root="$work/$label-$scenario-root"
        mkdir -p "$root"
        cp -a "$product/." "$root/"
        prepare_root "$root"
        cp "$candidate" "$root/consumer"
        run_capture "$work/$label-kernel-$scenario.stdout" \
            chroot "$root" /consumer "$scenario"
        compare_oracle "$label-kernel" "$scenario"
        run_capture "$work/$label-direct-$scenario.stdout" \
            chroot "$root" "$INTERPRETER" /consumer "$scenario"
        compare_oracle "$label-direct" "$scenario"
    done
}

expect_missing_link() {
    local label="$1"
    shift
    if "$@" >"$work/$label.stdout" 2>"$work/$label.stderr"; then
        fail "pre-provider $label link unexpectedly succeeded"
    fi
    local symbol
    for symbol in "${ACCOUNT_SYMBOLS[@]}"; do
        grep -Eq "undefined reference to .*$symbol|undefined symbol: $symbol" \
            "$work/$label.stderr" ||
            fail "pre-provider $label link did not expose missing $symbol"
    done
}

# Build the dynamic product first. Its installed driver owns the sole C object
# used unchanged by the oracle, both static links, and both dynamic links.
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

"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"
assert_symbols "$work/oracle" nm "$work/oracle-symbols.txt"

if [ "$expect_missing" -eq 1 ]; then
    # The red baseline first proves that this exact installed-header object
    # runs through pinned musl in private `/etc` fixtures. Only then may an
    # absent selected provider be attributed to the owned product links.
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
    printf 'owned account files: expected red PASS (one installed-header object ran through pinned musl; all four owned links expose the absent account-file providers; private-chroot oracle fixtures retained); evidence: %s\n' "$work"
    exit 0
fi

run_oracle_scenarios

# A supplied static product receives its static/static-PIE replay even if the
# dynamic product is supplied too. A dynamic-only invocation intentionally
# omits a disposable static build; no-argument qualification is the full six
# execution paths requested by the owned runtime campaign.
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
    done
fi

assert_symbols "$installed/usr/lib/libc.so" readelf "$work/dynamic-symbols.txt"
for mode in pie non-pie; do
    candidate="$work/dynamic-$mode"
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$candidate"
    receipt="$candidate.crabc-link.json"
    validate_sealed_link "$installed" "$work/workload.o" "$candidate" "$receipt" "$mode"
    run_dynamic_scenarios "dynamic-$mode" "$candidate" "$installed"
done

if [ -n "$static_product" ]; then
    retain_link_identities static static-pie pie non-pie
else
    retain_link_identities pie non-pie
fi
sha256sum -c "$work/header-input.sha256" >"$work/header-input-verified.txt"
if [ "$static_was_supplied" -eq 1 ] && [ "$dynamic_was_supplied" -eq 1 ]; then
    matrix='provided static/static-PIE plus provided dynamic PIE/non-PIE kernel/direct'
elif [ "$static_was_supplied" -eq 1 ]; then
    matrix='provided static/static-PIE plus disposable dynamic PIE/non-PIE kernel/direct'
elif [ "$dynamic_was_supplied" -eq 1 ]; then
    matrix='provided dynamic PIE/non-PIE kernel/direct'
else
    matrix='disposable static/static-PIE plus dynamic PIE/non-PIE kernel/direct'
fi
printf 'owned account files: PASS (same installed-header object through pinned musl; %s; source-and-installed-header C/C++ ABI, installed-header workload receipt, conventional private /etc fixtures, source-exact shadow parsing/TCB/no-ops/stream errors, usershell state, cuserid, workers, cancellation cleanup, raw status/stdout/stderr, and sealed link identities retained); evidence: %s\n' \
    "$matrix" "$work"
