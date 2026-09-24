#!/usr/bin/env bash
# Installed selected C-ABI-compatibility behavior against pinned musl 1.2.6.
#
# Two installed-header objects are compiled once through the dynamic driver.
# The behavior object links unchanged against static pinned musl and every
# owned static/static-PIE and dynamic PIE/non-PIE kernel/direct entry. The
# allocator-interposition object replaces the public malloc family in the
# executable and links against dynamic pinned musl and both owned dynamic
# modes. Every compared run retains raw status, stdout, and stderr.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_c_abi_compat_probe.c"
readonly interposition_probe="$ROOT/compat/x86_64/owned_c_abi_compat_interposition_probe.c"
readonly interpreter=/lib/ld-crabc-x86_64.so.1
readonly musl_interpreter=/lib/ld-musl-x86_64.so.1
readonly -a scenarios=(search qsort gettext diagnostics allocation)
readonly -a interposition_scenarios=(tree hash gettext)
# The documented crabc profile limits have no pinned-musl comparison: musl
# implements DES and file-backed message catalogs, crabc selects neither.
readonly expected_profile='des-inert=1,1,77
catgets-default=default-message
catclose=0
owned-c-abi-compat-profile-ok'
declare -a link_identity_records=()

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned C ABI compatibility: %s\n' "$*" >&2
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
[ "$(uname -sm)" = 'Linux x86_64' ] || fail 'requires native Linux/x86-64'

python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
static_product = Path(sys.argv[3]) if sys.argv[3] else None
dynamic_product = Path(sys.argv[4]) if sys.argv[4] else None
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('C ABI compatibility TMPDIR must be a physical checkout .work directory')
for product, name in ((static_product, 'static'), (dynamic_product, 'dynamic')):
    if product and (not product.is_dir() or not product.is_relative_to(root / '.work')):
        raise SystemExit(f'C ABI compatibility {name} product must be a checkout .work directory')
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
        raise SystemExit(f'C ABI compatibility has an unknown product family: {family}')
except ProductEvidenceError as error:
    raise SystemExit(f'C ABI compatibility {family} product payload is invalid: {error}') from error
PY
}

if [ "$static_was_supplied" -eq 1 ]; then
    validate_product_payload "$provided_static" static
fi
if [ "$dynamic_was_supplied" -eq 1 ]; then
    validate_product_payload "$provided_dynamic" dynamic
fi

readonly work="$(mktemp -d "$TMPDIR/owned-c-abi-compat.XXXXXX")"
chmod a+rx "$work"
printf 'C ABI compatibility evidence: %s\n' "$work"
trap 'printf "owned C ABI compatibility failed near %s; evidence: %s\\n" "${step:-setup}" "$work" >&2' ERR

# Every target runs in a clean environment with one known variable so
# secure_getenv's ordinary-process result is observable.
run_capture() {
    local output="$1" status
    shift

    step="run ${output##*/}"
    if timeout 30 env -i PATH="$PATH" CRABC_PROBE=present "$@" \
            >"$output" 2>"${output%.stdout}.stderr"; then
        status=0
    else
        status=$?
    fi
    printf '%s\n' "$status" >"${output%.stdout}.status"
    # Equal oracle/candidate failures are never evidence; stop at the first
    # failed target after retaining its raw streams.
    [ "$status" -eq 0 ] || fail "expected success, got ${status}: $*"
}

compare_oracle() {
    local oracle="$1" candidate="$2"

    cmp "$oracle.stdout" "$candidate.stdout" ||
        fail "stdout differs from pinned musl: ${candidate##*/}"
    cmp "$oracle.stderr" "$candidate.stderr" ||
        fail "stderr differs from pinned musl: ${candidate##*/}"
    cmp "$oracle.status" "$candidate.status" ||
        fail "status differs from pinned musl: ${candidate##*/}"
}

check_profile() {
    local prefix="$1"

    [ "$(cat "$prefix.stdout")" = "$expected_profile" ] ||
        fail "documented profile output differs: ${prefix##*/}"
    [ ! -s "$prefix.stderr" ] || fail "documented profile wrote stderr: ${prefix##*/}"
}

validate_sealed_link() {
    local product="$1" workload="$2" executable="$3" receipt="$4" linkage="$5"
    local identity="$work/$linkage.link-identity.json"

    step="validate $linkage link"
    python3 -B - "$ROOT" "$product" "$workload" "$executable" "$receipt" \
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
    raise SystemExit(f'C ABI compatibility sealed link evidence: {error}') from error
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
records = {}
for item in sys.argv[separator + 1:]:
    linkage, raw_path = item.split(':', 1)
    if linkage in records:
        raise SystemExit(f'duplicate retained link identity: {linkage}')
    identity = json.loads(Path(raw_path).read_text(encoding='utf-8'))
    if not isinstance(identity, dict) or set(identity) != expected_fields or identity['linkage'] != linkage:
        raise SystemExit(f'retained {linkage} link identity drifted')
    records[linkage] = identity
if not expected_linkages or set(records) != expected_linkages:
    raise SystemExit('retained C ABI compatibility link identities omit a product mode')
Path(sys.argv[1]).write_text(
    json.dumps({
        'schema': 'crabc.x86_64-owned-c-abi-compat-link-identities/v1',
        'expected_linkages': sorted(expected_linkages),
        'links': records,
    }, indent=2, sort_keys=True) + '\n',
    encoding='utf-8',
)
PY
}

# Record the installed driver's header boundary for one object without
# replacing the object the driver itself emitted.
audit_installed_compile() {
    local product="$1" source="$2" object="$3" name="$4"

    step="audit $name compile"
    python3 -B - "$product" "$source" "$object" "$work/$name.compile.json" "$work/$name.d" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

product, source, workload, record_path, dependency_file = map(Path, sys.argv[1:])
source_path = source.resolve(strict=True)
headers = (product / 'usr/include').resolve(strict=True)
sys.path.insert(0, str(product / 'share/crabc'))
import crabc_cc_static as compiler_contract

command = [compiler_contract.compiler(), '-nostdinc', '-isystem', str(headers),
    '-std=c11', '-ffreestanding', '-fno-builtin', '-fstack-protector-strong', '-fPIE', '-M', str(source_path)]
with dependency_file.open('xb') as output:
    subprocess.run(command, check=True, env=compiler_contract.clean_environment(),
                   stdin=subprocess.DEVNULL, stdout=output)
text = dependency_file.read_text(encoding='utf-8').replace('\\\n', ' ')
dependencies = text.split(':', 1)[1].split() if ':' in text else []
if not dependencies:
    raise SystemExit('C ABI compatibility installed-driver dependency output is empty')
paths = []
for name in dependencies:
    path = Path(name).resolve(strict=True)
    if path != source_path and not path.is_relative_to(headers):
        raise SystemExit(f'C ABI compatibility dependency escaped the installed headers: {path}')
    paths.append(path)
if source_path not in paths:
    raise SystemExit('C ABI compatibility dependency output omits the workload source')

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

record = {
    'schema': 'crabc.x86_64-owned-c-abi-compat-compile/v1',
    'driver_sha256': digest(product / 'bin/crabc-cc-dynamic'),
    'manifest_sha256': digest(product / 'share/crabc/manifest.json'),
    'source_sha256': digest(source_path),
    'object_sha256': digest(workload),
    'dependency_audit_command': command,
    'dependencies': {str(path): digest(path) for path in paths},
}
record_path.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8')
PY
}

assert_exported_interposers() {
    local executable="$1" symbols="$2" name matches

    readelf --dyn-syms -W "$executable" >"$symbols"
    for name in malloc calloc realloc free; do
        matches="$(awk -v name="$name" '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == name { count++ } END { print count + 0 }' "$symbols")"
        [ "$matches" -eq 1 ] || fail "executable does not export interposer $name: ${executable##*/}"
    done
}

# Build the dynamic product first so its installed driver emits both objects.
if [ "$dynamic_was_supplied" -eq 0 ]; then
    step='build dynamic product'
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi
readonly installed="$(realpath "$provided_dynamic")"
validate_product_payload "$installed" dynamic

step='compile workloads'
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$probe" -o "$work/workload.o"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$interposition_probe" -o "$work/interposition.o"
audit_installed_compile "$installed" "$probe" "$work/workload.o" workload
audit_installed_compile "$installed" "$interposition_probe" "$work/interposition.o" interposition

bash "$ROOT/compat/x86_64/run_musl_oracle.sh" >/dev/null
step='link static musl oracle'
"$oracle_cc" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"
mkdir -p "$work/oracle-root"
cp "$work/oracle" "$work/oracle-root/consumer"
for scenario in "${scenarios[@]}"; do
    run_capture "$work/oracle-$scenario.stdout" chroot "$work/oracle-root" /consumer "$scenario"
    grep -qx "owned-c-abi-compat-$scenario-ok" "$work/oracle-$scenario.stdout" ||
        fail "pinned musl did not complete $scenario"
done

static_product=''
if [ "$static_was_supplied" -eq 1 ]; then
    static_product="$provided_static"
elif [ "$dynamic_was_supplied" -eq 0 ]; then
    step='build static product'
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-sysroot" >"$work/static-build.json"
    static_product="$work/static-sysroot"
fi
if [ -n "$static_product" ]; then
    validate_product_payload "$static_product" static
    for mode in static static-pie; do
        candidate="$work/static-$mode"
        receipt="$candidate.receipt.json"
        step="link $mode"
        (
            cd "$work"
            "$static_product/bin/crabc-cc" "-$mode" \
                --link-receipt "$(basename "$receipt")" "$work/workload.o" -o "$candidate"
        )
        validate_sealed_link "$static_product" "$work/workload.o" "$candidate" "$receipt" "$mode"
        root="$work/static-$mode-root"
        mkdir -p "$root"
        cp "$candidate" "$root/consumer"
        for scenario in "${scenarios[@]}"; do
            run_capture "$work/static-$mode-$scenario.stdout" chroot "$root" /consumer "$scenario"
            compare_oracle "$work/oracle-$scenario" "$work/static-$mode-$scenario"
        done
        run_capture "$work/static-$mode-profile.stdout" chroot "$root" /consumer profile
        check_profile "$work/static-$mode-profile"
    done
fi

for mode in pie non-pie; do
    candidate="$work/dynamic-$mode"
    step="link dynamic $mode"
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$candidate"
    validate_sealed_link "$installed" "$work/workload.o" "$candidate" "$candidate.crabc-link.json" "$mode"
    root="$work/dynamic-$mode-root"
    mkdir -p "$root"
    cp -a "$installed/." "$root/"
    cp "$candidate" "$root/consumer"
    for entry in kernel direct; do
        command=(/consumer)
        [ "$entry" = kernel ] || command=("$interpreter" /consumer)
        for scenario in "${scenarios[@]}"; do
            run_capture "$work/dynamic-$mode-$entry-$scenario.stdout" \
                chroot "$root" "${command[@]}" "$scenario"
            compare_oracle "$work/oracle-$scenario" "$work/dynamic-$mode-$entry-$scenario"
        done
        run_capture "$work/dynamic-$mode-$entry-profile.stdout" chroot "$root" "${command[@]}" profile
        check_profile "$work/dynamic-$mode-$entry-profile"
    done
done

# Allocator interposition compares each dynamic mode with the same pinned
# musl executable kind; static archives cannot replace their one-CGU owners.
for mode in pie non-pie; do
    if [ "$mode" = pie ]; then
        oracle_flags=(-fPIE -pie)
    else
        oracle_flags=(-fno-pie -no-pie)
    fi
    step="link interposition $mode"
    "$oracle_cc" -std=c11 "${oracle_flags[@]}" -rdynamic "$work/interposition.o" \
        -Wl,--dynamic-linker,"$musl_interpreter" -o "$work/interpose-oracle-$mode"
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" -rdynamic "$work/interposition.o" \
        -o "$work/interpose-candidate-$mode"
    assert_exported_interposers "$work/interpose-oracle-$mode" "$work/interpose-oracle-$mode.symbols"
    assert_exported_interposers "$work/interpose-candidate-$mode" "$work/interpose-candidate-$mode.symbols"

    oracle_root="$work/interpose-oracle-$mode-root"
    mkdir -p "$oracle_root/lib"
    cp /opt/musl-1.2.6/lib/libc.so "$oracle_root$musl_interpreter"
    ln -s ld-musl-x86_64.so.1 "$oracle_root/lib/libc.so"
    cp "$work/interpose-oracle-$mode" "$oracle_root/consumer"
    candidate_root="$work/interpose-candidate-$mode-root"
    mkdir -p "$candidate_root"
    cp -a "$installed/." "$candidate_root/"
    cp "$work/interpose-candidate-$mode" "$candidate_root/consumer"
    for scenario in "${interposition_scenarios[@]}"; do
        oracle_prefix="$work/interpose-oracle-$mode-$scenario"
        run_capture "$oracle_prefix.stdout" chroot "$oracle_root" /consumer "$scenario"
        grep -qx "owned-c-abi-compat-interpose-$scenario-ok" "$oracle_prefix.stdout" ||
            fail "pinned musl did not complete interposition $scenario"
        for entry in kernel direct; do
            command=(/consumer)
            [ "$entry" = kernel ] || command=("$interpreter" /consumer)
            candidate_prefix="$work/interpose-candidate-$mode-$entry-$scenario"
            run_capture "$candidate_prefix.stdout" chroot "$candidate_root" "${command[@]}" "$scenario"
            compare_oracle "$oracle_prefix" "$candidate_prefix"
        done
    done
done

if [ -n "$static_product" ]; then
    retain_link_identities static static-pie pie non-pie
    matrix='static/static-PIE plus dynamic PIE/non-PIE kernel/direct'
else
    retain_link_identities pie non-pie
    matrix='dynamic PIE/non-PIE kernel/direct'
fi
trap - ERR
printf 'owned C ABI compatibility: PASS (installed objects through pinned musl; %s; search/queue/hash, qsort helper, gettext, diagnostics, allocation policy, documented DES/catalog profile, and dynamic public-allocator interposition traces); evidence: %s\n' \
    "$matrix" "$work"
