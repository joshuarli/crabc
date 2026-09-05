#!/usr/bin/env bash
# Installed clone/vfork/daemon behavior against pinned musl 1.2.6.
#
# One C object compiled through the installed dynamic driver is linked by the
# pinned musl oracle and every selected owned product mode. The three probe
# scenarios retain raw stdout, stderr, and process status before their existing
# exact stream comparison is accepted.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_process_trio_probe.c"
readonly interpreter=/lib/ld-crabc-x86_64.so.1
declare -a link_identity_records=()

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned process trio: %s\n' "$*" >&2
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

# Supplied paths must name contained physical products before this runner makes
# its disposable evidence directory. The shared validator below separately
# checks each product payload again while binding every output receipt.
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
static_product = Path(sys.argv[3]) if sys.argv[3] else None
dynamic_product = Path(sys.argv[4]) if sys.argv[4] else None
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('process-trio TMPDIR must be a physical checkout .work directory')
for product, name in ((static_product, 'static'), (dynamic_product, 'dynamic')):
    if product and (not product.is_dir() or not product.is_relative_to(root / '.work')):
        raise SystemExit(f'process-trio {name} product must be a checkout .work directory')
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
        raise SystemExit(f'process-trio has an unknown product family: {family}')
except ProductEvidenceError as error:
    raise SystemExit(f'process-trio {family} product payload is invalid: {error}') from error
PY
}

if [ "$static_was_supplied" -eq 1 ]; then
    validate_product_payload "$provided_static" static
fi
if [ "$dynamic_was_supplied" -eq 1 ]; then
    validate_product_payload "$provided_dynamic" dynamic
fi

readonly work="$(mktemp -d "$TMPDIR/owned-process-trio.XXXXXX")"
chmod a+rx "$work"
printf 'process-trio evidence: %s\n' "$work"

run_capture() {
    local output="$1" status
    shift

    if timeout 20 env -i PATH="$PATH" "$@" >"$output" 2>"${output%.stdout}.stderr"; then
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

assert_static_symbols() {
    local archive="$1" symbols="$2" symbol

    nm -g --defined-only "$archive" >"$symbols"
    for symbol in clone vfork daemon; do
        [ "$(awk -v name="$symbol" '$2 == "T" && $3 == name { count++ } END { print count + 0 }' "$symbols")" -eq 1 ] ||
            fail "static archive does not provide exactly one strong ${symbol}"
    done
}

assert_dynamic_symbols() {
    local library="$1" symbols="$2" symbol

    readelf --dyn-syms -W "$library" >"$symbols"
    for symbol in clone vfork daemon; do
        [ "$(awk -v name="$symbol" '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == name { count++ } END { print count + 0 }' "$symbols")" -eq 1 ] ||
            fail "shared libc does not provide exactly one global-default ${symbol}"
    done
}

# The common validator owns both receipt schemas. Persisting its return value
# retains the exact product, workload, output, and receipt identities used for
# each executable; it also proves the static no-DSO boundary and the dynamic
# no-foreign-import/application-DSO boundary before a process executes.
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
from owned_posix_product_evidence import ProductEvidenceError
from owned_posix_product_evidence import validate_link

try:
    identity = validate_link(
        Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), sys.argv[6]
    )
except ProductEvidenceError as error:
    raise SystemExit(f'process-trio sealed link evidence: {error}') from error
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
    raise SystemExit('retained process-trio link identities have no expected modes')
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
    raise SystemExit('retained process-trio link identities omit a product mode')
Path(sys.argv[1]).write_text(
    json.dumps(
        {
            'schema': 'crabc.x86_64-owned-process-trio-link-identities/v1',
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

"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$probe" -o "$work/workload.o"
"$oracle_cc" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"
prepare_root "$work/oracle-root"
for scenario in ordinary errors redirect; do
    cp "$work/oracle" "$work/oracle-root/consumer"
    run_capture "$work/oracle-$scenario.stdout" \
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
    assert_static_symbols "$static_product/usr/lib/libc.a" "$work/static-symbols.txt"
    for mode in static static-pie; do
        candidate="$work/static-$mode"
        receipt="$candidate.receipt.json"
        (
            cd "$work"
            "$static_product/bin/crabc-cc" "-$mode" \
                --link-receipt "$(basename "$receipt")" "$work/workload.o" -o "$candidate"
        )
        validate_sealed_link "$static_product" "$work/workload.o" "$candidate" "$receipt" "$mode"
        root="$work/static-$mode-root"
        prepare_root "$root"
        cp "$candidate" "$root/consumer"
        for scenario in ordinary errors redirect; do
            run_capture "$work/static-$mode-$scenario.stdout" \
                chroot "$root" /consumer "$scenario"
            compare_oracle "static-$mode" "$scenario"
        done
    done
fi

assert_dynamic_symbols "$installed/usr/lib/libc.so" "$work/dynamic-symbols.txt"
for mode in pie non-pie; do
    candidate="$work/dynamic-$mode"
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$candidate"
    receipt="$candidate.crabc-link.json"
    validate_sealed_link "$installed" "$work/workload.o" "$candidate" "$receipt" "$mode"
    root="$work/dynamic-$mode-root"
    mkdir -p "$root"
    cp -a "$installed/." "$root/"
    prepare_root "$root"
    cp "$candidate" "$root/consumer"
    for scenario in ordinary errors redirect; do
        run_capture "$work/dynamic-$mode-kernel-$scenario.stdout" \
            chroot "$root" /consumer "$scenario"
        compare_oracle "dynamic-$mode-kernel" "$scenario"
        run_capture "$work/dynamic-$mode-direct-$scenario.stdout" \
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
printf 'owned process trio: PASS (one installed object through pinned musl; %s; worker/child clone lifecycle and robust lists, vfork shared memory/exec, daemon redirection/lifecycle, syscall-error rollback; raw status/stdout/stderr and sealed link identities retained); evidence: %s\n' \
    "$matrix" "$work"
