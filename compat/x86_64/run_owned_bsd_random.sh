#!/usr/bin/env bash
# Installed BSD random-family evidence against pinned musl 1.2.6.
#
# The installed dynamic driver emits one C object.  Pinned musl and every
# supplied owned product link that exact object; single-thread traces compare
# raw status/stdout/stderr.  Both implementations also execute the concurrent
# scenarios, whose probes assert only schedule-independent invariants.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_bsd_random_probe.c"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1
readonly -a BSD_RANDOM_SYMBOLS=(random srandom initstate setstate)
readonly -a ORACLE_SCENARIOS=(core state fork-active)
# Kept as a named class because these are invariant witnesses rather than an
# ordered trace.  Unlike the old candidate-only rand witness, musl executes
# them too: each reports a scheduler-independent pass record.
readonly -a CANDIDATE_ONLY_SCENARIOS=(concurrent-random concurrent-state)
readonly -a ALL_SCENARIOS=("${ORACLE_SCENARIOS[@]}" "${CANDIDATE_ONLY_SCENARIOS[@]}")

usage() {
    printf 'usage: %s [--extracted] --static-sysroot STATIC_SYSROOT DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned BSD random: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -sm)" = 'Linux x86_64' ] || fail 'requires native Linux/x86-64'
[ -x "$ORACLE_CC" ] || fail 'missing pinned musl compiler'
[ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] || fail 'TMPDIR must be checkout-local .work storage'

extracted=0
static_product=''
dynamic_product=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --extracted)
            [ "$extracted" -eq 0 ] || usage
            extracted=1
            shift
            ;;
        --static-sysroot)
            [ -z "$static_product" ] && [ "$#" -ge 2 ] && [ -n "$2" ] || usage
            case "$2" in -*) usage ;; esac
            static_product="$2"
            shift 2
            ;;
        -*|'')
            usage
            ;;
        *)
            [ -z "$dynamic_product" ] || usage
            dynamic_product="$1"
            shift
            ;;
    esac
done
[ -n "$static_product" ] && [ -n "$dynamic_product" ] || usage

# Reject lexical traversal and bind both inputs to physical checkout .work
# products before the product validators inspect their contents.
python3 -B - "$ROOT" "$static_product" "$dynamic_product" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
for raw, name in ((sys.argv[2], 'static product'), (sys.argv[3], 'dynamic product'),
                  (sys.argv[4], 'TMPDIR')):
    lexical = Path(raw)
    if any(part == '..' for part in lexical.parts):
        raise SystemExit(f'owned BSD random {name} must be a physical checkout .work directory')
    candidate = lexical if lexical.is_absolute() else Path.cwd() / lexical
    if not candidate.is_dir() or candidate.resolve() != candidate:
        raise SystemExit(f'owned BSD random {name} is not a physical directory')
    if not candidate.resolve().is_relative_to(root / '.work'):
        raise SystemExit(f'owned BSD random {name} must be a checkout .work directory')
PY
static_product="$(realpath "$static_product")"
dynamic_product="$(realpath "$dynamic_product")"
[ "$static_product" != "$dynamic_product" ] || fail 'static and dynamic products must differ'

validate_product() {
    local product="$1" family="$2"

    python3 -B - "$ROOT" "$product" "$family" <<'PY'
from pathlib import Path
import sys

root, product, family = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, str(root / 'compat/x86_64'))
from owned_posix_product_evidence import (
    ProductEvidenceError,
    _validate_dynamic_product,
    _validate_static_product,
)

try:
    if family == 'static':
        _validate_static_product(product)
    else:
        _validate_dynamic_product(product)
except ProductEvidenceError as error:
    raise SystemExit(f'owned BSD random {family} product is invalid: {error}') from error
PY
}

validate_product "$static_product" static
validate_product "$dynamic_product" dynamic

readonly work="$(mktemp -d "$TMPDIR/owned-bsd-random.XXXXXX")"
chmod a+rx "$work"

run_capture() {
    local label="$1" status
    shift
    if timeout 45 env -i PATH="$PATH" TZ=UTC "$@" >"$work/$label.stdout" 2>"$work/$label.stderr"; then
        status=0
    else
        status=$?
    fi
    printf '%s\n' "$status" >"$work/$label.status"
    [ "$status" -eq 0 ] || fail "expected success for $label, got $status"
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

validate_sealed_link() {
    local product="$1" workload="$2" executable="$3" receipt="$4" linkage="$5" label="$6"

    python3 -B - "$ROOT" "$product" "$workload" "$executable" "$receipt" "$linkage" \
        >"$work/$label.link-identity.json" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
sys.path.insert(0, str(root / 'compat/x86_64'))
from owned_posix_product_evidence import ProductEvidenceError, validate_link

try:
    record = validate_link(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]),
                           Path(sys.argv[5]), sys.argv[6])
except ProductEvidenceError as error:
    raise SystemExit(f'owned BSD random link receipt is invalid: {error}') from error
json.dump(record, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write('\n')
PY
}

assert_provider_symbols() {
    local artifact="$1" selector="$2" report="$3"

    if [ "$selector" = nm ]; then
        nm -g --defined-only "$artifact" >"$report"
    else
        readelf --dyn-syms -W "$artifact" >"$report"
    fi
    python3 -B - "$report" "$selector" "${BSD_RANDOM_SYMBOLS[@]}" <<'PY'
from collections import Counter
from pathlib import Path
import sys

lines = Path(sys.argv[1]).read_text(encoding='utf-8').splitlines()
selector = sys.argv[2]
expected = Counter({symbol: 1 for symbol in sys.argv[3:]})
actual = Counter()
for line in lines:
    fields = line.split()
    if selector == 'nm' and len(fields) == 3 and fields[1] == 'T' and fields[2] in expected:
        actual[fields[2]] += 1
    if selector == 'readelf' and len(fields) == 8 and fields[3:6] == ['FUNC', 'GLOBAL', 'DEFAULT'] \
            and fields[6] != 'UND' and fields[7] in expected:
        actual[fields[7]] += 1
if actual != expected:
    raise SystemExit(f'owned BSD random provider definitions drifted: {actual!r}')
PY
}

run_oracle_scenarios() {
    local scenario root
    for scenario in "${ALL_SCENARIOS[@]}"; do
        root="$work/oracle-$scenario-root"
        prepare_empty_root "$root"
        cp "$work/oracle" "$root/consumer"
        run_capture "oracle-$scenario" chroot "$root" /consumer "$scenario"
    done
}

run_static_scenarios() {
    local label="$1" candidate="$2" scenario root
    for scenario in "${ALL_SCENARIOS[@]}"; do
        root="$work/$label-$scenario-root"
        prepare_empty_root "$root"
        cp "$candidate" "$root/consumer"
        run_capture "$label-$scenario" chroot "$root" /consumer "$scenario"
        compare_oracle "$label" "$scenario"
    done
}

run_dynamic_scenarios() {
    local label="$1" candidate="$2" scenario root entry
    for scenario in "${ALL_SCENARIOS[@]}"; do
        root="$work/$label-$scenario-root"
        mkdir -p "$root"
        cp -a "$dynamic_product/." "$root/"
        prepare_empty_root "$root"
        cp "$candidate" "$root/consumer"
        for entry in kernel direct; do
            if [ "$entry" = kernel ]; then
                run_capture "$label-$entry-$scenario" chroot "$root" /consumer "$scenario"
            else
                run_capture "$label-$entry-$scenario" chroot "$root" "$INTERPRETER" /consumer "$scenario"
            fi
            compare_oracle "$label-$entry" "$scenario"
        done
    done
}

# Source and pinned-musl header witnesses prove that the same feature-selected
# declarations compile before the installed driver produces the common object.
"$ORACLE_CC" -std=c11 -D_BSD_SOURCE -fno-builtin -pthread -I"$ROOT/include" \
    -c "$PROBE" -o "$work/source-header.o"
"$ORACLE_CC" -std=c11 -D_BSD_SOURCE -fno-builtin -pthread \
    -c "$PROBE" -o "$work/oracle-header.o"
"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -D_BSD_SOURCE -fno-builtin \
    -pthread -c "$PROBE" -o "$work/workload.o"
"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"

assert_provider_symbols "$static_product/usr/lib/libc.a" nm "$work/static-symbols.txt"
assert_provider_symbols "$dynamic_product/usr/lib/libc.so" readelf "$work/dynamic-symbols.txt"
run_oracle_scenarios

# static-et-exec and static-pie both record a --link-receipt.  The installed
# dynamic driver seals its normal links beside each executable.
candidate="$work/static-et-exec"
receipt="$candidate.receipt.json"
(
    cd "$work"
    "$static_product/bin/crabc-cc" -static --link-receipt "$(basename "$receipt")" \
        "$work/workload.o" -o "$candidate"
)
validate_sealed_link "$static_product" "$work/workload.o" "$candidate" "$receipt" static static-et-exec
run_static_scenarios static-et-exec "$candidate"

candidate="$work/static-pie"
receipt="$candidate.receipt.json"
(
    cd "$work"
    "$static_product/bin/crabc-cc" -static-pie --link-receipt "$(basename "$receipt")" \
        "$work/workload.o" -o "$candidate"
)
validate_sealed_link "$static_product" "$work/workload.o" "$candidate" "$receipt" static-pie static-pie
run_static_scenarios static-pie "$candidate"

for mode in pie non-pie; do
    candidate="$work/dynamic-$mode"
    "$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$candidate"
    receipt="$candidate.crabc-link.json"
    validate_sealed_link "$dynamic_product" "$work/workload.o" "$candidate" "$receipt" "$mode" "dynamic-$mode"
    run_dynamic_scenarios "dynamic-$mode" "$candidate"
done

python3 -B - "$work/source-receipt.json" "$ROOT" "$PROBE" "$static_product" "$dynamic_product" "$work/workload.o" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

output, root, probe, static, dynamic, workload = map(Path, sys.argv[1:])
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
output.write_text(json.dumps({
    'schema': 'crabc.x86_64-owned-bsd-random-source/v1',
    'inputs': {
        'probe': {'path': str(probe), 'sha256': digest(probe)},
        'runner': {'path': str(root / 'compat/x86_64/run_owned_bsd_random.sh'),
                   'sha256': digest(root / 'compat/x86_64/run_owned_bsd_random.sh')},
        'port': {'path': str(root / 'libc/src/c_abi/x86_64/bsd_random.rs'),
                 'sha256': digest(root / 'libc/src/c_abi/x86_64/bsd_random.rs')},
        'installed_object': {'path': str(workload), 'sha256': digest(workload)},
    },
    'products': {
        'static_manifest_sha256': digest(static / 'share/crabc/manifest.json'),
        'dynamic_manifest_sha256': digest(dynamic / 'share/crabc/manifest.json'),
    },
}, indent=2, sort_keys=True) + '\n', encoding='utf-8')
PY
sha256sum "$PROBE" "$ROOT/compat/x86_64/run_owned_bsd_random.sh" \
    "$ROOT/libc/src/c_abi/x86_64/bsd_random.rs" >"$work/source-input.sha256"
matrix='static-et-exec/static-pie plus dynamic-pie-kernel/direct and dynamic-non-pie-kernel/direct'
if [ "$extracted" -eq 1 ]; then
    matrix="$matrix; extracted product route"
fi
printf 'owned BSD random: PASS (same installed-header object through pinned musl; %s; source/oracle/installed headers, reseed/default/state classes through 272 bytes, errno 0..7, pointer/buffer restoration, invariant concurrency, active-worker fork repair, provider symbols, link-receipt identities, and source receipt); evidence: %s\n' \
    "$matrix" "$work"
