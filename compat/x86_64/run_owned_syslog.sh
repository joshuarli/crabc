#!/usr/bin/env bash
# Pinned-musl syslog differential through sealed installed x86 products.
#
# The consumer binds /dev/log only after each invocation has entered its own
# disposable chroot.  Neither this runner nor the consumer writes host /dev.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_syslog_probe.c"
readonly interpreter=/lib/ld-crabc-x86_64.so.1

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
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
        -*)
            usage
            ;;
        *)
            [ "$dynamic_was_supplied" -eq 0 ] || usage
            [ -n "$1" ] || usage
            provided_dynamic="$1"
            dynamic_was_supplied=1
            shift
            ;;
    esac
done
[ "$(uname -sm)" = 'Linux x86_64' ]

if [ "$static_was_supplied" -eq 1 ]; then
    provided_static="$(realpath "$provided_static")"
fi
if [ "$dynamic_was_supplied" -eq 1 ]; then
    provided_dynamic="$(realpath "$provided_dynamic")"
fi

python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
static_argument = sys.argv[3]
dynamic_argument = sys.argv[4]
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned syslog TMPDIR must be a physical checkout .work directory')
if static_argument:
    product = Path(static_argument)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('owned syslog static product must be a checkout .work directory')
if dynamic_argument:
    product = Path(dynamic_argument)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('owned syslog product must be a checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-syslog.XXXXXX")"
chmod a+rx "$work"
printf 'owned syslog evidence: %s\n' "$work"

bash "$ROOT/compat/x86_64/run_musl_oracle.sh" >/dev/null

prepare_execution_root() {
    local root="$1"
    mkdir -p "$root/dev"
    : >"$root/dev/console"
}

run_in_root() {
    local root="$1" output="$2" status
    shift 2
    if timeout 40 env -i PATH="$PATH" TZ=UTC+12 chroot "$root" "$@" \
        >"$output" 2>"${output%.stdout}.stderr"; then
        status=0
    else
        status=$?
    fi
    printf '%s\n' "$status" >"${output%.stdout}.status"
    return "$status"
}

run_scenarios() {
    local execution_root="$1" consumer="$2" label="$3"
    local entry="${4:-kernel}" output scenario
    local -a command=("$consumer")

    if [ "$entry" = direct ]; then command=("$interpreter" "$consumer"); fi
    for scenario in normal worker fork cancellation; do
        # Each consumer clears a stale private socket name itself.  Resetting
        # the private regular console here makes LOG_CONS output observable
        # without relying on an ordering artifact from another scenario.
        : >"$execution_root/dev/console"
        printf 'owned syslog running %s/%s/%s\n' "$label" "$entry" "$scenario"
        output="$work/$label-$entry-$scenario.stdout"
        if ! run_in_root "$execution_root" "$output" "${command[@]}" "$scenario"; then
            printf 'owned syslog %s/%s/%s: child failed\n' "$label" "$entry" "$scenario" >&2
            return 1
        fi
        grep -qx "owned-syslog-$scenario-ok" "$output"
        if [ "$label" != oracle ]; then
            cmp "$work/oracle-kernel-$scenario.status" "${output%.stdout}.status"
            cmp "$work/oracle-kernel-$scenario.stdout" "$output"
            cmp "$work/oracle-kernel-$scenario.stderr" "${output%.stdout}.stderr"
        fi
    done
}

audit_consumer() {
    local family="$1" mode="$2" candidate="$3" receipt="$4" provider="$5"
    readelf -hW "$candidate" >"$candidate.header"
    readelf -lW "$candidate" >"$candidate.segments"
    readelf -dW "$candidate" >"$candidate.dynamic"
    readelf -sW "$candidate" >"$candidate.symbols"
    readelf -sW "$provider" >"$candidate.provider-symbols"
    python3 -B - "$family" "$mode" "$candidate" "$receipt" "$candidate.provider-symbols" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

family, mode, candidate_text, receipt_text, provider_symbols_text = sys.argv[1:]
candidate = Path(candidate_text)
receipt = json.loads(Path(receipt_text).read_text())

def require(value, message):
    if not value:
        raise SystemExit('owned syslog artifact: ' + message)

expected_format = (
    'crabc-x86-64-owned-dynamic-sysroot-v1'
    if family == 'dynamic' else 'crabc-x86-64-sealed-static-driver-v1'
)
require(receipt.get('schema') == 1 and receipt.get('format') == expected_format,
        'sealed driver receipt')
output_hash = receipt.get('output_sha256') if family == 'dynamic' else receipt.get('output', {}).get('sha256')
require(output_hash == hashlib.sha256(candidate.read_bytes()).hexdigest(),
        'output receipt hash')
header = Path(str(candidate) + '.header').read_text()
require('Advanced Micro Devices X86-64' in header, 'machine')
expected_type = 'DYN' if mode in ('pie', 'static-pie') else 'EXEC'
require(re.search(r'Type:\s+' + expected_type + r'\s', header), 'ELF mode')
segments = Path(str(candidate) + '.segments').read_text()
dynamic = Path(str(candidate) + '.dynamic').read_text()
interpreters = re.findall(r'Requesting program interpreter: ([^\]]+)\]', segments)
needed = re.findall(r'\(NEEDED\).*\[([^\]]+)\]', dynamic)
require(interpreters == (['/lib/ld-crabc-x86_64.so.1'] if family == 'dynamic' else []),
        'interpreter boundary')
require(needed == (['libc.so'] if family == 'dynamic' else []),
        'owned runtime dependencies')
require('(TEXTREL)' not in dynamic, 'text relocations')
symbols = Path(str(candidate) + '.symbols').read_text()
for name in ('closelog', 'openlog', 'setlogmask', 'syslog', 'vsyslog'):
    require(re.search(r'\b' + name + r'$', symbols, re.M), 'linked provider ' + name)
# A static consumer incorporates the weak definition. A dynamic consumer
# correctly retains an undefined import, so inspect its installed libc
# provider rather than incorrectly requiring the executable to define it.
provider_symbols = Path(provider_symbols_text).read_text()
require(re.search(r'\bWEAK\s+\w+\s+\w+\s+vsyslog$', provider_symbols, re.M),
        'weak vsyslog alias')
PY
}

audit_owned_link() {
    local product="$1" object="$2" candidate="$3" receipt="$4" linkage="$5" identity="$6"

    python3 -B - "$ROOT" "$product" "$object" "$candidate" "$receipt" "$linkage" "$identity" <<'PY'
import json
from pathlib import Path
import sys

root, product, workload, executable, receipt = map(Path, sys.argv[1:6])
linkage = sys.argv[6]
output = Path(sys.argv[7])
sys.path.insert(0, str(root / "compat/x86_64"))
from owned_posix_product_evidence import ProductEvidenceError, validate_link

try:
    record = validate_link(product, workload, executable, receipt, linkage)
except ProductEvidenceError as error:
    raise SystemExit(f"owned syslog link evidence: {error}") from error
if output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.is_symlink():
    raise SystemExit("owned syslog link evidence output is unsafe")
with output.open("x", encoding="utf-8", newline="\n") as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
}

bind_workload_object() {
    local initial_source_sha256="$1" identity="$2" binding="$3"

    python3 -B - "$probe" "$work/workload.o" "$initial_source_sha256" "$identity" "$binding" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

source, workload, initial_source_sha256, identity_path, binding_path = sys.argv[1:]
source_path = Path(source).resolve(strict=True)
workload_path = Path(workload).resolve(strict=True)
identity = json.loads(Path(identity_path).read_text(encoding="utf-8"))
expected_identity = {
    "linkage", "product", "product_format", "product_manifest_sha256",
    "workload_sha256", "executable_sha256", "receipt_sha256",
}
if not isinstance(identity, dict) or set(identity) != expected_identity:
    raise SystemExit("owned syslog link identity drifted")

def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()

if digest(source_path) != initial_source_sha256:
    raise SystemExit("owned syslog workload source changed before binding")
if digest(workload_path) != identity["workload_sha256"]:
    raise SystemExit("owned syslog receipt names another workload object")
record = {
    "schema": 1,
    "format": "crabc-x86-64-owned-syslog-workload-binding-v1",
    "source": {"path": str(source_path), "sha256": initial_source_sha256},
    "workload": {"path": str(workload_path), "sha256": identity["workload_sha256"]},
}
path = Path(binding_path)
if path.exists() or path.is_symlink():
    if path.is_symlink() or not path.is_file() or json.loads(path.read_text(encoding="utf-8")) != record:
        raise SystemExit("owned syslog workload object binding drifted")
elif not path.parent.is_dir() or path.parent.is_symlink():
    raise SystemExit("owned syslog workload binding output is unsafe")
else:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write("\n")
if digest(source_path) != initial_source_sha256:
    raise SystemExit("owned syslog workload object binding drifted")
PY
}

link_product() {
    local family="$1" product="$2" mode="$3"
    local driver entry label candidate receipt identity execution_root

    if [ "$family" = static ]; then
        driver="$product/bin/crabc-cc"
        entry="-$mode"
        label="static-$mode"
    else
        driver="$product/bin/crabc-cc-dynamic"
        entry="--dynamic-$mode"
        label="dynamic-$mode"
    fi
    candidate="$work/$label-consumer"
    if [ "$family" = static ]; then
        receipt="$candidate.receipt.json"
        (cd "$work" && "$driver" "$entry" --link-receipt "$(basename "$receipt")" \
            "$work/workload.o" -o "$candidate")
    else
        receipt="$candidate.crabc-link.json"
        (cd "$work" && "$driver" "$entry" "$work/workload.o" -o "$candidate")
    fi
    if [ "$family" = static ]; then
        audit_consumer "$family" "$mode" "$candidate" "$receipt" "$candidate"
    else
        audit_consumer "$family" "$mode" "$candidate" "$receipt" "$product/usr/lib/libc.so"
    fi
    identity="$work/$label-link-evidence.json"
    audit_owned_link "$product" "$work/workload.o" "$candidate" "$receipt" "$mode" "$identity"
    bind_workload_object "$source_sha256_before_compile" "$identity" \
        "$work/workload-object-binding.json"
    execution_root="$work/$label-root"
    cp -a "$product" "$execution_root"
    prepare_execution_root "$execution_root"
    cp "$candidate" "$execution_root/consumer"
    run_scenarios "$execution_root" /consumer "$label"
    if [ "$family" = dynamic ]; then
        run_scenarios "$execution_root" /consumer "$label" direct
    fi
    printf 'owned syslog %s: PASS\n' "$label"
}

if [ "$dynamic_was_supplied" -eq 0 ]; then
    provided_dynamic="$work/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
readonly installed="$provided_dynamic"

# Match the installed dynamic driver's fixed source translator, header
# boundary, and preprocessor-relevant compile flags before it produces the one
# workload object below.
/usr/bin/gcc -std=c11 -nostdinc -isystem "$installed/usr/include" \
    -ffreestanding -fno-builtin -fno-stack-protector -fPIE -E -H "$probe" \
    >/dev/null 2>"$work/installed.headers"
for header in errno.h fcntl.h poll.h pthread.h sys/socket.h sys/un.h sys/wait.h syslog.h time.h unistd.h; do
    grep -Fq "$installed/usr/include/$header" "$work/installed.headers"
done

# This is the sole behavior workload object. The dynamic driver's supported
# PIE compile path has no absolute 32-bit relocations, then its exact bytes
# cross into musl and every sealed static/dynamic link.
source_sha256_before_compile="$(sha256sum "$probe" | awk '{ print $1 }')"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin -fno-stack-protector \
    -c "$probe" -o "$work/workload.o"
if [ "$source_sha256_before_compile" != "$(sha256sum "$probe" | awk '{ print $1 }')" ]; then
    printf 'owned syslog: workload source changed while compiling its bound object\n' >&2
    exit 1
fi
sha256sum "$work/workload.o" >"$work/workload.sha256"
if readelf -rW "$work/workload.o" | grep -Eq 'R_X86_64_(32|32S)'; then
    printf 'owned syslog: installed PIE workload object has an absolute 32-bit relocation\n' >&2
    exit 1
fi

mkdir "$work/oracle-root"
prepare_execution_root "$work/oracle-root"
"$oracle_cc" -static -fno-pie -no-pie -pthread "$work/workload.o" \
    -o "$work/oracle-root/consumer"
run_scenarios "$work/oracle-root" /consumer oracle
printf 'owned syslog pinned-musl oracle: PASS\n'

static_product=''
if [ "$static_was_supplied" -eq 1 ]; then
    static_product="$provided_static"
elif [ "$dynamic_was_supplied" -eq 0 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-product" >"$work/static-build.json"
    static_product="$work/static-product"
fi
if [ -n "$static_product" ]; then
    link_product static "$static_product" static
    link_product static "$static_product" static-pie
    if [ "$static_was_supplied" -eq 1 ] && [ "$dynamic_was_supplied" -eq 1 ]; then
        matrix='provided static/static-PIE plus provided dynamic PIE/non-PIE kernel/direct'
    else
        matrix='static/static-PIE plus dynamic PIE/non-PIE kernel/direct'
    fi
else
    matrix='provided dynamic PIE/non-PIE kernel/direct'
fi

link_product dynamic "$installed" pie
link_product dynamic "$installed" non-pie

printf 'owned syslog: PASS (same installed-header workload object with pinned musl; private AF_UNIX /dev/log and console, static/static-PIE/dynamic-PIE/non-PIE, main/worker/fork/deferred-cancellation, raw status/stdout/stderr, and shared-validator receipts; %s); evidence: %s\n' \
    "$matrix" "$work"
