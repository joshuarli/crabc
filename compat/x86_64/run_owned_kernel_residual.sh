#!/usr/bin/env bash
# Pinned-musl differential for residual system.kernel-admin C spellings.
#
# One installed-driver object calls the eighteen names that are deliberately
# outside the existing linux-control, syslog, and system-cancellation cases.
# It is linked first to musl, then unchanged to each static/dynamic product.
# Each selector has a private process/root boundary, retains raw status and
# streams, and compares them to the pinned reference.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_kernel_residual_probe.c"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1
readonly OWNED_SYMBOLS='__sched_cpucount confstr fpathconf getdtablesize gethostid membarrier pathconf personality prctl sched_getparam sched_getscheduler sched_setparam sched_setscheduler setdomainname sethostname syscall sysconf ulimit'
readonly CASES=(
    cpucount
    configuration
    sysconf-signal-stack
    hostid-membarrier
    personality
    prctl
    scheduler
    syscall
    ulimit
    uts-namespace
    uts-seccomp
    all
)

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
    raise SystemExit('owned kernel residual TMPDIR must be a physical checkout .work directory')
if static_argument:
    product = Path(static_argument)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('owned kernel residual static product must be a checkout .work directory')
if dynamic_argument:
    product = Path(dynamic_argument)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('owned kernel residual product must be a checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-kernel-residual.XXXXXX")"
chmod a+rx "$work"
printf 'owned kernel residual evidence: %s\n' "$work"

run_in_root() {
    local root="$1" output="$2" status
    shift 2
    if timeout 30 env -i PATH="$PATH" chroot "$root" "$@" \
        >"$output" 2>"${output%.stdout}.stderr"; then
        status=0
    else
        status=$?
    fi
    printf '%s\n' "$status" >"${output%.stdout}.status"
    return "$status"
}

run_case_in_root() {
    local root="$1" label="$2" selector="$3" output
    shift 3
    output="$work/$label-$selector.stdout"
    if ! run_in_root "$root" "$output" "$@" /consumer "$selector"; then
        printf 'owned kernel residual %s %s: child failed\n' "$label" "$selector" >&2
        return 1
    fi
    if ! grep -qx "owned-kernel-residual-$selector-ok" "$output"; then
        printf 'owned kernel residual %s %s: success marker missing\n' "$label" "$selector" >&2
        return 1
    fi
}

compare_case_output() {
    local label="$1" selector="$2"
    cmp "$work/oracle-$selector.status" "$work/$label-$selector.status"
    cmp "$work/oracle-$selector.stdout" "$work/$label-$selector.stdout"
    cmp "$work/oracle-$selector.stderr" "$work/$label-$selector.stderr"
}

run_oracle_cases() {
    local selector
    for selector in "${CASES[@]}"; do
        run_case_in_root "$work/oracle-root" oracle "$selector"
    done
}

assert_static_symbols() {
    local archive="$1" table symbol
    table="$work/static-symbols.txt"
    nm -g --defined-only "$archive" >"$table"
    for symbol in $OWNED_SYMBOLS; do
        [ "$(awk -v symbol="$symbol" '$3 == symbol && ($2 == "T" || $2 == "W") { count++ } END { print count + 0 }' "$table")" -eq 1 ] || {
            printf 'owned kernel residual: static symbol missing or duplicate: %s\n' "$symbol" >&2
            return 1
        }
    done
}

assert_dynamic_symbols() {
    local shared="$1" table symbol
    table="$work/dynamic-symbols.txt"
    readelf --dyn-syms -W "$shared" >"$table"
    for symbol in $OWNED_SYMBOLS; do
        [ "$(awk -v symbol="$symbol" '$4 == "FUNC" && ($5 == "GLOBAL" || $5 == "WEAK") && $6 == "DEFAULT" && $7 != "UND" && $8 == symbol { count++ } END { print count + 0 }' "$table")" -eq 1 ] || {
            printf 'owned kernel residual: dynamic symbol missing or duplicate: %s\n' "$symbol" >&2
            return 1
        }
    done
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
    raise SystemExit(f"owned kernel residual link evidence: {error}") from error
if output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.is_symlink():
    raise SystemExit("owned kernel residual link evidence output is unsafe")
with output.open("x", encoding="utf-8", newline="\n") as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
}

bind_dynamic_inputs() {
    local object="$1" initial_source_sha256="$2" identity="$3" binding="$4"

    python3 -B - "$PROBE" "$object" "$initial_source_sha256" "$identity" "$binding" <<'PY'
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
    raise SystemExit("owned kernel residual dynamic identity drifted")

def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()

if digest(source_path) != initial_source_sha256:
    raise SystemExit("owned kernel residual workload source changed before dynamic binding")
if digest(workload_path) != identity["workload_sha256"]:
    raise SystemExit("owned kernel residual dynamic identity names another workload object")
record = {
    "schema": 1,
    "format": "crabc-x86-64-owned-kernel-residual-dynamic-binding-v1",
    "source": {"path": str(source_path), "sha256": initial_source_sha256},
    "workload": {"path": str(workload_path), "sha256": identity["workload_sha256"]},
    "product": {
        "root": identity["product"],
        "format": identity["product_format"],
        "manifest_sha256": identity["product_manifest_sha256"],
    },
}
path = Path(binding_path)
if path.exists() or path.is_symlink():
    if path.is_symlink() or not path.is_file() or json.loads(path.read_text(encoding="utf-8")) != record:
        raise SystemExit("owned kernel residual dynamic source, product, or object binding drifted")
elif not path.parent.is_dir() or path.parent.is_symlink():
    raise SystemExit("owned kernel residual dynamic binding output is unsafe")
else:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write("\n")
if digest(source_path) != initial_source_sha256:
    raise SystemExit("owned kernel residual dynamic source, product, or object binding drifted")
PY
}

run_static_mode() {
    local product="$1" mode="$2" candidate receipt root selector failures=0
    candidate="$work/consumer-static-$mode"
    receipt="$candidate.receipt.json"
    (cd "$work" && "$product/bin/crabc-cc" "-$mode" \
        --link-receipt "$(basename "$receipt")" "$work/workload.o" -o "$candidate")
    audit_owned_link "$product" "$work/workload.o" "$candidate" "$receipt" "$mode" \
        "$work/static-$mode-link-evidence.json"
    root="$work/static-$mode-root"
    mkdir "$root"
    cp "$candidate" "$root/consumer"
    for selector in "${CASES[@]}"; do
        if ! run_case_in_root "$root" "static-$mode" "$selector"; then
            failures=1
            continue
        fi
        if ! compare_case_output "static-$mode" "$selector"; then
            printf 'owned kernel residual static-%s %s: raw result differs from pinned musl\n' \
                "$mode" "$selector" >&2
            failures=1
        fi
    done
    [ "$failures" -eq 0 ]
}

run_dynamic_mode() {
    local product="$1" mode="$2" entry="$3" candidate receipt identity root selector output failures=0
    candidate="$work/consumer-dynamic-$mode"
    receipt="$candidate.crabc-link.json"
    if [ ! -f "$candidate" ]; then
        "$product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$candidate"
        readelf -hW "$candidate" >"$work/consumer-dynamic-$mode.header"
        readelf -lW "$candidate" >"$work/consumer-dynamic-$mode.segments"
        readelf -dW "$candidate" >"$work/consumer-dynamic-$mode.dynamic"
    fi
    identity="$work/dynamic-$mode-$entry-link-evidence.json"
    audit_owned_link "$product" "$work/workload.o" "$candidate" "$receipt" "$mode" "$identity"
    bind_dynamic_inputs "$work/workload.o" "$source_sha256_before_compile" \
        "$identity" "$work/dynamic-input-binding.json"
    root="$work/dynamic-$mode-$entry-root"
    cp -a "$product" "$root"
    cp "$candidate" "$root/consumer"
    for selector in "${CASES[@]}"; do
        output="$work/dynamic-$mode-$entry-$selector.stdout"
        if [ "$entry" = direct ]; then
            if ! run_in_root "$root" "$output" "$INTERPRETER" /consumer "$selector"; then
                printf 'owned kernel residual dynamic-%s-%s %s: child failed\n' \
                    "$mode" "$entry" "$selector" >&2
                failures=1
                continue
            fi
        elif ! run_in_root "$root" "$output" /consumer "$selector"; then
            printf 'owned kernel residual dynamic-%s-%s %s: child failed\n' \
                "$mode" "$entry" "$selector" >&2
            failures=1
            continue
        fi
        if ! grep -qx "owned-kernel-residual-$selector-ok" "$output"; then
            printf 'owned kernel residual dynamic-%s-%s %s: success marker missing\n' \
                "$mode" "$entry" "$selector" >&2
            failures=1
            continue
        fi
        if ! compare_case_output "dynamic-$mode-$entry" "$selector"; then
            printf 'owned kernel residual dynamic-%s-%s %s: raw result differs from pinned musl\n' \
                "$mode" "$entry" "$selector" >&2
            failures=1
        fi
    done
    [ "$failures" -eq 0 ]
}

bash "$ROOT/compat/x86_64/run_musl_oracle.sh" >/dev/null
"$ORACLE_CC" -std=c11 -I"$ROOT/include" -E -H "$PROBE" \
    >/dev/null 2>"$work/oracle.headers"
for header in errno.h sched.h signal.h sys/auxv.h sys/membarrier.h sys/personality.h sys/prctl.h sys/resource.h sys/syscall.h ulimit.h unistd.h; do
    grep -Fq "$ROOT/include/$header" "$work/oracle.headers"
done

if [ "$dynamic_was_supplied" -eq 0 ]; then
    provided_dynamic="$work/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
readonly installed="$provided_dynamic"

# This is the sole behavior workload object. The static pinned-musl reference
# is linked from it before every candidate uses identical bytes.
source_sha256_before_compile="$(sha256sum "$PROBE" | awk '{ print $1 }')"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"
if [ "$source_sha256_before_compile" != "$(sha256sum "$PROBE" | awk '{ print $1 }')" ]; then
    printf 'owned kernel residual: workload source changed while compiling its bound object\n' >&2
    exit 1
fi
"$ORACLE_CC" -static -fno-pie -no-pie "$work/workload.o" -o "$work/oracle"
mkdir "$work/oracle-root"
cp "$work/oracle" "$work/oracle-root/consumer"
run_oracle_cases
printf 'owned kernel residual pinned-musl oracle: PASS\n'

static_product=''
if [ "$static_was_supplied" -eq 1 ]; then
    static_product="$provided_static"
elif [ "$dynamic_was_supplied" -eq 0 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-product" >"$work/static-build.json"
    static_product="$work/static-product"
fi
if [ -n "$static_product" ]; then
    assert_static_symbols "$static_product/usr/lib/libc.a"
    run_static_mode "$static_product" static
    run_static_mode "$static_product" static-pie
    if [ "$static_was_supplied" -eq 1 ] && [ "$dynamic_was_supplied" -eq 1 ]; then
        matrix='provided static/static-PIE plus provided dynamic PIE/non-PIE kernel/direct'
    else
        matrix='static/static-PIE plus dynamic PIE/non-PIE kernel/direct'
    fi
else
    matrix='provided dynamic PIE/non-PIE kernel/direct'
fi

assert_dynamic_symbols "$installed/usr/lib/libc.so"
for mode in pie non-pie; do
    for entry in kernel direct; do
        run_dynamic_mode "$installed" "$mode" "$entry"
    done
done

printf 'owned kernel residual: PASS (same project-header object with pinned musl; configuration, scheduler ENOSYS/output preservation, host identity, membarrier, personality, variadic prctl/syscall/ulimit, and private UTS/seccomp negatives; %s); evidence: %s\n' "$matrix" "$work"
