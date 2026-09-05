#!/usr/bin/env bash
# Pinned-musl environment lifecycle differential through sealed x86 products.
#
# One installed-driver C object is linked to each candidate and the pinned musl
# reference. The allocation-failure subcase is self-contained in a disposable
# child that returns ENOMEM for future brk/mmap growth; it adds no production
# allocator hook or driver escape.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_environment_lifecycle_probe.c"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1
readonly NORMAL_SCENARIO=normal
readonly ALLOCATION_SCENARIO=allocation-failure
declare -a link_identity_records=()

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

provided_static=''
provided_dynamic=''
dynamic_was_supplied=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] || usage
            [ -z "$provided_static" ] || usage
            provided_static="$2"
            shift 2
            ;;
        --*)
            usage
            ;;
        *)
            [ -z "$provided_dynamic" ] || usage
            provided_dynamic="$1"
            dynamic_was_supplied=1
            shift
            ;;
    esac
done
if [ -n "$provided_static" ]; then
    provided_static="$(realpath -e "$provided_static")"
fi
if [ -n "$provided_dynamic" ]; then
    provided_dynamic="$(realpath -e "$provided_dynamic")"
fi

python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
static_product = Path(sys.argv[3]) if sys.argv[3] else None
dynamic_product = Path(sys.argv[4]) if sys.argv[4] else None
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / ".work"):
    raise SystemExit("owned environment-lifecycle TMPDIR must be a physical checkout .work directory")
for product, name in ((static_product, "static"), (dynamic_product, "dynamic")):
    if product and (not product.is_dir() or not product.is_relative_to(root / ".work")):
        raise SystemExit(
            f"owned environment-lifecycle {name} product must be a checkout .work directory"
        )
PY

readonly work="$(mktemp -d "$TMPDIR/owned-environment-lifecycle.XXXXXX")"
chmod a+rx "$work"
printf 'owned environment lifecycle evidence: %s\n' "$work"

fail() {
    printf 'owned environment lifecycle: %s\n' "$*" >&2
    exit 1
}

run_capture() {
    local output="$1"
    shift
    local status

    set +e
    timeout 40 env -i PATH="$PATH" "$@" >"$output" 2>"${output}.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"${output}.status"
    [ "$status" -eq 0 ] || fail "expected success, got ${status}: $*"
}

compare_oracle() {
    local label="$1" scenario="$2" root="$3"
    shift 3
    local output="$work/${label}-${scenario}.stdout"

    run_capture "$output" chroot "$root" "$@"
    cmp "$work/oracle-${scenario}.stdout" "$output" ||
        fail "stdout differs from pinned musl for ${label}/${scenario}"
    cmp "$work/oracle-${scenario}.stdout.stderr" "${output}.stderr" ||
        fail "stderr differs from pinned musl for ${label}/${scenario}"
    cmp "$work/oracle-${scenario}.stdout.status" "${output}.status" ||
        fail "status differs from pinned musl for ${label}/${scenario}"
}

# The common validator owns the receipt schemas. This runner records exactly
# its returned identity rather than duplicating a partial receipt audit.
validate_sealed_link() {
    local product="$1" workload="$2" executable="$3" receipt="$4" linkage="$5"
    local identity="$work/${linkage}.link-identity.json"

    python3 -B - "$ROOT" "$product" "$workload" "$executable" "$receipt" \
        "$linkage" >"$identity" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "compat" / "x86_64"))
from owned_posix_product_evidence import validate_link

identity = validate_link(
    Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), sys.argv[6]
)
json.dump(identity, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
PY
    link_identity_records+=("$linkage:$identity")
}

verify_retained_link_identity() {
    local product="$1" workload="$2" executable="$3" receipt="$4" linkage="$5" identity="$6"

    python3 -B - "$ROOT" "$product" "$workload" "$executable" "$receipt" \
        "$linkage" "$identity" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "compat" / "x86_64"))
from owned_posix_product_evidence import validate_link

expected = validate_link(
    Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), sys.argv[6]
)
try:
    received = json.loads(Path(sys.argv[7]).read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"retained link identity is unreadable: {error}") from error
if received != expected:
    raise SystemExit("retained link identity differs from shared validator")
PY
}

# Receipt/object/output tampering belongs to the validator's focused tests.
# This runner adds the boundary it introduces: the persisted identity itself
# must not be interchangeable with a different validator result.
assert_retained_identity_tampering_rejected() {
    local product="$1" workload="$2" executable="$3" receipt="$4" linkage="$5" identity="$6"
    local forged="$work/forged-${linkage}.link-identity.json" status

    cp "$identity" "$forged"
    python3 -B - "$forged" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
record = json.loads(path.read_text(encoding="utf-8"))
record["workload_sha256"] = "0" * 64
path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
    set +e
    verify_retained_link_identity "$product" "$workload" "$executable" "$receipt" \
        "$linkage" "$forged" >"$work/forged-${linkage}.stdout" \
        2>"$work/forged-${linkage}.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$work/forged-${linkage}.status"
    [ "$status" -ne 0 ] || fail "retained ${linkage} identity tampering was accepted"
    grep -Fxq 'retained link identity differs from shared validator' \
        "$work/forged-${linkage}.stderr" ||
        fail "retained ${linkage} identity tampering reported the wrong failure"
}

retain_link_identities() {
    python3 -B - "$work/link-identities.json" "${link_identity_records[@]}" <<'PY'
import json
from pathlib import Path
import sys

expected_fields = {
    "linkage", "product", "product_format", "product_manifest_sha256",
    "workload_sha256", "executable_sha256", "receipt_sha256",
}
records = {}
for item in sys.argv[2:]:
    linkage, raw_path = item.split(":", 1)
    if linkage in records:
        raise SystemExit(f"duplicate retained link identity: {linkage}")
    try:
        identity = json.loads(Path(raw_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"retained {linkage} identity is unreadable: {error}") from error
    if not isinstance(identity, dict) or set(identity) != expected_fields:
        raise SystemExit(f"retained {linkage} identity fields drifted")
    if identity["linkage"] != linkage:
        raise SystemExit(f"retained {linkage} identity linkage drifted")
    records[linkage] = identity
Path(sys.argv[1]).write_text(
    json.dumps({"schema": "crabc.x86_64-owned-posix-link-identities/v1", "links": records},
               sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
}

assert_static_providers() {
    local archive="$1" symbols="$2" symbol
    nm -g --defined-only "$archive" >"$symbols"
    for symbol in getenv setenv putenv unsetenv clearenv; do
        [ "$(awk -v name="$symbol" '$2 == "T" && $3 == name { count++ } END { print count + 0 }' "$symbols")" -eq 1 ] ||
            fail "static archive does not provide exactly one strong ${symbol}"
    done
    [ "$(awk '$2 ~ /^[BD]$/ && $3 == "__environ" { count++ } END { print count + 0 }' "$symbols")" -eq 1 ] ||
        fail "static archive does not provide one __environ object"
}

assert_dynamic_providers() {
    local library="$1" symbols="$2" symbol
    readelf --dyn-syms --wide "$library" >"$symbols"
    for symbol in getenv setenv putenv unsetenv clearenv; do
        [ "$(awk -v name="$symbol" '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == name { count++ } END { print count + 0 }' "$symbols")" -eq 1 ] ||
            fail "shared libc does not provide exactly one global-default ${symbol}"
    done
    for symbol in __environ environ _environ ___environ; do
        [ "$(awk -v name="$symbol" '$4 == "OBJECT" && $6 == "DEFAULT" && $7 != "UND" && $8 == name { count++ } END { print count + 0 }' "$symbols")" -eq 1 ] ||
            fail "shared libc does not provide exactly one environment object ${symbol}"
    done
}

if [ -z "$provided_dynamic" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$work/dynamic-product" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-product"
fi
readonly installed="$(realpath -e "$provided_dynamic")"

"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"
sha256sum "$work/workload.o" >"$work/workload.sha256"
[ "$(awk '{ print $1 }' "$work/workload.sha256")" = "$(sha256sum "$work/workload.o" | awk '{ print $1 }')" ] ||
    fail "installed-driver workload object digest changed before linking"

"$ORACLE_CC" -std=c11 -I"$installed/usr/include" -nostdinc \
    -E -H "$PROBE" >/dev/null 2>"$work/headers.trace"
for header in errno.h spawn.h stdlib.h sys/wait.h unistd.h; do
    grep -Fq "$installed/usr/include/$header" "$work/headers.trace" ||
        fail "workload did not use the installed ${header}"
done

mkdir "$work/oracle-root"
"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$work/workload.o" \
    -o "$work/oracle-root/consumer"
for scenario in "$NORMAL_SCENARIO" "$ALLOCATION_SCENARIO"; do
    command=(/consumer)
    [ "$scenario" = "$NORMAL_SCENARIO" ] || command+=("$scenario")
    run_capture "$work/oracle-${scenario}.stdout" \
        chroot "$work/oracle-root" "${command[@]}"
done

static_product=''
if [ -n "$provided_static" ]; then
    static_product="$provided_static"
elif [ "$dynamic_was_supplied" -eq 0 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-product" >"$work/static-build.json"
    static_product="$work/static-product"
fi
if [ -n "$static_product" ]; then
    assert_static_providers "$static_product/usr/lib/libc.a" \
        "$work/static-symbols.txt"
    for mode in static static-pie; do
        receipt="$work/consumer-$mode.receipt.json"
        (
            cd "$work"
            "$static_product/bin/crabc-cc" "-$mode" \
                --link-receipt "$(basename "$receipt")" "$work/workload.o" \
                -o "$work/consumer-$mode"
        )
        validate_sealed_link "$static_product" "$work/workload.o" \
            "$work/consumer-$mode" "$receipt" "$mode"
        mkdir "$work/$mode-root"
        cp "$work/consumer-$mode" "$work/$mode-root/consumer"
        compare_oracle "$mode" "$NORMAL_SCENARIO" "$work/$mode-root" /consumer
        compare_oracle "$mode" "$ALLOCATION_SCENARIO" "$work/$mode-root" \
            /consumer "$ALLOCATION_SCENARIO"
    done
fi

assert_dynamic_providers "$installed/usr/lib/libc.so" "$work/dynamic-symbols.txt"
for mode in pie non-pie; do
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" \
        -o "$work/consumer-$mode"
    receipt="$work/consumer-$mode.crabc-link.json"
    validate_sealed_link "$installed" "$work/workload.o" "$work/consumer-$mode" \
        "$receipt" "$mode"
    cp -a "$installed" "$work/$mode-root"
    cp "$work/consumer-$mode" "$work/$mode-root/consumer"
    compare_oracle "dynamic-$mode-kernel" "$NORMAL_SCENARIO" \
        "$work/$mode-root" /consumer
    compare_oracle "dynamic-$mode-direct" "$NORMAL_SCENARIO" \
        "$work/$mode-root" "$INTERPRETER" /consumer
    compare_oracle "dynamic-$mode-kernel" "$ALLOCATION_SCENARIO" \
        "$work/$mode-root" /consumer "$ALLOCATION_SCENARIO"
    compare_oracle "dynamic-$mode-direct" "$ALLOCATION_SCENARIO" \
        "$work/$mode-root" "$INTERPRETER" /consumer "$ALLOCATION_SCENARIO"
done

retain_link_identities
assert_retained_identity_tampering_rejected "$installed" "$work/workload.o" \
    "$work/consumer-pie" "$work/consumer-pie.crabc-link.json" pie \
    "$work/pie.link-identity.json"

printf 'owned environment lifecycle: PASS (same installed-driver C object through musl and sealed owned static/static-PIE/dynamic PIE/non-PIE kernel/direct links; raw status/stdout/stderr and shared-validator identities retained; caller-serialized replacement/removal/clear, fixture-seccomp ENOMEM rollback, direct environ and borrowed values, fork snapshot, exec and spawn child environments); evidence: %s\n' "$work"
