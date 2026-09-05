#!/usr/bin/env bash
# Native kernel mechanisms through sealed owned products, with pinned-musl ABI.
#
# The installed dynamic driver compiles one workload object. Pinned musl and
# static/static-PIE/dynamic PIE/non-PIE links consume that exact object, so the
# 18-symbol Linux-control probe has one header and application boundary.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_linux_control_probe.c"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1
declare -a link_identity_records=()

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
    provided_static="$(realpath -e "$provided_static")"
fi
if [ "$dynamic_was_supplied" -eq 1 ]; then
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
    raise SystemExit("Linux control TMPDIR must be a physical checkout .work directory")
for product, name in ((static_product, "static"), (dynamic_product, "dynamic")):
    if product and (not product.is_dir() or not product.is_relative_to(root / ".work")):
        raise SystemExit(f"Linux control {name} product must be a checkout .work directory")
PY

readonly work="$(mktemp -d "$TMPDIR/owned-linux-control.XXXXXX")"
chmod a+rx "$work"
printf 'Linux control evidence: %s\n' "$work"

fail() {
    printf 'owned Linux control: %s\n' "$*" >&2
    exit 1
}

run_capture() {
    local output="$1"
    shift
    local status

    set +e
    timeout 30 env -i PATH="$PATH" "$@" >"$output" 2>"${output}.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"${output}.status"
    if [ "$status" -ne 0 ]; then
        printf 'owned Linux control process failed with status %s: %s\n' \
            "$status" "$*" >&2
        return 1
    fi
}

compare_oracle() {
    local label="$1" root="$2"
    shift 2
    local output="$work/$label.stdout"

    run_capture "$output" chroot "$root" "$@"
    cmp "$work/oracle.stdout" "$output" ||
        fail "stdout differs from pinned musl for $label"
    cmp "$work/oracle.stdout.stderr" "${output}.stderr" ||
        fail "stderr differs from pinned musl for $label"
    cmp "$work/oracle.stdout.status" "${output}.status" ||
        fail "process status differs from pinned musl for $label"
}

# The common validator owns receipt schemas and ELF assertions. Persist exactly
# its returned identity instead of copying a partial validation into this leaf.
validate_sealed_link() {
    local product="$1" workload="$2" executable="$3" receipt="$4" linkage="$5"
    local identity="$work/$linkage.link-identity.json"

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
    json.dumps(
        {"schema": "crabc.x86_64-owned-posix-link-identities/v1", "links": records},
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n",
    encoding="utf-8",
)
PY
}

audit_installed_headers() {
    local product="$1"

    python3 -B - "$product" "$work" "$PROBE" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

product, work, source = map(Path, sys.argv[1:])
sys.path.insert(0, str(product / "share" / "crabc"))
import crabc_cc_static as compiler_contract

dependency_command = [
    compiler_contract.compiler(), "-nostdinc", "-isystem", str(product / "usr" / "include"),
    "-std=c11", "-ffreestanding", "-fno-builtin", "-fstack-protector-strong", "-fPIE",
    "-M", str(source),
]
with (work / "workload.d").open("wb") as output:
    subprocess.run(
        dependency_command, stdout=output, check=True, env=compiler_contract.clean_environment()
    )
dependencies = (work / "workload.d").read_text(encoding="utf-8").replace("\\\n", " ").split(":", 1)[1].split()
headers = product / "usr" / "include"
if not dependencies or str(source) not in dependencies:
    raise SystemExit("Linux control installed-header dependency roster omits the workload source")
for name in dependencies:
    path = Path(name).resolve(strict=True)
    if path != source and not path.is_relative_to(headers):
        raise SystemExit(f"Linux control dependency escapes installed headers: {path}")

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

record = {
    "schema": "crabc.x86_64-owned-linux-control-compile/v1",
    "driver_sha256": digest(product / "bin" / "crabc-cc-dynamic"),
    "manifest_sha256": digest(product / "share" / "crabc" / "manifest.json"),
    "source_sha256": digest(source),
    "object_sha256": digest(work / "workload.o"),
    "dependency_audit_command": dependency_command,
    "dependencies": {name: digest(Path(name)) for name in dependencies},
}
(work / "compile.json").write_text(
    json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
}

if [ "$dynamic_was_supplied" -eq 0 ]; then
    provided_dynamic="$work/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
readonly installed="$provided_dynamic"

"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"
audit_installed_headers "$installed"

mkdir "$work/oracle-root"
"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$work/workload.o" \
    -o "$work/oracle-root/consumer"
run_capture "$work/oracle.stdout" chroot "$work/oracle-root" /consumer
grep -qx owned-linux-control-ok "$work/oracle.stdout" ||
    fail "pinned musl oracle did not complete the Linux-control probe"

static_product=''
if [ "$static_was_supplied" -eq 1 ]; then
    static_product="$provided_static"
elif [ "$dynamic_was_supplied" -eq 0 ]; then
    static_product="$work/static-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$static_product" >"$work/static-build.json"
fi
if [ -n "$static_product" ]; then
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
        compare_oracle "$mode" "$work/$mode-root" /consumer
    done
fi

for mode in pie non-pie; do
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" \
        -o "$work/consumer-$mode"
    receipt="$work/consumer-$mode.crabc-link.json"
    validate_sealed_link "$installed" "$work/workload.o" \
        "$work/consumer-$mode" "$receipt" "$mode"
    readelf -hW "$work/consumer-$mode" >"$work/consumer-$mode.header"
    readelf -lW "$work/consumer-$mode" >"$work/consumer-$mode.segments"
    readelf -dW "$work/consumer-$mode" >"$work/consumer-$mode.dynamic"
    cp -a "$installed" "$work/$mode-root"
    cp "$work/consumer-$mode" "$work/$mode-root/consumer"
    compare_oracle "dynamic-$mode-kernel" "$work/$mode-root" /consumer
    compare_oracle "dynamic-$mode-direct" "$work/$mode-root" "$INTERPRETER" /consumer
done

retain_link_identities

if [ "$static_was_supplied" -eq 0 ] && [ "$dynamic_was_supplied" -eq 0 ]; then
    result="default static/static-PIE and dynamic PIE/non-PIE"
elif [ "$static_was_supplied" -eq 1 ] && [ "$dynamic_was_supplied" -eq 1 ]; then
    result="supplied static/static-PIE and dynamic PIE/non-PIE"
elif [ "$static_was_supplied" -eq 1 ]; then
    result="supplied static/static-PIE and default dynamic PIE/non-PIE"
else
    result="supplied dynamic PIE/non-PIE"
fi
printf 'owned Linux control: PASS (%s; one installed-driver workload object through pinned musl; retained stdout/stderr/status triplets, installed-header dependency audit and shared-validator link identities; 18-symbol capability, process-memory and ptrace word semantics); evidence: %s\n' \
    "$result" "$work"
