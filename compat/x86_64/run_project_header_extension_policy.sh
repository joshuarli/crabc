#!/usr/bin/env bash
# Reviewed project-only C-ABI extension header evidence.
#
# The C fixture records exact direct-include callable types and Linux
# capability widths.  The C++ fixture includes the same eight paths, leaves
# stdatomic.h deliberately empty, and takes every other callable's address.
# Static/static-PIE links use all callable addresses; dynamic PIE/non-PIE links
# use the selected owned dynamic exports. Neither object executes a capability
# or module operation.
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly C_PROBE="$ROOT/compat/x86_64/project_header_extension_probe.c"
readonly CXX_PROBE="$ROOT/compat/x86_64/project_header_extension_probe.cpp"
readonly -a SYMBOLS=(
    capget capset daemon delete_module dn_expand dn_skipname drand48 erand48
    init_module jrand48 lcong48 lrand48 mrand48 nrand48 pthread_atfork seed48
    srand48 strverscmp
)
readonly -a DYNAMIC_SYMBOLS=(capget capset daemon delete_module init_module)
declare -a link_identity_records=()
declare -a executed_linkages=()

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

fail() {
    printf 'project header extensions: %s\n' "$*" >&2
    exit 1
}

provided_static=''
provided_dynamic=''
static_was_supplied=0
dynamic_was_supplied=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] && [ "$static_was_supplied" -eq 0 ] && [ -n "$2" ] || usage
            case "$2" in -*) usage ;; esac
            provided_static="$2"
            static_was_supplied=1
            shift 2
            ;;
        -*|'') usage ;;
        *)
            [ "$dynamic_was_supplied" -eq 0 ] || usage
            provided_dynamic="$1"
            dynamic_was_supplied=1
            shift
            ;;
    esac
done
if [ "$static_was_supplied" -eq 1 ]; then provided_static="$(realpath -e "$provided_static")"; fi
if [ "$dynamic_was_supplied" -eq 1 ]; then provided_dynamic="$(realpath -e "$provided_dynamic")"; fi

python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
supplied = ((Path(sys.argv[3]) if sys.argv[3] else None, "static"),
            (Path(sys.argv[4]) if sys.argv[4] else None, "dynamic"))
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / ".work"):
    raise SystemExit("project header extension TMPDIR must be a physical checkout .work directory")
for product, name in supplied:
    if product and (not product.is_dir() or not product.is_relative_to(root / ".work")):
        raise SystemExit(f"project header extension {name} product must be a checkout .work directory")
PY

validate_product_payload() {
    local product="$1" family="$2"
    python3 -B - "$ROOT" "$product" "$family" <<'PY'
from pathlib import Path
import sys

root, product, family = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, str(root / "compat/x86_64"))
from owned_posix_product_evidence import ProductEvidenceError, _validate_dynamic_product, _validate_static_product
try:
    if family == "static":
        _validate_static_product(product)
    elif family == "dynamic":
        _validate_dynamic_product(product)
    else:
        raise SystemExit(f"unknown project header extension product family: {family}")
except ProductEvidenceError as error:
    raise SystemExit(f"project header extension {family} product is invalid: {error}") from error
PY
}

if [ "$static_was_supplied" -eq 1 ]; then validate_product_payload "$provided_static" static; fi
if [ "$dynamic_was_supplied" -eq 1 ]; then validate_product_payload "$provided_dynamic" dynamic; fi

readonly work="$(mktemp -d "$TMPDIR/project-header-extension-policy.XXXXXX")"
chmod a+rx "$work"
printf 'project header extension evidence: %s\n' "$work"

validate_sealed_link() {
    local product="$1" workload="$2" executable="$3" receipt="$4" linkage="$5"
    local identity="$work/$linkage.link-identity.json"
    python3 -B - "$ROOT" "$product" "$workload" "$executable" "$receipt" "$linkage" >"$identity" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "compat/x86_64"))
from owned_posix_product_evidence import ProductEvidenceError, validate_link
try:
    identity = validate_link(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), sys.argv[6])
except ProductEvidenceError as error:
    raise SystemExit(f"project header extension sealed link evidence: {error}") from error
json.dump(identity, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
PY
    link_identity_records+=("$linkage:$identity")
}

retain_link_identities() {
    python3 -B - "$work/link-identities.json" "$@" -- "${link_identity_records[@]}" <<'PY'
import json
from pathlib import Path
import sys

fields = {"linkage", "product", "product_format", "product_manifest_sha256", "workload_sha256", "executable_sha256", "receipt_sha256"}
separator = sys.argv.index("--")
expected = set(sys.argv[2:separator])
records = {}
for item in sys.argv[separator + 1:]:
    linkage, identity_path = item.split(":", 1)
    if linkage in records:
        raise SystemExit(f"duplicate retained project header extension linkage: {linkage}")
    try:
        identity = json.loads(Path(identity_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"retained project header extension identity is unreadable: {error}") from error
    if not isinstance(identity, dict) or set(identity) != fields or identity.get("linkage") != linkage:
        raise SystemExit(f"retained project header extension identity drifted: {linkage}")
    records[linkage] = identity
if set(records) != expected:
    raise SystemExit("retained project header extension links omit a product mode")
Path(sys.argv[1]).write_text(json.dumps({
    "schema": "crabc.x86_64-project-header-extension-link-identities/v1",
    "expected_linkages": sorted(expected), "links": records,
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

audit_installed_headers() {
    local product="$1"
    python3 -B - "$product" "$work" "$C_PROBE" "$CXX_PROBE" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

product, work, c_source, cxx_source = map(Path, sys.argv[1:])
sys.path.insert(0, str(product / "share/crabc"))
import crabc_cc_static as compiler_contract
headers = (product / "usr/include").resolve(strict=True)

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

records = {}
for language, standard, source, object_path in (
    ("c", "c11", c_source.resolve(strict=True), work / "c-types.o"),
    ("c++", "c++17", cxx_source.resolve(strict=True), work / "cxx-addresses.o"),
):
    command = [compiler_contract.compiler(), "-nostdinc", "-isystem", str(headers), "-x", language,
               f"-std={standard}", *compiler_contract.HOSTED_TRANSLATION_FLAGS, "-fPIE", "-M", str(source)]
    dependency_file = work / f"{language}.d"
    with dependency_file.open("xb") as output:
        subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output, check=True, env=compiler_contract.clean_environment())
    try:
        dependencies = dependency_file.read_text(encoding="utf-8").replace("\\\n", " ").split(":", 1)[1].split()
    except (IndexError, UnicodeDecodeError) as error:
        raise SystemExit(f"project header extension {language} dependency output is invalid: {error}") from error
    resolved = []
    for item in dependencies:
        path = Path(item).resolve(strict=True)
        if path != source and not path.is_relative_to(headers):
            raise SystemExit(f"project header extension {language} dependency escapes installed headers: {path}")
        resolved.append(path)
    if source not in resolved:
        raise SystemExit(f"project header extension {language} dependency output omits its source")
    records[language] = {
        "source_sha256": digest(source), "object_sha256": digest(object_path),
        "dependency_audit_command": command, "dependencies": {str(path): digest(path) for path in resolved},
    }
(work / "compile.json").write_text(json.dumps({
    "schema": "crabc.x86_64-project-header-extension-compile/v1",
    "driver_sha256": digest(product / "bin/crabc-cc-dynamic"),
    "manifest_sha256": digest(product / "share/crabc/manifest.json"), "sources": records,
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

assert_cxx_undefineds() {
    local object="$1" observed="$2"
    shift 2
    nm -u "$object" | awk '{print $NF}' | sort -u >"$observed"
    printf '%s\n' "$@" | sort -u >"$observed.expected"
    cmp "$observed.expected" "$observed" || fail "C++ direct-header undefined symbol roster drifted"
    if grep -Eq '^_Z' "$observed"; then
        fail "C++ direct-header linkage is mangled"
    fi
}

assert_static_symbols() {
    local archive="$1" symbols="$work/static-symbols.txt" symbol count
    nm -g --defined-only "$archive" >"$symbols"
    for symbol in "${SYMBOLS[@]}"; do
        count="$(awk -v name="$symbol" '$NF == name { count++ } END { print count + 0 }' "$symbols")"
        [ "$count" -eq 1 ] || fail "static archive does not provide exactly one ${symbol}"
    done
}

assert_dynamic_symbols() {
    local library="$1" symbols="$work/dynamic-symbols.txt" symbol count
    readelf --dyn-syms -W "$library" >"$symbols"
    for symbol in "${DYNAMIC_SYMBOLS[@]}"; do
        count="$(awk -v name="$symbol" '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == name { count++ } END { print count + 0 }' "$symbols")"
        [ "$count" -eq 1 ] || fail "shared libc does not provide exactly one global-default ${symbol}"
    done
}

if [ "$dynamic_was_supplied" -eq 0 ]; then
    provided_dynamic="$work/dynamic-sysroot"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
readonly installed="$provided_dynamic"
validate_product_payload "$installed" dynamic

"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin -c "$C_PROBE" -o "$work/c-types.o"
python3 -B - "$installed" "$CXX_PROBE" "$work/cxx-addresses.o" <<'PY'
from pathlib import Path
import subprocess
import sys

product, source, output = map(Path, sys.argv[1:])
sys.path.insert(0, str(product / "share/crabc"))
import crabc_cc_static as compiler_contract
subprocess.run(
    [
        compiler_contract.compiler(), "-nostdinc", "-isystem", str(product / "usr/include"),
        "-x", "c++", "-std=c++17", "-ffreestanding", "-fno-builtin",
        "-fstack-protector-strong", "-fPIE", "-c", str(source), "-o", str(output),
    ],
    check=True,
    env=compiler_contract.clean_environment(),
    stdin=subprocess.DEVNULL,
)
PY
python3 -B - "$installed" "$CXX_PROBE" "$work/cxx-dynamic-addresses.o" <<'PY'
from pathlib import Path
import subprocess
import sys

product, source, output = map(Path, sys.argv[1:])
sys.path.insert(0, str(product / "share/crabc"))
import crabc_cc_static as compiler_contract
subprocess.run(
    [
        compiler_contract.compiler(), "-nostdinc", "-isystem", str(product / "usr/include"),
        "-x", "c++", "-std=c++17", "-DCRABC_PROJECT_HEADER_DYNAMIC",
        "-ffreestanding", "-fno-builtin", "-fstack-protector-strong", "-fPIE",
        "-c", str(source), "-o", str(output),
    ],
    check=True,
    env=compiler_contract.clean_environment(),
    stdin=subprocess.DEVNULL,
)
PY
audit_installed_headers "$installed"
assert_cxx_undefineds "$work/cxx-addresses.o" "$work/cxx-undefined.txt" "${SYMBOLS[@]}"
assert_cxx_undefineds "$work/cxx-dynamic-addresses.o" "$work/cxx-dynamic-undefined.txt" "${DYNAMIC_SYMBOLS[@]}"

static_product=''
if [ "$static_was_supplied" -eq 1 ]; then
    static_product="$provided_static"
elif [ "$dynamic_was_supplied" -eq 0 ]; then
    static_product="$work/static-sysroot"
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$static_product" >"$work/static-build.json"
fi
if [ -n "$static_product" ]; then
    validate_product_payload "$static_product" static
    assert_static_symbols "$static_product/usr/lib/libc.a"
    for mode in static static-pie; do
        receipt="$work/$mode.receipt.json"
        (
            cd "$work"
            "$static_product/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$receipt")" \
                "$work/cxx-addresses.o" -o "$work/$mode-consumer"
        )
        validate_sealed_link "$static_product" "$work/cxx-addresses.o" "$work/$mode-consumer" "$receipt" "$mode"
        executed_linkages+=("$mode")
    done
fi

assert_dynamic_symbols "$installed/usr/lib/libc.so"
for mode in pie non-pie; do
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/cxx-dynamic-addresses.o" -o "$work/$mode-consumer"
    validate_sealed_link "$installed" "$work/cxx-dynamic-addresses.o" "$work/$mode-consumer" "$work/$mode-consumer.crabc-link.json" "$mode"
    executed_linkages+=("$mode")
done

if [ -n "$static_product" ]; then
    retain_link_identities static static-pie pie non-pie
else
    retain_link_identities pie non-pie
fi
linkage_summary="${executed_linkages[0]}"
for linkage in "${executed_linkages[@]:1}"; do
    linkage_summary+="/$linkage"
done
printf 'project header extensions: PASS (direct C/C++ types and capability widths; C++ unmangled addresses through owned %s sealed links; no capability or module operation executed); evidence: %s\n' "$linkage_summary" "$work"
