#!/usr/bin/env bash
# Bounded SHA-crypt C ABI through sealed installed x86 products.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/libc_crypt_probe.c"
readonly EXECUTION_EVIDENCE="$ROOT/compat/x86_64/owned_crypt_runtime_evidence.py"
readonly PROFILE_EVIDENCE="$ROOT/compat/x86_64/owned_crypt_profile.py"

fail() {
    printf 'owned crypt runtime: %s\n' "$*" >&2
    exit 1
}

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

[ "$(uname -sm)" = 'Linux x86_64' ] || fail 'requires native Linux/x86-64'

# Supplied products and evidence are physical checkout-local artifacts.  Do
# this before canonicalizing a supplied spelling so a symlink cannot become an
# otherwise plausible product root.
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_static" "$provided_dynamic" <<'PY_PRODUCTS'
from pathlib import Path
import os
import stat
import sys

root = Path(sys.argv[1]).resolve(strict=True)
temporary_text, static_text, dynamic_text = sys.argv[2:]

def physical_directory(text: str, description: str) -> None:
    path = Path(text)
    if not path.is_absolute():
        path = Path(os.path.abspath(path))
    if ".." in path.parts:
        raise SystemExit(f"owned crypt runtime {description} has lexical parent traversal")
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current /= part
            if stat.S_ISLNK(current.lstat().st_mode):
                raise SystemExit(f"owned crypt runtime {description} traverses a symlink")
        if not stat.S_ISDIR(path.lstat().st_mode):
            raise SystemExit(f"owned crypt runtime {description} is not a physical directory")
    except OSError as error:
        raise SystemExit(f"owned crypt runtime {description} is unreadable") from error
    if not path.is_relative_to(root / ".work"):
        raise SystemExit(f"owned crypt runtime {description} must be a checkout .work directory")

physical_directory(temporary_text, "TMPDIR")
if static_text:
    physical_directory(static_text, "static product")
if dynamic_text:
    physical_directory(dynamic_text, "dynamic product")
PY_PRODUCTS

[ -x "$ORACLE_CC" ] || fail 'missing pinned musl oracle compiler'

if [ "$static_was_supplied" -eq 1 ]; then
    provided_static="$(realpath -e -- "$provided_static")"
fi
if [ "$dynamic_was_supplied" -eq 1 ]; then
    provided_dynamic="$(realpath -e -- "$provided_dynamic")"
fi

readonly work="$(mktemp -d "$TMPDIR/owned-crypt-runtime.XXXXXX")"
chmod a+rx "$work"
printf 'owned crypt runtime evidence: %s\n' "$work"

bash "$ROOT/compat/x86_64/run_musl_oracle.sh" >/dev/null

# Disposable products are siblings of the evidence leaf, never children: the
# profile reader rejects a product inside the leaf because leaf children are
# execution copies of the product rather than the product itself.
built_products=''
if [ "$dynamic_was_supplied" -eq 0 ]; then
    built_products="$(mktemp -d "$TMPDIR/owned-crypt-runtime-products.XXXXXX")"
    chmod a+rx "$built_products"
    printf 'owned crypt runtime disposable products: %s\n' "$built_products"
fi

if [ "$dynamic_was_supplied" -eq 0 ]; then
    provided_dynamic="$built_products/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
readonly installed="$provided_dynamic"

# The default receipt covers both product kinds.  A positional dynamic product
# intentionally remains a dynamic-only replay, while a supplied static product
# still needs a dynamic product to produce the one installed-header object.
static_product=''
if [ "$static_was_supplied" -eq 1 ]; then
    static_product="$provided_static"
elif [ "$dynamic_was_supplied" -eq 0 ]; then
    static_product="$built_products/static-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$static_product" >"$work/static-build.json"
fi

python3 -B "$PROFILE_EVIDENCE" prepare --work "$work" --product "$installed"

# One object is compiled through the installed dynamic driver.  Its candidate
# macro activates the existing fixture's public/private aliases, buffer and
# overlap guards, null behavior, SHA-256/SHA-512 vectors, and excluded-format
# assertions.  The Python half records the installed compiler contract and
# every physical source/header input before sealing the object bytes.
compile_receipt() {
    local action="$1"
    python3 -B - "$action" "$installed" "$work" "$PROBE" "${source_sha256_before_compile:-}" <<'PY_COMPILE'
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

action, product_text, work_text, source_text, initial_source_hash = sys.argv[1:]
product = Path(product_text).resolve(strict=True)
work = Path(work_text).resolve(strict=True)
source = Path(source_text).resolve(strict=True)
headers = product / "usr/include"
driver = product / "bin/crabc-cc-dynamic"
helper = product / "share/crabc/crabc_cc_static.py"
manifest = product / "share/crabc/manifest.json"
object_path = work / "workload.o"
preparation_path = work / "compile-preparation.json"
record_path = work / "compile.json"
dependencies_path = work / "installed-header-dependencies.d"

for path, description in ((headers, "installed headers"), (driver, "installed driver"),
                          (helper, "installed compiler helper"), (manifest, "installed manifest")):
    if not path.is_file() and not path.is_dir():
        raise SystemExit(f"owned crypt runtime compile: missing {description}")

sys.path.insert(0, str(product / "share/crabc"))
import crabc_cc_static as compiler_contract
if Path(compiler_contract.__file__).resolve() != helper.resolve():
    raise SystemExit("owned crypt runtime compile: installed helper import drifted")


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def bindings() -> dict[str, dict[str, str]]:
    compiler = Path(compiler_contract.compiler()).resolve(strict=True)
    return {
        "manifest": {"path": str(manifest), "sha256": digest(manifest)},
        "driver": {"path": str(driver), "sha256": digest(driver)},
        "installed_helper": {"path": str(helper), "sha256": digest(helper)},
        "compiler": {"path": str(compiler), "sha256": digest(compiler)},
    }


def pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"owned crypt runtime compile: invalid receipt: {error}") from error
    if not isinstance(value, dict):
        raise SystemExit("owned crypt runtime compile: receipt is not an object")
    return value

caller_flags = [
    "-std=c11", "-D_GNU_SOURCE", "-DCRABC_X86_CRYPT_CANDIDATE",
    "-fno-builtin", "-fno-stack-protector",
]
prefix = [
    "-nostdinc", "-isystem", str(headers), "-ffreestanding", "-fno-builtin",
    "-fstack-protector-strong",
]
actual_compile = [
    str(driver), "--dynamic-pie", *caller_flags, "-c", str(source), "-o", str(object_path),
]
dependency_command = [
    str(Path(compiler_contract.compiler()).resolve(strict=True)), *prefix, *caller_flags,
    "-fPIE", "-M", str(source),
]
required_headers = tuple(
    headers / name for name in ("crypt.h", "string.h", "unistd.h", "features.h", "bits/alltypes.h")
)

if action == "capture":
    if digest(source) != initial_source_hash:
        raise SystemExit("owned crypt runtime compile: source changed before translation")
    environment = {**compiler_contract.clean_environment(), "TMPDIR": str(work)}
    with dependencies_path.open("wb") as output:
        subprocess.run(
            dependency_command, stdout=output, stderr=subprocess.PIPE, check=True, env=environment,
        )
    text = dependencies_path.read_text(encoding="utf-8").replace("\\\n", " ")
    try:
        dependency_names = text.split(":", 1)[1].split()
    except IndexError as error:
        raise SystemExit("owned crypt runtime compile: dependency audit lacks a list") from error
    dependencies = [Path(name).resolve(strict=True) for name in dependency_names]
    if len(dependencies) != len(set(dependencies)) or source not in dependencies:
        raise SystemExit("owned crypt runtime compile: dependency roster drifted")
    if any(path != source and not path.is_relative_to(headers) for path in dependencies):
        raise SystemExit("owned crypt runtime compile: dependency escaped installed headers")
    if any(header not in dependencies for header in required_headers):
        raise SystemExit("owned crypt runtime compile: required installed header is absent")
    preparation = {
        "schema": "crabc.x86_64-owned-crypt-runtime-compile-preparation/v1",
        "installed_dynamic": {"root": str(product), **bindings(),
                              "clean_environment": compiler_contract.clean_environment()},
        "translation": {"driver_mode": "--dynamic-pie", "effective_codegen_flag": "-fPIE",
                        "caller_flags": caller_flags, "driver_compile_prefix": prefix,
                        "actual_compile_command": actual_compile,
                        "dependency_audit_command": dependency_command},
        "source": {"path": str(source), "sha256": initial_source_hash},
        "dependencies": {str(path): digest(path) for path in dependencies},
        "dependency_audit": {"path": str(dependencies_path), "sha256": digest(dependencies_path)},
    }
    preparation_path.write_text(json.dumps(preparation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
elif action == "seal":
    preparation = load(preparation_path)
    if preparation.get("schema") != "crabc.x86_64-owned-crypt-runtime-compile-preparation/v1":
        raise SystemExit("owned crypt runtime compile: preparation schema drifted")
    if digest(source) != initial_source_hash or not object_path.is_file():
        raise SystemExit("owned crypt runtime compile: source or object changed while translating")
    dependencies = preparation.get("dependencies")
    if not isinstance(dependencies, dict) or not dependencies:
        raise SystemExit("owned crypt runtime compile: preparation dependencies drifted")
    for path_text, expected in dependencies.items():
        path = Path(path_text)
        if not isinstance(expected, str) or not path.is_file() or digest(path) != expected:
            raise SystemExit("owned crypt runtime compile: source/header changed while translating")
    receipt = {
        "schema": "crabc.x86_64-owned-crypt-runtime-compile/v1",
        "preparation": preparation,
        "object": {"path": str(object_path), "sha256": digest(object_path)},
    }
    record_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
elif action == "verify":
    receipt = load(record_path)
    if set(receipt) != {"schema", "preparation", "object"} or receipt.get("schema") != "crabc.x86_64-owned-crypt-runtime-compile/v1":
        raise SystemExit("owned crypt runtime compile: sealed receipt fields drifted")
    preparation = receipt.get("preparation")
    object_record = receipt.get("object")
    if not isinstance(preparation, dict) or not isinstance(object_record, dict):
        raise SystemExit("owned crypt runtime compile: sealed receipt records drifted")
    if preparation.get("schema") != "crabc.x86_64-owned-crypt-runtime-compile-preparation/v1":
        raise SystemExit("owned crypt runtime compile: preparation schema drifted")
    expected_installed = {"root": str(product), **bindings(), "clean_environment": compiler_contract.clean_environment()}
    if preparation.get("installed_dynamic") != expected_installed:
        raise SystemExit("owned crypt runtime compile: installed compiler binding drifted")
    expected_translation = {"driver_mode": "--dynamic-pie", "effective_codegen_flag": "-fPIE",
                            "caller_flags": caller_flags, "driver_compile_prefix": prefix,
                            "actual_compile_command": actual_compile,
                            "dependency_audit_command": dependency_command}
    if preparation.get("translation") != expected_translation:
        raise SystemExit("owned crypt runtime compile: translation contract drifted")
    if preparation.get("source") != {"path": str(source), "sha256": digest(source)}:
        raise SystemExit("owned crypt runtime compile: source identity drifted")
    dependencies = preparation.get("dependencies")
    if not isinstance(dependencies, dict) or not dependencies:
        raise SystemExit("owned crypt runtime compile: dependency roster drifted")
    for path_text, expected in dependencies.items():
        path = Path(path_text)
        if not isinstance(path_text, str) or not isinstance(expected, str) or not path.is_file() or digest(path) != expected:
            raise SystemExit("owned crypt runtime compile: installed dependency changed")
    dependency_audit = preparation.get("dependency_audit")
    if dependency_audit != {"path": str(dependencies_path), "sha256": digest(dependencies_path)}:
        raise SystemExit("owned crypt runtime compile: dependency audit changed")
    if object_record != {"path": str(object_path), "sha256": digest(object_path)}:
        raise SystemExit("owned crypt runtime compile: workload object changed")
else:
    raise SystemExit("owned crypt runtime compile: unknown receipt action")
PY_COMPILE
}

source_sha256_before_compile="$(sha256sum "$PROBE" | awk '{ print $1 }')"
compile_receipt capture
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -D_GNU_SOURCE \
    -DCRABC_X86_CRYPT_CANDIDATE -fno-builtin -fno-stack-protector \
    -c "$PROBE" -o "$work/workload.o"
[ "$source_sha256_before_compile" = "$(sha256sum "$PROBE" | awk '{ print $1 }')" ] \
    || fail 'fixture source changed while the installed driver translated it'
compile_receipt seal

readelf -rW "$work/workload.o" >"$work/workload.relocations"
if grep -Eq 'R_X86_64_(32|32S)' "$work/workload.relocations"; then
    fail 'installed dynamic-PIE fixture object has an absolute 32-bit relocation'
fi

assert_static_provider() {
    local archive="$1" symbols="$work/static-crypt-symbols"
    nm -A --defined-only "$archive" >"$symbols"
    python3 -B - "$symbols" <<'PY_STATIC_SYMBOLS'
from pathlib import Path
import sys

symbols = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
expected = {
    "crypt": "T", "crypt_r": "W", "__crypt_r": "T", "__crypt_sha256": "T",
    "__crypt_sha512": "T", "__crypt_md5": "T", "__crypt_blowfish": "T",
}
owners: dict[str, str] = {}
for name, binding in expected.items():
    matches = []
    for line in symbols:
        fields = line.split()
        if fields and fields[-1] == name:
            prefix = line.split(":", 2)
            matches.append((":".join(prefix[:2]), fields[-2]))
    if len(matches) != 1 or matches[0][1] != binding:
        raise SystemExit(f"owned crypt runtime: static provider binding drifted for {name}")
    owners[name] = matches[0][0]
# musl's weak_alias(__crypt_r, crypt_r) lives in __crypt_r's object; the other
# providers may have their own members, as musl's crypt*.o objects do.
if owners["crypt_r"] != owners["__crypt_r"]:
    raise SystemExit("owned crypt runtime: static crypt_r alias and __crypt_r have different object owners")
if any("__crabc_x86_crypt" in line for line in symbols):
    raise SystemExit("owned crypt runtime: static archive leaked a test-only crypt export")
PY_STATIC_SYMBOLS
}

assert_dynamic_provider() {
    local library="$1" symbols="$work/dynamic-crypt-symbols"
    readelf --dyn-syms --wide "$library" >"$symbols"
    python3 -B - "$symbols" <<'PY_DYNAMIC_SYMBOLS'
import re
from pathlib import Path
import sys

lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
expected = {
    "crypt": "GLOBAL", "crypt_r": "WEAK", "__crypt_r": "GLOBAL",
    "__crypt_sha256": "GLOBAL", "__crypt_sha512": "GLOBAL", "__crypt_md5": "GLOBAL",
    "__crypt_blowfish": "GLOBAL",
}
for name, binding in expected.items():
    expression = re.compile(
        rf"^\s*\d+:\s+\S+\s+\d+\s+FUNC\s+{binding}\s+DEFAULT\s+\S+\s+{re.escape(name)}$"
    )
    if sum(bool(expression.match(line)) for line in lines) != 1:
        raise SystemExit(f"owned crypt runtime: dynamic provider binding drifted for {name}")
if any("__crabc_x86_crypt" in line for line in lines):
    raise SystemExit("owned crypt runtime: shared libc leaked a test-only crypt export")
PY_DYNAMIC_SYMBOLS
}

audit_owned_link() {
    local product="$1" object="$2" candidate="$3" receipt="$4" mode="$5" identity="$6"
    python3 -B - "$ROOT" "$product" "$object" "$candidate" "$receipt" "$mode" "$identity" <<'PY_LINK'
import json
from pathlib import Path
import sys

root, product, object_path, candidate, receipt, mode, identity = sys.argv[1:]
sys.path.insert(0, str(Path(root) / "compat/x86_64"))
from owned_posix_product_evidence import ProductEvidenceError, validate_link
try:
    record = validate_link(Path(product), Path(object_path), Path(candidate), Path(receipt), mode)
except ProductEvidenceError as error:
    raise SystemExit(f"owned crypt runtime link evidence: {error}") from error
output = Path(identity)
if output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.is_symlink():
    raise SystemExit("owned crypt runtime link evidence output is unsafe")
with output.open("x", encoding="utf-8", newline="\n") as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY_LINK
}

audit_execution_payload() {
    local action="$1" product="$2" execution_root="$3" source_consumer="$4" \
        execution_consumer="$5" record="$6"
    python3 -B "$EXECUTION_EVIDENCE" "$action" --product "$product" \
        --execution-root "$execution_root" --source-consumer "$source_consumer" \
        --execution-consumer "$execution_consumer" --record "$record"
}

run_capture() {
    local label="$1"
    # The owner derives the finite command from its label and retains the
    # actual command, clean environment, raw streams and exit status.
    python3 -B "$PROFILE_EVIDENCE" runtime --work "$work" --label "$label"
    grep -qx 'crypt ok' "$work/$label.stdout" || fail "$label did not report the fixture success marker"
}

compare_oracle() {
    local label="$1" suffix
    for suffix in stdout stderr status; do
        cmp "$work/oracle.$suffix" "$work/$label.$suffix"
    done
}

# This oracle run covers the existing fixture's shared public SHA vectors.  The
# candidate-only macro intentionally remains off: its guards specify this
# provider's narrower unsupported/null/buffer contract rather than musl's full
# historical crypt surface.
python3 -B "$PROFILE_EVIDENCE" abi-oracle --work "$work"
compile_receipt verify
run_capture oracle

if [ -n "$static_product" ]; then
    assert_static_provider "$static_product/usr/lib/libc.a"
    for mode in static static-pie; do
        candidate="$work/$mode-consumer"
        receipt="$work/$mode.receipt.json"
        (
            cd "$work"
            "$static_product/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$receipt")" \
                workload.o -o "$(basename "$candidate")"
        )
        audit_owned_link "$static_product" "$work/workload.o" "$candidate" "$receipt" \
            "$mode" "$work/$mode-link-evidence.json"
        compile_receipt verify
        run_capture "$mode"
        compare_oracle "$mode"
        printf 'owned crypt runtime %s: PASS\n' "$mode"
    done
fi

assert_dynamic_provider "$installed/usr/lib/libc.so"
# Link and copy both dynamic entry forms before launching either one.  Their
# immutable records therefore bind the source product and every execution
# root's full manifest payload, manifest aliases, and consumer before the
# first candidate process starts.
for mode in pie non-pie; do
    candidate="$work/dynamic-$mode-consumer"
    receipt="$candidate.crabc-link.json"
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$candidate"
    audit_owned_link "$installed" "$work/workload.o" "$candidate" "$receipt" "$mode" \
        "$work/dynamic-$mode-link-evidence.json"
    compile_receipt verify
    execution_root="$work/dynamic-$mode-root"
    cp -a "$installed" "$execution_root"
    cp "$candidate" "$execution_root/consumer"
    audit_execution_payload record "$installed" "$execution_root" "$candidate" \
        "$execution_root/consumer" "$work/dynamic-$mode-execution-payload.json"
    audit_execution_payload audit "$installed" "$execution_root" "$candidate" \
        "$execution_root/consumer" "$work/dynamic-$mode-execution-payload.json" \
        >"$work/dynamic-$mode-execution-pre.json"
done

for mode in pie non-pie; do
    execution_root="$work/dynamic-$mode-root"
    run_capture "dynamic-$mode-kernel"
    compare_oracle "dynamic-$mode-kernel"
    run_capture "dynamic-$mode-direct"
    compare_oracle "dynamic-$mode-direct"
    audit_execution_payload audit "$installed" "$execution_root" "$work/dynamic-$mode-consumer" \
        "$execution_root/consumer" "$work/dynamic-$mode-execution-payload.json" \
        >"$work/dynamic-$mode-execution-post.json"
    printf 'owned crypt runtime dynamic-%s: PASS\n' "$mode"
done

# Seal once more after all candidate execution.  Comparing the canonical
# audits ensures no source, product copy, alias, or consumer changed between
# the pre-run, post-run, and final boundaries.
for mode in pie non-pie; do
    execution_root="$work/dynamic-$mode-root"
    audit_execution_payload audit "$installed" "$execution_root" "$work/dynamic-$mode-consumer" \
        "$execution_root/consumer" "$work/dynamic-$mode-execution-payload.json" \
        >"$work/dynamic-$mode-execution-final.json"
    cmp "$work/dynamic-$mode-execution-pre.json" "$work/dynamic-$mode-execution-post.json"
    cmp "$work/dynamic-$mode-execution-pre.json" "$work/dynamic-$mode-execution-final.json"
done
compile_receipt verify

python3 -B "$PROFILE_EVIDENCE" extend --work "$work" --product "$installed"

if [ -n "$static_product" ]; then
    matrix='pinned musl plus supplied/build static/static-PIE and dynamic PIE/non-PIE kernel/direct'
else
    matrix='pinned musl plus supplied dynamic PIE/non-PIE kernel/direct'
fi
printf 'owned crypt runtime: PASS (one installed-header ABI fixture object and one 32-vector observer object; %s; canonical SHA-256/SHA-512, public/private aliases, weak crypt_r, caller/shared-buffer overlap, null and excluded MD5/bcrypt/malformed rejection); evidence: %s\n' \
    "$matrix" "$work"
