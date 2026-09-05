#!/usr/bin/env bash
# Source-defined system/pclose wait ownership with an isolated test exec target.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly WITNESS="$ROOT/compat/x86_64/run_pthread_wait_witness.py"
readonly PROBE="$ROOT/compat/x86_64/owned_system_cancellation_probe.c"
readonly CHILD="$ROOT/compat/x86_64/owned_system_cancellation_child.c"

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
            [ -n "$2" ] || usage
            case "$2" in
                -*) usage ;;
            esac
            [ -z "$provided_static" ] || usage
            provided_static="$2"
            shift 2
            ;;
        -*)
            usage
            ;;
        *)
            [ -n "$1" ] || usage
            [ -z "$provided_dynamic" ] || usage
            provided_dynamic="$1"
            dynamic_was_supplied=1
            shift
            ;;
    esac
done
if [ -n "$provided_static" ]; then
    provided_static="$(realpath -e -- "$provided_static")"
fi
if [ -n "$provided_dynamic" ]; then
    provided_dynamic="$(realpath -e -- "$provided_dynamic")"
fi

[ "$(uname -sm)" = 'Linux x86_64' ]
# Validate supplied roots before creating the evidence directory. A replayed
# product remains a physical checkout `.work` product, never an ambient tree.
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_static" "$provided_dynamic" <<'PY_PRODUCTS'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
static_product = Path(sys.argv[3]) if sys.argv[3] else None
dynamic_product = Path(sys.argv[4]) if sys.argv[4] else None
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / ".work"):
    raise SystemExit("system cancellation TMPDIR must be a physical checkout .work directory")
for product, name in ((static_product, "static"), (dynamic_product, "dynamic")):
    if product and (not product.is_dir() or not product.is_relative_to(root / ".work")):
        raise SystemExit(f"system cancellation {name} product must be a checkout .work directory")
PY_PRODUCTS

readonly work="$(mktemp -d "$TMPDIR/owned-system-cancellation.XXXXXX")"
chmod a+rx "$work"
printf 'owned system cancellation evidence: %s\n' "$work"

run_witness_case() {
    local execution_root="$1" label="$2" status=0
    shift 2
    timeout 30 env -i PATH="$PATH" python3 -B "$WITNESS" "$execution_root" "$@" \
        >"$work/$label.stdout" 2>"$work/$label.stderr" || status=$?
    printf '%s\n' "$status" >"$work/$label.status"
    [ "$status" -eq 0 ]
}

compare_case() {
    local reference="$1" candidate="$2" suffix
    for suffix in stdout stderr status; do
        cmp "$work/$reference.$suffix" "$work/$candidate.$suffix"
    done
}

run_consumer() {
    local execution_root="$1" consumer="$2" label="$3" scenario
    for scenario in normal failure timeout; do
        local -a arguments=()
        if [ "$scenario" != normal ]; then arguments=("$scenario"); fi
        printf 'system cancellation running %s/%s\n' "$label" "$scenario"
        run_witness_case "$execution_root" "$label-$scenario" "$consumer" "${arguments[@]}"
        if [ "$scenario" = normal ]; then
            grep -qx owned-system-cancellation-ok "$work/$label-$scenario.stdout"
        fi
        if [ "$label" != oracle ]; then
            compare_case "oracle-$scenario" "$label-$scenario"
        fi
    done
}

run_direct_consumer() {
    local execution_root="$1" label="$2" scenario
    for scenario in normal failure timeout; do
        local -a arguments=()
        if [ "$scenario" != normal ]; then arguments=("$scenario"); fi
        printf 'system cancellation running %s-direct/%s\n' "$label" "$scenario"
        run_witness_case "$execution_root" "$label-direct-$scenario" \
            /lib/ld-crabc-x86_64.so.1 /consumer "${arguments[@]}"
        compare_case "oracle-$scenario" "$label-direct-$scenario"
    done
}

# Compile the only two application inputs once through the supplied (or
# disposable) dynamic product. Dynamic PIE deliberately selects `-fPIE`, not
# `-fPIC`: native links below prove these unchanged ET_REL objects serve musl,
# static ET_EXEC/static PIE, and dynamic PIE/non-PIE entry paths.
audit_canonical_objects() {
    local dynamic_product="$1"
    python3 -B - "$dynamic_product" "$work" "$PROBE" "$CHILD" <<'PY_COMPILE'
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

product, work, probe, child = map(Path, sys.argv[1:])
product = product.resolve()
work = work.resolve()
probe = probe.resolve()
child = child.resolve()
headers = product / "usr/include"
driver = product / "bin/crabc-cc-dynamic"
helper = product / "share/crabc/crabc_cc_static.py"
manifest = product / "share/crabc/manifest.json"
sys.path.insert(0, str(product / "share/crabc"))
import crabc_cc_static as compiler_contract
if Path(compiler_contract.__file__).resolve() != helper.resolve():
    raise SystemExit("system cancellation compile helper is not installed")

def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()

def binding(path: Path) -> dict[str, str]:
    return {"path": str(path), "sha256": digest(path)}

compiler = Path(compiler_contract.compiler())
clean_environment = compiler_contract.clean_environment()
audit_environment = {**clean_environment, "TMPDIR": str(work)}

prefix = [
    "-nostdinc", "-isystem", str(headers), "-ffreestanding", "-fno-builtin",
    "-fstack-protector-strong",
]
caller_flags = ["-std=c11", "-fno-builtin", "-fno-stack-protector"]
translation = {
    "driver_mode": "--dynamic-pie",
    "effective_codegen_flag": "-fPIE",
    "driver_compile_prefix": prefix,
    "caller_flags": caller_flags,
    "not_selected": ["-fPIC", "-fno-pie"],
}
roles = (
    ("consumer", probe, {probe, probe.parent / "owned_cancellation_proc_witness.h"},
     ("errno.h", "pthread.h", "stdio.h", "stdlib.h", "signal.h", "sys/wait.h", "poll.h", "bits/alltypes.h")),
    ("child", child, {child}, ("stdio.h", "stdlib.h", "string.h", "signal.h", "unistd.h", "bits/alltypes.h")),
)
objects = []
for role, source, source_files, required_headers in roles:
    object_path = work / f"{role}.o"
    dependency_path = work / f"{role}.d"
    actual_compile_command = [str(driver), "--dynamic-pie", *caller_flags,
                              "-c", str(source), "-o", str(object_path)]
    dependency_command = [str(compiler), *prefix, *caller_flags, "-fPIE", "-M", str(source)]
    with dependency_path.open("wb") as output:
        subprocess.run(dependency_command, stdout=output, stderr=subprocess.PIPE, check=True, env=audit_environment)
    text = dependency_path.read_text(encoding="utf-8").replace("\\\n", " ")
    try:
        names = text.split(":", 1)[1].split()
    except IndexError as error:
        raise SystemExit(f"system cancellation compile audit lacks a dependency list for {role}") from error
    dependencies = [Path(name).resolve(strict=True) for name in names]
    if source not in dependencies:
        raise SystemExit(f"system cancellation compile audit omits its {role} source")
    if len(dependencies) != len(set(dependencies)):
        raise SystemExit(f"system cancellation compile audit repeats a {role} dependency")
    for dependency in dependencies:
        if dependency not in source_files and not dependency.is_relative_to(headers):
            raise SystemExit(f"system cancellation compile audit escapes installed headers for {role}: {dependency}")
    for header in required_headers:
        if headers / header not in dependencies:
            raise SystemExit(f"system cancellation compile audit omits {role} header: {header}")
    relocation_path = work / f"{role}.relocations"
    with relocation_path.open("wb") as output:
        subprocess.run(["/usr/bin/readelf", "-rW", str(object_path)], stdout=output, check=True, env=audit_environment)
    relocations = relocation_path.read_text(encoding="utf-8")
    if "R_X86_64_32" in relocations or "R_X86_64_32S" in relocations:
        raise SystemExit(f"system cancellation canonical {role} object is not PIE-relocatable")
    objects.append({
        "role": role,
        "source": str(source),
        "source_sha256": digest(source),
        "object": str(object_path),
        "object_sha256": digest(object_path),
        "actual_compile_command": actual_compile_command,
        "dependency_audit_command": dependency_command,
        "dependency_audit": {"path": dependency_path.name, "sha256": digest(dependency_path)},
        "dependencies": {str(path): digest(path) for path in dependencies},
        "relocations": {"path": relocation_path.name, "sha256": digest(relocation_path)},
    })
if objects[0]["object_sha256"] == objects[1]["object_sha256"]:
    raise SystemExit("system cancellation consumer and child objects unexpectedly coincide")
record = {
    "schema": "crabc.system-cancellation-compile/v2",
    "installed_dynamic": {
        "root": str(product),
        "manifest": binding(manifest),
        "driver": binding(driver),
        "installed_helper": binding(helper),
        "compiler": binding(compiler),
        "clean_environment": clean_environment,
    },
    "translation": translation,
    "objects": objects,
}
(work / "compile.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_COMPILE
}

assert_canonical_compile_receipt() {
    local dynamic_product="$1"
    python3 -B - "$dynamic_product" "$work" "$PROBE" "$CHILD" <<'PY_VERIFY'
from hashlib import sha256
import json
from pathlib import Path
import sys

product, work, probe, child = map(Path, sys.argv[1:])
product = product.resolve(strict=True)
work = work.resolve(strict=True)
probe = probe.resolve(strict=True)
child = child.resolve(strict=True)
headers = (product / "usr/include").resolve(strict=True)
driver = product / "bin/crabc-cc-dynamic"
helper = product / "share/crabc/crabc_cc_static.py"
manifest = product / "share/crabc/manifest.json"

def fail(message: str) -> None:
    raise SystemExit("system cancellation canonical compile: " + message)

def digest(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        fail(f"non-physical artifact: {path}")
    return sha256(path.read_bytes()).hexdigest()

def compiler_digest(path: Path) -> str:
    try:
        return sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        fail(f"compiler is unreadable: {path}: {error}")

def binding(path: Path, *, compiler: bool = False) -> dict[str, str]:
    return {"path": str(path), "sha256": compiler_digest(path) if compiler else digest(path)}

try:
    record = json.loads((work / "compile.json").read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"receipt is unreadable: {error}")
if not isinstance(record, dict) or set(record) != {"schema", "installed_dynamic", "translation", "objects"}:
    fail("receipt fields drifted")
sys.path.insert(0, str(product / "share/crabc"))
import crabc_cc_static as compiler_contract
if Path(compiler_contract.__file__).resolve() != helper.resolve():
    fail("helper is not installed")
compiler = Path(compiler_contract.compiler())
clean_environment = compiler_contract.clean_environment()
prefix = [
    "-nostdinc", "-isystem", str(headers), "-ffreestanding", "-fno-builtin",
    "-fstack-protector-strong",
]
caller_flags = ["-std=c11", "-fno-builtin", "-fno-stack-protector"]
expected_translation = {
    "driver_mode": "--dynamic-pie",
    "effective_codegen_flag": "-fPIE",
    "driver_compile_prefix": prefix,
    "caller_flags": caller_flags,
    "not_selected": ["-fPIC", "-fno-pie"],
}
expected_installed = {
    "root": str(product),
    "manifest": binding(manifest),
    "driver": binding(driver),
    "installed_helper": binding(helper),
    "compiler": binding(compiler, compiler=True),
    "clean_environment": clean_environment,
}
if record["schema"] != "crabc.system-cancellation-compile/v2":
    fail("receipt schema drifted")
if record["installed_dynamic"] != expected_installed:
    fail("installed driver/helper/compiler changed after links")
if record["translation"] != expected_translation:
    fail("translation flags drifted")
roles = {
    "consumer": (
        probe, {probe, probe.parent / "owned_cancellation_proc_witness.h"},
        ("errno.h", "pthread.h", "stdio.h", "stdlib.h", "signal.h", "sys/wait.h", "poll.h", "bits/alltypes.h"),
    ),
    "child": (
        child, {child}, ("stdio.h", "stdlib.h", "string.h", "signal.h", "unistd.h", "bits/alltypes.h"),
    ),
}
objects = record["objects"]
if (not isinstance(objects, list) or not all(isinstance(item, dict) for item in objects) or
        [item.get("role") for item in objects] != ["consumer", "child"]):
    fail("object role roster drifted")
for item in objects:
    role = item["role"]
    source, source_files, required_headers = roles[role]
    object_path = work / f"{role}.o"
    dependency_path = work / f"{role}.d"
    relocation_path = work / f"{role}.relocations"
    expected_fields = {
        "role", "source", "source_sha256", "object", "object_sha256", "actual_compile_command",
        "dependency_audit_command", "dependency_audit", "dependencies", "relocations",
    }
    if set(item) != expected_fields:
        fail(f"{role} receipt fields drifted")
    if (item["source"] != str(source) or item["source_sha256"] != digest(source) or
            item["object"] != str(object_path) or item["object_sha256"] != digest(object_path)):
        fail(f"canonical compile source changed after links: {role}")
    expected_actual_command = [str(driver), "--dynamic-pie", *caller_flags,
                               "-c", str(source), "-o", str(object_path)]
    expected_dependency_command = [str(compiler), *prefix, *caller_flags, "-fPIE", "-M", str(source)]
    if item["actual_compile_command"] != expected_actual_command:
        fail(f"{role} actual compile command drifted")
    if item["dependency_audit_command"] != expected_dependency_command:
        fail(f"{role} dependency command drifted")
    if item["dependency_audit"] != {"path": dependency_path.name, "sha256": digest(dependency_path)}:
        fail(f"{role} dependency audit changed after links")
    if item["relocations"] != {"path": relocation_path.name, "sha256": digest(relocation_path)}:
        fail(f"{role} relocations changed after links")
    dependencies = item["dependencies"]
    if not isinstance(dependencies, dict) or not dependencies:
        fail(f"{role} dependency roster drifted")
    for name, identity in dependencies.items():
        if not isinstance(name, str) or not isinstance(identity, str):
            fail(f"{role} dependency identity drifted")
        path = Path(name).resolve(strict=True)
        if path in source_files:
            if digest(path) != identity:
                fail(f"canonical compile source changed after links: {path}")
        elif path.is_relative_to(headers):
            if digest(path) != identity:
                fail(f"canonical compile header changed after links: {path}")
        else:
            fail(f"{role} dependency escaped installed headers: {path}")
    if str(source) not in dependencies:
        fail(f"{role} dependency audit omits its source")
    for header in required_headers:
        if str(headers / header) not in dependencies:
            fail(f"{role} dependency audit omits {header}")
if objects[0]["object_sha256"] == objects[1]["object_sha256"]:
    fail("consumer and child objects unexpectedly coincide")
PY_VERIFY
}

audit_musl_links() {
    python3 -B - "$work/compile.json" "$work/oracle-root/consumer" "$work/oracle-root/bin/sh" "$ORACLE_CC" <<'PY_MUSL'
from hashlib import sha256
import json
from pathlib import Path
import sys

compile_path, consumer, child, oracle = map(Path, sys.argv[1:])
record = json.loads(compile_path.read_text(encoding="utf-8"))
objects = {item.get("role"): item for item in record.get("objects", [])}
if set(objects) != {"consumer", "child"}:
    raise SystemExit("system cancellation musl audit lacks the canonical object roles")
digest = lambda path: sha256(path.read_bytes()).hexdigest()
links = {
    "consumer": (consumer, ["-static", "-fno-pie", "-no-pie", "-pthread"]),
    "child": (child, ["-static", "-fno-pie", "-no-pie"]),
}
for role, (output, _) in links.items():
    object_path = Path(objects[role].get("object", ""))
    if (not object_path.is_file() or object_path.is_symlink() or
            objects[role].get("object_sha256") != digest(object_path) or
            not output.is_file() or output.is_symlink()):
        raise SystemExit(f"system cancellation musl {role} object/output identity drifted")
evidence = {
    "schema": "crabc.system-cancellation-musl-links/v1",
    "oracle": {"path": str(oracle), "sha256": digest(oracle)},
    "links": {
        role: {
            "object": objects[role]["object"],
            "object_sha256": objects[role]["object_sha256"],
            "output": str(output),
            "output_sha256": digest(output),
            "flags": flags,
        }
        for role, (output, flags) in links.items()
    },
}
compile_path.with_name("musl-links.json").write_text(
    json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY_MUSL
}

# This audit is intentionally local to the two-source system-cancellation
# protocol. `owned_posix_product_evidence.validate_link` accepts one workload
# object and cannot prove that the fixed child and consumer stayed separate.
audit_link() {
    local family="$1" product="$2" dynamic_product="$3" mode="$4" role="$5"
    local candidate="$6" object_path="$7" receipt="$8"
    readelf -hW "$candidate" >"$candidate.header"
    readelf -lW "$candidate" >"$candidate.segments"
    readelf -dW "$candidate" >"$candidate.dynamic"
    python3 -B - "$family" "$product" "$dynamic_product" "$mode" "$role" \
        "$candidate" "$object_path" "$receipt" "$work/compile.json" "$PROBE" "$CHILD" <<'PY_AUDIT'
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

(
    family, product_text, dynamic_product_text, mode, role, candidate_text,
    object_text, receipt_text, compile_text, probe_text, child_text,
) = sys.argv[1:]
root = Path(product_text).resolve()
dynamic_product = Path(dynamic_product_text).resolve()
candidate = Path(candidate_text).resolve()
object_path = Path(object_text).resolve()
receipt_path = Path(receipt_text).resolve()
compile_path = Path(compile_text).resolve()
sources = {"consumer": Path(probe_text).resolve(), "child": Path(child_text).resolve()}

def fail(message: str) -> None:
    raise SystemExit("system cancellation artifact: " + message)

def digest(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        fail(f"non-physical artifact: {path}")
    return sha256(path.read_bytes()).hexdigest()

def load(path: Path, description: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{description} is unreadable: {error}")
    if path.is_symlink() or not isinstance(value, dict):
        fail(f"{description} identity drifted")
    return value

compile_record = load(compile_path, "canonical compile receipt")
expected_translation = {
    "driver_mode": "--dynamic-pie",
    "effective_codegen_flag": "-fPIE",
    "driver_compile_prefix": [
        "-nostdinc", "-isystem", str(dynamic_product / "usr/include"), "-ffreestanding",
        "-fno-builtin", "-fstack-protector-strong",
    ],
    "caller_flags": ["-std=c11", "-fno-builtin", "-fno-stack-protector"],
    "not_selected": ["-fPIC", "-fno-pie"],
}
sys.path.insert(0, str(dynamic_product / "share/crabc"))
import crabc_cc_static as compiler_contract
helper = dynamic_product / "share/crabc/crabc_cc_static.py"
if Path(compiler_contract.__file__).resolve() != helper.resolve():
    fail("canonical compile helper is not installed")
compiler = Path(compiler_contract.compiler())
clean_environment = compiler_contract.clean_environment()
def compiler_digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()

installed = compile_record.get("installed_dynamic")
expected_installed = {
    "root": str(dynamic_product),
    "manifest": {
        "path": str(dynamic_product / "share/crabc/manifest.json"),
        "sha256": digest(dynamic_product / "share/crabc/manifest.json"),
    },
    "driver": {
        "path": str(dynamic_product / "bin/crabc-cc-dynamic"),
        "sha256": digest(dynamic_product / "bin/crabc-cc-dynamic"),
    },
    "installed_helper": {"path": str(helper), "sha256": digest(helper)},
    "compiler": {"path": str(compiler), "sha256": compiler_digest(compiler)},
    "clean_environment": clean_environment,
}
if (compile_record.get("schema") != "crabc.system-cancellation-compile/v2" or
        not isinstance(installed, dict) or installed != expected_installed or
        compile_record.get("translation") != expected_translation):
    fail("canonical installed-header compile identity drifted")
objects = compile_record.get("objects")
if (not isinstance(objects, list) or not all(isinstance(item, dict) for item in objects) or
        [item.get("role") for item in objects] != ["consumer", "child"]):
    fail("canonical object role roster drifted")
by_role = {item["role"]: item for item in objects}
selected = by_role.get(role)
if role not in sources or not isinstance(selected, dict):
    fail("selected canonical object role drifted")
relocations = compile_path.with_name(role + ".relocations")
dependency_path = compile_path.with_name(role + ".d")
expected_object_fields = {
    "role", "source", "source_sha256", "object", "object_sha256", "actual_compile_command",
    "dependency_audit_command", "dependency_audit", "dependencies", "relocations",
}
expected_actual_compile_command = [
    str(dynamic_product / "bin/crabc-cc-dynamic"), "--dynamic-pie",
    *expected_translation["caller_flags"], "-c", str(sources[role]), "-o", str(object_path),
]
if (set(selected) != expected_object_fields or selected.get("source") != str(sources[role]) or
        selected.get("source_sha256") != digest(sources[role]) or
        selected.get("object") != str(object_path) or selected.get("object_sha256") != digest(object_path) or
        selected.get("actual_compile_command") != expected_actual_compile_command or
        selected.get("dependency_audit") != {"path": dependency_path.name, "sha256": digest(dependency_path)} or
        selected.get("relocations") != {"path": relocations.name, "sha256": digest(relocations)}):
    fail("selected canonical object identity drifted")
dependencies = selected.get("dependencies")
if not isinstance(dependencies, dict) or not dependencies:
    fail("selected canonical object lacks its header dependency audit")
headers = dynamic_product / "usr/include"
allowed_source_files = {
    "consumer": {sources["consumer"], sources["consumer"].parent / "owned_cancellation_proc_witness.h"},
    "child": {sources["child"]},
}[role]
required_headers = {
    "consumer": ("errno.h", "pthread.h", "stdio.h", "stdlib.h", "signal.h", "sys/wait.h", "poll.h", "bits/alltypes.h"),
    "child": ("stdio.h", "stdlib.h", "string.h", "signal.h", "unistd.h", "bits/alltypes.h"),
}[role]
expected_dependency_command = [
    str(compiler), *expected_translation["driver_compile_prefix"],
    *expected_translation["caller_flags"], "-fPIE", "-M", str(sources[role]),
]
if selected.get("dependency_audit_command") != expected_dependency_command:
    fail("selected canonical dependency command drifted")
for name, expected in dependencies.items():
    path = Path(name).resolve()
    if (not isinstance(name, str) or not isinstance(expected, str) or
            (path not in allowed_source_files and not path.is_relative_to(headers)) or digest(path) != expected):
        fail("selected canonical header dependency identity drifted")
if str(sources[role]) not in dependencies:
    fail("selected canonical dependency audit omits its source")
for header_name in required_headers:
    if str(headers / header_name) not in dependencies:
        fail(f"selected canonical dependency audit omits {role} header: {header_name}")

manifest_path = root / "share/crabc/manifest.json"
manifest = load(manifest_path, "link product manifest")
receipt = load(receipt_path, "link receipt")
header = Path(str(candidate) + ".header").read_text(encoding="utf-8")
segments = Path(str(candidate) + ".segments").read_text(encoding="utf-8")
dynamic = Path(str(candidate) + ".dynamic").read_text(encoding="utf-8")
library = root / "usr/lib"

if family == "static":
    expected_mode = {
        "static": ("static-et-exec", "ET_EXEC", "EXEC", "crt1.o", False),
        "static-pie": ("static-pie", "ET_DYN", "DYN", "rcrt1.o", True),
    }.get(mode)
    if expected_mode is None:
        fail("unknown static linkage")
    mode_id, elf_type, readelf_type, crt, pie = expected_mode
    installed_manifest = manifest.get("installed")
    payload = installed_manifest.get("files") if isinstance(installed_manifest, dict) else None
    if (manifest.get("schema") != 1 or manifest.get("format") != "crabc-x86-64-owned-static-sysroot-v1" or
            manifest.get("target") != "x86_64-unknown-linux-musl" or not isinstance(payload, dict)):
        fail("static product manifest identity drifted")
    runtime = (
        ("crt-entry", library / crt), ("crt-prologue", library / "crti.o"),
        ("libc", library / "libc.a"), ("builtins", library / "libcrabc-builtins.a"),
        ("crt-epilogue", library / "crtn.o"),
    )
    for runtime_role, path in runtime:
        if payload.get(path.relative_to(root).as_posix()) != digest(path):
            fail(f"static manifest/runtime identity drifted: {runtime_role}")
    expected_records = [
        {"role": runtime_role, "path": path.relative_to(root).as_posix(), "sha256": digest(path)}
        for runtime_role, path in runtime
    ] + [{"role": "application", "path": str(object_path), "sha256": digest(object_path)}]
    expected_contract = [
        "ld.lld", "-static", *(["-pie"] if pie else []), "--no-dynamic-linker", "--no-undefined",
        "--gc-sections", "-z", "relro", "-z", "now", "-e", "_start", str(library / crt),
        str(library / "crti.o"), "<application-objects>", str(library / "libc.a"),
        str(library / "libcrabc-builtins.a"), str(library / "crtn.o"), "-o", "<output>",
    ]
    if (receipt.get("schema") != 1 or receipt.get("format") != "crabc-x86-64-sealed-static-driver-v1" or
            receipt.get("target") != "x86_64-unknown-linux-musl" or receipt.get("mode") != {
                "id": mode_id, "elf_type": elf_type, "crt_object": crt, "interpreter": "absent"
            } or receipt.get("input_receipts") != expected_records or
            receipt.get("owned_link_contract") != expected_contract or
            receipt.get("output") != {"path": str(candidate), "sha256": digest(candidate)}):
        fail("static receipt or canonical object binding drifted")
    linker = receipt.get("resolved_linker")
    if not isinstance(linker, dict):
        fail("static receipt lacks resolved linker identity")
    linker_path = Path(linker.get("path", ""))
    if linker_path.name != "ld.lld" or linker.get("sha256") != digest(linker_path):
        fail("static receipt resolved linker identity drifted")
    for field, suffix in (("map", ".map"), ("trace", ".trace")):
        sidecar = receipt_path.with_suffix(suffix)
        if receipt.get(field) != {"path": sidecar.name, "sha256": digest(sidecar)}:
            fail(f"static receipt {field} identity drifted")
    trace = receipt_path.with_suffix(".trace").read_text(encoding="utf-8").splitlines()
    direct = {str(library / crt), str(library / "crti.o"), str(object_path), str(library / "crtn.o")}
    archives = {str(library / "libc.a"), str(library / "libcrabc-builtins.a")}
    seen = set()
    for line in trace:
        if line in direct:
            seen.add(line)
        elif any(line == archive or (line.startswith(archive + "(") and line.endswith(")")) for archive in archives):
            seen.add(next(archive for archive in archives if line == archive or (line.startswith(archive + "(") and line.endswith(")"))))
        else:
            fail(f"static trace escaped owned inputs: {line}")
    if seen != direct | archives:
        fail("static trace omitted an owned or canonical object input")
    if (not re.search(r"Type:\s+" + readelf_type + r"\s", header) or
            "Advanced Micro Devices X86-64" not in header or "INTERP" in segments or
            re.findall(r"\(NEEDED\).*\[([^\]]+)\]", dynamic) or "(TEXTREL)" in dynamic):
        fail("static ELF boundary drifted")
elif family == "dynamic":
    expected_mode = {"pie": ("pie", "DYN", "Scrt1.o"), "non-pie": ("exec", "EXEC", "crt1.o")}.get(mode)
    if expected_mode is None:
        fail("unknown dynamic linkage")
    receipt_mode, readelf_type, crt = expected_mode
    payload = manifest.get("files")
    if (manifest.get("schema") != 1 or manifest.get("format") != "crabc-x86-64-owned-dynamic-sysroot-v1" or
            manifest.get("target") != "x86_64-unknown-linux-musl" or not isinstance(payload, dict)):
        fail("dynamic product manifest identity drifted")
    runtime = [library / "crti.o", library / "libc.so", library / "crtn.o", library / crt, library / "crabc-dynamic-attach.o"]
    archive = library / "libcrabc-builtins.a"
    for path in [*runtime, archive]:
        if payload.get(path.relative_to(root).as_posix()) != digest(path):
            fail(f"dynamic manifest/runtime identity drifted: {path.name}")
    expected_inputs = [{"path": str(path), "sha256": digest(path)} for path in [*runtime, object_path, archive]]
    expected_runtime = sorted(path.relative_to(root).as_posix() for path in [*runtime, archive])
    linker = receipt.get("resolved_linker")
    if not isinstance(linker, dict):
        fail("dynamic receipt lacks resolved linker identity")
    linker_path = Path(linker.get("path", ""))
    if linker_path.name != "ld.lld" or linker.get("sha256") != digest(linker_path):
        fail("dynamic receipt resolved linker identity drifted")
    expected_command = [
        str(linker_path), *(["-pie"] if mode == "pie" else []), "--hash-style=sysv", "-z", "relro",
        "-z", "now", "-z", "noexecstack", "-z", "text", "--no-undefined", "--allow-shlib-undefined",
        "--enable-new-dtags", "-rpath", "/usr/lib", "--dynamic-linker", "/lib/ld-crabc-x86_64.so.1",
        str(library / crt), str(library / "crabc-dynamic-attach.o"), str(library / "crti.o"),
        str(object_path), str(library / "libc.so"), str(archive), str(library / "crtn.o"), "-o", str(candidate),
    ]
    if (receipt.get("schema") != 1 or receipt.get("format") != "crabc-x86-64-owned-dynamic-sysroot-v1" or
            receipt.get("mode") != receipt_mode or receipt.get("binding") != "now" or
            receipt.get("runtime_imports") != [] or receipt.get("application_runpath") != "/usr/lib" or
            receipt.get("application_dsos") != {} or receipt.get("output_path") != str(candidate) or
            receipt.get("output_sha256") != digest(candidate) or receipt.get("manifest_sha256") != digest(manifest_path) or
            receipt.get("owned_runtime_inputs") != expected_runtime or receipt.get("input_receipts") != expected_inputs or
            receipt.get("link_command") != expected_command):
        fail("dynamic receipt or canonical object binding drifted")
    trace = receipt.get("link_trace")
    if not isinstance(trace, list):
        fail("dynamic receipt trace drifted")
    direct = {str(path) for path in [*runtime, object_path]}
    seen = set()
    for line in trace:
        if line in direct:
            seen.add(line)
        elif line == str(archive) or (line.startswith(str(archive) + "(") and line.endswith(")")):
            seen.add(str(archive))
        else:
            fail(f"dynamic trace escaped owned inputs: {line}")
    # LLD may omit an unextracted builtins archive from `--trace`; its exact
    # receipt identity and link command above still bind the archive. Every
    # direct runtime and selected canonical object must remain visible.
    if seen != direct:
        fail("dynamic trace omitted a direct owned or canonical object input")
    interpreters = re.findall(r"Requesting program interpreter: ([^\]]+)\]", segments)
    needed = re.findall(r"\(NEEDED\).*\[([^\]]+)\]", dynamic)
    if (not re.search(r"Type:\s+" + readelf_type + r"\s", header) or
            "Advanced Micro Devices X86-64" not in header or
            interpreters != ["/lib/ld-crabc-x86_64.so.1"] or needed != ["libc.so"] or "(TEXTREL)" in dynamic):
        fail("dynamic ELF boundary drifted")
else:
    fail("unknown product family")

evidence = {
    "schema": "crabc.system-cancellation-link/v1",
    "family": family,
    "linkage": mode,
    "role": role,
    "link_product": {"path": str(root), "manifest_sha256": digest(manifest_path)},
    "canonical_compile_receipt_sha256": digest(compile_path),
    "canonical_object": {"path": str(object_path), "sha256": digest(object_path)},
    "candidate": {"path": str(candidate), "sha256": digest(candidate)},
    "receipt": {"path": str(receipt_path), "sha256": digest(receipt_path)},
}
Path(str(candidate) + ".evidence.json").write_text(
    json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY_AUDIT
}

run_product() {
    local family="$1" product="$2" mode role
    local -a modes=(static static-pie)
    local driver="$product/bin/crabc-cc"
    if [ "$family" = dynamic ]; then
        modes=(pie non-pie)
        driver="$product/bin/crabc-cc-dynamic"
    fi
    for mode in "${modes[@]}"; do
        local label="$family-$mode"
        local execution_root="$work/$label-root"
        local entry="-$mode"
        if [ "$family" = dynamic ]; then entry="--dynamic-$mode"; fi
        cp -a "$product" "$execution_root"
        mkdir -p "$execution_root/bin"
        for role in consumer child; do
            local object_path="$work/$role.o"
            local candidate="$work/$label-$role"
            local receipt="$candidate.crabc-link.json"
            local -a receipt_arguments=()
            if [ "$family" = static ]; then
                receipt="$candidate.receipt.json"
                receipt_arguments=(--link-receipt "$(basename "$receipt")")
            fi
            (
                cd "$work"
                TMPDIR="$work" "$driver" "$entry" "${receipt_arguments[@]}" "$object_path" -o "$candidate"
            )
            audit_link "$family" "$product" "$installed_dynamic" "$mode" "$role" \
                "$candidate" "$object_path" "$receipt"
            if [ "$role" = child ]; then
                cp "$candidate" "$execution_root/bin/sh"
            else
                cp "$candidate" "$execution_root/consumer"
            fi
        done
        run_consumer "$execution_root" /consumer "$label"
        if [ "$family" = dynamic ]; then
            # The fixed-path child keeps its owned interpreter; direct entry
            # varies only the initial consumer entry path.
            run_direct_consumer "$execution_root" "$label"
        fi
        printf 'system cancellation %s: PASS\n' "$label"
    done
}

# Build the dynamic product first because it owns the common installed-header
# translation. A supplied static root only selects the two static links; it
# never becomes a second compiler authority for either source role.
if [ -z "$provided_dynamic" ]; then
    provided_dynamic="$work/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
readonly installed_dynamic="$provided_dynamic"
"$installed_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -fno-stack-protector -c "$PROBE" -o "$work/consumer.o"
"$installed_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -fno-stack-protector -c "$CHILD" -o "$work/child.o"
audit_canonical_objects "$installed_dynamic"
assert_canonical_compile_receipt "$installed_dynamic"

mkdir -p "$work/oracle-root/bin"
TMPDIR="$work" "$ORACLE_CC" -static -fno-pie -no-pie -pthread "$work/consumer.o" \
    -o "$work/oracle-root/consumer"
TMPDIR="$work" "$ORACLE_CC" -static -fno-pie -no-pie "$work/child.o" \
    -o "$work/oracle-root/bin/sh"
assert_canonical_compile_receipt "$installed_dynamic"
audit_musl_links
run_consumer "$work/oracle-root" /consumer oracle
printf 'system cancellation pinned-musl oracle: PASS\n'

static_product=''
if [ -n "$provided_static" ]; then
    static_product="$provided_static"
elif [ "$dynamic_was_supplied" -eq 0 ]; then
    static_product="$work/static-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$static_product" >"$work/static-build.json"
fi
if [ -n "$static_product" ]; then
    run_product static "$static_product"
    assert_canonical_compile_receipt "$installed_dynamic"
fi
run_product dynamic "$installed_dynamic"
assert_canonical_compile_receipt "$installed_dynamic"
printf 'owned system cancellation: PASS (two canonical installed-header objects link unchanged to pinned musl, static/static-PIE and dynamic kernel/direct entries; source system/pclose waits, child ownership and supervisor cleanup remain contained); evidence: %s\n' "$work"
