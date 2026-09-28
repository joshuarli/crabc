#!/usr/bin/env python3
"""Replay the native-shadow executable, initial DSO and dlopen receipt."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Mapping

import native_shadow_receipt as shared


ROOT = Path(__file__).resolve().parents[2]
RUNNER = "owned-native-allocator-dso"
CASES = (
    "oracle-pie", "kernel-pie", "direct-pie",
    "oracle-non-pie", "kernel-non-pie", "direct-non-pie", "runner",
)
PARAMETERS = {
    "CASE_TIMEOUT": "30", "MODES": "pie,non-pie", "ENTRIES": "kernel,direct",
    "DSOS": "initial,dlopen-plugin", "ENVIRONMENT": "empty-with-pinned-PATH",
}
PRODUCT_PATHS = {
    "dynamic-manifest": "share/crabc/manifest.json",
    "dynamic-product-state": "share/crabc/dynamic-product-state.json",
    "dynamic-libc-provenance": "share/crabc/libc-shared.provenance.json",
    "dynamic-libc": "usr/lib/libc.so",
    "dynamic-loader": "lib/ld-crabc-x86_64.so.1",
    "dynamic-driver": "bin/crabc-cc-dynamic",
}
PRODUCTS = set(PRODUCT_PATHS) | {
    "musl-libc", "musl-interpreter", "musl-family-bindings", "candidate-family-bindings",
    "source-library", "link-producer", "oracle-wrapper", "oracle-gcc", "oracle-specs", "candidate-linker",
    "object-initial", "object-plugin", "object-probe",
    "oracle-initial-dso", "oracle-plugin-dso", "candidate-initial-dso", "candidate-plugin-dso",
    "oracle-probe-pie", "oracle-probe-non-pie", "candidate-probe-pie", "candidate-probe-non-pie",
    *(f"link-{arm}-{role}" for arm in ("oracle", "candidate") for role in ("initial", "plugin")),
    *(f"candidate-link-sidecar-{role}" for role in ("initial", "plugin")),
}
MALLOC_FAMILY = {
    "malloc", "free", "calloc", "realloc", "reallocarray", "aligned_alloc",
    "posix_memalign", "memalign", "valloc", "malloc_usable_size",
}
TRANSCRIPT = (
    b"one malloc family and errno contract in every image\n"
    b"cross-image transfers: 27 orders\n"
    b"worker blocks cross images\n"
    b"plugin retained after dlclose\n"
    b"plugin fini\n"
    b"executable fini\n"
    b"initial fini\n"
)


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise shared.ReceiptError(f"{RUNNER}: {reason}")


def json_file(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise shared.ReceiptError(f"{RUNNER}: unreadable {path.name}: {error}") from error
    require(isinstance(value, dict), f"{path.name} is malformed")
    return value


def product_source_digest(root: Path) -> str:
    """Recompute the installed product's content, path and mode source seal."""

    result = subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", str(root), "ls-files", "-z",
         "--cached", "--others", "--exclude-standard"],
        capture_output=True, check=False,
    )
    require(result.returncode == 0, "cannot enumerate dynamic product source")
    names = sorted(set(result.stdout.split(b"\0")) - {b""})
    digest = hashlib.sha256()
    try:
        for name in names:
            path = root / os.fsdecode(name)
            mode = path.lstat().st_mode
            data = os.fsencode(os.readlink(path)) if stat.S_ISLNK(mode) else path.read_bytes()
            digest.update(name + b"\0" + str(stat.S_IMODE(mode)).encode() + b"\0")
            digest.update(hashlib.sha256(data).digest())
    except OSError as error:
        raise shared.ReceiptError(f"{RUNNER}: cannot read dynamic product source: {error}") from error
    return digest.hexdigest()


def readelf(path: Path, *options: str) -> str:
    try:
        result = subprocess.run(["readelf", *options, str(path)], capture_output=True, text=True, check=False)
    except OSError as error:
        raise shared.ReceiptError(f"{RUNNER}: readelf unavailable: {error}") from error
    require(result.returncode == 0 and not result.stderr, f"ELF inspection failed for {path.name}")
    return result.stdout


def elf(path: Path, expected_type: str) -> tuple[str, str, str, dict[str, tuple[str, str, str, str]]]:
    header = readelf(path, "-h")
    require("Class:                             ELF64" in header
            and "Data:                              2's complement, little endian" in header
            and "Machine:                           Advanced Micro Devices X86-64" in header,
            f"{path.name} has the wrong ELF ABI")
    match = re.search(r"^\s*Type:\s+(\w+)", header, re.M)
    require(match is not None and match.group(1) == expected_type, f"{path.name} has the wrong ELF type")
    dynamic = readelf(path, "-dW") if expected_type != "REL" else ""
    program_headers = readelf(path, "-lW") if expected_type in {"DYN", "EXEC"} else ""
    symbols = {}
    for line in readelf(path, "--dyn-syms", "-W").splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].endswith(":") and fields[0][:-1].isdigit():
            symbols[fields[7]] = (fields[3], fields[4], fields[5], fields[6])
    return dynamic, program_headers, header, symbols


def needed(dynamic: str) -> list[str]:
    return re.findall(r"\(NEEDED\).*Shared library: \[([^]]+)\]", dynamic)


def soname(dynamic: str) -> list[str]:
    return re.findall(r"\(SONAME\).*Library soname: \[([^]]+)\]", dynamic)


def interpreter(program_headers: str) -> list[str]:
    return re.findall(r"Requesting program interpreter: ([^]]+)\]", program_headers)


def family_bindings(symbols: dict[str, tuple[str, str, str, str]]) -> bytes:
    lines = [f"{name} {kind} {binding} {visibility}"
             for name, (kind, binding, visibility, section) in symbols.items()
             if name in MALLOC_FAMILY and kind == "FUNC" and section != "UND"]
    return ("\n".join(sorted(lines)) + "\n").encode()


def check_link_identity(value: object, path: str, expected: Mapping[str, object], label: str) -> None:
    require(isinstance(value, dict) and set(value) == {"path", "sha256", "size"},
            f"{label} identity is malformed")
    require(value == {"path": path, "sha256": expected["sha256"], "size": expected["size"]},
            f"{label} identity differs")


def check_dso_link(root: Path, directory: Path, receipt: shared.Receipt,
                   manifest: dict, state: dict, work: str, arm: str, role: str) -> None:
    """Match one executed link record and owned sidecar to retained inputs."""

    products = receipt.products
    native_work = f"/workspace/{work}"
    name = f"{arm}-{role}"
    record = json_file(directory / "products" / f"link-{name}")
    require(set(record) == {"schema", "arm", "role", "cwd", "product", "command",
                            "inputs", "tools", "output", "sidecar"}
            and record["schema"] == "crabc.x86_64-owned-native-allocator-dso-link/v1"
            and record["arm"] == arm and record["role"] == role and record["cwd"] == "/workspace",
            f"{name} link record differs")
    inputs = record["inputs"]
    require(isinstance(inputs, dict) and set(inputs) == {"source", "object", "libc", "tool"},
            f"{name} link input roster differs")
    source = root / "compat/x86_64/owned_native_allocator_dso_library.c"
    require(products["source-library"]["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest(),
            "DSO library source differs from checkout")
    producer = root / "compat/x86_64/owned_native_allocator_dso.py"
    require(products["link-producer"]["sha256"] == hashlib.sha256(producer.read_bytes()).hexdigest(),
            "DSO link producer differs from checkout")
    check_link_identity(inputs["source"], "/workspace/compat/x86_64/owned_native_allocator_dso_library.c",
                        products["source-library"], f"{name} source")
    object_path = f"{native_work}/objects/{role}.o"
    check_link_identity(inputs["object"], object_path, products[f"object-{role}"], f"{name} object")
    output_path = (f"{native_work}/libdso-{role}.so" if arm == "candidate"
                   else f"{native_work}/oracle/libdso-{role}.so")
    check_link_identity(record["output"], output_path, products[f"{name}-dso"], f"{name}-dso link output")

    tools = record["tools"]
    if arm == "oracle":
        require(record["product"] is None and record["sidecar"] is None
                and isinstance(tools, dict) and set(tools) == {"gcc", "specs"},
                f"{name} oracle link tools differ")
        tool_path = "/usr/local/bin/crabc-x86_64-musl-gcc"
        check_link_identity(inputs["tool"], tool_path, products["oracle-wrapper"], f"{name} wrapper")
        check_link_identity(inputs["libc"], "/opt/musl-1.2.6/lib/libc.so",
                            products["musl-libc"], f"{name} libc")
        check_link_identity(tools["gcc"], "/usr/bin/gcc", products["oracle-gcc"], f"{name} gcc")
        check_link_identity(tools["specs"], "/opt/musl-1.2.6/lib/musl-gcc.specs",
                            products["oracle-specs"], f"{name} specs")
        command = [tool_path, "-shared", object_path,
                   f"-Wl,-z,now,-soname,libdso-{role}.so", "-o", output_path]
        require(record["command"] == command, f"{name} oracle link command differs")
        return

    product_root = record["product"]
    require(isinstance(product_root, str) and Path(product_root).is_absolute()
            and Path(product_root).is_relative_to(Path("/workspace/.work"))
            and ".." not in Path(product_root).parts,
            f"{name} selected dynamic product path differs")
    require(isinstance(tools, dict) and set(tools) == {"linker"},
            f"{name} candidate link tools differ")
    tool_path = f"{product_root}/bin/crabc-cc-dynamic"
    check_link_identity(inputs["tool"], tool_path, products["dynamic-driver"], f"{name} driver")
    check_link_identity(inputs["libc"], f"{product_root}/usr/lib/libc.so",
                        products["dynamic-libc"], f"{name} libc")
    require(record["command"] == [tool_path, "--dynamic-shared-object", object_path, "-o", output_path],
            f"{name} candidate link command differs")
    sidecar_path = f"{output_path}.crabc-link.json"
    check_link_identity(record["sidecar"], sidecar_path,
                        products[f"candidate-link-sidecar-{role}"], f"{name} sidecar")
    sidecar = json_file(directory / "products" / f"candidate-link-sidecar-{role}")
    linker_path = (f"/opt/rustup/toolchains/{manifest['toolchain']}-x86_64-unknown-linux-musl"
                   "/lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld")
    check_link_identity(tools["linker"], linker_path, products["candidate-linker"], f"{name} linker")
    require(sidecar.get("resolved_linker") == {"path": linker_path,
                                               "sha256": products["candidate-linker"]["sha256"]}
            and sidecar.get("schema") == 2 and sidecar.get("format") == manifest.get("format")
            and sidecar.get("mode") == "shared" and sidecar.get("binding") == "now"
            and sidecar.get("runtime_imports") == [] and sidecar.get("application_dsos") == {}
            and sidecar.get("application_runpath") == "/usr/lib"
            and sidecar.get("application_rpath") is None
            and sidecar.get("application_search_kind") == "runpath"
            and sidecar.get("application_hash_style") == "sysv"
            and sidecar.get("campaign_complete") is False,
            f"{name} owned link mode differs")
    require(sidecar.get("output_path") == output_path
            and sidecar.get("output_sha256") == products[f"{name}-dso"]["sha256"]
            and sidecar.get("manifest_sha256") == products["dynamic-manifest"]["sha256"],
            f"{name} link output differs")
    library = f"{product_root}/usr/lib"
    crti, libc, crtn = (f"{library}/{item}" for item in ("crti.o", "libc.so", "crtn.o"))
    builtins = f"{library}/libcrabc-builtins.a"
    expected_inputs = [
        {"path": crti, "sha256": state["payload_files"].get("usr/lib/crti.o")},
        {"path": libc, "sha256": products["dynamic-libc"]["sha256"]},
        {"path": crtn, "sha256": state["payload_files"].get("usr/lib/crtn.o")},
        {"path": object_path, "sha256": products[f"object-{role}"]["sha256"]},
        {"path": builtins, "sha256": state["payload_files"].get("usr/lib/libcrabc-builtins.a")},
    ]
    require(all(isinstance(item["sha256"], str) for item in expected_inputs)
            and sidecar.get("input_receipts") == expected_inputs
            and sidecar.get("owned_runtime_inputs") == sorted(("usr/lib/crti.o", "usr/lib/crtn.o",
                                                                 "usr/lib/libc.so", "usr/lib/libcrabc-builtins.a"))
            and sidecar.get("link_trace") == [crti, object_path, libc, crtn],
            f"{name} owned link inputs differ")
    command = [linker_path, "-shared", "--hash-style=sysv", "--eh-frame-hdr", "-z", "relro",
               "-z", "now", "-z", "noexecstack", "-z", "text", "--no-undefined",
               "--allow-shlib-undefined", "--enable-new-dtags", "-rpath", "/usr/lib",
               "-soname", f"libdso-{role}.so", crti, object_path, libc, builtins, crtn,
               "-o", output_path]
    require(sidecar.get("link_command") == command, f"{name} owned link command differs")


def read_native_allocator_dso_receipt(
    root: Path = ROOT, *, seal: Mapping[str, str] | None = None,
) -> shared.Receipt:
    """Require every mode, image identity and musl-equivalent raw transcript."""

    receipt = shared.read_receipt(root, RUNNER, seal=seal)
    directory = receipt.path.parent
    require(dict(receipt.parameters) == PARAMETERS, "canonical parameters differ")
    require(tuple(case["id"] for case in receipt.cases) == CASES, "case roster is incomplete or reordered")
    require(set(receipt.products) in (PRODUCTS, PRODUCTS | {"dynamic-build"}), "product roster differs")
    raw = json_file(receipt.path)
    work = raw.get("work")
    require(isinstance(work, str) and Path(work).parent == Path(".work/x86_64/tmp")
            and Path(work).name.startswith("owned-native-allocator-dso."), "work directory differs")

    records = {case["id"]: case for case in receipt.cases}
    for name in CASES:
        expected = {"runner.status"} if name == "runner" else {
            f"{name}.stdout", f"{name}.stderr", f"{name}.status",
        }
        require(set(records[name]["logs"]) == expected, f"{name} raw log roster differs")
        require((directory / "logs" / f"{name}.status").read_bytes() == b"0\n", f"{name} status differs")
        if name != "runner":
            require((directory / "logs" / f"{name}.stderr").read_bytes() == b"", f"{name} stderr differs")
            require((directory / "logs" / f"{name}.stdout").read_bytes() == TRANSCRIPT,
                    f"{name} differs from pinned musl transcript")
    for mode in ("pie", "non-pie"):
        oracle = (directory / "logs" / f"oracle-{mode}.stdout").read_bytes()
        for entry in ("kernel", "direct"):
            require((directory / "logs" / f"{entry}-{mode}.stdout").read_bytes() == oracle,
                    f"{entry}-{mode} transcript differs from oracle")

    manifest = json_file(directory / "products/dynamic-manifest")
    state = json_file(directory / "products/dynamic-product-state")
    provenance = json_file(directory / "products/dynamic-libc-provenance")
    require(manifest.get("target") == "x86_64-unknown-linux-musl"
            and isinstance(manifest.get("files"), dict), "dynamic manifest identity differs")
    require(state.get("allocator_backend") == "native-shadow"
            and provenance.get("allocator_backend") == "native-shadow", "allocator backend identity differs")
    require(state.get("schema") == "crabc.x86_64-owned-dynamic-materialization/v1"
            and state.get("status") == "materialized-unqualified"
            and state.get("modes") == ["dynamic-pie", "dynamic-non-pie", "dynamic-shared-object"]
            and isinstance(state.get("payload_files"), dict), "dynamic product state differs")
    require(state.get("source_sha256") == product_source_digest(root),
            "dynamic product source differs from checkout")
    for name, relative in PRODUCT_PATHS.items():
        if name != "dynamic-manifest":
            require(manifest["files"].get(relative) == receipt.products[name]["sha256"],
                    f"{name} differs from installed manifest")
        if name not in {"dynamic-manifest", "dynamic-product-state"}:
            require(state["payload_files"].get(relative) == receipt.products[name]["sha256"],
                    f"dynamic product payload differs for {name}")
    products = directory / "products"
    libc_dynamic, _, _, libc_symbols = elf(products / "dynamic-libc", "DYN")
    musl_dynamic, _, _, musl_symbols = elf(products / "musl-libc", "DYN")
    elf(products / "dynamic-loader", "DYN")
    elf(products / "musl-interpreter", "DYN")
    for name in ("object-initial", "object-plugin", "object-probe"):
        elf(products / name, "REL")
    require((products / "musl-family-bindings").read_bytes() == family_bindings(musl_symbols)
            and (products / "candidate-family-bindings").read_bytes() == family_bindings(libc_symbols)
            and (products / "musl-family-bindings").read_bytes() == (products / "candidate-family-bindings").read_bytes(),
            "malloc-family symbol bindings differ")
    require("libc.so" not in needed(libc_dynamic) and "libc.so" not in needed(musl_dynamic),
            "libc imports another libc")

    for arm in ("oracle", "candidate"):
        for role in ("initial", "plugin"):
            check_dso_link(root, directory, receipt, manifest, state, work, arm, role)
            name = f"{arm}-{role}-dso"
            dynamic, _, _, symbols = elf(products / name, "DYN")
            require(soname(dynamic) == [f"libdso-{role}.so"] and needed(dynamic) == ["libc.so"],
                    f"{name} linkage differs")
            expected_runpath = ["/usr/lib"] if arm == "candidate" else []
            require(re.findall(r"\(RUNPATH\).*Library runpath: \[([^]]+)\]", dynamic) == expected_runpath,
                    f"{name} runpath differs")
            api = f"dso_api_{role}"
            require(api in symbols and symbols[api][0:2] == ("FUNC", "GLOBAL")
                    and symbols[api][3] != "UND", f"{name} API identity differs")
        for mode, image_type in (("pie", "DYN"), ("non-pie", "EXEC")):
            name = f"{arm}-probe-{mode}"
            dynamic, headers, _, symbols = elf(products / name, image_type)
            require(set(needed(dynamic)) == {"libdso-initial.so", "libc.so"}
                    and len(needed(dynamic)) == 2 and "libdso-plugin.so" not in needed(dynamic),
                    f"{name} initial-DSO linkage differs")
            expected_interpreter = ("/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1" if arm == "oracle"
                                    else "/lib/ld-crabc-x86_64.so.1")
            require(interpreter(headers) == [expected_interpreter], f"{name} interpreter identity differs")
            require(all(symbol in symbols and symbols[symbol][3] == "UND"
                        for symbol in ("dso_api_initial", "dlopen", "dlsym", "dlclose"))
                    and "dso_api_plugin" not in symbols, f"{name} dlopen identity differs")
            if arm == "candidate":
                require(re.findall(r"\(RUNPATH\).*Library runpath: \[([^]]+)\]", dynamic) == ["/usr/lib"],
                        f"{name} runpath differs")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=["check"])
    parser.parse_args()
    try:
        result = read_native_allocator_dso_receipt()
    except shared.ReceiptError as error:
        parser.exit(1, f"{error}\n")
    print(f"{RUNNER}: {len(result.cases) - 1} passing cases; {result.path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
