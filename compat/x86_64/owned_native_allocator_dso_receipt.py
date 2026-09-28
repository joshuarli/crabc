#!/usr/bin/env python3
"""Replay the native-shadow executable, initial DSO and dlopen receipt."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
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
    "object-initial", "object-plugin", "object-probe",
    "oracle-initial-dso", "oracle-plugin-dso", "candidate-initial-dso", "candidate-plugin-dso",
    "oracle-probe-pie", "oracle-probe-non-pie", "candidate-probe-pie", "candidate-probe-non-pie",
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
    for name, relative in PRODUCT_PATHS.items():
        if name != "dynamic-manifest":
            require(manifest["files"].get(relative) == receipt.products[name]["sha256"],
                    f"{name} differs from installed manifest")
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
            name = f"{arm}-{role}-dso"
            dynamic, _, _, symbols = elf(products / name, "DYN")
            require(soname(dynamic) == [f"libdso-{role}.so"] and needed(dynamic) == ["libc.so"],
                    f"{name} linkage differs")
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
