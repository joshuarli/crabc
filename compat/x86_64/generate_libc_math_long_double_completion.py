#!/usr/bin/env python3
"""Generate the fixed musl 1.2.6 x86 binary80 fdiml/exp10l leaf.

This provenance tool is not part of the Rust build.  It accepts an explicitly
supplied, digest-checked musl source tree and writes the checked assembly that
`math_long_double_completion.rs` includes.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXPECTED_MUSL_TREE_DIGEST = (
    "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88"
)
EXPECTED_COMPILER_VERSION = "gcc (Alpine 15.2.0) 15.2.0"
EXPECTED_COMPILER_TARGET = "x86_64-alpine-linux-musl"
EXPECTED_COMPILER_WRAPPER_DIGEST = (
    "9b28cac06b7a1f35331ca06e23a1fc3fa7be9a6f85d9c6006363e8185001c90a"
)
SOURCES = (
    "src/math/fdiml.c",
    "src/math/exp10l.c",
)
COMPILE_FLAGS = (
    "-std=c99",
    "-ffreestanding",
    "-frounding-math",
    "-O2",
    "-fno-align-jumps",
    "-fno-align-functions",
    "-fno-align-loops",
    "-fno-align-labels",
    "-fira-region=one",
    "-fira-hoist-pressure",
    "-freorder-blocks-algorithm=simple",
    "-fno-prefetch-loop-arrays",
    "-fno-tree-ch",
    "-fomit-frame-pointer",
    "-fno-unwind-tables",
    "-fno-asynchronous-unwind-tables",
    "-ffunction-sections",
    "-fdata-sections",
    "-fno-stack-protector",
    # Pinned musl's .lo model keeps table addresses valid in installed libc.so.
    "-fPIC",
    "-fno-ident",
)


def normalized_tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob("*") if path.is_file())
    for path in files:
        relative = path.relative_to(root).as_posix().encode()
        contents = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return digest.hexdigest()


def compiler_environment() -> dict[str, str]:
    """Keep ambient compiler/search-path variables out of fixed assembly."""
    environment = os.environ.copy()
    for name in (
        "CPATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "LIBRARY_PATH",
        "GCC_EXEC_PREFIX",
        "COMPILER_PATH",
    ):
        environment.pop(name, None)
    return environment


def checked_compiler(command: str, *, environment: dict[str, str] | None = None) -> str:
    """Require the exact pinned musl-GCC wrapper, version, and target."""
    compiler = Path(command).resolve()
    if not compiler.is_file():
        raise SystemExit(f"pinned compiler is not a regular file: {compiler}")
    digest = hashlib.sha256(compiler.read_bytes()).hexdigest()
    if digest != EXPECTED_COMPILER_WRAPPER_DIGEST:
        raise SystemExit(
            "pinned compiler wrapper digest mismatch: "
            f"expected {EXPECTED_COMPILER_WRAPPER_DIGEST}, got {digest}"
        )
    environment = compiler_environment() if environment is None else environment
    version_lines = subprocess.run(
        [str(compiler), "--version"],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    ).stdout.splitlines()
    compiler_version = version_lines[0] if version_lines else ""
    if compiler_version != EXPECTED_COMPILER_VERSION:
        raise SystemExit(
            "pinned compiler version mismatch: "
            f"expected {EXPECTED_COMPILER_VERSION!r}, got {compiler_version!r}"
        )
    compiler_target = subprocess.run(
        [str(compiler), "-dumpmachine"],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    ).stdout.strip()
    if compiler_target != EXPECTED_COMPILER_TARGET:
        raise SystemExit(
            "pinned compiler target mismatch: "
            f"expected {EXPECTED_COMPILER_TARGET!r}, got {compiler_target!r}"
        )
    return str(compiler)


def transform_assembly(relative: str, text: str) -> str:
    """Give assembler-local labels file-specific names before concatenation."""
    tag = re.sub(r"[^A-Za-z0-9_]+", "_", Path(relative).with_suffix("").as_posix())
    text = re.sub(
        r"(?<![A-Za-z0-9_.])\.L([A-Za-z0-9_.$]+)",
        rf".Lcrabc_x86_math_long_double_completion_{tag}_\1",
        text,
    )
    text = re.sub(r"^\s*\.file\s+.*\n", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*\.ident\s+.*\n", "", text, flags=re.MULTILINE)
    text = re.sub(
        r'^\s*\.section\s+\.note\.GNU-stack[^\n]*\n',
        "",
        text,
        flags=re.MULTILINE,
    )
    return text.rstrip() + "\n"


def notices(source_root: Path) -> list[str]:
    result: list[str] = []
    for relative in SOURCES:
        text = (source_root / relative).read_text()
        for comment in re.findall(r"/\*.*?\*/", text, re.DOTALL):
            if "Copyright" in comment and comment not in result:
                result.append(comment)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--musl-source", required=True, type=Path)
    parser.add_argument("--cc", default="/usr/local/bin/crabc-x86_64-musl-gcc")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "libc/src/c_abi/x86_64/math_long_double_completion_musl_x86_64.S",
    )
    args = parser.parse_args()

    source_root = args.musl_source.resolve()
    actual_digest = normalized_tree_digest(source_root)
    if actual_digest != EXPECTED_MUSL_TREE_DIGEST:
        raise SystemExit(
            "musl source tree digest mismatch: "
            f"expected {EXPECTED_MUSL_TREE_DIGEST}, got {actual_digest}"
        )
    compiler = checked_compiler(args.cc)

    include_flags = (
        f"-I{source_root / 'src/internal'}",
        f"-I{source_root / 'src/include'}",
        f"-I{source_root / 'arch/x86_64'}",
        f"-I{source_root / 'arch/generic'}",
        f"-I{source_root / 'include'}",
    )
    blocks = [
        "/*",
        " * Fixed musl 1.2.6 x86 binary80 fdiml/exp10l translation.",
        " * Generated by compat/x86_64/generate_libc_math_long_double_completion.py;",
        " * see math_long_double_completion.rs for source/license/ABI contract.",
        " *",
        " * Remaining musl-authored portions retain musl's MIT license; the",
        " * pinned release license is recorded by compat/upstreams.toml.",
        " */",
        *notices(source_root),
    ]
    with tempfile.TemporaryDirectory(prefix="crabc-math-long-double-generate.") as temp:
        temporary = Path(temp)
        for index, relative in enumerate(SOURCES):
            assembly = temporary / f"{index:03}.s"
            subprocess.run(
                [
                    compiler,
                    *COMPILE_FLAGS,
                    *include_flags,
                    "-S",
                    str(source_root / relative),
                    "-o",
                    str(assembly),
                ],
                check=True,
            )
            blocks.append(f"\n/* musl-1.2.6/{relative} */")
            blocks.append(transform_assembly(relative, assembly.read_text()))
    blocks.append('\n.section .note.GNU-stack,"",@progbits\n')
    output = "\n".join(blocks)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output)
    print(f"wrote {args.output} ({output.count(chr(10))} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
