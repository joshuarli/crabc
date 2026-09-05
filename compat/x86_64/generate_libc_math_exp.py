#!/usr/bin/env python3
"""Generate the fixed musl 1.2.6 x86 exp/expf assembly translation.

This development/provenance tool is deliberately outside the Rust build. The
checked assembly is the build input, so `crabc-libc` never invokes a foreign C
compiler while retaining musl's fixed scalar table reductions, gradual
underflow path, and exact IEEE overflow/underflow expressions.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXPECTED_MUSL_TREE_DIGEST = (
    "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88"
)
PUBLIC_SOURCES = (
    "src/math/exp.c",
    "src/math/expf.c",
)

# The binary64/binary32 entries share exactly these Arm tables and explicit
# overflow/underflow expression providers. They are renamed and localized in
# the checked assembly, so none is accidentally promoted into the archive ABI.
PRIVATE_SOURCES = (
    "src/math/exp_data.c",
    "src/math/exp2f_data.c",
    "src/math/__math_oflow.c",
    "src/math/__math_oflowf.c",
    "src/math/__math_uflow.c",
    "src/math/__math_uflowf.c",
    "src/math/__math_xflow.c",
    "src/math/__math_xflowf.c",
)
PRIVATE_SYMBOLS = (
    "__exp_data",
    "__exp2f_data",
    "__math_oflow",
    "__math_oflowf",
    "__math_uflow",
    "__math_uflowf",
    "__math_xflow",
    "__math_xflowf",
)
RENAME = {
    name: f"crabc_x86_math_exp_{name}"
    for name in PRIVATE_SYMBOLS
}

# Fixed SSE evaluation, no contracted FMA, and standard excess precision keep
# binary32/binary64 results and musl's source operation order reproducible.
COMPILE_FLAGS = (
    "-D_XOPEN_SOURCE=700",
    "-std=c99",
    "-ffreestanding",
    "-frounding-math",
    "-ffp-contract=off",
    "-fexcess-precision=standard",
    "-mfpmath=sse",
    "-mno-avx",
    "-mno-avx2",
    "-mno-fma",
    "-mno-fma4",
    "-fno-builtin-exp",
    "-fno-builtin-expf",
    "-fno-tree-vectorize",
    "-fno-tree-slp-vectorize",
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
SYMBOL = r"[A-Za-z_.$][A-Za-z0-9_.$]*"


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


def replace_symbol(text: str, old: str, new: str) -> str:
    pattern = rf"(?<![A-Za-z0-9_.]){re.escape(old)}(?![A-Za-z0-9_.$])"
    return re.sub(pattern, new, text)


def transform_assembly(relative: str, text: str) -> str:
    """Localize the bounded closure and avoid concatenated-label collisions."""

    tag = re.sub(r"[^A-Za-z0-9_]+", "_", Path(relative).with_suffix("").as_posix())
    globals_and_weak = set(
        re.findall(rf"^\s*\.(?:globl|global|weak)\s+({SYMBOL})\s*$", text, re.MULTILINE)
    )
    typed = set(
        re.findall(
            rf"^\s*\.type\s+({SYMBOL})\s*,\s*@(?:function|object)\s*$",
            text,
            re.MULTILINE,
        )
    )
    for name in sorted(typed - globals_and_weak, key=len, reverse=True):
        if not name.startswith(".L"):
            text = replace_symbol(text, name, f"crabc_x86_math_exp_{tag}_{name}")

    for old, new in sorted(RENAME.items(), key=lambda item: len(item[0]), reverse=True):
        text = replace_symbol(text, old, new)
    for private in RENAME.values():
        text = re.sub(
            rf"^(\s*)\.globl\s+{re.escape(private)}\s*$",
            rf"\1.local\t{private}",
            text,
            flags=re.MULTILINE,
        )

    text = re.sub(
        r"(?<![A-Za-z0-9_.])\.L([A-Za-z0-9_.$]+)",
        rf".Lcrabc_x86_math_exp_{tag}_\1",
        text,
    )
    text = re.sub(r"^\s*\.file\s+.*\n", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*\.ident\s+.*\n", "", text, flags=re.MULTILINE)
    text = re.sub(
        r"^\s*\.section\s+\.note\.GNU-stack[^\n]*\n",
        "",
        text,
        flags=re.MULTILINE,
    )
    return text.rstrip() + "\n"


def retained_notices(source_root: Path) -> list[str]:
    """Retain each copyright-bearing input notice in the generated assembly."""

    notices: list[str] = []
    for relative in PUBLIC_SOURCES + PRIVATE_SOURCES:
        text = (source_root / relative).read_text()
        for comment in re.findall(r"/\*.*?\*/", text, re.DOTALL):
            if "Copyright" in comment and comment not in notices:
                notices.append(comment)
    return notices


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--musl-source", required=True, type=Path)
    parser.add_argument("--cc", default="/usr/local/bin/crabc-x86_64-musl-gcc")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "libc/src/c_abi/x86_64/math_exp_musl_x86_64.S",
    )
    arguments = parser.parse_args()

    source_root = arguments.musl_source.resolve()
    actual_digest = normalized_tree_digest(source_root)
    if actual_digest != EXPECTED_MUSL_TREE_DIGEST:
        raise SystemExit(
            "musl source tree digest mismatch: "
            f"expected {EXPECTED_MUSL_TREE_DIGEST}, got {actual_digest}"
        )
    compiler_version = subprocess.run(
        [arguments.cc, "--version"], check=True, capture_output=True, text=True
    ).stdout.splitlines()[0]
    if "15.2.0" not in compiler_version:
        raise SystemExit(f"expected pinned GCC 15.2.0, got: {compiler_version}")

    include_flags = (
        f"-I{source_root / 'src/internal'}",
        f"-I{source_root / 'src/include'}",
        f"-I{source_root / 'arch/x86_64'}",
        f"-I{source_root / 'arch/generic'}",
        f"-I{source_root / 'include'}",
    )
    blocks = [
        "/*",
        " * Fixed musl 1.2.6 x86-64 exp/expf assembly translation.",
        " * Generated by compat/x86_64/generate_libc_math_exp.py; see",
        " * math_exp.rs for the source/license/ABI contract.",
        " *",
        " * The musl-distributed portions retain the Arm MIT notices below; musl's MIT license",
        " * for the 1.2.6 distribution is recorded by compat/upstreams.toml.",
        " */",
    ]
    blocks.extend(retained_notices(source_root))
    with tempfile.TemporaryDirectory(prefix="crabc-math-exp-generate.") as temp:
        temp_root = Path(temp)
        for index, relative in enumerate(PUBLIC_SOURCES + PRIVATE_SOURCES):
            assembly = temp_root / f"{index:03}.s"
            subprocess.run(
                [
                    arguments.cc,
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
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(output)
    print(f"wrote {arguments.output} ({output.count(chr(10))} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
