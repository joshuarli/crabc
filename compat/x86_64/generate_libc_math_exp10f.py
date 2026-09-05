#!/usr/bin/env python3
"""Generate the fixed musl 1.2.6 x86 GNU ``exp10f``/``pow10f`` leaf.

This provenance tool is outside the Rust build.  The checked assembly is the
build input, so the archive never invokes a foreign C compiler.
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

# musl exposes exp10f and the GNU weak same-address pow10f alias from this one
# source.  Its direct closure uses modff plus binary32/binary64 exp2 paths.
PUBLIC_SOURCES = ("src/math/exp10f.c",)
PRIVATE_SOURCES = (
    "src/math/modff.c",
    "src/math/exp2.c",
    "src/math/exp2f.c",
    "src/math/exp_data.c",
    "src/math/exp2f_data.c",
    "src/math/__math_oflow.c",
    "src/math/__math_oflowf.c",
    "src/math/__math_uflow.c",
    "src/math/__math_uflowf.c",
    "src/math/__math_xflow.c",
    "src/math/__math_xflowf.c",
)
NOTICE_SOURCES = (*PUBLIC_SOURCES, *PRIVATE_SOURCES)
PRIVATE_RENAMES = {
    "modff": "crabc_x86_math_exp10f_provider_modff",
    "exp2": "crabc_x86_math_exp10f_provider_exp2",
    "exp2f": "crabc_x86_math_exp10f_provider_exp2f",
    "__exp_data": "crabc_x86_math_exp10f_data_exp",
    "__exp2f_data": "crabc_x86_math_exp10f_data_exp2f",
    "__math_oflow": "crabc_x86_math_exp10f_helper_oflow",
    "__math_oflowf": "crabc_x86_math_exp10f_helper_oflowf",
    "__math_uflow": "crabc_x86_math_exp10f_helper_uflow",
    "__math_uflowf": "crabc_x86_math_exp10f_helper_uflowf",
    "__math_xflow": "crabc_x86_math_exp10f_helper_xflow",
    "__math_xflowf": "crabc_x86_math_exp10f_helper_xflowf",
}

# Preserve musl's generic scalar arithmetic and all-rounding-mode operation
# order.  The disabled vector/FMA paths keep the resulting assembly auditable.
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
    "-fno-builtin-exp10f",
    "-fno-builtin-pow10f",
    "-fno-builtin-modff",
    "-fno-builtin-exp2",
    "-fno-builtin-exp2f",
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
    for path in sorted(path for path in root.rglob("*") if path.is_file()):
        relative = path.relative_to(root).as_posix().encode()
        contents = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return digest.hexdigest()


def replace_symbol(text: str, old: str, new: str) -> str:
    return re.sub(
        rf"(?<![A-Za-z0-9_.]){re.escape(old)}(?![A-Za-z0-9_.$])", new, text
    )


def make_private_symbol_local(text: str, symbol: str) -> str:
    return re.sub(
        rf"^(\s*)\.(?:globl|global|weak)\s+{re.escape(symbol)}\s*$",
        rf"\1.local {symbol}",
        text,
        flags=re.MULTILINE,
    )


def transform_assembly(relative: str, text: str) -> str:
    """Namespace TU-local labels and localize every closure provider."""
    tag = re.sub(r"[^A-Za-z0-9_]+", "_", Path(relative).with_suffix("").as_posix())
    for old, new in sorted(PRIVATE_RENAMES.items(), key=lambda item: -len(item[0])):
        text = make_private_symbol_local(replace_symbol(text, old, new), new)
    globals_and_weak = set(
        re.findall(
            rf"^\s*\.(?:globl|global|weak)\s+({SYMBOL})\s*$", text, re.MULTILINE
        )
    )
    typed = set(
        re.findall(
            rf"^\s*\.type\s+({SYMBOL})\s*,\s*@(?:function|object)\s*$",
            text,
            re.MULTILINE,
        )
    )
    for name in sorted(
        typed - globals_and_weak - set(PRIVATE_RENAMES.values()),
        key=len,
        reverse=True,
    ):
        if not name.startswith(".L"):
            text = replace_symbol(text, name, f"crabc_x86_math_exp10f_{tag}_{name}")
    text = re.sub(
        r"(?<![A-Za-z0-9_.])\.L([A-Za-z0-9_.$]+)",
        rf".Lcrabc_x86_math_exp10f_{tag}_\1",
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
    notices: list[str] = []
    for relative in NOTICE_SOURCES:
        for comment in re.findall(
            r"/\*.*?\*/", (source_root / relative).read_text(), re.DOTALL
        ):
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
        default=ROOT / "libc/src/c_abi/x86_64/math_exp10f_musl_x86_64.S",
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
        " * Fixed musl 1.2.6 generic x86-64 GNU exp10f/pow10f translation.",
        " * Generated by compat/x86_64/generate_libc_math_exp10f.py; see",
        " * math_exp10f.rs for the source/license/ABI contract.",
        " *",
        " * The musl-distributed portions retain the Arm notices below; musl's MIT license",
        " * for the 1.2.6 distribution is recorded by compat/upstreams.toml.",
        " */",
    ]
    blocks.extend(retained_notices(source_root))
    with tempfile.TemporaryDirectory(prefix="crabc-x86-math-exp10f-") as temporary:
        temporary_root = Path(temporary)
        for index, relative in enumerate((*PUBLIC_SOURCES, *PRIVATE_SOURCES)):
            assembly = temporary_root / f"{index:03}.S"
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
            blocks.extend(
                (
                    f"/* musl-1.2.6/{relative} */",
                    transform_assembly(relative, assembly.read_text()),
                )
            )
    blocks.append('.section .note.GNU-stack,"",@progbits')
    output = "\n".join(blocks) + "\n"
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(output)
    print(f"wrote {arguments.output} ({output.count(chr(10))} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
