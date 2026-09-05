#!/usr/bin/env python3
"""Generate the fixed musl 1.2.6 owned x86 scalar-math completion leaf.

This provenance tool is not part of the Rust build. The checked assembly is
the build input, so the installed owned-static sysroot never invokes a foreign
C compiler or links ambient libm.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "scripts"))
import build_x86_64_owned_sysroot as producer
from generate_libc_math_long_double_completion import checked_compiler


EXPECTED_MUSL_TREE_DIGEST = (
    "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88"
)

# The fma wrappers include musl's generic implementation when the pinned
# baseline compiler is forbidden from selecting FMA3/FMA4. `scalbn` is the one
# private fma provider. hypot deliberately calls the selected sqrt siblings;
# log1p has no callable source dependency.
PUBLIC_SOURCES = (
    "src/math/x86_64/fma.c",
    "src/math/x86_64/fmaf.c",
    "src/math/hypot.c",
    "src/math/hypotf.c",
    "src/math/log1p.c",
    "src/math/log1pf.c",
)
PRIVATE_SOURCES = ("src/math/scalbn.c",)
NOTICE_SOURCES = (
    "src/math/fma.c",
    "src/math/fmaf.c",
    "src/math/hypot.c",
    "src/math/hypotf.c",
    "src/math/log1p.c",
    "src/math/log1pf.c",
    "src/math/scalbn.c",
)
PUBLIC_SYMBOLS = ("fma", "fmaf", "hypot", "hypotf", "log1p", "log1pf")
PRIVATE_RENAMES = {
    "scalbn": "crabc_x86_math_scalar_completion_provider_scalbn",
}

# Preserve musl's generic scalar, all-rounding-mode operation order. In
# particular, no x87 extended precision, AVX, packed-SIMD, or FMA ISA path can
# enter this baseline component. `-fPIC` is required because the same checked
# assembly is part of the materialized installed static sysroot.
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
    "-fno-builtin-fma",
    "-fno-builtin-fmaf",
    "-fno-builtin-hypot",
    "-fno-builtin-hypotf",
    "-fno-builtin-log1p",
    "-fno-builtin-log1pf",
    "-fno-builtin-sqrt",
    "-fno-builtin-sqrtf",
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
    "-fPIC",
    "-fno-ident",
)
SYMBOL = r"[A-Za-z_.$][A-Za-z0-9_.$]*"


def generation_environment() -> dict[str, str]:
    """Use physical checkout-owned state, never caller scratch or search paths."""
    return producer.deterministic_environment()


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
    """Namespace TU-local symbols and localize the one private provider."""
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
            text = replace_symbol(
                text, name, f"crabc_x86_math_scalar_completion_{tag}_{name}"
            )
    text = re.sub(
        r"(?<![A-Za-z0-9_.])\.L([A-Za-z0-9_.$]+)",
        rf".Lcrabc_x86_math_scalar_completion_{tag}_\1",
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


def source_defines(relative: str) -> tuple[str, ...]:
    if relative in ("src/math/x86_64/fma.c", "src/math/scalbn.c"):
        return (f"-Dscalbn={PRIVATE_RENAMES['scalbn']}",)
    return ()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--musl-source", required=True, type=Path)
    parser.add_argument("--cc", default="/usr/local/bin/crabc-x86_64-musl-gcc")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "libc/src/c_abi/x86_64/math_scalar_completion_musl_x86_64.S",
    )
    arguments = parser.parse_args()

    source_root = arguments.musl_source.resolve()
    actual_digest = normalized_tree_digest(source_root)
    if actual_digest != EXPECTED_MUSL_TREE_DIGEST:
        raise SystemExit(
            "musl source tree digest mismatch: "
            f"expected {EXPECTED_MUSL_TREE_DIGEST}, got {actual_digest}"
        )
    environment = generation_environment()
    compiler = checked_compiler(arguments.cc, environment=environment)
    include_flags = (
        f"-I{source_root / 'src/internal'}",
        f"-I{source_root / 'src/include'}",
        f"-I{source_root / 'arch/x86_64'}",
        f"-I{source_root / 'arch/generic'}",
        f"-I{source_root / 'include'}",
    )
    blocks = [
        "/*",
        " * Fixed musl 1.2.6 generic x86-64 scalar-math completion.",
        " * Generated by compat/x86_64/generate_libc_math_scalar_completion.py; see",
        " * math_scalar_completion.rs for the source/license/ABI contract.",
        " *",
        " * The normal musl-authored portions retain musl's MIT license; the",
        " * exact release license is recorded by compat/upstreams.toml.",
        " */",
    ]
    blocks.extend(retained_notices(source_root))
    with tempfile.TemporaryDirectory(
        prefix="crabc-x86-math-scalar-completion-", dir=environment["TMPDIR"]
    ) as temporary:
        temporary_root = Path(temporary)
        for index, relative in enumerate((*PUBLIC_SOURCES, *PRIVATE_SOURCES)):
            assembly = temporary_root / f"{index:03}.S"
            subprocess.run(
                [
                    compiler,
                    *COMPILE_FLAGS,
                    *source_defines(relative),
                    *include_flags,
                    "-S",
                    str(source_root / relative),
                    "-o",
                    str(assembly),
                ],
                check=True,
                env=environment,
            )
            blocks.extend(
                (
                    f"/* musl-1.2.6/{relative} */",
                    transform_assembly(relative, assembly.read_text()),
                )
            )
    blocks.append('.section .note.GNU-stack,"",@progbits')
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text("\n".join(blocks) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
