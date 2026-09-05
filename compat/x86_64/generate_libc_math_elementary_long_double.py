#!/usr/bin/env python3
"""Generate the fixed musl 1.2.6 x86 math.elementary-long-double leaf.

This development/provenance tool is not part of the Rust build. The checked
assembly is the build input, so `crabc-libc` never invokes a foreign compiler.
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

# These are the eighteen public binary80 entries not already supplied by the
# existing x87 elementary artifact. Together, the two leaves own every symbol
# in `math.elementary-long-double` from compat/crabc-rs/coverage.toml.
PUBLIC_SOURCES = (
    "src/math/acoshl.c",
    "src/math/asinhl.c",
    "src/math/atanhl.c",
    "src/math/cbrtl.c",
    "src/math/copysignl.c",
    "src/math/coshl.c",
    "src/math/cosl.c",
    "src/math/fmal.c",
    "src/math/fmaxl.c",
    "src/math/fminl.c",
    "src/math/hypotl.c",
    "src/math/powl.c",
    "src/math/roundl.c",
    "src/math/sincosl.c",
    "src/math/sinhl.c",
    "src/math/sinl.c",
    "src/math/tanhl.c",
    "src/math/tanl.c",
)

# The trigonometric sources require this fixed musl closure. The two binary64
# helpers exist only to support argument reduction and remain local, so this
# capability does not select public binary64 elementary math.
PRIVATE_SOURCES = (
    "src/math/__cosl.c",
    "src/math/__polevll.c",
    "src/math/__rem_pio2l.c",
    "src/math/__rem_pio2_large.c",
    "src/math/__sinl.c",
    "src/math/__tanl.c",
    "src/math/floor.c",
    "src/math/scalbn.c",
)

PRIVATE_SYMBOLS = (
    "__cosl",
    "__p1evll",
    "__polevll",
    "__rem_pio2l",
    "__rem_pio2_large",
    "__sinl",
    "__tanl",
    "floor",
    "scalbn",
)

RENAME = {
    name: (
        "crabc_x86_math_elementary_long_double_internal_" + name[2:]
        if name.startswith("__")
        else "crabc_x86_math_elementary_long_double_provider_" + name
    )
    for name in PRIVATE_SYMBOLS
}

COMPILE_FLAGS = (
    "-D_XOPEN_SOURCE=700",
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
    tag = re.sub(r"[^A-Za-z0-9_]+", "_", Path(relative).with_suffix("").as_posix())
    globals_and_weak = set(
        re.findall(rf"^\s*\.(?:globl|global|weak)\s+({SYMBOL})\s*$", text, re.MULTILINE)
    )
    typed = set(
        re.findall(rf"^\s*\.type\s+({SYMBOL})\s*,\s*@(?:function|object)\s*$", text, re.MULTILINE)
    )
    for name in sorted(typed - globals_and_weak, key=len, reverse=True):
        if not name.startswith(".L"):
            text = replace_symbol(
                text, name, f"crabc_x86_math_elementary_long_double_{tag}_{name}"
            )

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
        rf".Lcrabc_x86_math_elementary_long_double_{tag}_\1",
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


def retained_notices(source_root: Path) -> list[str]:
    """Retain each distinct copyright-bearing upstream C notice verbatim."""
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
        default=ROOT
        / "libc/src/c_abi/x86_64/math_elementary_long_double_musl_x86_64.S",
    )
    args = parser.parse_args()

    source_root = args.musl_source.resolve()
    actual_digest = normalized_tree_digest(source_root)
    if actual_digest != EXPECTED_MUSL_TREE_DIGEST:
        raise SystemExit(
            "musl source tree digest mismatch: "
            f"expected {EXPECTED_MUSL_TREE_DIGEST}, got {actual_digest}"
        )
    compiler_version = subprocess.run(
        [args.cc, "--version"], check=True, capture_output=True, text=True
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
        " * Fixed musl 1.2.6 x86-64 math.elementary-long-double translation.",
        " * Generated by compat/x86_64/generate_libc_math_elementary_long_double.py;",
        " * see math_elementary_long_double.rs for the source/license/ABI contract.",
        " *",
        " * The remaining musl-authored portions retain musl's MIT license; the",
        " * exact release license is recorded by compat/upstreams.toml.",
        " */",
        *retained_notices(source_root),
    ]
    with tempfile.TemporaryDirectory(prefix="crabc-math-elementary-long-double-generate.") as temp:
        temp_root = Path(temp)
        for index, relative in enumerate(PUBLIC_SOURCES + PRIVATE_SOURCES):
            assembly = temp_root / f"{index:03}.s"
            subprocess.run(
                [
                    args.cc,
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
