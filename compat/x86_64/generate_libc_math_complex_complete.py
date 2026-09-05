#!/usr/bin/env python3
"""Generate the fixed musl 1.2.6 x86 complete math.complex translation.

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

# The nine real/imaginary accessors and conjugation entries already live in
# math_complex.rs. These sources own the other 57 public capability entries
# and the two private scaled-exponential helpers used by cexp{,f}.
COMPLEX_SOURCES = (
    "src/complex/__cexp.c",
    "src/complex/__cexpf.c",
    "src/complex/cabs.c",
    "src/complex/cabsf.c",
    "src/complex/cabsl.c",
    "src/complex/cacos.c",
    "src/complex/cacosf.c",
    "src/complex/cacosh.c",
    "src/complex/cacoshf.c",
    "src/complex/cacoshl.c",
    "src/complex/cacosl.c",
    "src/complex/carg.c",
    "src/complex/cargf.c",
    "src/complex/cargl.c",
    "src/complex/casin.c",
    "src/complex/casinf.c",
    "src/complex/casinh.c",
    "src/complex/casinhf.c",
    "src/complex/casinhl.c",
    "src/complex/casinl.c",
    "src/complex/catan.c",
    "src/complex/catanf.c",
    "src/complex/catanh.c",
    "src/complex/catanhf.c",
    "src/complex/catanhl.c",
    "src/complex/catanl.c",
    "src/complex/ccos.c",
    "src/complex/ccosf.c",
    "src/complex/ccosh.c",
    "src/complex/ccoshf.c",
    "src/complex/ccoshl.c",
    "src/complex/ccosl.c",
    "src/complex/cexp.c",
    "src/complex/cexpf.c",
    "src/complex/cexpl.c",
    "src/complex/clog.c",
    "src/complex/clogf.c",
    "src/complex/clogl.c",
    "src/complex/cpow.c",
    "src/complex/cpowf.c",
    "src/complex/cpowl.c",
    "src/complex/cproj.c",
    "src/complex/cprojf.c",
    "src/complex/cprojl.c",
    "src/complex/csin.c",
    "src/complex/csinf.c",
    "src/complex/csinh.c",
    "src/complex/csinhf.c",
    "src/complex/csinhl.c",
    "src/complex/csinl.c",
    "src/complex/csqrt.c",
    "src/complex/csqrtf.c",
    "src/complex/csqrtl.c",
    "src/complex/ctan.c",
    "src/complex/ctanf.c",
    "src/complex/ctanh.c",
    "src/complex/ctanhf.c",
    "src/complex/ctanhl.c",
    "src/complex/ctanl.c",
)

# Complex transcendental algorithms need scalar operations internally. These
# exact musl providers are renamed and localized below; none becomes another
# public x86 elementary capability or archive export.
PRIVATE_SOURCES = (
    "src/math/atan.c",
    "src/math/atanf.c",
    "src/math/atan2.c",
    "src/math/atan2f.c",
    "src/math/copysign.c",
    "src/math/copysignf.c",
    "src/math/copysignl.c",
    "src/math/cos.c",
    "src/math/cosf.c",
    "src/math/cosh.c",
    "src/math/coshf.c",
    "src/math/exp.c",
    "src/math/expf.c",
    "src/math/expm1.c",
    "src/math/expm1f.c",
    "src/math/x86_64/fabs.c",
    "src/math/x86_64/fabsf.c",
    "src/math/floor.c",
    "src/math/hypot.c",
    "src/math/hypotf.c",
    "src/math/hypotl.c",
    "src/math/log.c",
    "src/math/logf.c",
    "src/math/scalbn.c",
    "src/math/sin.c",
    "src/math/sinf.c",
    "src/math/sinh.c",
    "src/math/sinhf.c",
    "src/math/x86_64/sqrt.c",
    "src/math/x86_64/sqrtf.c",
    "src/math/tan.c",
    "src/math/tanf.c",
    "src/math/__cos.c",
    "src/math/__cosdf.c",
    "src/math/exp2f_data.c",
    "src/math/exp_data.c",
    "src/math/__expo2.c",
    "src/math/__expo2f.c",
    "src/math/log_data.c",
    "src/math/logf_data.c",
    "src/math/__math_divzero.c",
    "src/math/__math_divzerof.c",
    "src/math/__math_invalid.c",
    "src/math/__math_invalidf.c",
    "src/math/__math_oflow.c",
    "src/math/__math_oflowf.c",
    "src/math/__math_uflow.c",
    "src/math/__math_uflowf.c",
    "src/math/__math_xflow.c",
    "src/math/__math_xflowf.c",
    "src/math/__rem_pio2.c",
    "src/math/__rem_pio2f.c",
    "src/math/__rem_pio2_large.c",
    "src/math/__sin.c",
    "src/math/__sindf.c",
    "src/math/__tan.c",
    "src/math/__tandf.c",
)

PRIVATE_SYMBOLS = (
    "__cos",
    "__cosdf",
    "__exp2f_data",
    "__exp_data",
    "__expo2",
    "__expo2f",
    "__ldexp_cexp",
    "__ldexp_cexpf",
    "__log_data",
    "__logf_data",
    "__math_divzero",
    "__math_divzerof",
    "__math_invalid",
    "__math_invalidf",
    "__math_oflow",
    "__math_oflowf",
    "__math_uflow",
    "__math_uflowf",
    "__math_xflow",
    "__math_xflowf",
    "__muldc3",
    "__mulsc3",
    "__mulxc3",
    "__rem_pio2",
    "__rem_pio2f",
    "__rem_pio2_large",
    "__sin",
    "__sindf",
    "__tan",
    "__tandf",
    "atan",
    "atanf",
    "atan2",
    "atan2f",
    "copysign",
    "copysignf",
    "copysignl",
    "cos",
    "cosf",
    "cosh",
    "coshf",
    "exp",
    "expf",
    "expm1",
    "expm1f",
    "fabs",
    "fabsf",
    "floor",
    "hypot",
    "hypotf",
    "hypotl",
    "log",
    "logf",
    "scalbn",
    "sin",
    "sinf",
    "sinh",
    "sinhf",
    "sqrt",
    "sqrtf",
    "tan",
    "tanf",
)

RENAME = {
    name: (
        "crabc_x86_math_complex_internal_" + name[2:]
        if name.startswith("__")
        else "crabc_x86_math_complex_elementary_" + name
    )
    for name in PRIVATE_SYMBOLS
}

COMPILE_FLAGS = (
    "-D_XOPEN_SOURCE=700",
    "-std=c99",
    "-ffreestanding",
    "-fexcess-precision=standard",
    "-frounding-math",
    "-fno-strict-aliasing",
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
    # Match the pinned libc.so oracle's .lo compilation. PIC can affect SSE
    # register allocation and therefore which NaN operand payload is retained.
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
            text = replace_symbol(text, name, f"crabc_x86_math_complex_{tag}_{name}")

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
        rf".Lcrabc_x86_math_complex_{tag}_\1",
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
    # All complex sources are concatenated into one global-assembly input.
    # GCC's function/data sections otherwise collide with the independently
    # selected scalar closures (for example both private complex support and
    # the public log closure use `.text.log`). Preserve the source compiler's
    # sectioning, but make the private complex source ownership explicit so
    # `--gc-sections` cannot retain an unrelated closure through its name.
    text = re.sub(
        r"^(\s*\.section\s+)(\.(?:text|rodata|data|bss)[A-Za-z0-9_.$]*)(?=,|\s*$)",
        rf"\1\2.crabc_x86_math_complex_{tag}",
        text,
        flags=re.MULTILINE,
    )
    return text.rstrip() + "\n"


def retained_notices(source_root: Path) -> list[str]:
    """Retain each distinct copyright-bearing upstream C notice verbatim."""
    notices: list[str] = []
    for relative in COMPLEX_SOURCES + PRIVATE_SOURCES:
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
        default=ROOT / "libc/src/c_abi/x86_64/math_complex_complete_musl_x86_64.S",
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
        " * Fixed musl 1.2.6 x86-64 complete math.complex translation.",
        " * Generated by compat/x86_64/generate_libc_math_complex_complete.py;",
        " * see math_complex_complete.rs for the source/license/ABI contract.",
        " *",
        " * The remaining musl-authored portions retain musl's MIT license; the",
        " * exact release license is recorded by compat/upstreams.toml.",
        " */",
        *retained_notices(source_root),
        """/*
 * Private __mulsc3/__muldc3/__mulxc3 support is a direct source translation
 * of LLVM compiler-rt 22.1.3. Part of the LLVM Project, under the Apache
 * License v2.0 with LLVM Exceptions.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */""",
    ]
    with tempfile.TemporaryDirectory(prefix="crabc-math-complex-generate.") as temp:
        temp_root = Path(temp)
        for index, relative in enumerate(COMPLEX_SOURCES + PRIVATE_SOURCES):
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

        support_source = ROOT / "compat/x86_64/complex_mul_support.c"
        support_assembly = temp_root / "complex_mul_support.s"
        subprocess.run(
            [
                args.cc,
                *COMPILE_FLAGS,
                *include_flags,
                "-S",
                str(support_source),
                "-o",
                str(support_assembly),
            ],
            check=True,
        )
        blocks.append("\n/* compiler-rt-22.1.3 complex multiplication support */")
        blocks.append(
            transform_assembly(
                "compiler-rt/complex_mul_support.c", support_assembly.read_text()
            )
        )
    blocks.append('\n.section .note.GNU-stack,"",@progbits\n')
    output = "\n".join(blocks)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output)
    print(f"wrote {args.output} ({output.count(chr(10))} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
