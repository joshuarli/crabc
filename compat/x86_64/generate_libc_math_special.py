#!/usr/bin/env python3
"""Generate the fixed musl 1.2.6 x86 math.special assembly translation.

This is a development/provenance tool, not part of the Rust build. The checked
assembly is the build input so `crabc-libc` never invokes a foreign compiler.
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

# These sources own the 80 capability entries that were not already present in
# the x86 archive. Weak aliases in remainder{,f}.c and lgamma*_r.c supply the
# historical public spellings; signgam.c supplies lgamma's observable state.
PUBLIC_SOURCES = (
    "src/math/erf.c",
    "src/math/erff.c",
    "src/math/erfl.c",
    "src/math/finite.c",
    "src/math/finitef.c",
    "src/math/frexp.c",
    "src/math/frexpf.c",
    "src/math/frexpl.c",
    "src/math/ilogb.c",
    "src/math/ilogbf.c",
    "src/math/ilogbl.c",
    "src/math/j0.c",
    "src/math/j0f.c",
    "src/math/j1.c",
    "src/math/j1f.c",
    "src/math/jn.c",
    "src/math/jnf.c",
    "src/math/ldexp.c",
    "src/math/ldexpf.c",
    "src/math/ldexpl.c",
    "src/math/lgamma.c",
    "src/math/lgamma_r.c",
    "src/math/lgammaf.c",
    "src/math/lgammaf_r.c",
    "src/math/lgammal.c",
    "src/math/x86_64/llrint.c",
    "src/math/x86_64/llrintf.c",
    "src/math/llround.c",
    "src/math/llroundf.c",
    "src/math/llroundl.c",
    "src/math/logb.c",
    "src/math/logbf.c",
    "src/math/logbl.c",
    "src/math/x86_64/lrint.c",
    "src/math/x86_64/lrintf.c",
    "src/math/lround.c",
    "src/math/lroundf.c",
    "src/math/lroundl.c",
    "src/math/modf.c",
    "src/math/modff.c",
    "src/math/modfl.c",
    "src/math/nan.c",
    "src/math/nanf.c",
    "src/math/nanl.c",
    "src/math/nextafter.c",
    "src/math/nextafterf.c",
    "src/math/nextafterl.c",
    "src/math/nexttoward.c",
    "src/math/nexttowardf.c",
    "src/math/nexttowardl.c",
    "src/math/remainder.c",
    "src/math/remainderf.c",
    "src/math/remquo.c",
    "src/math/remquof.c",
    "src/math/scalb.c",
    "src/math/scalbf.c",
    "src/math/scalbln.c",
    "src/math/scalblnf.c",
    "src/math/scalblnl.c",
    "src/math/scalbn.c",
    "src/math/scalbnf.c",
    "src/math/scalbnl.c",
    "src/math/signgam.c",
    "src/math/significand.c",
    "src/math/significandf.c",
    "src/math/tgamma.c",
    "src/math/tgammaf.c",
    "src/math/tgammal.c",
)

# Special-function algorithms need elementary operations internally. These
# exact musl providers are renamed and localized below: none becomes another
# public x86 elementary capability or archive export.
PRIVATE_SOURCES = (
    "src/math/__cos.c",
    "src/math/__cosdf.c",
    "src/math/__cosl.c",
    "src/math/__polevll.c",
    "src/math/__sin.c",
    "src/math/__sindf.c",
    "src/math/__sinl.c",
    "src/math/cos.c",
    "src/math/cosf.c",
    "src/math/exp.c",
    "src/math/expf.c",
    "src/math/x86_64/fabs.c",
    "src/math/x86_64/fabsf.c",
    "src/math/floor.c",
    "src/math/floorf.c",
    "src/math/log.c",
    "src/math/logf.c",
    "src/math/pow.c",
    "src/math/powl.c",
    "src/math/rint.c",
    "src/math/rintf.c",
    "src/math/round.c",
    "src/math/roundf.c",
    "src/math/roundl.c",
    "src/math/sin.c",
    "src/math/sinf.c",
    "src/math/sinl.c",
    "src/math/x86_64/sqrt.c",
    "src/math/x86_64/sqrtf.c",
    "src/math/exp2f_data.c",
    "src/math/exp_data.c",
    "src/math/log_data.c",
    "src/math/logf_data.c",
    "src/math/pow_data.c",
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
    "src/math/__rem_pio2l.c",
    "src/math/__rem_pio2_large.c",
)

PRIVATE_SYMBOLS = (
    "__cos",
    "__cosdf",
    "__cosl",
    "__exp2f_data",
    "__exp_data",
    "__lgamma_r",
    "__lgammaf_r",
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
    "__p1evll",
    "__polevll",
    "__pow_log_data",
    "__rem_pio2",
    "__rem_pio2f",
    "__rem_pio2l",
    "__rem_pio2_large",
    "__sin",
    "__sindf",
    "__sinl",
    "cos",
    "cosf",
    "exp",
    "expf",
    "fabs",
    "fabsf",
    "floor",
    "floorf",
    "log",
    "logf",
    "pow",
    "powl",
    "rint",
    "rintf",
    "round",
    "roundf",
    "roundl",
    "sin",
    "sinf",
    "sinl",
    "sqrt",
    "sqrtf",
)

RENAME = {
    name: (
        "crabc_x86_math_special_internal_" + name[2:]
        if name.startswith("__")
        else "crabc_x86_math_special_elementary_" + name
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
            text = replace_symbol(text, name, f"crabc_x86_math_special_{tag}_{name}")

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
        rf".Lcrabc_x86_math_special_{tag}_\1",
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--musl-source", required=True, type=Path)
    parser.add_argument("--cc", default="/usr/local/bin/crabc-x86_64-musl-gcc")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "libc/src/c_abi/x86_64/math_special_musl_x86_64.S",
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
        " * Fixed musl 1.2.6 x86-64 math.special assembly translation.",
        " * Generated by compat/x86_64/generate_libc_math_special.py; see",
        " * math_special.rs for the source/license/ABI contract.",
        " *",
        " * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.",
        " * Developed at SunPro, a Sun Microsystems, Inc. business.",
        " * Permission to use, copy, modify, and distribute this software is",
        " * freely granted, provided that this notice is preserved.",
        " *",
        " * Copyright (c) 2008 Stephen L. Moshier <steve@moshier.net>",
        " * Permission to use, copy, modify, and distribute this software for any",
        " * purpose with or without fee is hereby granted, provided that the above",
        " * copyright notice and this permission notice appear in all copies.",
        " * THE SOFTWARE IS PROVIDED \"AS IS\" AND THE AUTHOR DISCLAIMS ALL WARRANTIES",
        " * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF",
        " * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR",
        " * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES",
        " * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN",
        " * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF",
        " * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.",
        " *",
        " * The remaining musl-authored portions retain musl's MIT license; the",
        " * exact release license is recorded by compat/upstreams.toml.",
        " */",
    ]
    with tempfile.TemporaryDirectory(prefix="crabc-math-special-generate.") as temp:
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
