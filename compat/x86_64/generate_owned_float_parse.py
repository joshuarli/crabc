#!/usr/bin/env python3
"""Generate the native musl floating scanner used by strto* entries."""
import argparse
import re
import subprocess
import tempfile
from pathlib import Path

from generate_libc_math_long_double_completion import ROOT, COMPILE_FLAGS, checked_compiler, normalized_tree_digest
from generate_owned_printf_float import generation_environment
from generate_owned_scanf import NATIVE_MUSL_TREE_DIGEST


def generate_related(root, compiler, includes, names, environment, output_dir):
    groups = {
        "float_parse_musl_support": ("src/internal/shgetc.c", "src/math/scalbn.c", "src/math/scalbnl.c", "src/math/copysignl.c", "src/math/fabsl.c", "src/math/fmodl.c"),
        "float_parse_musl_entry": ("src/stdlib/strtod.c", "src/stdlib/atof.c"),
        "float_parse_locale_musl": ("src/stdlib/wcstod.c",),
        "float_parse_locale_aliases": ("src/locale/strtod_l.c",),
    }
    with tempfile.TemporaryDirectory(prefix="owned-float-related.", dir=environment["TMPDIR"]) as temporary:
        for stem, paths in groups.items():
            blocks = ["/* AArch64 translation of pinned native musl; see float_parse.rs for provenance and license. */"]
            for index, relative in enumerate(paths):
                unit = Path(temporary) / f"{index}.S"
                subprocess.run([compiler, *COMPILE_FLAGS, "-D_GNU_SOURCE",
                    *(f"-I{root / item}" for item in includes),
                    *(f"-D{old}={new}" for old, new in names.items()),
                    "-S", str(root / relative), "-o", str(unit)], check=True, env=environment)
                text = unit.read_text()
                text = re.sub(r"(?<![A-Za-z0-9_.])\.L([A-Za-z0-9_.$]+)", f".Lcrabc_{stem}_{index}_\\1", text)
                text = re.sub(r"^\s*\.(file|ident)\s+.*\n", "", text, flags=re.MULTILINE)
                if stem == "float_parse_musl_support":
                    text = re.sub(r"(?m)^(\s*)\.global(\s+crabc_x86_float_parse_)(?!shlim\b)", r"\1.local\2", text)
                blocks.extend((f"/* musl-1.2.6/{relative} */", text))
            (output_dir / f"{stem}_aarch64.S").write_text("\n".join(blocks))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--musl-source", required=True, type=Path)
    parser.add_argument("--arch", choices=("x86_64", "aarch64"), default="x86_64")
    parser.add_argument("--cc", default="/usr/local/bin/crabc-x86_64-musl-gcc")
    parser.add_argument("--output", type=Path, default=ROOT / "libc/src/c_abi/x86_64/float_parse_musl_x86_64.S")
    args = parser.parse_args()
    if args.arch == "aarch64":
        args.output = args.output.with_name(args.output.name.replace("_x86_64.S", "_aarch64.S"))
    root = args.musl_source.resolve()
    if normalized_tree_digest(root) != NATIVE_MUSL_TREE_DIGEST:
        raise SystemExit("pinned native musl tree digest mismatch")
    environment = generation_environment()
    compiler = checked_compiler(args.cc, environment=environment, arch=args.arch)
    names = {
        "__floatscan": "crabc_x86_float_parse_floatscan",
        "__shgetc": "crabc_x86_float_parse_shgetc",
        "__shlim": "crabc_x86_float_parse_shlim",
        "___errno_location": "__errno_location",
        "scalbn": "crabc_x86_float_parse_scalbn",
        "scalbnl": "crabc_x86_float_parse_scalbnl",
        "copysignl": "crabc_x86_float_parse_copysignl",
        "fabsl": "crabc_x86_float_parse_fabsl",
        "fmodl": "crabc_x86_float_parse_fmodl",
    }
    includes = ("src/include", "src/internal", f"arch/{args.arch}", "arch/generic")
    with tempfile.TemporaryDirectory(prefix="owned-float-parse.", dir=environment["TMPDIR"]) as temporary:
        assembly = Path(temporary) / "floatscan.S"
        command = [compiler, *COMPILE_FLAGS, "-D_GNU_SOURCE",
                   *(f"-I{root / item}" for item in includes),
                   *(f"-D{old}={new}" for old, new in names.items()),
                   "-S", str(root / "src/internal/floatscan.c"), "-o", str(assembly)]
        subprocess.run(command, check=True, env=environment)
        text = assembly.read_text()
    text = re.sub(r"(?<![A-Za-z0-9_.])\.L([A-Za-z0-9_.$]+)", r".Lcrabc_x86_float_parse_scan_\1", text)
    local_names = {
        "scanexp": "crabc_x86_float_parse_scanexp",
        "decfloat": "crabc_x86_float_parse_decfloat",
        "CSWTCH.17": "crabc_x86_float_parse_CSW17",
        "CSWTCH.16": "crabc_x86_float_parse_CSW16",
        "th.0": "crabc_x86_float_parse_th_0",
        "p10s.1": "crabc_x86_float_parse_p10s_1",
    }
    for old, new in local_names.items():
        text = re.sub(r"(?<![A-Za-z0-9_])" + re.escape(old) + r"(?![A-Za-z0-9_])", new, text)
    text = re.sub(r"^\s*\.(file|ident)\s+.*\n", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*\.hidden\s+__errno_location\s*\n", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*\.(globl|global|hidden)\s+crabc_x86_float_parse_(floatscan|shlim|shgetc)\s*\n", "", text, flags=re.MULTILINE)
    header = "/*\n * Pinned native musl x86-64 src/internal/floatscan.c assembly translation.\n * See float_parse.rs for source mapping and license.\n */\n"
    if args.arch == "aarch64":
        header = header.replace("x86-64", "aarch64")
    args.output.write_text(header + text)
    if args.arch == "aarch64":
        generate_related(root, compiler, includes, names, environment, args.output.parent)


if __name__ == "__main__":
    main()
