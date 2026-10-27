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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--musl-source", required=True, type=Path)
    parser.add_argument("--cc", default="/usr/local/bin/crabc-x86_64-musl-gcc")
    parser.add_argument("--output", type=Path, default=ROOT / "libc/src/c_abi/x86_64/float_parse_musl_x86_64.S")
    args = parser.parse_args()
    root = args.musl_source.resolve()
    if normalized_tree_digest(root) != NATIVE_MUSL_TREE_DIGEST:
        raise SystemExit("pinned native musl tree digest mismatch")
    environment = generation_environment()
    compiler = checked_compiler(args.cc, environment=environment)
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
    includes = ("src/include", "src/internal", "arch/x86_64", "arch/generic")
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
    text = re.sub(r"^\s*\.(globl|hidden)\s+crabc_x86_float_parse_(floatscan|shlim|shgetc)\s*\n", "", text, flags=re.MULTILINE)
    header = "/*\n * Pinned native musl x86-64 src/internal/floatscan.c assembly translation.\n * See float_parse.rs for source mapping and license.\n */\n"
    args.output.write_text(header + text)


if __name__ == "__main__":
    main()
