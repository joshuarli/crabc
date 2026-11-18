#!/usr/bin/env python3
"""Native harness architecture settings."""
import platform
import shlex
import sys

from core_image import core_image_id


def native_arch(machine=None):
    machine = machine or platform.machine()
    aliases = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
    if machine not in aliases:
        raise SystemExit(f"unsupported host architecture: {machine}")
    arch = aliases[machine]
    triple = f"{arch}-unknown-linux-musl"
    return {
        "arch": arch,
        "platform": "linux/amd64" if arch == "x86_64" else "linux/arm64",
        "image": core_image_id(arch),
        "target_triple": triple,
        "linker_variable": f"CARGO_TARGET_{triple.upper().replace('-', '_')}_LINKER",
        "linker": f"/usr/local/bin/crabc-{arch}-mold-gcc",
        "oracle": f"/usr/local/bin/crabc-{arch}-musl-gcc",
        "oracle_prefix": f"{arch}-linux-musl",
        "work_name": arch,
    }


if __name__ == "__main__":
    if len(sys.argv) > 2:
        raise SystemExit("usage: native_arch.py [machine]")
    for key, value in native_arch(sys.argv[1] if len(sys.argv) == 2 else None).items():
        print(f"{key}={shlex.quote(value)}")
