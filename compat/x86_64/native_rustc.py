from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import native_build_tools
from scripts.rust_toolchain import pinned_toolchain


def compiler_path() -> Path:
    toolchain = pinned_toolchain(ROOT)
    environment = os.environ.copy()
    environment["RUSTUP_TOOLCHAIN"] = toolchain
    completed = subprocess.run(
        ["rustup", "which", "rustc"],
        check=False,
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"could not resolve pinned rustc: {completed.stderr}")
    path = Path(completed.stdout.strip())
    expected = Path("/opt/rustup/toolchains") / f"{toolchain}-x86_64-unknown-linux-musl/bin/rustc"
    if path != expected or not path.is_file():
        raise RuntimeError(f"rustup selected an unexpected compiler path: {path}")
    return path


def compile_command() -> list[str]:
    return native_build_tools.compile_command(compiler_path())


def final_link_command() -> list[str]:
    return [*compile_command(), "-C", f"linker={native_build_tools.CARGO_LINKER}"]


if __name__ == "__main__":
    try:
        if len(sys.argv) == 1 or sys.argv[1:] == ["compile"]:
            command = compile_command()
        elif sys.argv[1:] == ["final-link"]:
            command = final_link_command()
        elif sys.argv[1:] == ["mold"]:
            sys.stdout.write(str(native_build_tools.MOLD) + "\n")
            raise SystemExit(0)
        elif sys.argv[1:] == ["environment"]:
            for key, value in native_build_tools.environment().items():
                sys.stdout.buffer.write(os.fsencode(key) + b"\0" + os.fsencode(value) + b"\0")
            raise SystemExit(0)
        else:
            raise ValueError("expected compile, final-link, mold, or environment mode")
        for argument in command:
            sys.stdout.buffer.write(os.fsencode(argument) + b"\0")
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: native pinned rustc selection: {error}", file=sys.stderr)
        raise SystemExit(1)
