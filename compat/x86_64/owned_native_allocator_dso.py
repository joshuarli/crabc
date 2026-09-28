#!/usr/bin/env python3
"""Execute one application-DSO link and retain its physical inputs and tools."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-owned-native-allocator-dso-link/v1"
ORACLE_WRAPPER = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
ORACLE_GCC = Path("/usr/bin/gcc")
ORACLE_SPECS = Path("/opt/musl-1.2.6/lib/musl-gcc.specs")
ORACLE_LIBC = Path("/opt/musl-1.2.6/lib/libc.so")


def identity(path: Path) -> dict[str, object]:
    """Record the exact bytes of one regular link input or tool."""

    if not path.is_file() or path.is_symlink():
        raise ValueError(f"DSO link input is missing or not physical: {path}")
    data = path.read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def link(work: Path, product: Path | None, arm: str, role: str) -> Path:
    if not work.is_dir() or not work.is_relative_to(ROOT / ".work"):
        raise ValueError("DSO link work must be inside the checkout .work directory")
    obj = work / "objects" / f"{role}.o"
    output = (work / f"libdso-{role}.so" if arm == "candidate"
              else work / "oracle" / f"libdso-{role}.so")
    source = ROOT / "compat/x86_64/owned_native_allocator_dso_library.c"
    if arm == "candidate":
        if product is None or not product.is_dir() or not product.is_relative_to(ROOT / ".work"):
            raise ValueError("candidate DSO link requires a checkout-owned dynamic product")
        tool = product / "bin/crabc-cc-dynamic"
        libc = product / "usr/lib/libc.so"
        command = [str(tool), "--dynamic-shared-object", str(obj), "-o", str(output)]
    else:
        if product is not None:
            raise ValueError("oracle DSO link accepts no candidate product")
        tool = ORACLE_WRAPPER
        libc = ORACLE_LIBC
        command = [str(tool), "-shared", str(obj), "-Wl,-z,now,-soname,libdso-" + role + ".so",
                   "-o", str(output)]

    before = {"source": identity(source), "object": identity(obj), "libc": identity(libc),
              "tool": identity(tool)}
    tools = ({"gcc": identity(ORACLE_GCC), "specs": identity(ORACLE_SPECS)}
             if arm == "oracle" else {})
    subprocess.run(command, cwd=ROOT, check=True)
    for name, recorded in before.items():
        if identity(Path(str(recorded["path"]))) != recorded:
            raise ValueError(f"DSO link {name} changed while executing")
    for name, recorded in tools.items():
        if identity(Path(str(recorded["path"]))) != recorded:
            raise ValueError(f"DSO link {name} changed while executing")

    sidecar = None
    if arm == "candidate":
        sidecar_path = Path(str(output) + ".crabc-link.json")
        sidecar = identity(sidecar_path)
        resolved = json.loads(sidecar_path.read_text()).get("resolved_linker")
        if not isinstance(resolved, dict) or not isinstance(resolved.get("path"), str):
            raise ValueError("candidate DSO link omitted its resolved linker")
        linker = identity(Path(resolved["path"]))
        if linker["sha256"] != resolved.get("sha256"):
            raise ValueError("candidate DSO link changed its resolved linker")
        tools = {"linker": linker}

    record = {"schema": SCHEMA, "arm": arm, "role": role, "cwd": str(ROOT),
              "product": str(product) if product is not None else None,
              "command": command, "inputs": before, "tools": tools,
              "output": identity(output), "sidecar": sidecar}
    path = work / f"link-{arm}-{role}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--product", type=Path)
    parser.add_argument("--arm", choices=("candidate", "oracle"), required=True)
    parser.add_argument("--role", choices=("initial", "plugin"), required=True)
    args = parser.parse_args()
    link(args.work, args.product, args.arm, args.role)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
