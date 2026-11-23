#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = {
    "x86_64": (
        "owned-syscall-alias-image-inputs-current.json",
        "owned_pthread_timed_feature_image_inputs_current.json",
        "owned_resolver_alias_image_inputs.json",
        "owned_resolver_network_image_inputs.json",
        "owned_classic_netdb_image_inputs.json",
    ),
    "aarch64": (
        "owned_resolver_alias_image_inputs_aarch64.json",
        "owned_resolver_network_image_inputs_aarch64.json",
        "owned_classic_netdb_image_inputs_aarch64.json",
    ),
}


def stale_manifests(root: Path) -> list[str]:
    with (root / "rust-toolchain.toml").open("rb") as stream:
        channel = tomllib.load(stream)["toolchain"]["channel"]
    stale = []
    for arch, names in MANIFESTS.items():
        compiler = f"/opt/rustup/toolchains/{channel}-{arch}-unknown-linux-musl/bin/rustc"
        for name in names:
            path = root / "compat/x86_64" / name
            manifest = json.loads(path.read_text(encoding="utf-8"))
            if compiler not in manifest["files"]:
                stale.append(name)
    return stale


def main() -> int:
    stale = stale_manifests(ROOT)
    if stale:
        for name in stale:
            print(name, file=sys.stderr)
        return 1
    print("source image toolchain paths: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
