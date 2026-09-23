"""Read the repository's selected Rust channel from rust-toolchain.toml."""

from __future__ import annotations

import tomllib
from pathlib import Path


def pinned_toolchain(root: Path | None = None) -> str:
    repository = root or Path(__file__).resolve().parents[1]
    with (repository / "rust-toolchain.toml").open("rb") as manifest:
        channel = tomllib.load(manifest)["toolchain"]["channel"]
    if not isinstance(channel, str) or not channel:
        raise ValueError("rust-toolchain.toml must select a non-empty toolchain channel")
    return channel


if __name__ == "__main__":
    print(pinned_toolchain())
