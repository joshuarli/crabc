#!/usr/bin/env python3
"""Build every declared crabc-rs static-library example from its manifest.

The examples are independent no_std proof artifacts. Building a target by name
keeps Cargo's allocator and feature resolution scoped to that artifact; a
single ``cargo build --examples`` combines otherwise independent artifacts and
can require an allocator for probes that build alone without one. The manifest
therefore owns each target name and its ``required-features`` declaration, and
this runner invokes those declared targets one at a time.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import tomllib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ManifestError(ValueError):
    """The example manifest cannot describe a complete build set."""


class BuildError(RuntimeError):
    """A manifest-declared Cargo target failed to build."""

    def __init__(self, target: str, returncode: int) -> None:
        super().__init__(f"example {target!r} failed with cargo exit status {returncode}")
        self.returncode = returncode


@dataclass(frozen=True)
class ExampleTarget:
    """One named static-library proof target and its explicit feature boundary."""

    name: str
    source: Path
    required_features: tuple[str, ...]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestError(message)


def load_examples(manifest: Path) -> tuple[ExampleTarget, ...]:
    """Load and validate every ``[[example]]`` target from ``Cargo.toml``."""

    try:
        with manifest.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ManifestError(f"cannot read {manifest}: {error}") from error

    raw_features = raw.get("features", {})
    require(isinstance(raw_features, dict), f"{manifest}: [features] must be a table")
    feature_names = set(raw_features)

    raw_examples = raw.get("example", [])
    require(isinstance(raw_examples, list) and raw_examples, f"{manifest}: no [[example]] targets")

    targets: list[ExampleTarget] = []
    seen_names: set[str] = set()
    for index, raw_target in enumerate(raw_examples, start=1):
        require(isinstance(raw_target, dict), f"{manifest}: example {index} must be a table")
        name = raw_target.get("name")
        path = raw_target.get("path")
        required_features = raw_target.get("required-features", [])
        require(isinstance(name, str) and name, f"{manifest}: example {index} has no name")
        require(isinstance(path, str) and path, f"{manifest}: example {name!r} has no path")
        require(
            isinstance(required_features, list) and all(isinstance(feature, str) and feature for feature in required_features),
            f"{manifest}: example {name!r} has invalid required-features",
        )
        require(name not in seen_names, f"{manifest}: duplicate example name {name!r}")
        seen_names.add(name)

        source = manifest.parent / path
        require(source.is_file(), f"{manifest}: example {name!r} source does not exist: {source}")
        unknown_features = [feature for feature in required_features if feature not in feature_names]
        require(
            not unknown_features,
            f"{manifest}: example {name!r} requires undeclared feature(s): {', '.join(unknown_features)}",
        )
        targets.append(ExampleTarget(name, source, tuple(required_features)))

    # This package keeps one target source per flat `examples/*.rs` file.  A
    # source added there without a manifest entry would otherwise escape the
    # dispatcher entirely, reintroducing a second implicit target inventory.
    examples_directory = manifest.parent / "examples"
    declared_sources = {target.source.resolve() for target in targets}
    undeclared_sources = sorted(
        source
        for source in examples_directory.glob("*.rs")
        if source.resolve() not in declared_sources
    )
    require(
        not undeclared_sources,
        f"{manifest}: example source(s) lack [[example]] entries: "
        + ", ".join(source.relative_to(manifest.parent).as_posix() for source in undeclared_sources),
    )

    return tuple(targets)


def build_command(cargo: str, target: ExampleTarget) -> tuple[str, ...]:
    """Return the isolated release build command for one manifest target."""

    command = [
        cargo,
        "build",
        "-p",
        "crabc-rs",
        "--example",
        target.name,
        "--release",
        "--no-default-features",
    ]
    if target.required_features:
        command.extend(("--features", ",".join(target.required_features)))
    return tuple(command)


def run_builds(
    targets: Sequence[ExampleTarget],
    cargo: str,
    runner: Callable[[tuple[str, ...]], Any],
) -> None:
    """Build every declared target independently and stop at the first failure."""

    for target in targets:
        result = runner(build_command(cargo, target))
        returncode = getattr(result, "returncode", None)
        if returncode != 0:
            raise BuildError(target.name, int(returncode))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("crabc-rs/Cargo.toml"))
    parser.add_argument("--cargo", default=os.environ.get("CARGO", "cargo"))
    parser.add_argument("--verbose", action="store_true", help="print each derived Cargo command")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    def runner(command: tuple[str, ...]) -> subprocess.CompletedProcess[bytes]:
        if args.verbose:
            print(f"$ {shlex.join(command)}")
        return subprocess.run(command, check=False)

    try:
        targets = load_examples(args.manifest)
        run_builds(targets, args.cargo, runner)
    except ManifestError as error:
        print(f"example manifest: ERROR: {error}", file=sys.stderr)
        return 2
    except BuildError as error:
        print(f"example build: ERROR: {error}", file=sys.stderr)
        return error.returncode or 1

    print(f"example build: PASS ({len(targets)} manifest-declared targets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
