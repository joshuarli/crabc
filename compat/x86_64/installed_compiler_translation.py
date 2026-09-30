#!/usr/bin/env python3
"""Read the installed drivers' hosted C translation flags from a product.

Dynamic products carry ``HOSTED_TRANSLATION_FLAGS`` in their copied compiler
helper; static products carry it in their self-contained sealed driver.
Runners and receipt readers that replay or audit that translation (header
traces, dependency audits, byte-identical replays) take the tuple from the
same product through ``hosted_translation_flags`` instead of restating it, so
the audited command and the driver's command cannot drift apart.

Run as a script with one product directory, it prints one flag per line for
shell runners.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import sys

HELPER = Path("share/crabc/crabc_cc_static.py")
STATIC_DRIVER = Path("bin/crabc-cc")
MANIFEST = Path("share/crabc/manifest.json")
NAME = "HOSTED_TRANSLATION_FLAGS"


class TranslationFlagsError(RuntimeError):
    """The product has no well-formed hosted translation contract."""


def hosted_translation_flags(product: Path) -> tuple[str, ...]:
    """Parse the installed compiler's literal ``HOSTED_TRANSLATION_FLAGS`` tuple.

    The compiler is parsed, never imported: host-side receipt replays must not
    execute product-supplied Python. A self-contained static driver must have
    the exact path and bytes attested by its static-product manifest. The
    assignment must be one top-level literal tuple of option strings.
    """

    helper = Path(product) / HELPER
    try:
        if helper.is_symlink():
            raise TranslationFlagsError(f"installed compiler helper is not a regular file: {helper}")
        if helper.is_file():
            source = helper.read_bytes()
        else:
            manifest = Path(product) / MANIFEST
            if manifest.is_symlink() or not manifest.is_file():
                raise TranslationFlagsError(f"installed static compiler manifest is not a regular file: {manifest}")
            record = json.loads(manifest.read_bytes())
            if (not isinstance(record, dict) or record.get("schema") != 1
                    or record.get("format") != "crabc-x86-64-owned-static-sysroot-v1"
                    or record.get("target") != "x86_64-unknown-linux-musl"):
                raise TranslationFlagsError(f"installed compiler does not declare a static product: {manifest}")
            driver = record.get("sealed_static_driver")
            if (not isinstance(driver, dict)
                    or driver.get("format") != "crabc-x86-64-sealed-static-driver-v1"
                    or driver.get("path") != STATIC_DRIVER.as_posix()):
                raise TranslationFlagsError(f"installed static compiler declaration differs: {manifest}")
            helper = Path(product) / STATIC_DRIVER
            if helper.is_symlink() or not helper.is_file() or not os.access(helper, os.X_OK):
                raise TranslationFlagsError(f"installed static compiler is not an executable regular file: {helper}")
            source = helper.read_bytes()
            installed = record.get("installed")
            files = installed.get("files") if isinstance(installed, dict) else None
            if (not isinstance(files, dict)
                    or files.get(STATIC_DRIVER.as_posix()) != hashlib.sha256(source).hexdigest()):
                raise TranslationFlagsError(f"installed static compiler bytes differ from its manifest: {helper}")
        tree = ast.parse(source, filename=str(helper))
    except (OSError, SyntaxError, ValueError) as error:
        raise TranslationFlagsError(f"installed compiler helper cannot be parsed: {helper}") from error
    values = [
        node.value for node in tree.body
        if isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name) and node.targets[0].id == NAME
    ]
    if len(values) != 1:
        raise TranslationFlagsError(f"installed compiler helper does not assign {NAME} exactly once: {helper}")
    try:
        flags = ast.literal_eval(values[0])
    except ValueError as error:
        raise TranslationFlagsError(f"installed compiler helper {NAME} is not a literal: {helper}") from error
    if type(flags) is not tuple or not all(type(flag) is str and flag.startswith("-") for flag in flags):
        raise TranslationFlagsError(f"installed compiler helper has malformed {NAME}: {helper}")
    return flags


def main(arguments: list[str]) -> int:
    if len(arguments) != 1:
        print("usage: installed_compiler_translation.py PRODUCT", file=sys.stderr)
        return 2
    try:
        flags = hosted_translation_flags(Path(arguments[0]))
    except TranslationFlagsError as error:
        print(f"installed compiler translation: {error}", file=sys.stderr)
        return 1
    for flag in flags:
        print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
