#!/usr/bin/env python3
"""Read the installed drivers' hosted C translation flags from a product.

Both installed drivers prepend ``HOSTED_TRANSLATION_FLAGS`` from the product's
copied ``share/crabc/crabc_cc_static.py`` to every application translation.
Runners and receipt readers that replay or audit that translation (header
traces, dependency audits, byte-identical replays) take the tuple from the
same product through ``hosted_translation_flags`` instead of restating it, so
the audited command and the driver's command cannot drift apart.

Run as a script with one product directory, it prints one flag per line for
shell runners.
"""
from __future__ import annotations

import ast
from pathlib import Path
import sys

HELPER = Path("share/crabc/crabc_cc_static.py")
NAME = "HOSTED_TRANSLATION_FLAGS"


class TranslationFlagsError(RuntimeError):
    """The product has no well-formed hosted translation contract."""


def hosted_translation_flags(product: Path) -> tuple[str, ...]:
    """Parse the product helper's literal ``HOSTED_TRANSLATION_FLAGS`` tuple.

    The helper is parsed, never imported: host-side receipt replays must not
    execute product-supplied Python. The assignment must be one top-level
    literal tuple of option strings.
    """

    helper = Path(product) / HELPER
    if helper.is_symlink() or not helper.is_file():
        raise TranslationFlagsError(f"installed compiler helper is not a regular file: {helper}")
    try:
        tree = ast.parse(helper.read_bytes(), filename=str(helper))
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
