#!/usr/bin/env python3
"""Prepare a versioned native stress remainder from an immutable frozen fixture.

The native FILE contract is exercised by READ_FILE, and asynchronous cancellation
by ASYNC_LOOP, in the separately owned I/O cancellation workload. Only the two
main calls that combine those contracts incorrectly are replaced here. Definitions
and every other byte remain available for source review and frozen replay.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

ORIGINAL_SHA256 = "b8ac2a2d8e68d214b348c12ed6ebe579935aad94496127ea676a6d2527b4fad3"
PROFILES = ("native-v1", "frozen")
REPLACEMENTS = (
    ("deferred_stdio_probe",
     b'    run_probe_with_timeout(deferred_stdio_probe, "deferred stdio cancellation probe");\n',
     b'    /* Native FILE non-cancellation contract: READ_FILE evidence is required separately. */\n'),
    ("asynchronous_stdio_probe",
     b'    run_probe_with_timeout(asynchronous_stdio_probe, "asynchronous stdio cancellation probe");\n',
     b'    /* Native asynchronous cancellation contract: ASYNC_LOOP evidence is required separately. */\n'),
)


class SourceProfileError(ValueError):
    """The frozen source or selected transformation differs from its contract."""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def prepare(original, profile):
    """Return source bytes plus the exact two-line map, refusing source drift."""
    if profile not in PROFILES:
        raise SourceProfileError("unknown pthread stress source profile")
    if sha256(original) != ORIGINAL_SHA256:
        raise SourceProfileError("frozen pthread stress SHA-256 differs")
    for _, line, _ in REPLACEMENTS:
        if original.splitlines(keepends=True).count(line) != 1:
            raise SourceProfileError("frozen main must contain exactly one occurrence of each stdio probe call")
    if profile == "frozen":
        return original, []
    lines, records = original.splitlines(keepends=True), []
    for function, line, replacement in REPLACEMENTS:
        line_number = lines.index(line) + 1
        lines[line_number - 1] = replacement
        records.append({"line": line_number, "source_function": function,
                        "original_hex": line.hex(), "replacement_hex": replacement.hex()})
    return b"".join(lines), records


def materialize(original_path, output, profile):
    original_path, output = Path(original_path), Path(output)
    original = original_path.read_bytes()
    prepared, records = prepare(original, profile)
    with output.open("xb") as stream:
        stream.write(prepared)
    preparer = Path(__file__).resolve(strict=True)
    return {"schema": "crabc.x86_64-pthread-stress-source/v1", "profile": profile,
            "original": {"path": str(original_path), "sha256": sha256(original)},
            "prepared": {"path": str(output), "sha256": sha256(prepared)},
            "preparer": {"path": str(preparer), "sha256": sha256(preparer.read_bytes())},
            "replacements": records}
