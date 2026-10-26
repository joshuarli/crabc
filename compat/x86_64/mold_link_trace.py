"""Match a mold trace to its exact object and archive inputs."""

from __future__ import annotations

from typing import Sequence

from owned_posix_product_evidence import semantic_link_trace
from owned_syscall_alias_authority import archive_members


def validate_trace(lines: list[str], *, initial_objects: Sequence[str],
                   archives: Sequence[tuple[str, bytes]], final_objects: Sequence[str]) -> None:
    expected = list(initial_objects)
    seen: dict[str, bytes] = {}
    for path, data in archives:
        if path in seen:
            if seen[path] != data:
                raise ValueError(f"oracle archive identity differs between arguments: {path}")
            continue
        seen[path] = data
        expected.extend(f"{path}({name})" for name, _ in archive_members(data))
    expected.extend(final_objects)
    if semantic_link_trace(lines) != expected:
        raise ValueError("linker trace has missing, reordered, or ambient inputs or members")
