"""Small readelf-record predicates for syscall alias contract evidence.

ELF relocatable object symbols in separate function sections commonly both
have ``st_value == 0``.  A same-address alias check therefore retains the
defining section as well as member, value, and type; otherwise a forwarding
function can silently satisfy an archive-only value comparison.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import NamedTuple


# Musl leaves whose source deliberately names one ordinary public alias. The
# archive preserves an application override at each call; the shared libc link
# localizes those calls through the checked musl dynamic-list policy.
PUBLIC_ALIAS_SOURCE_CALLERS = (
    ("__fxstat", "fstat"),
    ("__fxstatat", "fstatat"),
    ("ftime", "clock_gettime"),
    ("getloadavg", "sysinfo"),
    ("sigignore", "sigaction"),
    ("siginterrupt", "sigaction"),
    ("sigset", "sigaction"),
)


def require_same_probe_object(
    probe: str, object_path: str, commands: Mapping[str, Sequence[str]]
) -> None:
    """Require all seven musl/candidate links to consume one compiled object.

    Recompiling the C source for the oracle changes the compiler/header input
    and cannot establish the installed object's ABI across the two providers.
    The collector separately seals the object's bytes before and after linking.
    """

    if probe not in {"contract", "override"}:
        raise ValueError("unknown syscall probe")
    expected = {
        f"{prefix}-{probe}-link"
        for prefix in (
            "oracle", "oracle-dynamic-pie", "oracle-dynamic-non-pie",
            "static", "static-pie", "dynamic-pie", "dynamic-non-pie",
        )
    }
    if set(commands) != expected:
        raise ValueError(f"{probe}: incomplete or additional probe links")
    for name, argv in commands.items():
        inputs = [arg for arg in argv if arg.endswith((".o", ".c", ".cc", ".cpp"))]
        if inputs != [object_path]:
            raise ValueError(f"{name}: link must consume the same compiled probe object")


class SymbolRow(NamedTuple):
    member: str
    value: str
    symbol_type: str
    binding: str
    visibility: str
    section: str
    name: str


def same_definition(left: SymbolRow, right: SymbolRow) -> bool:
    """Return whether two symbols designate one ELF function definition."""

    return (
        left.member == right.member
        and left.value == right.value
        and left.symbol_type == right.symbol_type
        and left.section == right.section
    )
