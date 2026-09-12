"""Small readelf-record predicates for the stdio alias contract runner.

ELF relocatable object symbols in different function sections commonly both
have ``st_value == 0``.  An alias assertion must therefore retain the defining
section as well as the address when it distinguishes a real ``.set`` alias
from a forwarding function.
"""

from __future__ import annotations

from typing import NamedTuple


class SymbolRow(NamedTuple):
    member: str
    value: str
    symbol_type: str
    binding: str
    visibility: str
    section: str
    name: str


def same_definition(left: SymbolRow, right: SymbolRow) -> bool:
    """Return whether two symbols designate the same ELF function definition."""

    return (
        left.member == right.member
        and left.value == right.value
        and left.symbol_type == right.symbol_type
        and left.section == right.section
    )
