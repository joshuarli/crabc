#!/usr/bin/env python3
"""Bind every c-abi-compat component to one current product cohort's primary pair.

Static preparation and dynamic qualification remain the owners of product
construction and validation; this adapter recovers their canonical pairs with
the same reader the resolver family uses. Every c-abi-compat component runs
against the primary static/dynamic pair only, so each root a component
declares (its invocation and every link identity or report it retained) must
be exactly that pair's physical path and manifest. It cannot construct a
product, execute a workload, or promote a capability.
"""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

import owned_resolver_family_cohort as canonical


SCHEMA = "crabc.x86_64-owned-c-abi-compat-family-cohort/v1"
PAIR = "primary"
KINDS = ("static", "dynamic")


class CAbiCompatFamilyCohortError(RuntimeError):
    """A component root is not the selected cohort's primary product."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CAbiCompatFamilyCohortError(message)


def canonical_products(root: Path, static_preparation: Path, dynamic_qualification: Path) -> tuple[
        dict[str, object], dict[str, dict[str, dict[str, object]]]]:
    """Return the current source seal and the three validated product pairs."""

    try:
        return canonical.canonical_products(root, static_preparation, dynamic_qualification)
    except canonical.ResolverFamilyCohortError as error:
        raise CAbiCompatFamilyCohortError(str(error)) from error


def bind_component(root: Path, identifier: str, declared: Mapping[str, object],
                   products: Mapping[str, Mapping[str, Mapping[str, object]]]) -> dict[str, object]:
    """Match one component's declared roots, by kind, to the primary pair.

    ``declared`` maps ``static``/``dynamic`` to the list of checkout-relative
    product roots the component's retained evidence names. A kind the
    component does not exercise has an empty list.
    """

    require(isinstance(declared, Mapping) and set(declared) == set(KINDS),
            f"{identifier} declared product kind roster differs")
    require(isinstance(declared["dynamic"], list) and declared["dynamic"],
            f"{identifier} declares no dynamic product")
    primary = products[PAIR]
    bound: dict[str, object] = {}
    for kind in KINDS:
        values = declared[kind]
        require(isinstance(values, list), f"{identifier} {kind} product declaration differs")
        if not values:
            bound[kind] = None
            continue
        for value in values:
            try:
                path = canonical._directory(root, value, f"{identifier} {kind} product")
                manifest = canonical._file_identity(root, path / "share/crabc/manifest.json",
                                                    f"{identifier} {kind} manifest")
            except canonical.ResolverFamilyCohortError as error:
                raise CAbiCompatFamilyCohortError(str(error)) from error
            require({"path": path.relative_to(root).as_posix(), "manifest": manifest} == primary[kind],
                    f"{identifier} {kind} product is not the cohort's primary {kind} product")
        bound[kind] = primary[kind]
    return {"pair": PAIR, "products": bound}
