#!/usr/bin/env python3
"""Bind resolver behavior readers to one current six-root product cohort.

This is a read-only resolver-family adapter.  Static preparation and dynamic
qualification remain the owners of product construction and validation.  The
adapter only recovers their exact primary/reproduction/extracted roots, then
requires every resolver component's already-validated declared product roots
to be members of that one cohort.  It cannot construct a product, execute a
resolver workload, or promote a capability.
"""

from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import stat
from typing import Any, Mapping

import owned_dynamic_qualification as dynamic
import owned_posix_static_products as static


SCHEMA = "crabc.x86_64-owned-resolver-family-cohort/v1"
PAIRS = {
    "primary": "installed",
    "reproduction": "second",
    "extracted": "extracted",
}
REQUIRED_COMPONENTS = (
    "resolver-network-physical",
    "classic-netdb",
    "resolver-alias-private-bodies",
    "resolver-cancellation",
    "protocol-database-product",
)
# A component can use a subset of the complete three-pair cohort.  The
# protocol-table reader necessarily binds all three pairs; the other readers
# name the exact pair(s) used by their retained behavior receipt.
EXPECTED_COMPONENT_ROOTS = {
    "resolver-network-physical": ("primary", "extracted"),
    "classic-netdb": ("selected",),
    "resolver-alias-private-bodies": ("selected",),
    "resolver-cancellation": ("selected",),
    "protocol-database-product": ("primary", "reproduction", "extracted"),
}


class ResolverFamilyCohortError(RuntimeError):
    """A component receipt is not bound to the selected six-root cohort."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ResolverFamilyCohortError(message)


def _physical_work_path(root: Path, path: Path, description: str, *, directory: bool) -> Path:
    """Return one physical evidence node below this checkout's ``.work`` root."""

    value = path.absolute()
    try:
        metadata = value.lstat()
        resolved = value.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ResolverFamilyCohortError(f"cannot read {description}: {path}") from error
    require(resolved == value and not value.is_symlink() and value.is_relative_to(root / ".work"),
            f"{description} is not a physical checkout .work path")
    require(stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode),
            f"{description} has the wrong type")
    return value


def _file_identity(root: Path, path: Path, description: str) -> dict[str, object]:
    path = _physical_work_path(root, path, description, directory=False)
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256(path.read_bytes()).hexdigest(),
        "byte_length": path.stat().st_size,
        "mode": stat.S_IMODE(path.stat().st_mode),
    }


def _directory(root: Path, value: object, description: str) -> Path:
    require(isinstance(value, str) and value, f"{description} path is absent")
    relative = Path(value)
    require(not relative.is_absolute() and relative.parts and
            all(part not in {"", ".", ".."} for part in relative.parts),
            f"{description} path escapes checkout")
    return _physical_work_path(root, root / relative, description, directory=True)


def _canonical_products(root: Path, static_preparation: Path, dynamic_qualification: Path) -> tuple[
        dict[str, object], dict[str, dict[str, dict[str, object]]]]:
    """Recover three aligned static/dynamic pairs from their owning receipts."""

    root = root.resolve(strict=True)
    require(root == dynamic.ROOT.resolve(), "dynamic qualification belongs to another checkout")
    static_preparation = _physical_work_path(root, static_preparation, "static preparation receipt", directory=False)
    dynamic_qualification = _physical_work_path(root, dynamic_qualification, "dynamic qualification receipt", directory=False)

    try:
        prepared = static.validate_receipt(root, static_preparation)
        qualified = dynamic.validate_receipt(dynamic_qualification)
        source = static.source_identity(root)
    except (static.PreparationError, dynamic.QualificationError, OSError, ValueError) as error:
        raise ResolverFamilyCohortError(f"canonical product receipt rejected: {error}") from error

    require(prepared.get("source") == source, "static preparation is not current source")
    require(qualified.get("source_sha256") == source["content_sha256"],
            "dynamic qualification is not current source")
    require(qualified.get("family_completion") is False and qualified.get("public_support") is False,
            "dynamic qualification cannot complete the resolver family")

    static_paths = static.product_paths(static_preparation.parent)
    work_value = qualified.get("work")
    dynamic_work = _directory(root, work_value, "dynamic qualification work")
    products: dict[str, dict[str, dict[str, object]]] = {}
    for label, dynamic_label in PAIRS.items():
        static_product = _physical_work_path(root, static_paths[label], f"{label} static product", directory=True)
        dynamic_product = _physical_work_path(root, dynamic_work / dynamic_label,
                                              f"{label} dynamic product", directory=True)
        static_manifest = _file_identity(root, static_product / "share/crabc/manifest.json",
                                         f"{label} static manifest")
        dynamic_manifest = _file_identity(root, dynamic_product / "share/crabc/manifest.json",
                                          f"{label} dynamic manifest")
        static_record = prepared.get("products", {}).get(label)
        require(isinstance(static_record, dict) and static_record.get("path") == static_product.relative_to(root).as_posix()
                and static_record.get("manifest") == {
                    "path": static_manifest["path"], "sha256": static_manifest["sha256"],
                    "size": static_manifest["byte_length"],
                }, f"{label} static preparation product identity differs")
        dynamic_products = qualified.get("products")
        require(isinstance(dynamic_products, dict) and dynamic_products.get(dynamic_label) == dynamic_manifest["sha256"],
                f"{label} dynamic qualification product identity differs")
        products[label] = {
            "static": {"path": static_product.relative_to(root).as_posix(), "manifest": static_manifest},
            "dynamic": {"path": dynamic_product.relative_to(root).as_posix(), "manifest": dynamic_manifest},
        }

    return {
        "revision": source["revision"],
        "content_sha256": source["content_sha256"],
        "static_preparation": _file_identity(root, static_preparation, "static preparation receipt"),
        "dynamic_qualification": _file_identity(root, dynamic_qualification, "dynamic qualification receipt"),
    }, products


def canonical_products(root: Path, static_preparation: Path, dynamic_qualification: Path) -> tuple[
        dict[str, object], dict[str, dict[str, dict[str, object]]]]:
    """Return the validated current source seal and its three product pairs.

    A family execution plan uses exactly these roots before any component
    runs, so the later cohort replay binds the same pairs it was given.
    """

    return _canonical_products(root, static_preparation, dynamic_qualification)


def _match_component_products(root: Path, identifier: str, value: object,
                              products: Mapping[str, Mapping[str, Mapping[str, object]]]) -> dict[str, object]:
    """Match one reader's declared roots to the canonical pair identities."""

    require(identifier in EXPECTED_COMPONENT_ROOTS, f"unknown resolver component binding: {identifier}")
    require(isinstance(value, dict) and set(value) == set(EXPECTED_COMPONENT_ROOTS[identifier]),
            f"{identifier} declared product root roster differs")
    matched: dict[str, object] = {}
    for declaration, kinds in value.items():
        require(isinstance(kinds, dict) and set(kinds) == {"static", "dynamic"},
                f"{identifier} {declaration} product kind roster differs")
        actual: dict[str, dict[str, object]] = {}
        candidates: set[str] | None = None
        for kind in ("static", "dynamic"):
            path = _directory(root, kinds[kind], f"{identifier} {declaration} {kind} product")
            manifest = _file_identity(root, path / "share/crabc/manifest.json",
                                      f"{identifier} {declaration} {kind} manifest")
            actual[kind] = {"path": path.relative_to(root).as_posix(), "manifest": manifest}
            matches = {label for label, pair in products.items() if pair[kind] == actual[kind]}
            candidates = matches if candidates is None else candidates & matches
        require(candidates is not None and len(candidates) == 1,
                f"{identifier} {declaration} roots do not form one canonical static/dynamic pair")
        label = candidates.pop()
        if declaration != "selected":
            require(label == declaration, f"{identifier} {declaration} binds another canonical pair")
        matched[declaration] = {"pair": label, "products": actual}
    return matched


def validate(root: Path, *, static_preparation: Path, dynamic_qualification: Path,
             component_products: Mapping[str, object]) -> dict[str, object]:
    """Validate the one current cohort and each component's declared roots.

    ``component_products`` is produced only after the five existing public
    readers have reconstructed their retained receipts.  This adapter therefore
    adds a product-cohort boundary and never substitutes for their behavior
    validation.
    """

    root = root.resolve(strict=True)
    require(set(component_products) == set(REQUIRED_COMPONENTS),
            "resolver cohort requires every behavior component replay")
    source, products = _canonical_products(root, static_preparation, dynamic_qualification)
    bindings = {
        identifier: _match_component_products(root, identifier, component_products[identifier], products)
        for identifier in REQUIRED_COMPONENTS
    }
    return {
        "schema": SCHEMA,
        "source": source,
        "products": products,
        "component_bindings": bindings,
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
    }
