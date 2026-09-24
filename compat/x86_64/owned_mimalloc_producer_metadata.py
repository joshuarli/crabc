#!/usr/bin/env python3
"""Account fixed-C mimalloc producer metadata for owned native products.

This reader consumes facts already authenticated by native_abi_elf_facts, the
two owned-product provenance records, and the selected dynamic-product manifest.
It does not build products, replay ELF collection, select public ABI providers,
or infer ownership from prefixes.
Its closed contract binds the selected libmimalloc-sys 0.1.49 source bundle,
the exact 424-name localization list, and four C producer metadata buckets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
import tomllib
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
MODULE_DIRECTORY = Path(__file__).resolve().parent
if str(MODULE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(MODULE_DIRECTORY))

import compiler_helper_evidence as compiler_helpers

CONTRACT_PATH = MODULE_DIRECTORY / "owned_mimalloc_producer_metadata.toml"
HIDDEN_LIST = ROOT / "libc/src/c_abi/x86_64/owned_mimalloc_hidden.list"
SCHEMA = "crabc.x86_64-owned-mimalloc-producer-metadata/v1"
RECEIPT_SCHEMA = "crabc.x86_64-owned-mimalloc-producer-metadata-receipt/v1"
ELF_FACTS_SCHEMA = "crabc.x86_64-native-abi-elf-facts/v1"
TARGET = "x86_64-unknown-linux-musl"
DYNAMIC_PRODUCT_MANIFEST_SCHEMA = 1
DYNAMIC_PRODUCT_MANIFEST_FORMAT = "crabc-x86-64-owned-dynamic-sysroot-v1"
DYNAMIC_PRODUCT_LIBC_PATH = "usr/lib/libc.so"
ELF_FACTS_STATUS = {
    "classification": "measurement-only-no-abi-selection-or-promotion",
    "family_completion": False,
    "promotion_ready": False,
    "public_support": False,
}
EXPECTED_RUST_ROOT_IMPORTS = (
    "_mi_auto_process_done",
    "_mi_auto_process_init",
    "mi_free",
    "mi_malloc_aligned",
    "mi_realloc_aligned",
    "mi_usable_size",
    "mi_zalloc",
)
# The Rust root takes the address of one C allocator data object:
# `pthread_tsd.rs` recognizes `_mi_heap_default_key` as the storage of the C
# backend's own thread-exit key and gives it the private slot beyond
# PTHREAD_KEYS_MAX. Only the address is used; the word stays C-owned.
EXPECTED_RUST_ROOT_DATA_REFERENCES = ("_mi_heap_default_key",)
EXPECTED_DATA_OBJECTS = (
    "_mi_cpu_has_popcnt",
    "_mi_heap_default_key",
    "_mi_stats_main",
)
EXPECTED_TLS_OBJECT = "mi_thread_locals"
EXPECTED_WEAK_NULL_FALLBACK = "_ZSt15get_new_handlerv"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
LINKER_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class ProducerMetadataError(ValueError):
    """A C-producer contract input is malformed, stale, or differs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProducerMetadataError(message)


def same(left: object, right: object) -> bool:
    """Keep JSON Booleans and numbers distinct unlike Python equality."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same(value, right[key]) for key, value in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
    return left == right


def mapping(value: object, description: str, keys: set[str] | None = None) -> dict[str, Any]:
    require(type(value) is dict, f"{description} is not an object")
    result = value
    if keys is not None:
        require(set(result) == keys, f"{description} fields differ")
    return result


def require_keys(value: Mapping[str, Any], keys: set[str], description: str) -> None:
    """Allow unrelated producer fields while refusing an omitted authority field."""
    require(keys <= set(value), f"{description} omits required fields")


def text(value: object, description: str, *, empty: bool = False) -> str:
    require(type(value) is str and (empty or bool(value)), f"{description} is not a string")
    return value


def sha256(value: object, description: str) -> str:
    result = text(value, description)
    require(SHA256_RE.fullmatch(result) is not None, f"{description} is not a SHA-256")
    return result


def positive(value: object, description: str) -> int:
    require(type(value) is int and value > 0, f"{description} is not a positive integer")
    return value


def nonnegative(value: object, description: str) -> int:
    require(type(value) is int and value >= 0, f"{description} is not a nonnegative integer")
    return value


def names(value: object, description: str) -> list[str]:
    require(type(value) is list, f"{description} is not a list")
    result = [text(item, description) for item in value]
    require(result == sorted(set(result)), f"{description} must be sorted and unique")
    require(all(LINKER_NAME_RE.fullmatch(item) is not None for item in result),
            f"{description} contains an invalid linker name")
    return result


def stable_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def physical_identity(path: Path, description: str) -> dict[str, object]:
    try:
        details = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ProducerMetadataError(f"{description} is missing or unsafe: {path}") from error
    require(stat.S_ISREG(details.st_mode) and not path.is_symlink() and resolved == path,
            f"{description} is not a physical regular file")
    return {
        "path": str(path),
        "sha256": sha256_file(path),
        "size": details.st_size,
        "mode": stat.S_IMODE(details.st_mode),
    }


def _exact_metadata(value: object, description: str) -> dict[str, str]:
    record = mapping(value, description, {"type", "binding", "visibility"})
    result = {field: text(record[field], f"{description}.{field}") for field in ("type", "binding", "visibility")}
    require(result["type"] in {"FUNC", "OBJECT", "TLS"}, f"{description}.type is unsupported")
    require(result["binding"] in {"GLOBAL", "WEAK", "LOCAL"}, f"{description}.binding is unsupported")
    require(result["visibility"] == "DEFAULT", f"{description}.visibility is not DEFAULT")
    return result


def _source_reference(value: object, description: str) -> dict[str, str]:
    record = mapping(value, description, {"path", "sha256"})
    path = text(record["path"], f"{description}.path")
    require(path.startswith("libmimalloc-sys/c_src/mimalloc/v3/"), f"{description}.path leaves pinned v3 source")
    return {"path": path, "sha256": sha256(record["sha256"], f"{description}.sha256")}


def _source_layout(
    value: object,
    description: str,
    source_hashes: Mapping[str, str],
) -> dict[str, object]:
    """Bind a selected object's C spelling and source-required layout authority.

    This is intentionally distinct from the compiler/linker placement recorded
    in ``producer.static_section_alignment``.  A section can be over-aligned
    without changing the C type's required alignment.
    """
    record = mapping(
        value,
        description,
        {
            "definition_path",
            "definition_sha256",
            "definition_line",
            "declaration",
            "c_type",
            "size_basis",
            "alignment_path",
            "alignment_sha256",
            "alignment_line",
            "alignment_basis",
            "source_required_alignment",
            "include_route",
        },
    )
    definition_path = text(record["definition_path"], f"{description}.definition_path")
    definition_sha256 = sha256(record["definition_sha256"], f"{description}.definition_sha256")
    alignment_path = text(record["alignment_path"], f"{description}.alignment_path")
    alignment_sha256 = sha256(record["alignment_sha256"], f"{description}.alignment_sha256")
    require(source_hashes.get(definition_path) == definition_sha256,
            f"{description} definition source is not pinned")
    require(source_hashes.get(alignment_path) == alignment_sha256,
            f"{description} alignment source is not pinned")
    return {
        "definition_path": definition_path,
        "definition_sha256": definition_sha256,
        "definition_line": positive(record["definition_line"], f"{description}.definition_line"),
        "declaration": text(record["declaration"], f"{description}.declaration"),
        "c_type": text(record["c_type"], f"{description}.c_type"),
        "size_basis": text(record["size_basis"], f"{description}.size_basis"),
        "alignment_path": alignment_path,
        "alignment_sha256": alignment_sha256,
        "alignment_line": positive(record["alignment_line"], f"{description}.alignment_line"),
        "alignment_basis": text(record["alignment_basis"], f"{description}.alignment_basis"),
        "source_required_alignment": positive(
            record["source_required_alignment"], f"{description}.source_required_alignment"
        ),
        "include_route": text(record["include_route"], f"{description}.include_route"),
    }


def _producer_layout(value: object, description: str) -> dict[str, int]:
    record = mapping(value, description, {"static_section_alignment"})
    return {
        "static_section_alignment": positive(
            record["static_section_alignment"], f"{description}.static_section_alignment"
        ),
    }


def _validate_contract(value: object) -> dict[str, Any]:
    contract = mapping(
        value,
        "fixed-C mimalloc producer contract",
        {
            "schema",
            "target",
            "backend",
            "source_provenance",
            "build",
            "shared_localization",
            "metadata",
            "rust_root_imports",
            "rust_root_data_references",
            "status_flags",
            "boundaries",
        },
    )
    require(contract["schema"] == SCHEMA, "fixed-C mimalloc producer schema differs")
    require(contract["target"] == TARGET, "fixed-C mimalloc producer target differs")

    backend = mapping(contract["backend"], "allocator backend", {"crate", "version", "checksum", "mimalloc_version", "version_macro"})
    require(
        backend == {
            "crate": "libmimalloc-sys",
            "version": "0.1.49",
            "checksum": "6a45a52f43e1c16f667ccfe4dd8c85b7f7c204fd5e3bf46c5b0db9a5c3c0b8e9",
            "mimalloc_version": "3.3.2",
            "version_macro": 30302,
        },
        "allocator backend pin differs",
    )

    provenance = mapping(
        contract["source_provenance"],
        "allocator source provenance",
        {
            "members_file",
            "members_sha256",
            "members_count",
            "upstream_prefix",
            "upstream_source_count",
            "upstream_sources_sha256",
            "project_header_source_count",
            "project_header_sources_sha256",
            "static_translation_unit",
            "public_header",
            "weak_fallback_source",
            "upstream_sources",
            "project_header_sources",
        },
    )
    members_file = text(provenance["members_file"], "allocator member source")
    require(members_file == HIDDEN_LIST.relative_to(ROOT).as_posix(), "allocator member source path differs")
    sha256(provenance["members_sha256"], "allocator member source SHA-256")
    require(positive(provenance["members_count"], "allocator member count") == 424,
            "allocator member count differs")
    prefix = text(provenance["upstream_prefix"], "allocator upstream prefix")
    require(prefix == "libmimalloc-sys/c_src/mimalloc/v3/", "allocator upstream prefix differs")
    upstream_sources = mapping(provenance["upstream_sources"], "allocator upstream source map")
    normalized_sources: dict[str, str] = {}
    for path, digest in upstream_sources.items():
        require(type(path) is str and path.startswith(prefix), "allocator upstream source path differs")
        normalized_sources[path] = sha256(digest, f"allocator upstream source {path}")
    require(len(normalized_sources) == positive(provenance["upstream_source_count"], "allocator upstream source count"),
            "allocator upstream source count differs")
    require(stable_sha256(normalized_sources) == sha256(provenance["upstream_sources_sha256"], "allocator upstream source map SHA-256"),
            "allocator upstream source map digest differs")
    project_sources = mapping(provenance["project_header_sources"], "allocator installed header source map")
    normalized_project_sources: dict[str, str] = {}
    for path, digest in project_sources.items():
        require(type(path) is str and path.startswith("include/"), "allocator installed header source path differs")
        normalized_project_sources[path] = sha256(digest, f"allocator installed header source {path}")
    require(
        set(normalized_project_sources) == {"include/bits/alltypes.h", "include/pthread.h"}
        and len(normalized_project_sources) == positive(
            provenance["project_header_source_count"], "allocator installed header source count"
        ),
        "allocator installed header source roster differs",
    )
    require(
        stable_sha256(normalized_project_sources) == sha256(
            provenance["project_header_sources_sha256"], "allocator installed header source map SHA-256"
        ),
        "allocator installed header source map digest differs",
    )
    for key, expected in (
        ("static_translation_unit", "libmimalloc-sys/c_src/mimalloc/v3/src/static.c"),
        ("public_header", "libmimalloc-sys/c_src/mimalloc/v3/include/mimalloc.h"),
        ("weak_fallback_source", "libmimalloc-sys/c_src/mimalloc/v3/src/alloc.c"),
    ):
        reference = _source_reference(provenance[key], f"allocator {key}")
        require(reference["path"] == expected and normalized_sources.get(reference["path"]) == reference["sha256"],
                f"allocator {key} does not bind the upstream source map")

    build = mapping(contract["build"], "allocator build flags", {"static_target_flags", "shared_allocator_flags", "lifecycle_profile"})
    require(type(build["static_target_flags"]) is list and type(build["shared_allocator_flags"]) is list,
            "allocator build flags are not lists")
    static_flags = [text(item, "static allocator flag") for item in build["static_target_flags"]]
    shared_flags = [text(item, "shared allocator flag") for item in build["shared_allocator_flags"]]
    require(static_flags == [
        "-nostdinc", "-isystem", "$CRABC_SOURCE/include", "-fPIC", "-ftls-model=initial-exec",
        "-fstack-protector-strong", "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
        "-ffile-prefix-map=$CRABC_SOURCE=/crabc", "-MD", "-MF", "$CRABC_X86_BUILD/allocator.d",
    ], "static allocator build flags differ")
    require(shared_flags == [
        "-nostdinc", "-isystem", "$SOURCE/include", "-fPIC", "-ftls-model=initial-exec",
        "-fstack-protector-strong", "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
        "-ffile-prefix-map=$SOURCE=/crabc", "-MD", "-MF", "$BUILD/allocator.d",
    ], "shared allocator build flags differ")
    lifecycle = mapping(
        build["lifecycle_profile"],
        "allocator lifecycle profile",
        {"backend_implicit_attach_detach", "c_define", "rust_cfg", "same_image_entries"},
    )
    require(lifecycle == {
        "backend_implicit_attach_detach": "absent",
        "c_define": "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
        "rust_cfg": "crabc_owned_mimalloc_lifecycle",
        "same_image_entries": [
            "__crabc_x86_owned_mimalloc_process_initializer",
            "__crabc_x86_owned_mimalloc_process_finalizer",
        ],
    }, "allocator lifecycle profile differs")

    localization = mapping(
        contract["shared_localization"],
        "shared allocator localization",
        {"linker_policy", "linker_script_sha256", "version_script_argument"},
    )
    require(localization["linker_policy"] == "exact-local-symbols", "shared allocator localization policy differs")
    sha256(localization["linker_script_sha256"], "shared allocator linker script SHA-256")
    require(localization["version_script_argument"] == "--version-script=$BUILD/libc-mimalloc-hidden.exports",
            "shared allocator version-script argument differs")

    metadata = mapping(contract["metadata"], "allocator metadata", {"strong_functions", "weak_null_fallback", "data_objects", "tls_object"})
    strong = mapping(metadata["strong_functions"], "strong allocator functions", {"static", "shared", "excluded_names"})
    strong["static"] = _exact_metadata(strong["static"], "strong allocator static metadata")
    strong["shared"] = _exact_metadata(strong["shared"], "strong allocator shared metadata")
    require(strong["static"] == {"type": "FUNC", "binding": "GLOBAL", "visibility": "DEFAULT"},
            "strong allocator static metadata differs")
    require(strong["shared"] == {"type": "FUNC", "binding": "LOCAL", "visibility": "DEFAULT"},
            "strong allocator shared metadata differs")

    weak = mapping(metadata["weak_null_fallback"], "weak null fallback", {"name", "static", "shared", "source_semantics"})
    weak["name"] = text(weak["name"], "weak null fallback name")
    weak["static"] = _exact_metadata(weak["static"], "weak null fallback static metadata")
    weak["shared"] = _exact_metadata(weak["shared"], "weak null fallback shared metadata")
    require(
        weak["name"] == EXPECTED_WEAK_NULL_FALLBACK
        and weak["static"] == {"type": "FUNC", "binding": "WEAK", "visibility": "DEFAULT"}
        and weak["shared"] == {"type": "FUNC", "binding": "LOCAL", "visibility": "DEFAULT"}
        and weak["source_semantics"] == "defined-null-fallback",
        "weak null fallback contract differs",
    )

    source_hashes = {**normalized_sources, **normalized_project_sources}
    raw_data = metadata["data_objects"]
    require(type(raw_data) is list and len(raw_data) == len(EXPECTED_DATA_OBJECTS), "allocator data object roster differs")
    data: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_data):
        item = mapping(
            raw,
            f"allocator data object {index}",
            {"name", "static", "shared", "size_bytes", "source", "producer"},
        )
        item["name"] = text(item["name"], f"allocator data object {index} name")
        item["static"] = _exact_metadata(item["static"], f"allocator data object {item['name']} static metadata")
        item["shared"] = _exact_metadata(item["shared"], f"allocator data object {item['name']} shared metadata")
        item["size_bytes"] = positive(item["size_bytes"], f"allocator data object {item['name']} size")
        item["source"] = _source_layout(
            item["source"], f"allocator data object {item['name']} source layout", source_hashes
        )
        item["producer"] = _producer_layout(
            item["producer"], f"allocator data object {item['name']} producer layout"
        )
        require(item["static"] == {"type": "OBJECT", "binding": "GLOBAL", "visibility": "DEFAULT"},
                f"allocator data object {item['name']} static metadata differs")
        require(item["shared"] == {"type": "OBJECT", "binding": "LOCAL", "visibility": "DEFAULT"},
                f"allocator data object {item['name']} shared metadata differs")
        data.append(item)
    require(tuple(item["name"] for item in data) == EXPECTED_DATA_OBJECTS, "allocator data object names differ")

    tls = mapping(
        metadata["tls_object"],
        "allocator TLS object",
        {"name", "static", "shared", "size_bytes", "source", "producer"},
    )
    tls["name"] = text(tls["name"], "allocator TLS object name")
    tls["static"] = _exact_metadata(tls["static"], "allocator TLS static metadata")
    tls["shared"] = _exact_metadata(tls["shared"], "allocator TLS shared metadata")
    tls["size_bytes"] = positive(tls["size_bytes"], "allocator TLS size")
    tls["source"] = _source_layout(tls["source"], "allocator TLS source layout", source_hashes)
    tls["producer"] = _producer_layout(tls["producer"], "allocator TLS producer layout")
    require(
        tls["name"] == EXPECTED_TLS_OBJECT
        and tls["static"] == {"type": "TLS", "binding": "GLOBAL", "visibility": "DEFAULT"}
        and tls["shared"] == {"type": "TLS", "binding": "LOCAL", "visibility": "DEFAULT"},
        "allocator TLS metadata differs",
    )

    excluded = names(strong["excluded_names"], "strong allocator function exclusions")
    require(
        excluded == sorted([weak["name"], *(item["name"] for item in data), tls["name"]]),
        "strong allocator function exclusions differ",
    )

    imports = mapping(contract["rust_root_imports"], "Rust-root C imports", {"names"})
    import_names = names(imports["names"], "Rust-root C imports")
    require(tuple(import_names) == EXPECTED_RUST_ROOT_IMPORTS, "Rust-root C import roster differs")
    references = mapping(contract["rust_root_data_references"], "Rust-root C data references", {"names"})
    reference_names = names(references["names"], "Rust-root C data references")
    require(tuple(reference_names) == EXPECTED_RUST_ROOT_DATA_REFERENCES
            and set(reference_names) <= {item["name"] for item in data},
            "Rust-root C data reference roster differs")

    status_flags = mapping(contract["status_flags"], "producer status flags", {"family_completion", "promotion_ready", "public_support"})
    require(all(type(status_flags[name]) is bool and status_flags[name] is False for name in status_flags),
            "producer status flags must remain false")
    boundaries = mapping(
        contract["boundaries"],
        "producer boundaries",
        {"public_malloc_interposition", "fixed_c_backend", "qualified_rust_backend_promotion"},
    )
    require(boundaries == {
        "public_malloc_interposition": "separate-component",
        "fixed_c_backend": "selected-current-backend",
        "qualified_rust_backend_promotion": "removes-this-private-c-producer-contract",
    }, "producer boundary contract differs")

    return {
        "schema": SCHEMA,
        "target": TARGET,
        "backend": dict(backend),
        "source_provenance": {
            **dict(provenance),
            "upstream_sources": normalized_sources,
            "project_header_sources": normalized_project_sources,
        },
        "build": {
            "static_target_flags": static_flags,
            "shared_allocator_flags": shared_flags,
            "lifecycle_profile": dict(lifecycle),
        },
        "shared_localization": dict(localization),
        "metadata": {
            "strong_functions": dict(strong),
            "weak_null_fallback": dict(weak),
            "data_objects": data,
            "tls_object": dict(tls),
        },
        "rust_root_imports": {"names": import_names},
        "rust_root_data_references": {"names": reference_names},
        "status_flags": dict(status_flags),
        "boundaries": dict(boundaries),
    }


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    """Load the reviewed policy. Public accounting cannot inject another policy."""
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ProducerMetadataError(f"cannot load fixed-C mimalloc producer contract: {error}") from error
    return _validate_contract(raw)


def contract_members(contract: Mapping[str, Any]) -> list[str]:
    """Read the existing exact localizing roster; no prefix creates membership."""
    source = mapping(contract["source_provenance"], "loaded allocator source provenance")
    try:
        content = HIDDEN_LIST.read_bytes()
    except OSError as error:
        raise ProducerMetadataError(f"cannot read allocator member roster: {error}") from error
    require(sha256_file(HIDDEN_LIST) == source["members_sha256"], "allocator member roster member count/digest differs")
    result = content.decode("utf-8").splitlines()
    require(
        len(result) == source["members_count"]
        and result == sorted(set(result))
        and all(LINKER_NAME_RE.fullmatch(item) is not None for item in result),
        "allocator member roster member count/digest differs",
    )
    return result


def selected_metadata() -> dict[str, dict[str, dict[str, object]]]:
    """Project the reviewed static/shared metadata for every exact private name.

    This policy projection intentionally contains no observed ELF values.  A
    consumer can attach its own authenticated facts while using the same finite
    424-name source contract instead of re-creating the four metadata buckets.
    """
    contract = load_contract()
    metadata = contract["metadata"]
    data = {item["name"]: item for item in metadata["data_objects"]}
    tls = metadata["tls_object"]
    weak = metadata["weak_null_fallback"]
    result: dict[str, dict[str, dict[str, object]]] = {}
    for name in contract_members(contract):
        layout: Mapping[str, Any] | None = None
        if name in data:
            expected = data[name]
            layout = expected
        elif name == tls["name"]:
            expected = tls
            layout = expected
        elif name == weak["name"]:
            expected = weak
        else:
            expected = metadata["strong_functions"]
        static = dict(expected["static"])
        shared = dict(expected["shared"])
        if layout is not None:
            static.update({
                "size_bytes": layout["size_bytes"],
                # Generic consumers compare both a defining section and
                # st_value.  Use the C source minimum in both roles; the
                # account keeps exact static section over-alignment separate.
                "alignment_bytes": layout["source"]["source_required_alignment"],
            })
            shared.update({
                "size_bytes": layout["size_bytes"],
                "alignment_bytes": layout["source"]["source_required_alignment"],
            })
        result[name] = {
            "static": static,
            "shared": shared,
        }
    require(len(result) == 424, "selected producer metadata roster differs")
    return result


def _require_exact_source_map(value: object, contract: Mapping[str, Any], description: str) -> dict[str, str]:
    record = mapping(value, description)
    normalized: dict[str, str] = {}
    for path, digest in record.items():
        require(type(path) is str, f"{description} source path is not a string")
        normalized[path] = sha256(digest, f"{description} source {path}")
    source = contract["source_provenance"]
    prefix = source["upstream_prefix"]
    upstream = {path: digest for path, digest in normalized.items() if path.startswith(prefix)}
    require(upstream == source["upstream_sources"], f"{description} pinned v3 source map differs")
    project_headers = {
        path: digest
        for path, digest in normalized.items()
        if path in source["project_header_sources"]
    }
    require(
        project_headers == source["project_header_sources"],
        f"{description} installed header source map differs",
    )
    require(
        all(path.startswith(prefix) for path in normalized if path.startswith("libmimalloc-sys/")),
        f"{description} includes a non-v3 libmimalloc-sys source",
    )
    return normalized


def _crate_pin(contract: Mapping[str, Any]) -> dict[str, str]:
    backend = contract["backend"]
    return {
        "name": backend["crate"],
        "version": backend["version"],
        "checksum": backend["checksum"],
    }


def _member_records(value: object, description: str) -> dict[str, str]:
    require(type(value) is list and len(value) >= 2, f"{description} does not contain a C and a Rust member")
    result: dict[str, str] = {}
    for index, raw in enumerate(value):
        record = mapping(raw, f"{description} member {index}", {"name", "sha256"})
        name = text(record["name"], f"{description} member {index} name")
        require(name not in result, f"{description} repeats a member")
        result[name] = sha256(record["sha256"], f"{description} member {name} SHA-256")
    return result


def _member_roles(records: Mapping[str, str], description: str) -> tuple[str, list[str]]:
    """Split selected members into the one C allocator object and the Rust objects.

    The installed static archive has one Rust member per libc module; the
    shared link selects one Rust object.
    """
    c_members = [name for name in records if re.fullmatch(r"[0-9a-f]+-static\.o", name) is not None]
    rust_members = sorted(name for name in records if name.endswith(".rcgu.o"))
    require(len(c_members) == 1 and rust_members and set(c_members + rust_members) == set(records),
            f"{description} member roles differ")
    return c_members[0], rust_members


def _shared_member_records(value: object, description: str) -> dict[str, str]:
    record = mapping(value, description)
    require(len(record) == 2, f"{description} does not contain exactly two members")
    result: dict[str, str] = {}
    for name, digest in record.items():
        member = text(name, f"{description} member name")
        result[member] = sha256(digest, f"{description} member {member} SHA-256")
    return result


def _validate_static_provenance(
    provenance: object, contract: Mapping[str, Any],
) -> tuple[str, str, str, list[str], dict[str, str]]:
    record = mapping(provenance, "static allocator provenance")
    require_keys(record, {"archive", "selected_members", "allocator_backend"}, "static allocator provenance")
    archive = mapping(record["archive"], "static libc archive", {"name", "sha256"})
    require(archive["name"] == "libc.a", "static allocator archive name differs")
    archive_sha256 = sha256(archive["sha256"], "static allocator archive SHA-256")
    selected = _member_records(record["selected_members"], "static allocator selected members")
    c_member, rust_members = _member_roles(selected, "static allocator selected")
    backend = mapping(record["allocator_backend"], "static allocator backend")
    require_keys(
        backend,
        {
            "archive_sha256", "crate", "implementation", "member", "member_sha256",
            "source_and_header_sha256", "target_flags", "lifecycle_profile",
        },
        "static allocator backend",
    )
    producer_archive_sha256 = sha256(backend["archive_sha256"], "static allocator producer archive SHA-256")
    require(same(backend["crate"], _crate_pin(contract)), "static allocator crate pin differs")
    require(backend["implementation"] == "accepted C backend; native Rust promotion remains separate",
            "static allocator implementation boundary differs")
    require(backend["member"] == c_member and backend["member_sha256"] == selected[c_member],
            "static allocator C member provenance differs")
    _require_exact_source_map(backend["source_and_header_sha256"], contract, "static allocator source provenance")
    require(backend["target_flags"] == contract["build"]["static_target_flags"], "static allocator build flags differ")
    require(backend["lifecycle_profile"] == contract["build"]["lifecycle_profile"],
            "static allocator lifecycle profile differs")
    return archive_sha256, producer_archive_sha256, c_member, rust_members, selected


def _validate_shared_provenance(
    provenance: object, contract: Mapping[str, Any], c_member: str, c_sha256: str,
    elf_facts: Mapping[str, Any], shared_manifest: Mapping[str, Any],
) -> tuple[str, dict[str, str]]:
    record = mapping(provenance, "shared allocator provenance")
    require_keys(
        record,
        {
            "accepted_allocator", "allocator_headers", "allocator_flags", "selected_members",
            "shared_mimalloc_hidden_exports", "libc_shared_link_command",
        },
        "shared allocator provenance",
    )
    require(same(record["accepted_allocator"], _crate_pin(contract)), "shared allocator crate pin differs")
    _require_exact_source_map(record["allocator_headers"], contract, "shared allocator source provenance")
    require(record["allocator_flags"] == contract["build"]["shared_allocator_flags"], "shared allocator build flags differ")
    selected = _shared_member_records(record["selected_members"], "shared allocator selected members")
    require(selected.get(c_member) == c_sha256, "shared selected member differs from static C provider")
    _, rust_members = _member_roles(selected, "shared allocator selected")
    require(len(rust_members) == 1, "shared allocator selected member roles differ")
    rust_member = rust_members[0]
    visibility = mapping(
        record["shared_mimalloc_hidden_exports"],
        "shared allocator localization provenance",
        {"source", "member_count", "members", "linker_script_sha256", "linker_policy"},
    )
    source = mapping(visibility["source"], "shared allocator localization source", {"path", "sha256", "mode"})
    expected_source = contract["source_provenance"]
    require(
        source == {
            "path": expected_source["members_file"],
            "sha256": expected_source["members_sha256"],
            "mode": 0o644,
        },
        "shared allocator localization source differs",
    )
    require(
        visibility["member_count"] == expected_source["members_count"]
        and visibility["members"] == contract_members(contract)
        and visibility["linker_script_sha256"] == contract["shared_localization"]["linker_script_sha256"]
        and visibility["linker_policy"] == contract["shared_localization"]["linker_policy"],
        "shared allocator localization provenance differs",
    )
    command = record["libc_shared_link_command"]
    require(type(command) is list and all(type(item) is str for item in command), "shared allocator link command is malformed")
    require(command.count(contract["shared_localization"]["version_script_argument"]) == 1,
            "shared allocator link did not use the exact version script")
    if any("--exclude-libs" in item for item in command) or "shared_compiler_helper_archive" in record:
        # Only the separate helper owner can admit its exact archive exclusion.
        # The C object remains governed by the 424-name version script above.
        try:
            compiler_helpers.shared_libc_archive_policy_from_product(record, shared_manifest, elf_facts, root=ROOT)
        except (compiler_helpers.CompilerHelperEvidenceError, OSError, ValueError) as error:
            raise ProducerMetadataError(f"shared allocator link helper archive policy rejected: {error}") from error
    require(command.count(f"$BUILD/objects/{c_member}") == 1,
            "shared allocator link does not select the C provider object exactly once")
    require(command.count(f"$BUILD/objects/{rust_member}") == 1,
            "shared allocator link does not select its Rust root object exactly once")
    return rust_member, selected


def _symbol_tables(value: object, description: str, expected: set[str]) -> dict[str, list[dict[str, Any]]]:
    require(type(value) is list, f"{description} symbol tables are not a list")
    result: dict[str, list[dict[str, Any]]] = {}
    for index, raw in enumerate(value):
        table = mapping(raw, f"{description} table {index}")
        require_keys(table, {"name", "rows"}, f"{description} table {index}")
        name = text(table["name"], f"{description} table {index} name")
        require(name not in result and name in expected, f"{description} symbol table roster differs")
        require(type(table["rows"]) is list, f"{description} {name} rows are not a list")
        result[name] = [mapping(row, f"{description} {name} row {row_index}")
                        for row_index, row in enumerate(table["rows"])]
    require(set(result) == expected, f"{description} symbol table roster differs")
    return result


def _static_members(
    facts: Mapping[str, Any], static_members: Mapping[str, str], c_member: str, rust_members: Sequence[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rows = facts["facts"]["candidate-static"]
    require(type(rows) is list and len(rows) == len(static_members), "static ELF member roster differs")
    records: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(rows):
        member = mapping(raw, f"static ELF member {index}")
        name = text(member.get("member"), f"static ELF member {index} name")
        require(name not in records and member.get("member_occurrence") == 0, "static ELF member occurrence differs")
        records[name] = member
    require(set(records) == set(static_members), "static ELF member roster differs from archive map")
    return records[c_member], [records[name] for name in rust_members]


def _validate_elf_facts(facts: object, static_archive_sha256: str) -> dict[str, Any]:
    report = mapping(facts, "ELF facts report")
    require_keys(report, {"schema", "target", "status", "collector_execution_source", "artifacts", "facts"}, "ELF facts report")
    require(report["schema"] == ELF_FACTS_SCHEMA and report["target"] == TARGET, "ELF facts schema/target differs")
    require(same(report["status"], ELF_FACTS_STATUS), "ELF facts status differs")
    collector = mapping(report["collector_execution_source"], "ELF facts collector source", {"revision", "content_sha256", "clean"})
    require(
        len(text(collector["revision"], "ELF facts collector revision")) == 40
        and SHA256_RE.fullmatch(text(collector["content_sha256"], "ELF facts collector digest")) is not None
        and type(collector["clean"]) is bool,
        "ELF facts collector source is malformed",
    )
    artifacts = mapping(report["artifacts"], "ELF facts artifacts")
    require_keys(artifacts, {"candidate-static", "candidate-shared"}, "ELF facts artifacts")
    static = mapping(artifacts["candidate-static"], "ELF facts static artifact")
    require_keys(static, {"identity"}, "ELF facts static artifact")
    static_identity = mapping(static["identity"], "ELF facts static identity")
    require_keys(static_identity, {"sha256"}, "ELF facts static identity")
    require(static_identity["sha256"] == static_archive_sha256, "ELF facts static archive differs from static provenance")
    shared = mapping(artifacts["candidate-shared"], "ELF facts shared artifact")
    require_keys(shared, {"identity"}, "ELF facts shared artifact")
    shared_identity = mapping(shared["identity"], "ELF facts shared identity")
    require_keys(shared_identity, {"sha256"}, "ELF facts shared identity")
    sha256(shared_identity["sha256"], "ELF facts shared artifact SHA-256")
    fact_placements = mapping(report["facts"], "ELF facts placements")
    require_keys(fact_placements, {"candidate-static", "candidate-shared"}, "ELF facts placements")
    return report


def _shared_artifact_identity(report: Mapping[str, Any]) -> dict[str, object]:
    """Return the final DSO identity that a dynamic manifest must name.

    The ELF facts reader owns authentication of this record.  This component
    only keeps the final ``libc.so`` identity connected to the product manifest
    instead of assuming matching source/member bytes identify a linked DSO.
    """
    artifact = mapping(report["artifacts"]["candidate-shared"], "ELF facts shared artifact")
    identity = mapping(artifact["identity"], "ELF facts shared identity")
    require_keys(identity, {"path", "sha256", "size", "mode"}, "ELF facts shared identity")
    return {
        "path": text(identity["path"], "ELF facts shared artifact path"),
        "sha256": sha256(identity["sha256"], "ELF facts shared artifact SHA-256"),
        "size": positive(identity["size"], "ELF facts shared artifact size"),
        "mode": nonnegative(identity["mode"], "ELF facts shared artifact mode"),
    }


def _validate_shared_product_manifest(
    value: object,
    shared_identity: Mapping[str, object],
) -> dict[str, object]:
    """Join authenticated shared facts to the selected dynamic product manifest.

    Product replay remains the caller's precondition.  This narrow join does
    not parse a whole sysroot: it validates only the stable manifest envelope
    and its authoritative ``usr/lib/libc.so`` digest.
    """
    manifest = mapping(value, "shared product manifest")
    require_keys(manifest, {"files", "format", "schema", "target"}, "shared product manifest")
    require(type(manifest["schema"]) is int and manifest["schema"] == DYNAMIC_PRODUCT_MANIFEST_SCHEMA,
            "shared product manifest schema differs")
    require(manifest["format"] == DYNAMIC_PRODUCT_MANIFEST_FORMAT,
            "shared product manifest format differs")
    require(manifest["target"] == TARGET, "shared product manifest target differs")
    files = mapping(manifest["files"], "shared product manifest files")
    manifest_libc_sha256 = sha256(files.get(DYNAMIC_PRODUCT_LIBC_PATH), "shared product manifest libc.so SHA-256")
    require(manifest_libc_sha256 == shared_identity["sha256"],
            "shared artifact identity differs from shared product manifest libc.so")
    return {
        "manifest_libc_so_path": DYNAMIC_PRODUCT_LIBC_PATH,
        "manifest_libc_so_sha256": manifest_libc_sha256,
        "elf_facts_identity": dict(shared_identity),
    }


def _named_row(rows: Sequence[Mapping[str, Any]], name: str, description: str) -> dict[str, Any]:
    result = [dict(row) for row in rows if row.get("name") == name]
    require(len(result) == 1, f"{description} must contain exactly one {name} row")
    require(result[0].get("section_index") != "UND", f"{description} {name} is not a definition")
    return result[0]


def _symbol_metadata(row: Mapping[str, Any], expected: Mapping[str, str], description: str) -> dict[str, Any]:
    name = text(row.get("name"), f"{description} name")
    require(row.get("raw_name") == name, f"{description} raw name differs")
    require(row.get("version") is None and row.get("version_default") is False, f"{description} version differs")
    require(row.get("type") == expected["type"], f"{description} type differs")
    require(row.get("binding") == expected["binding"], f"{description} binding differs")
    require(row.get("visibility") == expected["visibility"], f"{description} visibility differs")
    require(type(row.get("section_index")) is str and row["section_index"] not in {"", "UND"},
            f"{description} section differs")
    size = nonnegative(row.get("size_bytes"), f"{description} size")
    require(row.get("size") == str(size), f"{description} size spelling differs")
    return {
        "type": row["type"],
        "binding": row["binding"],
        "visibility": row["visibility"],
        "size_bytes": size,
        "section_index": row["section_index"],
        "definition": "defined",
    }


def _defining_section(
    member: Mapping[str, Any], row: Mapping[str, Any], description: str,
) -> dict[str, Any]:
    """Return one real section in this ELF placement's section domain.

    A complete-ELF symbol row can spell special indexes such as ``UND``,
    ``ABS``, or ``COM``.  Those spellings, section zero, and a stale numeric
    index are not a defining section for one of this finite producer's C
    definitions.  Keep this join local to the two authenticated placement
    domains instead of treating a matching symbol row as sufficient evidence
    of a body or object placement.
    """
    section_index = text(row.get("section_index"), f"{description} section index")
    require(re.fullmatch(r"[1-9][0-9]*", section_index) is not None,
            f"{description} defining section is not a positive numeric index")
    sections = member.get("sections")
    require(type(sections) is list, f"{description} sections are not a list")
    index = int(section_index)
    matches = [
        mapping(section, f"{description} section")
        for section in sections
        if type(section) is dict
        and type(section.get("index")) is int
        and section["index"] == index
    ]
    require(len(matches) == 1, f"{description} defining section is absent or duplicated")
    return matches[0]


def _function_defining_section(
    member: Mapping[str, Any], row: Mapping[str, Any], description: str,
) -> dict[str, Any]:
    """Require a selected C function to resolve to executable machine code."""
    section = _defining_section(member, row, description)
    flags = text(section.get("flags"), f"{description} defining section flags")
    require("X" in flags, f"{description} defining section is not executable")
    return section


def _section_alignment(member: Mapping[str, Any], row: Mapping[str, Any], description: str) -> int:
    section = _defining_section(member, row, description)
    return positive(section.get("alignment"), f"{description} section alignment")


def _symbol_value_alignment(
    row: Mapping[str, Any],
    required_alignment: int,
    description: str,
) -> dict[str, object]:
    """Check the ELF symbol value itself, including TLS-relative offsets.

    For a TLS symbol, ``st_value`` is an offset in its TLS block.  The same
    modulo test applies directly; subtracting the virtual address of ``.tdata``
    would turn that source-defined offset into an unrelated calculation.
    """
    value = text(row.get("value"), f"{description} symbol value")
    require(re.fullmatch(r"[0-9a-f]{16}", value) is not None,
            f"{description} symbol value spelling differs")
    numeric = int(value, 16)
    require(numeric % required_alignment == 0,
            f"symbol value alignment differs for {description}")
    return {
        "hex": value,
        "integer": numeric,
        "source_required_alignment": required_alignment,
        "modulo_source_required_alignment": numeric % required_alignment,
    }


def _validate_metadata_rows(
    contract: Mapping[str, Any],
    members: Sequence[str],
    c_member: Mapping[str, Any],
    shared: Mapping[str, Any],
) -> dict[str, Any]:
    c_rows = _symbol_tables(c_member.get("symbol_tables"), "static C provider", {".symtab"})[".symtab"]
    shared_tables = _symbol_tables(shared.get("symbol_tables"), "shared libc", {".dynsym", ".symtab"})
    shared_rows = shared_tables[".symtab"]
    dynsym_rows = shared_tables[".dynsym"]
    expected_names = set(members)
    provider_names = {row.get("name") for row in c_rows if row.get("name") in expected_names}
    shared_names = {row.get("name") for row in shared_rows if row.get("name") in expected_names}
    require(provider_names == expected_names, "static provider roster differs from exact hidden member list")
    require(shared_names == expected_names, "shared local provider roster differs from exact hidden member list")
    leaked = sorted({row.get("name") for row in dynsym_rows if row.get("name") in expected_names})
    require(not leaked, f"shared dynsym exposes private C producer names: {leaked}")

    metadata = contract["metadata"]
    weak = metadata["weak_null_fallback"]
    data = {item["name"]: item for item in metadata["data_objects"]}
    tls = metadata["tls_object"]
    special = {weak["name"], *data, tls["name"]}
    strong_names = [name for name in members if name not in special]
    require(len(strong_names) == 419, "strong function bucket count differs")

    strong_records: list[dict[str, Any]] = []
    for name in strong_names:
        static_row = _named_row(c_rows, name, "static C provider")
        shared_source_row = _named_row(shared_rows, name, "shared local provider")
        static = _symbol_metadata(static_row, metadata["strong_functions"]["static"],
                                  f"static strong function {name}")
        shared_row = _symbol_metadata(shared_source_row, metadata["strong_functions"]["shared"],
                                      f"shared strong function {name}")
        _function_defining_section(c_member, static_row, f"static strong function {name}")
        _function_defining_section(shared, shared_source_row, f"shared strong function {name}")
        require(static["size_bytes"] > 0 and shared_row["size_bytes"] > 0,
                f"strong function {name} has an empty definition")
        strong_records.append({"name": name, "static": static, "shared": shared_row})

    weak_static_row = _named_row(c_rows, weak["name"], "static weak null fallback")
    weak_shared_source_row = _named_row(shared_rows, weak["name"], "shared weak null fallback")
    weak_static = _symbol_metadata(weak_static_row, weak["static"], "static weak null fallback")
    weak_shared = _symbol_metadata(weak_shared_source_row, weak["shared"], "shared weak null fallback")
    _function_defining_section(c_member, weak_static_row, "static weak null fallback")
    _function_defining_section(shared, weak_shared_source_row, "shared weak null fallback")
    require(weak_static["size_bytes"] > 0 and weak_shared["size_bytes"] > 0,
            "weak null fallback has an empty definition")

    data_records: list[dict[str, Any]] = []
    for name in EXPECTED_DATA_OBJECTS:
        item = data[name]
        static_row = _named_row(c_rows, name, "static C data provider")
        shared_row = _named_row(shared_rows, name, "shared C data provider")
        static_metadata = _symbol_metadata(static_row, item["static"], f"static data {name}")
        shared_metadata = _symbol_metadata(shared_row, item["shared"], f"shared data {name}")
        require(
            static_metadata["size_bytes"] == item["size_bytes"]
            and shared_metadata["size_bytes"] == item["size_bytes"],
            f"data layout differs for {name}",
        )
        source_alignment = item["source"]["source_required_alignment"]
        static_alignment = _section_alignment(c_member, static_row, f"static data {name}")
        shared_alignment = _section_alignment(shared, shared_row, f"shared data {name}")
        require(static_alignment == item["producer"]["static_section_alignment"], f"data layout differs for {name}")
        require(shared_alignment >= source_alignment, f"data layout differs for {name}")
        data_records.append({
            "name": name,
            "static": static_metadata,
            "shared": shared_metadata,
            "layout": {
                "size_bytes": item["size_bytes"],
                "source": item["source"],
                "producer": item["producer"],
                "static_section_alignment": static_alignment,
                "shared_section_alignment": shared_alignment,
                "shared_source_minimum_alignment": source_alignment,
                "static_symbol_value": _symbol_value_alignment(
                    static_row, source_alignment, f"static data {name}"
                ),
                "shared_symbol_value": _symbol_value_alignment(
                    shared_row, source_alignment, f"shared data {name}"
                ),
            },
        })

    tls_static_row = _named_row(c_rows, tls["name"], "static C TLS provider")
    tls_shared_row = _named_row(shared_rows, tls["name"], "shared C TLS provider")
    tls_static = _symbol_metadata(tls_static_row, tls["static"], f"static TLS {tls['name']}")
    tls_shared = _symbol_metadata(tls_shared_row, tls["shared"], f"shared TLS {tls['name']}")
    require(
        tls_static["size_bytes"] == tls["size_bytes"] and tls_shared["size_bytes"] == tls["size_bytes"],
        f"TLS layout differs for {tls['name']}",
    )
    tls_source_alignment = tls["source"]["source_required_alignment"]
    tls_static_alignment = _section_alignment(c_member, tls_static_row, f"static TLS {tls['name']}")
    tls_shared_alignment = _section_alignment(shared, tls_shared_row, f"shared TLS {tls['name']}")
    require(tls_static_alignment == tls["producer"]["static_section_alignment"], f"TLS layout differs for {tls['name']}")
    require(tls_shared_alignment >= tls_source_alignment, f"TLS layout differs for {tls['name']}")

    return {
        "strong-functions": {
            "count": len(strong_records),
            "members": strong_records,
            "static_expected": metadata["strong_functions"]["static"],
            "shared_expected": metadata["strong_functions"]["shared"],
        },
        "weak-null-fallback": {
            "count": 1,
            "members": [{
                "name": weak["name"],
                "static": weak_static,
                "shared": weak_shared,
                "source": contract["source_provenance"]["weak_fallback_source"],
                "source_semantics": weak["source_semantics"],
            }],
        },
        "data-objects": {"count": len(data_records), "members": data_records},
        "initial-exec-tls": {
            "count": 1,
            "members": [{
                "name": tls["name"],
                "static": tls_static,
                "shared": tls_shared,
                "layout": {
                    "size_bytes": tls["size_bytes"],
                    "source": tls["source"],
                    "producer": tls["producer"],
                    "static_section_alignment": tls_static_alignment,
                    "shared_section_alignment": tls_shared_alignment,
                    "shared_source_minimum_alignment": tls_source_alignment,
                    "static_symbol_value": _symbol_value_alignment(
                        tls_static_row, tls_source_alignment, f"static TLS {tls['name']}"
                    ),
                    "shared_symbol_value": _symbol_value_alignment(
                        tls_shared_row, tls_source_alignment, f"shared TLS {tls['name']}"
                    ),
                },
            }],
        },
    }


def _rust_member_rows(rust_members: Sequence[Mapping[str, Any]]) -> list[list[dict[str, Any]]]:
    return [_symbol_tables(member.get("symbol_tables"), "static Rust member", {".symtab"})[".symtab"]
            for member in rust_members]


def _rust_references(member_rows: Sequence[Sequence[Mapping[str, Any]]], name: str,
                     description: str) -> list[dict[str, Any]]:
    """Return one undefined reference row per Rust member that names `name`."""
    references: list[dict[str, Any]] = []
    for rows in member_rows:
        matching = [dict(row) for row in rows if row.get("name") == name]
        require(len(matching) <= 1, f"static Rust member {description} repeats {name}")
        references.extend(matching)
    require(references, f"no static Rust member has the {description} {name}")
    return references


def _validate_rust_root_imports(
    contract: Mapping[str, Any],
    members: Sequence[str],
    rust_members: Sequence[Mapping[str, Any]],
    c_member: Mapping[str, Any],
    shared: Mapping[str, Any],
) -> list[dict[str, Any]]:
    member_rows = _rust_member_rows(rust_members)
    c_rows = _symbol_tables(c_member.get("symbol_tables"), "static C provider", {".symtab"})[".symtab"]
    shared_rows = _symbol_tables(shared.get("symbol_tables"), "shared libc", {".dynsym", ".symtab"})[".symtab"]
    imports = contract["rust_root_imports"]["names"]
    references = contract["rust_root_data_references"]["names"]
    observed_names = {
        row.get("name") for rows in member_rows for row in rows
        if row.get("name") in set(members) and row.get("section_index") == "UND"
    }
    require(observed_names == set(imports) | set(references), "Rust-root import roster differs")
    joins: list[dict[str, Any]] = []
    for name in imports:
        for import_row in _rust_references(member_rows, name, "import"):
            require(
                import_row.get("section_index") == "UND"
                and import_row.get("type") == "NOTYPE"
                and import_row.get("binding") == "GLOBAL"
                and import_row.get("visibility") == "DEFAULT"
                and import_row.get("version") is None
                and import_row.get("version_default") is False
                and import_row.get("size_bytes") == 0
                and import_row.get("size") == "0",
                f"Rust-root import metadata differs for {name}",
            )
        provider = _symbol_metadata(
            _named_row(c_rows, name, "static C provider for Rust-root import"),
            contract["metadata"]["strong_functions"]["static"],
            f"static C provider for Rust-root import {name}",
        )
        final = _symbol_metadata(
            _named_row(shared_rows, name, "shared final C provider for Rust-root import"),
            contract["metadata"]["strong_functions"]["shared"],
            f"shared final C provider for Rust-root import {name}",
        )
        joins.append({
            "name": name,
            "static_rust_import": {
                "type": import_row["type"],
                "binding": import_row["binding"],
                "visibility": import_row["visibility"],
                "section_index": import_row["section_index"],
            },
            "static_c_provider": provider,
            "shared_c_final_provider": final,
        })
    return joins


def _validate_rust_root_data_references(
    contract: Mapping[str, Any],
    rust_members: Sequence[Mapping[str, Any]],
    c_member: Mapping[str, Any],
    shared: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Join each Rust address reference to its C data-object provider."""
    member_rows = _rust_member_rows(rust_members)
    c_rows = _symbol_tables(c_member.get("symbol_tables"), "static C provider", {".symtab"})[".symtab"]
    shared_rows = _symbol_tables(shared.get("symbol_tables"), "shared libc", {".dynsym", ".symtab"})[".symtab"]
    data = {item["name"]: item for item in contract["metadata"]["data_objects"]}
    joins: list[dict[str, Any]] = []
    for name in contract["rust_root_data_references"]["names"]:
        for reference in _rust_references(member_rows, name, "data reference"):
            require(
                reference.get("section_index") == "UND"
                and reference.get("type") == "NOTYPE"
                and reference.get("binding") == "GLOBAL"
                and reference.get("visibility") == "DEFAULT"
                and reference.get("version") is None
                and reference.get("version_default") is False
                and reference.get("size_bytes") == 0,
                f"Rust-root data reference metadata differs for {name}",
            )
        joins.append({
            "name": name,
            "static_rust_reference": {
                "type": reference["type"],
                "binding": reference["binding"],
                "visibility": reference["visibility"],
                "section_index": reference["section_index"],
            },
            "static_c_provider": _symbol_metadata(
                _named_row(c_rows, name, "static C provider for Rust-root data reference"),
                data[name]["static"],
                f"static C provider for Rust-root data reference {name}",
            ),
            "shared_c_final_provider": _symbol_metadata(
                _named_row(shared_rows, name, "shared final C provider for Rust-root data reference"),
                data[name]["shared"],
                f"shared final C provider for Rust-root data reference {name}",
            ),
        })
    return joins


def account_producer_metadata(
    elf_facts: Mapping[str, Any],
    static_provenance: Mapping[str, Any],
    shared_provenance: Mapping[str, Any],
    shared_product_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Account exactly the private fixed-C producer obligations.

    Preconditions: elf_facts was authenticated by native_abi_elf_facts and
    each provenance mapping and the dynamic manifest came from the corresponding
    owned product. This function does not replay those larger receipts or choose
    a public provider.  The caller must authenticate the manifest/product join
    with the owning product reader before invoking this pure account.
    """
    contract = load_contract()
    members = contract_members(contract)
    (
        static_archive_sha256,
        producer_archive_sha256,
        c_member_name,
        rust_member_names,
        static_members,
    ) = _validate_static_provenance(
        static_provenance, contract
    )
    report = _validate_elf_facts(elf_facts, static_archive_sha256)
    shared_artifact = _validate_shared_product_manifest(
        shared_product_manifest, _shared_artifact_identity(report)
    )
    shared_rust_member, shared_members = _validate_shared_provenance(
        shared_provenance, contract, c_member_name, static_members[c_member_name], report, shared_product_manifest
    )
    c_member, rust_members = _static_members(report, static_members, c_member_name, rust_member_names)
    shared = mapping(report["facts"]["candidate-shared"], "shared ELF facts")
    buckets = _validate_metadata_rows(contract, members, c_member, shared)
    joins = _validate_rust_root_imports(contract, members, rust_members, c_member, shared)
    data_references = _validate_rust_root_data_references(contract, rust_members, c_member, shared)
    strong_names = {record["name"] for record in buckets["strong-functions"]["members"]}
    require(all(item["name"] in strong_names for item in joins),
            "Rust-root imports do not resolve through strong C providers")
    return {
        "schema": SCHEMA,
        "target": TARGET,
        "status": "component-pass-not-qualification",
        "status_flags": dict(contract["status_flags"]),
        "source_authority": {
            "backend": contract["backend"],
            "source_provenance": {
                "members_file": contract["source_provenance"]["members_file"],
                "members_sha256": contract["source_provenance"]["members_sha256"],
                "members_count": contract["source_provenance"]["members_count"],
                "upstream_sources_sha256": contract["source_provenance"]["upstream_sources_sha256"],
                "upstream_source_count": contract["source_provenance"]["upstream_source_count"],
                "project_header_sources_sha256": contract["source_provenance"]["project_header_sources_sha256"],
                "project_header_source_count": contract["source_provenance"]["project_header_source_count"],
                "static_translation_unit": contract["source_provenance"]["static_translation_unit"],
                "public_header": contract["source_provenance"]["public_header"],
                "weak_fallback_source": contract["source_provenance"]["weak_fallback_source"],
            },
            "build": contract["build"],
            "shared_localization": contract["shared_localization"],
        },
        "scope": {
            "member_count": len(members),
            "metadata_buckets": {name: buckets[name]["count"] for name in (
                "strong-functions", "weak-null-fallback", "data-objects", "initial-exec-tls"
            )},
            "rust_root_c_imports": len(joins),
            "shared_dynsym_private_names": "absent",
        },
        "archive_map": {
            "raw_cargo_allocator_archive_sha256": producer_archive_sha256,
            "reconstructed_static_libc_archive_sha256": static_archive_sha256,
            "static_c_member": c_member_name,
            "static_rust_members": rust_member_names,
            "shared_rust_root_member": shared_rust_member,
            "static_c_member_sha256": static_members[c_member_name],
            "shared_c_member_sha256": shared_members[c_member_name],
        },
        "fact_source": dict(report["collector_execution_source"]),
        "shared_product_binding": shared_artifact,
        "metadata_buckets": buckets,
        "rust_root_c_import_joins": joins,
        "rust_root_c_data_reference_joins": data_references,
        "boundaries": {
            **contract["boundaries"],
            "all_members_private_in_shared_dynsym": True,
            "allocator_family_completion": False,
            "allocator_promotion": False,
            "public_support": False,
        },
        "limits": [
            "Consumes already authenticated ELF facts and owned-product provenance; it does not replay either source receipt.",
            "Public malloc ABI, interposition, and runtime behavior are separate components.",
            "The seven Rust-root C joins are retained producer observations; their separate selection closure needs an installed consumer/map component.",
            "The fixed mimalloc v3.5.0 Rust-port oracle is distinct from this selected v3.3.2 C backend.",
            "A qualified Rust-backend promotion removes this C producer contract instead of transferring its metadata to Rust.",
        ],
    }


def _strict_json(path: Path, description: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ProducerMetadataError(f"{description} contains a duplicate JSON key {key}")
            result[key] = value
        return result

    try:
        raw = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ProducerMetadataError(f"{description} contains invalid JSON constant {value}")
            ),
        )
    except (OSError, json.JSONDecodeError) as error:
        raise ProducerMetadataError(f"cannot read {description}: {error}") from error
    return mapping(raw, description)


def _collector_identity() -> dict[str, object]:
    sources = {
        path.relative_to(ROOT).as_posix(): physical_identity(path, "producer collector source")
        for path in (Path(__file__).resolve(), CONTRACT_PATH, HIDDEN_LIST,
                     *(ROOT / relative for relative in compiler_helpers.SOURCE_FILES))
    }
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=False, capture_output=True, text=True)
    tree = subprocess.run(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, check=False, capture_output=True, text=True)
    status = subprocess.run(["git", "status", "--short"], cwd=ROOT, check=False, capture_output=True, text=True)
    require(revision.returncode == 0 and tree.returncode == 0 and status.returncode == 0,
            "cannot record producer collector source identity")
    return {
        "revision": revision.stdout.strip(),
        "tree": tree.stdout.strip(),
        "status": status.stdout,
        "sources": sources,
    }


def write_current_product_receipt(
    elf_facts_path: Path,
    static_provenance_path: Path,
    shared_provenance_path: Path,
    shared_manifest_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Bind one current product's authenticated inputs to this focused account."""
    require(output.parent.is_dir() and not output.parent.is_symlink(), "producer receipt output parent is invalid")
    require(not output.exists() and not output.is_symlink(), "producer receipt output already exists")
    inputs_before = {
        "elf_facts": physical_identity(elf_facts_path, "ELF facts report"),
        "static_provenance": physical_identity(static_provenance_path, "static provenance"),
        "shared_provenance": physical_identity(shared_provenance_path, "shared provenance"),
        "shared_manifest": physical_identity(shared_manifest_path, "shared product manifest"),
    }
    account = account_producer_metadata(
        _strict_json(elf_facts_path, "ELF facts report"),
        _strict_json(static_provenance_path, "static provenance"),
        _strict_json(shared_provenance_path, "shared provenance"),
        _strict_json(shared_manifest_path, "shared product manifest"),
    )
    inputs_after = {
        "elf_facts": physical_identity(elf_facts_path, "ELF facts report"),
        "static_provenance": physical_identity(static_provenance_path, "static provenance"),
        "shared_provenance": physical_identity(shared_provenance_path, "shared provenance"),
        "shared_manifest": physical_identity(shared_manifest_path, "shared product manifest"),
    }
    require(same(inputs_before, inputs_after), "producer receipt inputs changed during accounting")
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "status": "component-pass-not-qualification",
        "collector": _collector_identity(),
        "inputs": {"before": inputs_before, "after": inputs_after},
        "account": account,
        "limits": [
            "Input product authentication and source freshness are preconditions owned by the existing ELF and product readers; the shared manifest binds final libc.so bytes to the selected dynamic product.",
            "This receipt adds fixed-C producer metadata and archive/provider joins without creating another product builder or generic receipt framework.",
        ],
    }
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf-facts", type=Path, required=True)
    parser.add_argument("--static-provenance", type=Path, required=True)
    parser.add_argument("--shared-provenance", type=Path, required=True)
    parser.add_argument("--shared-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        write_current_product_receipt(
            args.elf_facts,
            args.static_provenance,
            args.shared_provenance,
            args.shared_manifest,
            args.output,
        )
    except ProducerMetadataError as error:
        print(f"fixed-C mimalloc producer metadata: {error}", file=sys.stderr)
        return 1
    print(f"fixed-C mimalloc producer metadata: PASS; evidence: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
