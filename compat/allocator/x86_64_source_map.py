#!/usr/bin/env python3
"""Validate the pinned Linux/x86-64 mimalloc engine source-map ratchet.

This is deliberately a source-provenance instrument, not an implementation
or behavior oracle.  It maps only reviewed source scopes to the current Rust
engine modules and keeps the x86-64 profile explicitly incomplete.  It never
reads the AArch64 port map or its ratchet.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat/allocator/x86_64-source-map-v3.5.0.json"
UPSTREAMS_PATH = ROOT / "compat/upstreams.toml"
DEFAULT_ARCHIVE_PATH = ROOT / "compat/allocator/.cache/mimalloc-3.5.0.tar.gz"
RESULT_SCOPE = (
    "Pinned source mapping and ratchet validation only; it does not establish "
    "behavioral parity, public C allocator API, or runtime integration."
)

TARGET_CONTEXT = {
    "architecture": "x86_64",
    "endianness": "little",
    "rust_target": "x86_64-unknown-linux-musl",
    "system": "linux",
}
VALID_STATUSES = frozenset({"implemented", "partial", "not-started", "inapplicable"})

# This is a reviewed inventory of source units relevant to the fixed engine
# profile.  Platform sources that cannot participate in Linux/x86-64 are not
# silently represented as missing port work; `static.c` and `track.h` have
# explicit inapplicable rows in the checked-in map instead.
REQUIRED_SOURCE_MEMBERS = (
    "include/mimalloc.h",
    "include/mimalloc-stats.h",
    "include/mimalloc/track.h",
    "include/mimalloc/bits.h",
    "include/mimalloc/atomic.h",
    "include/mimalloc/types.h",
    "include/mimalloc/internal.h",
    "include/mimalloc/prim.h",
    "include/mimalloc/prim-tls.h",
    "src/alloc.c",
    "src/alloc-aligned.c",
    "src/alloc-posix.c",
    "src/alloc-override.c",
    "src/free.c",
    "src/arena.c",
    "src/bitmap.c",
    "src/bitmap.h",
    "src/heap.c",
    "src/init.c",
    "src/libc.c",
    "src/options.c",
    "src/os.c",
    "src/page-map.c",
    "src/page-queue.c",
    "src/page.c",
    "src/random.c",
    "src/stats.c",
    "src/static.c",
    "src/subproc.c",
    "src/theap.c",
    "src/threadlocal.c",
    "src/prim/prim.c",
    "src/prim/prim-tls.c",
    "src/prim/unix/prim.c",
)

REQUIRED_UNIT_IDS = (
    "public-c-api-surface",
    "statistics-types-and-api",
    "tracking-hooks",
    "x86-64-width-and-bit-operations",
    "atomic-operation-facade",
    "core-layouts-and-configuration",
    "internal-engine-invariants",
    "primitive-interface",
    "tls-interface-and-thread-identity",
    "ordinary-allocation-paths",
    "aligned-allocation-paths",
    "posix-allocation-extensions",
    "allocator-interposition",
    "local-and-remote-free",
    "arena-lifecycle",
    "bitmap-algorithms",
    "bitmap-layout",
    "heap-lifecycle",
    "process-and-thread-initialization",
    "c-support-and-once",
    "option-processing",
    "os-allocation-policy",
    "page-map-lifecycle",
    "page-queue-kernels",
    "page-lifecycle",
    "random-state",
    "statistics-collection",
    "static-c-amalgamation",
    "subprocess-lifecycle",
    "thread-local-heap-lifecycle",
    "thread-local-storage-lifecycle",
    "platform-primitive-dispatch",
    "platform-tls-roots",
    "linux-unix-primitives",
)

# This external floor makes the source-map ratchet monotonic: changing the
# checked-in JSON's self-hash cannot erase a source scope already reviewed as
# implemented. New implemented scopes still require an explicit validator-code
# review through `IMPLEMENTED_SOURCE_REQUIREMENTS` below and a deliberate
# expansion of this baseline.
REQUIRED_IMPLEMENTED_UNIT_IDS = (
    "x86-64-width-and-bit-operations",
    "bitmap-algorithms",
    "bitmap-layout",
)

# An `implemented` source scope is deliberately rare.  The source map itself
# cannot prove a whole allocator, so only reviewed scalar scopes may use the
# stronger word. Bitmap native execution belongs to its M2 fragment/gate.
# The required definitions make the source claim concrete: a range containing
# only architecture/configuration macros cannot also claim the Rust bit helpers.
IMPLEMENTED_SOURCE_REQUIREMENTS = {
    "x86-64-width-and-bit-operations": {
        "member": "include/mimalloc/bits.h",
        "required_definitions": (
            b"static inline size_t mi_popcount",
            b"static inline size_t mi_ctz",
            b"static inline size_t mi_clz",
            b"static inline bool mi_bsf",
            b"static inline bool mi_bsr",
            b"static inline size_t mi_rotr",
            b"static inline size_t mi_rotl",
            b"static inline uint32_t mi_rotl32",
        ),
    },
    "bitmap-algorithms": {
        "member": "src/bitmap.c", "minimum_start_line": 26, "minimum_end_line": 1997,
        "required_definitions": (
            b"mi_bfield_atomic_clear_once_set", b"mi_bchunk_try_clearNC",
            b"mi_bitmap_setN", b"mi_bitmap_popcountN", b"mi_bitmap_try_find_and_claim_visit",
            b"_mi_bitmap_forall_set", b"_mi_bitmap_forall_setc_rangesn",
            b"mi_bbitmap_set_chunk_bin", b"mi_subproc_stat_increase",
            b"mi_subproc_stat_decrease", b"mi_subproc_stat_counter_increase",
            b"mi_bbitmap_try_find_and_clearN_",
        ),
    },
    "bitmap-layout": {
        "member": "src/bitmap.h", "minimum_start_line": 1, "minimum_end_line": 340,
        "required_definitions": (
            b"mi_bfield_t", b"mi_bchunk_t", b"mi_bitmap_t", b"mi_bbitmap_t",
            b"mi_bbitmap_try_find_and_clearN",
        ),
    },
}

EXPECTED_TOP_LEVEL_FIELDS = {
    "boundary",
    "format",
    "kind",
    "maturity",
    "overall",
    "profile",
    "ratchet",
    "source",
    "status_model",
    "target_context",
    "units",
    "upstream",
}
EXPECTED_BOUNDARY = {
    "native_execution": "not-assessed",
    "public_c_api": "excluded",
    "public_runtime_integration": "excluded",
    "source_map_scope": "private-engine-evidence-only",
}
MODULE_PATTERN = re.compile(r"crabc_mimalloc::([a-z][a-z0-9_]*)\Z")
HEX_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class SourceMapError(RuntimeError):
    """The checked-in x86-64 source-map contract is malformed or stale."""


def sha256_bytes(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def canonical_sha256(value: object) -> str:
    return sha256_bytes(
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
    )


def source_line_count(contents: bytes) -> int:
    if not contents:
        return 0
    return contents.count(b"\n") + (0 if contents.endswith(b"\n") else 1)


def source_range(contents: bytes, start_line: int, end_line: int) -> bytes:
    lines = contents.splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise SourceMapError(
            f"source anchor {start_line}-{end_line} is outside a {len(lines)}-line member"
        )
    return b"".join(lines[start_line - 1 : end_line])


def load_mimalloc_pin() -> dict[str, str]:
    try:
        upstreams = tomllib.loads(UPSTREAMS_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise SourceMapError(f"missing upstream pin file: {UPSTREAMS_PATH}") from error
    mimalloc = upstreams.get("mimalloc")
    if not isinstance(mimalloc, dict):
        raise SourceMapError("compat/upstreams.toml has no [mimalloc] table")

    required = ("archive_root", "revision", "sha256", "version")
    pin: dict[str, str] = {}
    for key in required:
        value = mimalloc.get(key)
        if not isinstance(value, str) or not value:
            raise SourceMapError(f"mimalloc pin is missing a string {key}")
        pin[key] = value
    if pin["version"] != "3.5.0" or pin["archive_root"] != "mimalloc-3.5.0":
        raise SourceMapError("x86-64 source map is fixed to the mimalloc v3.5.0 archive")
    if not re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]):
        raise SourceMapError("mimalloc archive checksum is not lowercase SHA-256")
    if not re.fullmatch(r"[0-9a-f]{40}", pin["revision"]):
        raise SourceMapError("mimalloc revision is not a lowercase commit identity")
    return pin


def load_contract() -> dict[str, Any]:
    try:
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise SourceMapError(f"missing checked-in x86-64 source map: {CONTRACT_PATH}") from error
    if not isinstance(contract, dict):
        raise SourceMapError("x86-64 source map must be a JSON object")
    return contract


def source_members_from_contract(contract: Mapping[str, Any]) -> tuple[str, ...]:
    source = contract.get("source")
    if not isinstance(source, dict):
        raise SourceMapError("x86-64 source map has no source record")
    records = source.get("members")
    if not isinstance(records, list):
        raise SourceMapError("x86-64 source map source.members must be a list")

    members: list[str] = []
    for record in records:
        if not isinstance(record, dict) or set(record) != {"line_count", "member", "sha256"}:
            raise SourceMapError("x86-64 source member record has an unsupported shape")
        member = record.get("member")
        if not isinstance(member, str):
            raise SourceMapError("x86-64 source member name is invalid")
        members.append(member)
    if tuple(members) != REQUIRED_SOURCE_MEMBERS:
        raise SourceMapError("x86-64 source map source-member inventory changed")
    return tuple(members)


def read_pinned_sources(
    archive_path: Path, pin: Mapping[str, str], members: tuple[str, ...]
) -> dict[str, bytes]:
    if not archive_path.is_file():
        raise SourceMapError(
            f"pinned mimalloc archive is unavailable: {archive_path}; run the native "
            "allocator oracle first to populate compat/allocator/.cache"
        )
    actual_archive_hash = sha256_bytes(archive_path.read_bytes())
    if actual_archive_hash != pin["sha256"]:
        raise SourceMapError(
            "mimalloc archive checksum mismatch: "
            f"expected {pin['sha256']}, got {actual_archive_hash}"
        )
    if len(members) != len(set(members)):
        raise SourceMapError("x86-64 source member list contains duplicates")

    sources: dict[str, bytes] = {}
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in members:
            archive_member = f"{pin['archive_root']}/{member}"
            matches = [entry for entry in archive.getmembers() if entry.name == archive_member]
            if len(matches) != 1 or not matches[0].isreg():
                raise SourceMapError(
                    f"pinned archive must contain one regular {archive_member} member"
                )
            stream = archive.extractfile(matches[0])
            if stream is None:
                raise SourceMapError(f"cannot read {archive_member} from pinned archive")
            sources[member] = stream.read()
    return sources


def require_string(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise SourceMapError(f"{description} must be a non-empty string")
    return value


def require_sha256(value: object, description: str) -> str:
    value = require_string(value, description)
    if not HEX_SHA256_PATTERN.fullmatch(value):
        raise SourceMapError(f"{description} must be lowercase SHA-256")
    return value


def validate_source_records(
    contract: Mapping[str, Any], pin: Mapping[str, str], sources: Mapping[str, bytes]
) -> list[dict[str, Any]]:
    source = contract.get("source")
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "members"}:
        raise SourceMapError("x86-64 source map source record changed")
    if source.get("archive_sha256") != pin["sha256"]:
        raise SourceMapError("x86-64 source map archive identity changed")
    records = source.get("members")
    if not isinstance(records, list):
        raise SourceMapError("x86-64 source map source.members is absent")
    if tuple(record.get("member") if isinstance(record, dict) else None for record in records) != REQUIRED_SOURCE_MEMBERS:
        raise SourceMapError("x86-64 source map source-member inventory changed")
    if set(sources) != set(REQUIRED_SOURCE_MEMBERS):
        raise SourceMapError("provided pinned source set does not match the x86-64 source inventory")

    normalized: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict) or set(record) != {"line_count", "member", "sha256"}:
            raise SourceMapError("x86-64 source member record has an unsupported shape")
        member = require_string(record.get("member"), "x86-64 source member")
        digest = require_sha256(record.get("sha256"), f"source hash for {member}")
        line_count = record.get("line_count")
        if not isinstance(line_count, int) or isinstance(line_count, bool) or line_count < 1:
            raise SourceMapError(f"source line count for {member} is invalid")
        contents = sources[member]
        expected = {
            "member": member,
            "sha256": sha256_bytes(contents),
            "line_count": source_line_count(contents),
        }
        if record != expected:
            raise SourceMapError(f"pinned source record drifted: {member}")
        normalized.append(expected)
    return normalized


def validate_rust_modules(value: object, unit_id: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(module, str) for module in value):
        raise SourceMapError(f"x86-64 source-map unit {unit_id} has invalid rust_modules")
    if value != sorted(set(value)):
        raise SourceMapError(f"x86-64 source-map unit {unit_id} rust_modules must be sorted and unique")
    for module in value:
        match = MODULE_PATTERN.fullmatch(module)
        if match is None:
            raise SourceMapError(f"x86-64 source-map unit {unit_id} has an invalid Rust module")
        module_path = ROOT / "crabc-mimalloc/src" / f"{match.group(1)}.rs"
        if not module_path.is_file():
            raise SourceMapError(
                f"x86-64 source-map unit {unit_id} names a missing Rust module: {module}"
            )
    return value


def validate_evidence(value: object, unit_id: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(path, str) for path in value):
        raise SourceMapError(f"x86-64 source-map unit {unit_id} has invalid evidence")
    if value != sorted(set(value)):
        raise SourceMapError(f"x86-64 source-map unit {unit_id} evidence must be sorted and unique")
    for relative_path in value:
        relative = Path(relative_path)
        candidate = ROOT / relative
        if relative.is_absolute() or ".." in relative.parts or not candidate.is_file():
            raise SourceMapError(
                f"x86-64 source-map unit {unit_id} evidence is not a workspace file: {relative_path}"
            )
    return value


def validate_units(
    contract: Mapping[str, Any], sources: Mapping[str, bytes]
) -> list[dict[str, Any]]:
    units = contract.get("units")
    if not isinstance(units, list):
        raise SourceMapError("x86-64 source map units must be a list")
    expected_fields = {
        "difference",
        "evidence",
        "id",
        "rust_modules",
        "source_anchor",
        "source_scope",
        "status",
    }
    normalized: list[dict[str, Any]] = []
    for unit in units:
        if not isinstance(unit, dict) or set(unit) != expected_fields:
            raise SourceMapError("x86-64 source-map unit has an unsupported shape")
        unit_id = require_string(unit.get("id"), "x86-64 source-map unit id")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", unit_id):
            raise SourceMapError(f"x86-64 source-map unit id is invalid: {unit_id}")
        source_scope = require_string(unit.get("source_scope"), f"source scope for {unit_id}")
        difference = require_string(unit.get("difference"), f"difference note for {unit_id}")
        status = unit.get("status")
        if status not in VALID_STATUSES:
            raise SourceMapError(f"x86-64 source-map unit {unit_id} has invalid status")
        anchor = unit.get("source_anchor")
        if not isinstance(anchor, dict) or set(anchor) != {
            "end_line",
            "member",
            "sha256",
            "start_line",
        }:
            raise SourceMapError(f"x86-64 source-map unit {unit_id} has invalid source anchor")
        member = require_string(anchor.get("member"), f"source member for {unit_id}")
        if member not in REQUIRED_SOURCE_MEMBERS:
            raise SourceMapError(f"x86-64 source-map unit {unit_id} points outside the source inventory")
        start_line = anchor.get("start_line")
        end_line = anchor.get("end_line")
        if (
            not isinstance(start_line, int)
            or isinstance(start_line, bool)
            or not isinstance(end_line, int)
            or isinstance(end_line, bool)
        ):
            raise SourceMapError(f"x86-64 source-map unit {unit_id} anchor lines are invalid")
        anchored_source = source_range(sources[member], start_line, end_line)
        actual_anchor_hash = sha256_bytes(anchored_source)
        if anchor.get("sha256") != actual_anchor_hash:
            raise SourceMapError(f"x86-64 source-map unit {unit_id} source anchor drifted")

        if status == "implemented":
            requirement = IMPLEMENTED_SOURCE_REQUIREMENTS.get(unit_id)
            if requirement is None:
                raise SourceMapError(
                    f"x86-64 source-map unit {unit_id} cannot claim implemented status before a reviewed ratchet expansion"
                )
            if member != requirement["member"]:
                raise SourceMapError(
                    f"x86-64 source-map unit {unit_id} has the wrong implemented source member"
                )
            if (start_line > requirement.get("minimum_start_line", start_line)
                    or end_line < requirement.get("minimum_end_line", end_line)):
                raise SourceMapError(f"x86-64 source-map unit {unit_id} shrank its reviewed source boundary")
            missing = [
                definition
                for definition in requirement["required_definitions"]
                if definition not in anchored_source
            ]
            if missing:
                raise SourceMapError(
                    f"x86-64 source-map unit {unit_id} does not anchor every claimed scalar helper"
                )

        modules = validate_rust_modules(unit.get("rust_modules"), unit_id)
        evidence = validate_evidence(unit.get("evidence"), unit_id)
        if status in {"partial", "implemented"} and (not modules or not evidence):
            raise SourceMapError(
                f"x86-64 source-map unit {unit_id} claims mapped work without Rust and evidence files"
            )
        if status in {"not-started", "inapplicable"} and (modules or evidence):
            raise SourceMapError(
                f"x86-64 source-map unit {unit_id} has an unstarted/inapplicable status with code evidence"
            )
        normalized.append(unit)

    if tuple(unit["id"] for unit in normalized) != REQUIRED_UNIT_IDS:
        raise SourceMapError("x86-64 source-map unit inventory changed")
    implemented_unit_ids = tuple(
        unit["id"] for unit in normalized if unit["status"] == "implemented"
    )
    if implemented_unit_ids != REQUIRED_IMPLEMENTED_UNIT_IDS:
        raise SourceMapError("x86-64 source-map implemented-status baseline changed")
    if tuple(unit["source_anchor"]["member"] for unit in normalized) != REQUIRED_SOURCE_MEMBERS:
        raise SourceMapError(
            "x86-64 source-map units must cover each reviewed source member exactly once"
        )
    return normalized


def status_counts(units: list[Mapping[str, Any]]) -> dict[str, int]:
    counts = Counter(str(unit["status"]) for unit in units)
    return {status: counts[status] for status in sorted(VALID_STATUSES)}


def validate_status_model(contract: Mapping[str, Any]) -> None:
    status_model = contract.get("status_model")
    if not isinstance(status_model, dict) or set(status_model) != VALID_STATUSES:
        raise SourceMapError("x86-64 source-map status model changed")
    for status, meaning in status_model.items():
        require_string(meaning, f"status-model meaning for {status}")

    overall = contract.get("overall")
    if not isinstance(overall, dict) or set(overall) != {"not_evidence", "reason", "status"}:
        raise SourceMapError("x86-64 source-map overall record changed")
    if overall.get("status") != "incomplete":
        raise SourceMapError(
            "a source map cannot claim x86-64 engine completion; retain overall.status=incomplete"
        )
    require_string(overall.get("reason"), "x86-64 source-map incomplete reason")
    not_evidence = overall.get("not_evidence")
    if (
        not isinstance(not_evidence, list)
        or not not_evidence
        or not all(isinstance(item, str) and item for item in not_evidence)
        or not_evidence != sorted(set(not_evidence))
    ):
        raise SourceMapError("x86-64 source-map not_evidence must be a sorted non-empty string list")


def validate_ratchet(
    contract: Mapping[str, Any], sources: list[dict[str, Any]], units: list[dict[str, Any]]
) -> None:
    ratchet = contract.get("ratchet")
    expected_fields = {
        "metadata_sha256",
        "source_member_count",
        "source_members_sha256",
        "status_counts",
        "unfinished_unit_count",
        "unit_count",
        "unit_ids_sha256",
        "units_sha256",
    }
    if not isinstance(ratchet, dict) or set(ratchet) != expected_fields:
        raise SourceMapError("x86-64 source-map ratchet changed")

    counts = status_counts(units)
    unfinished = sum(counts[status] for status in ("partial", "not-started"))
    metadata = {
        "boundary": contract["boundary"],
        "format": contract["format"],
        "kind": contract["kind"],
        "maturity": contract["maturity"],
        "overall": contract["overall"],
        "profile": contract["profile"],
        "status_model": contract["status_model"],
        "target_context": contract["target_context"],
        "upstream": contract["upstream"],
    }
    expected = {
        "metadata_sha256": canonical_sha256(metadata),
        "source_member_count": len(sources),
        "source_members_sha256": canonical_sha256(sources),
        "status_counts": counts,
        "unfinished_unit_count": unfinished,
        "unit_count": len(units),
        "unit_ids_sha256": sha256_bytes("\n".join(REQUIRED_UNIT_IDS).encode("utf-8")),
        "units_sha256": canonical_sha256(units),
    }
    if ratchet != expected:
        raise SourceMapError(
            "x86-64 source-map ratchet drifted; review the mapping and update its baseline deliberately"
        )
    if unfinished == 0:
        raise SourceMapError("x86-64 source map cannot have zero unfinished source scopes")


def validate_contract(contract: Mapping[str, Any], pin: Mapping[str, str], sources: Mapping[str, bytes]) -> None:
    if set(contract) != EXPECTED_TOP_LEVEL_FIELDS:
        raise SourceMapError("x86-64 source-map top-level schema changed")
    if contract.get("format") != 1:
        raise SourceMapError("unsupported x86-64 source-map format")
    if contract.get("kind") != "mimalloc-x86_64-engine-source-map":
        raise SourceMapError("x86-64 source-map kind changed")
    if contract.get("maturity") != "source-map-ratchet-foundation":
        raise SourceMapError("x86-64 source-map maturity changed")
    if contract.get("profile") != "linux-x86_64-mimalloc-engine-parity":
        raise SourceMapError("x86-64 source-map profile changed")
    if contract.get("target_context") != TARGET_CONTEXT:
        raise SourceMapError("x86-64 source-map target context changed")
    if contract.get("upstream") != {
        "archive_root": pin["archive_root"],
        "revision": pin["revision"],
        "version": pin["version"],
    }:
        raise SourceMapError("x86-64 source-map upstream identity changed")
    if contract.get("boundary") != EXPECTED_BOUNDARY:
        raise SourceMapError("x86-64 source-map boundary changed")

    validate_status_model(contract)
    normalized_sources = validate_source_records(contract, pin, sources)
    normalized_units = validate_units(contract, sources)
    validate_ratchet(contract, normalized_sources, normalized_units)


def checked_contract_result(archive_path: Path) -> dict[str, object]:
    """Validate the checked-in map and return only its bounded evidence result.

    Callers can include this record in a larger native-oracle report without
    treating a source map as execution, behavioral, public-API, or runtime
    integration evidence.  This helper never writes a contract or ratchet.
    """

    pin = load_mimalloc_pin()
    contract = load_contract()
    sources = read_pinned_sources(
        archive_path,
        pin,
        source_members_from_contract(contract),
    )
    validate_contract(contract, pin, sources)
    ratchet = contract["ratchet"]
    assert isinstance(ratchet, dict)
    target = contract["target_context"]
    assert isinstance(target, dict)
    status_counts = ratchet["status_counts"]
    assert isinstance(status_counts, dict)
    return {
        "contract": {
            "path": CONTRACT_PATH.relative_to(ROOT).as_posix(),
            "sha256": sha256_bytes(CONTRACT_PATH.read_bytes()),
        },
        "overall_status": contract["overall"]["status"],
        "profile": contract["profile"],
        "scope": RESULT_SCOPE,
        "source_member_count": ratchet["source_member_count"],
        "status": "passed",
        "status_counts": dict(status_counts),
        "target": dict(target),
        "unit_count": ratchet["unit_count"],
        "unfinished_unit_count": ratchet["unfinished_unit_count"],
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive",
        type=Path,
        default=DEFAULT_ARCHIVE_PATH,
        help="path to the SHA-256-pinned mimalloc v3.5.0 archive",
    )
    parser.add_argument(
        "--print-source-records",
        action="store_true",
        help="print verified source member hashes and line counts for reviewed contract updates",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    pin = load_mimalloc_pin()
    contract = load_contract()
    members = source_members_from_contract(contract)
    sources = read_pinned_sources(arguments.archive, pin, members)
    if arguments.print_source_records:
        records = [
            {
                "member": member,
                "sha256": sha256_bytes(sources[member]),
                "line_count": source_line_count(sources[member]),
            }
            for member in members
        ]
        print(json.dumps(records, indent=2))
        return 0
    validate_contract(contract, pin, sources)
    print("allocator x86_64 source-map ratchet: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SourceMapError as error:
        raise SystemExit(f"allocator x86_64 source-map ratchet: FAIL: {error}")
