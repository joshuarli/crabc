#!/usr/bin/env python3
"""Read and replay retained native x86-64 C-performance evidence.

This module deliberately has no execution entry point.  ``run_x86_64.py``
uses it while it has the pinned native image and its supplied dynamic product;
``check`` uses the same readers after that container has gone away.  The latter
therefore rehashes retained inputs and parses saved ELF/tool output instead of
silently requiring a host linker, musl tree, or native execution facility.

The native adapter compares objects compiled once with installed headers.  The
candidate and musl links are intentionally different provider products, so a
byte-for-byte executable comparison would be false evidence.  This reader
instead seals the shared object hashes and the declared ELF/runtime contract:
binding, hash style, direct ``DT_NEEDED`` edges, full application-DSO closure,
search path, runtime inventory, and the captured raw observations.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import re
import stat
import struct
import sys
from functools import lru_cache
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import x86_64_profile as performance_profile
import x86_64_peers as peers


SCHEMA = 1
KIND = "crabc-native-x86_64-c-performance"
SOURCE_MOUNT = "/workspace"
MUSL_VERSION = "1.2.6"
CPU_RESAMPLES = 10_000
FULL_SAMPLE_COUNT = 31
FULL_WARMUP_COUNT = 3
COLLECTOR_ATTEMPTS = 3
ROSTER_SCHEMA = "crabc.native-x86_64-c-performance-roster/v1"
ROSTER_KIND = "crabc-native-x86_64-c-performance-roster"
FIXED_MUSL_COMPILER = "/usr/local/bin/crabc-x86_64-musl-gcc"
FIXED_READELF = "/usr/bin/readelf"
FIXED_STRACE = "/usr/bin/strace"
FIXED_MUSL_LOADER = "/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1"
FIXED_MUSL_LIBC = "/opt/musl-1.2.6/lib/libc.so"
TIMING_LAUNCHER_SCHEMA = "crabc.perf.x86_64-timing-launcher/v1"
TIMING_LAUNCHER_SOURCE = "compat/perf/x86_64_timing_launcher.c"
TIMING_LAUNCHER_FLAGS = ("-static", "-no-pie", "-std=c11", "-O2")
IMAGE_TOOL_MANIFEST_FORMAT = "crabc-x86_64-performance-image-tools/v2"
FIXED_COMPILE_FLAGS = ("-std=c11", "-O3", "-fno-builtin")
APP_RUNPATH = "/app/lib:/usr/lib"
PERFORMANCE_CONTAINER_POLICY = "cgroupns=private,network=none,SYS_CHROOT,SYS_ADMIN,SYS_PTRACE,seccomp=unconfined"
COMPLETE_CORRECTNESS_OWNER = (
    "x86-64 correctness-closed predecessor chain: native POSIX aggregate/provider quartet "
    "and required final execution receipts"
)

IDENTITY_FIELDS = frozenset({"path", "sha256", "mode", "bytes"})

# These are intentionally scorecard obligations, rather than rows quietly
# omitted from the old 74-workload matrix.  The adapter must keep release false
# until separate owners provide them.
ABSENT_SCORECARD_OBLIGATIONS = {
    "clock-selections-beyond-monotonic": "no supported timing rows for the remaining clock selections",
    "allocator-medium-live-set": "no medium live-set allocation row",
    "allocator-free-refill-reuse": "no free/refill/reuse allocation row",
    "allocator-worker-local": "no worker-local allocation row",
    "loopback-network-timing": "no loopback timing row",
    "hermetic-hosts-dns-timing": "no hermetic hosts/DNS timing row",
    "primitive-empty-sub64-guard-adjacent": "no disposition matrix for empty, sub-64-byte, and guard-adjacent primitives",
    "per-workload-live-pss-plateaus": "the retained 74 workloads have no per-workload live-state PSS plateaus",
}

# Full qualification builds this finite output set once per provider.  The
# staged roots must contain these exact copied bytes; a report cannot point its
# parsed link evidence at one ELF while executing another.  Six memory-only
# observers are separate ELF artifacts, not replacements for the 74 frozen or
# 40 supplemental timed artifacts.
SUPPLEMENTAL_TIMED_LINK_NAMES = frozenset(performance_profile.SUPPLEMENTAL_TIMED_SOURCES)
LEGACY_MEMORY_LINK_NAMES = frozenset(performance_profile.LEGACY_MEMORY_ARTIFACTS.values())
SUPPLEMENTAL_MEMORY_LINK_NAMES = frozenset(performance_profile.SUPPLEMENTAL_MEMORY_ARTIFACTS.values())
FULL_LINK_NAMES = frozenset({
    "workload", "constructor", "graph",
    "libsymbols_1.so", "libsymbols_128.so", "libsymbols_1024.so",
    *(f"libbench_tls_growth_{index}.so" for index in range(8)),
    "libbench_graph_leaf_left.so", "libbench_graph_leaf_right.so",
    "libbench_graph_mid_left.so", "libbench_graph_mid_right.so", "libbench_graph_root.so",
    *SUPPLEMENTAL_TIMED_LINK_NAMES,
    *LEGACY_MEMORY_LINK_NAMES,
    *SUPPLEMENTAL_MEMORY_LINK_NAMES,
})
GRAPH_LINK_NAMES = frozenset({
    "libbench_graph_root.so", "graph", "x86_64_memory_observer_graph",
})
GRAPH_NEEDED = {
    "libbench_graph_leaf_left.so": ["libc.so"],
    "libbench_graph_leaf_right.so": ["libc.so"],
    "libbench_graph_mid_left.so": ["libbench_graph_leaf_left.so", "libc.so"],
    "libbench_graph_mid_right.so": ["libbench_graph_leaf_right.so", "libc.so"],
    "libbench_graph_root.so": ["libbench_graph_mid_left.so", "libbench_graph_mid_right.so", "libc.so"],
    "graph": ["libbench_graph_root.so", "libc.so"],
    "x86_64_memory_observer_graph": ["libbench_graph_root.so", "libc.so"],
}
GRAPH_DSO_NAMES = frozenset(name for name in GRAPH_NEEDED if name.endswith(".so"))
GRAPH_SOURCES = {
    "libbench_graph_leaf_left.so": "int bench_graph_leaf_left(void) { return 7; }\n",
    "libbench_graph_leaf_right.so": "int bench_graph_leaf_right(void) { return 11; }\n",
    "libbench_graph_mid_left.so": "extern int bench_graph_leaf_left(void); int bench_graph_mid_left(void) { return bench_graph_leaf_left() + 3; }\n",
    "libbench_graph_mid_right.so": "extern int bench_graph_leaf_right(void); int bench_graph_mid_right(void) { return bench_graph_leaf_right() + 4; }\n",
    "libbench_graph_root.so": "extern int bench_graph_mid_left(void); extern int bench_graph_mid_right(void); int bench_graph_root_value(void) { return bench_graph_mid_left() + bench_graph_mid_right() + 6; }\n",
}
STATIC_SOURCE_FILES = {
    "workload": "workload.c",
    "constructor": "startup_constructor.c",
    "startup_graph": "startup_graph.c",
    "symbols_128": "symbols.c",
    "tls_growth": "tls_growth_dso.c",
}
HEADER_FILES = (
    "diagnostic_marker.h",
    "pthread_create_join_tls_contract.h",
    "pthread_mutex_cond_ping_pong_contract.h",
    "pthread_mutex_uncontended_contract.h",
    "tls_growth_contract.h",
)
FULL_HEADER_PATHS = {
    **{name: f"compat/perf/fixtures/{name}" for name in HEADER_FILES},
    "x86_64_workload_protocol.h": "compat/perf/x86_64_workload_protocol.h",
    "x86_64_memory_observer_protocol.h": "compat/perf/x86_64_memory_observer_protocol.h",
    "x86_64_supplemental_memory_observer.h": "compat/perf/x86_64_supplemental_memory_observer.h",
    "x86_64-profile.toml": "compat/perf/x86_64-profile.toml",
}
FULL_OBJECT_NAMES = frozenset({
    "workload", "constructor", "startup_graph", "symbols_1", "symbols_128", "symbols_1024",
    *(f"tls_{index}" for index in range(8)),
    *(f"graph:{name}" for name in GRAPH_SOURCES),
    *(f"supplemental:{name}" for name in SUPPLEMENTAL_TIMED_LINK_NAMES),
    *(f"memory_observer:{name}" for name in LEGACY_MEMORY_LINK_NAMES),
    *(f"memory_observer:{name}" for name in SUPPLEMENTAL_MEMORY_LINK_NAMES),
})
FULL_SOURCE_NAMES = frozenset({
    *STATIC_SOURCE_FILES,
    "peer_helper", "dns_server", "timing_launcher",
    "symbols_1", "symbols_1024",
    *(f"graph:{name}" for name in GRAPH_SOURCES),
    *(f"supplemental:{name}" for name in SUPPLEMENTAL_TIMED_LINK_NAMES),
    *(f"memory_observer:{name}" for name in LEGACY_MEMORY_LINK_NAMES),
    *(f"memory_observer:{name}" for name in SUPPLEMENTAL_MEMORY_LINK_NAMES),
})
FULL_SOURCE_PATHS = {
    **{name: f"compat/perf/fixtures/{filename}" for name, filename in STATIC_SOURCE_FILES.items()},
    "peer_helper": "compat/perf/x86_64_peers.py",
    "dns_server": "compat/resolver-network/dns_server.py",
    "timing_launcher": TIMING_LAUNCHER_SOURCE,
    **{f"supplemental:{name}": path for name, path in performance_profile.SUPPLEMENTAL_TIMED_SOURCES.items()},
    **{
        f"memory_observer:{artifact}": performance_profile.LEGACY_MEMORY_SOURCES[family]
        for family, artifact in performance_profile.LEGACY_MEMORY_ARTIFACTS.items()
    },
    **{
        f"memory_observer:{artifact}": performance_profile.SUPPLEMENTAL_MEMORY_SOURCES[family]
        for family, artifact in performance_profile.SUPPLEMENTAL_MEMORY_ARTIFACTS.items()
    },
}


def generated_source_contents(name: str) -> str:
    """Return the one canonical generated source body for a full adapter run."""

    if name == "symbols_1":
        return '__attribute__((visibility("default"))) int bench_symbol_0(void) { return 0; }\n'
    if name == "symbols_1024":
        return "\n".join(
            f'__attribute__((visibility("default"))) int bench_symbol_{index}(void) {{ return {index}; }}'
            for index in range(1025)
        ) + "\n"
    if name.startswith("graph:"):
        try:
            return GRAPH_SOURCES[name.removeprefix("graph:")]
        except KeyError as error:
            raise EvidenceError(f"unknown generated graph source: {name}") from error
    raise EvidenceError(f"unknown generated source: {name}")


class EvidenceError(RuntimeError):
    """A retained file or report cannot support the claimed evidence."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path, label: str) -> dict[str, Any]:
    """Read one physical JSON object without accepting duplicate keys."""

    require(path.is_file() and not path.is_symlink(), f"{label} is not a physical regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_object)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{label} is not valid JSON: {path}") from error
    require(isinstance(value, dict), f"{label} is not a JSON object")
    return value


def sha256_file(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f"artifact is not a physical regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cpuinfo_diagnostics(raw: bytes) -> dict[str, list[str]]:
    """Extract readable CPU-model and frequency observations from raw cpuinfo.

    These fields are diagnostics, deliberately separate from the stable CPU
    identity hash.  Linux may refresh frequency and bogomips values while an
    attempt is running, so replay proves each derived list against its raw
    capture but never requires the before and after telemetry to be equal.
    """

    models: list[str] = []
    cpu_mhz: list[str] = []
    bogomips: list[str] = []
    for raw_line in raw.decode("utf-8", errors="replace").splitlines():
        key, separator, value = raw_line.partition(":")
        if not separator:
            continue
        normalized_key = key.strip()
        normalized_value = value.strip()
        if normalized_key == "model name":
            models.append(normalized_value)
        elif normalized_key == "cpu MHz":
            cpu_mhz.append(normalized_value)
        elif normalized_key == "bogomips":
            bogomips.append(normalized_value)
    return {
        "model_names": models,
        "cpu_mhz": cpu_mhz,
        "bogomips": bogomips,
    }


def cpuinfo_identity_sha256(raw: bytes) -> str:
    """Hash stable CPU identity fields while retaining live telemetry elsewhere.

    Linux regenerates ``cpu MHz`` and ``bogomips`` while an attempt is in
    progress.  They remain replayable diagnostics, but cannot make a clean
    before/after attempt appear to have changed machines.  This helper is
    shared by the producer and reader so a reported stable identity is always
    reconstructed from both retained raw captures.
    """

    volatile = {b"cpu MHz", b"bogomips"}
    lines: list[bytes] = []
    for line in raw.splitlines():
        name, separator, _value = line.partition(b":")
        if separator and name.strip() in volatile:
            continue
        lines.append(line)
    return hashlib.sha256(b"\n".join(lines) + b"\n").hexdigest()


def file_identity(path: Path) -> dict[str, Any]:
    """Return the portable identity used for all retained ordinary files."""

    path = path.resolve(strict=True)
    mode = stat.S_IMODE(path.stat().st_mode)
    return {"path": str(path), "sha256": sha256_file(path), "mode": mode, "bytes": path.stat().st_size}


def _valid_external_identity(record: object, label: str, path: str) -> None:
    """Validate an image-owned executable seal without probing the host.

    Host replay is intentionally tool-free.  The Docker image ID plus these
    immutable image file facts bind the native tool selection; asking a host
    replay to have the same compiler would silently make the reader depend on
    an ambient native toolchain.
    """

    require(isinstance(record, dict) and set(record) == IDENTITY_FIELDS, f"{label} identity fields drifted")
    require(record.get("path") == path, f"{label} path differs")
    require(isinstance(record.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is not None, f"{label} hash differs")
    require(type(record.get("mode")) is int and 0 <= record["mode"] <= 0o7777, f"{label} mode differs")
    require(type(record.get("bytes")) is int and record["bytes"] > 0, f"{label} byte length differs")


def _verify_image_tool_manifest(checkout: Path, record: object, *, index: int, tools: Mapping[str, Mapping[str, Any]]) -> None:
    """Bind retained tool bytes to the image-owned content manifest.

    The manifest is an ordinary file made during the Docker build and retained
    under the attempt root.  The dispatcher records the content-addressed
    image ID separately; replay can parse this copy without requiring Docker
    or any native tool on the host.
    """

    require(isinstance(record, dict) and set(record) == {"raw", "format", "tools"}
            and record["format"] == IMAGE_TOOL_MANIFEST_FORMAT,
            f"attempt {index} image tool manifest fields differ")
    raw = retained_file_identity(checkout, SOURCE_MOUNT, record["raw"], f"attempt {index} image tool manifest")
    try:
        lines = raw.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise EvidenceError(f"attempt {index} image tool manifest is unreadable") from error
    expected_paths = (FIXED_MUSL_COMPILER, FIXED_READELF, FIXED_STRACE, FIXED_MUSL_LOADER, FIXED_MUSL_LIBC)
    require(lines and lines[0] == f"format={IMAGE_TOOL_MANIFEST_FORMAT}"
            and len(lines) == 1 + len(expected_paths),
            f"attempt {index} image tool manifest contents differ")
    rebuilt: dict[str, str] = {}
    for line, expected_path in zip(lines[1:], expected_paths, strict=True):
        path, separator, digest = line.partition(" ")
        require(separator == " " and path == expected_path
                and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                and path not in rebuilt,
                f"attempt {index} image tool manifest row differs")
        rebuilt[path] = digest
    require(record["tools"] == rebuilt, f"attempt {index} image tool manifest record differs")
    require(rebuilt == {
        FIXED_MUSL_COMPILER: tools["musl_compiler"]["sha256"],
        FIXED_READELF: tools["readelf"]["sha256"],
        FIXED_STRACE: tools["strace"]["sha256"],
        FIXED_MUSL_LOADER: tools["musl_loader"]["sha256"],
        FIXED_MUSL_LIBC: tools["musl_libc"]["sha256"],
    }, f"attempt {index} image tool manifest does not bind selected tools")


def same_file_identity(record: Mapping[str, Any], path: Path, label: str) -> None:
    expected = {"path", "sha256", "mode", "bytes"}
    require(set(record) == expected, f"{label} identity fields drifted")
    actual = file_identity(path)
    require(record == actual, f"{label} identity differs: {path}")


def _relative_to_mount(value: str, source_mount: str) -> Path:
    require(isinstance(value, str) and value.startswith("/"), "recorded path is not absolute")
    source = Path(value)
    mount = Path(source_mount)
    try:
        relative = source.relative_to(mount)
    except ValueError as error:
        raise EvidenceError(f"recorded path escapes source mount {source_mount}: {value}") from error
    require(".." not in relative.parts, f"recorded path has parent traversal: {value}")
    return relative


def translate_source_path(checkout: Path, source_mount: str, value: str) -> Path:
    """Translate only the sealed container source mount for host replay."""

    require(source_mount == SOURCE_MOUNT, "retained evidence has an unexpected source mount")
    candidate = checkout.resolve(strict=True) / _relative_to_mount(value, source_mount)
    require(candidate.exists() and not candidate.is_symlink(), f"retained path is absent or symlinked: {candidate}")
    return candidate


def retained_file_identity(checkout: Path, source_mount: str, record: Mapping[str, Any], label: str) -> Path:
    expected = {"path", "sha256", "mode", "bytes"}
    require(set(record) == expected, f"{label} identity fields drifted")
    path = translate_source_path(checkout, source_mount, str(record["path"]))
    # Evidence is written beneath `/workspace` in the pinned image, while
    # `check` deliberately runs without native tools on a host checkout.  The
    # bytes/mode/size must match in both places; normalize the host pathname to
    # the retained source mount before comparing it.
    actual = container_file_identity(checkout, source_mount, path)
    require(record == actual, f"{label} identity differs")
    return path


def seal_files(paths: Mapping[str, Path]) -> dict[str, dict[str, Any]]:
    """Seal named source/header files in a stable order."""

    return {name: file_identity(path) for name, path in sorted(paths.items())}


def verify_file_seal(checkout: Path, source_mount: str, seal: Mapping[str, Any], label: str) -> None:
    require(isinstance(seal, dict) and seal, f"{label} has no file identities")
    for name, record in seal.items():
        require(isinstance(name, str) and name, f"{label} has an invalid file name")
        require(isinstance(record, dict), f"{label}:{name} identity is not an object")
        retained_file_identity(checkout, source_mount, record, f"{label}:{name}")


def _x86_module(checkout: Path, name: str) -> Any:
    directory = str(checkout / "compat/x86_64")
    if directory not in sys.path:
        sys.path.insert(0, directory)
    return importlib.import_module(name)


def dynamic_product_identity(checkout: Path, product: Path) -> dict[str, Any]:
    """Validate the supplied product's full manifest before using its bytes."""

    product = product.resolve(strict=True)
    try:
        product_reader = _x86_module(checkout, "owned_posix_product_evidence")
        manifest, files = product_reader._validate_dynamic_product(product)
    except (OSError, RuntimeError) as error:
        raise EvidenceError(f"invalid supplied dynamic product: {error}") from error
    return {
        "root": str(product),
        "manifest": file_identity(manifest),
        "payload": {name: file_identity(product / name) for name in sorted(files)},
        "driver": file_identity(product / "bin/crabc-cc-dynamic"),
        "installed_headers": str(product / "usr/include"),
        "format": "crabc-x86-64-owned-dynamic-sysroot-v1",
    }


def verify_dynamic_product_identity(checkout: Path, source_mount: str, record: Mapping[str, Any]) -> Path:
    expected = {"root", "manifest", "payload", "driver", "installed_headers", "format"}
    require(set(record) == expected, "dynamic product identity fields drifted")
    product = translate_source_path(checkout, source_mount, str(record["root"]))
    current = dynamic_product_identity(checkout, product)
    # The collector records container paths; replace only the root prefix when
    # comparing a host replay.  Every nested artifact identity remains exact.
    current["root"] = record["root"]
    current["installed_headers"] = record["installed_headers"]
    for identity in [current["manifest"], current["driver"], *current["payload"].values()]:
        identity["path"] = _recorded_path(checkout, source_mount, identity["path"])
    require(current == record, "supplied dynamic product changed after collection")
    return product


def verify_dynamic_product_prerequisite(
    checkout: Path,
    record: object,
    product: Mapping[str, Any],
    source_sha256: str,
) -> None:
    """Replay the existing 70-case dynamic-product owner before using it.

    A retained JSON hash only says that some qualification-shaped file existed.
    The owner reconstructs its three-product receipt, cases, and package
    evidence; this adapter then binds that validated result to the collector's
    source and supplied-product manifest.  It remains a product prerequisite,
    never the missing complete correctness-closed predecessor.
    """

    expected = {"status", "receipt", "source_sha256", "products"}
    require(isinstance(record, dict) and set(record) == expected
            and record["status"] == "validated-product-prerequisite",
            "collector lacks a validated dynamic-product prerequisite")
    receipt_path = retained_file_identity(checkout, SOURCE_MOUNT, record["receipt"],
                                          "collector dynamic product qualification receipt")
    try:
        qualification = _x86_module(checkout, "owned_dynamic_qualification")
        receipt = qualification.validate_receipt(receipt_path)
        current_source = qualification.source_digest()
    except (OSError, RuntimeError, ValueError) as error:
        raise EvidenceError(f"collector dynamic product qualification receipt is invalid: {error}") from error
    require(receipt.get("schema") == "crabc.x86_64-owned-dynamic-qualification/v1"
            and receipt.get("status") == "qualified-pending-review",
            "collector dynamic product qualification receipt is not a validated three-product record")
    products = receipt.get("products")
    require(isinstance(products, dict) and set(products) == {"installed", "second", "extracted"},
            "collector dynamic product qualification receipt lacks the exact three-product roster")
    manifest = product.get("manifest") if isinstance(product, dict) else None
    require(isinstance(manifest, dict) and isinstance(manifest.get("sha256"), str),
            "collector supplied product manifest identity is absent")
    require(record["products"] == products and all(value == manifest["sha256"] for value in products.values()),
            "collector dynamic product qualification receipt does not bind this supplied product")
    require(record["source_sha256"] == receipt.get("source_sha256") == current_source == source_sha256,
            "collector dynamic product qualification receipt source differs")


def _recorded_path(checkout: Path, source_mount: str, host_path: str) -> str:
    path = Path(host_path).resolve(strict=True)
    try:
        relative = path.relative_to(checkout.resolve(strict=True))
    except ValueError as error:
        raise EvidenceError(f"retained path escapes checkout: {path}") from error
    return str(Path(source_mount) / relative)


def _matches_recorded_source_path(checkout: Path, value: object, path: Path) -> bool:
    """Accept a live `/workspace` receipt during native collection or replay.

    Link receipts intentionally retain their real output paths.  The host-side
    reader translates only the known source mount, so it can validate the same
    receipt after the container has gone away without accepting arbitrary
    alternative output locations.
    """

    if not isinstance(value, str):
        return False
    resolved = str(path.resolve(strict=True))
    return value == resolved or value == _recorded_path(checkout, SOURCE_MOUNT, resolved)


def container_file_identity(checkout: Path, source_mount: str, path: Path) -> dict[str, Any]:
    record = file_identity(path)
    record["path"] = _recorded_path(checkout, source_mount, record["path"])
    return record


def inventory_tree(root: Path) -> list[dict[str, Any]]:
    """Seal every staged root entry, including the required ``/dev/null`` node."""

    root = root.resolve(strict=True)
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda candidate: candidate.as_posix()):
        relative = path.relative_to(root).as_posix()
        state = path.lstat()
        mode = stat.S_IMODE(state.st_mode)
        if stat.S_ISDIR(state.st_mode):
            entries.append({"path": relative, "kind": "directory", "mode": mode})
        elif stat.S_ISLNK(state.st_mode):
            # The supplied product deliberately carries the musl-loader
            # compatibility alias as a relative link.  Retain the spelling
            # rather than following it, then make the sealed inventory decide
            # whether the staged root may contain it.  A relative target may
            # legitimately climb from a canonical compatibility location to
            # the root's shared ``/lib`` payload; containment is decided from
            # its resolved destination below.
            target = os.readlink(path)
            target_path = Path(target)
            require(target and not target_path.is_absolute(),
                    f"runtime root symlink escapes its inventory: {relative}")
            try:
                resolved_target = (path.parent / target_path).resolve(strict=True)
            except OSError as error:
                raise EvidenceError(f"runtime root symlink target is unreadable: {relative}") from error
            try:
                resolved_target.relative_to(root)
            except ValueError as error:
                raise EvidenceError(f"runtime root symlink escapes its inventory: {relative}") from error
            entries.append({"path": relative, "kind": "symlink", "target": target})
        elif stat.S_ISREG(state.st_mode):
            entries.append({"path": relative, "kind": "file", "mode": mode, "sha256": sha256_file(path), "bytes": state.st_size})
        elif stat.S_ISCHR(state.st_mode):
            entries.append({
                "path": relative,
                "kind": "char-device",
                "mode": mode,
                "major": os.major(state.st_rdev),
                "minor": os.minor(state.st_rdev),
            })
        else:
            raise EvidenceError(f"runtime root has an unsupported entry: {relative}")
    return entries


def verify_inventory(root: Path, expected: object, label: str) -> None:
    require(isinstance(expected, list), f"{label} inventory is not a list")
    require(inventory_tree(root) == expected, f"{label} inventory changed")


def replay_observed_mappings(raw: str, recorded_root: str) -> list[str]:
    """Rebuild sealed-root file mappings from one retained ``/proc/PID/maps``.

    The runner may ignore anonymous kernel mappings, but an absolute file
    mapping must belong to the exact staged chroot tree.  Retaining only a
    hand-written list would let a later ambient loader fallback disappear from
    host replay, so the list is always recomputed from the raw observation.

    ``/proc/PID/maps`` is emitted inside the native container and therefore
    names the fixed ``/workspace`` mount.  Validate that recorded namespace
    first.  Host replay translates its resulting paths only afterwards; using
    the host checkout prefix here would incorrectly reject every legitimate
    retained map from the container.
    """

    require(isinstance(recorded_root, str), "recorded mapping root is not text")
    relative = _relative_to_mount(recorded_root, SOURCE_MOUNT)
    prefix = str(Path(SOURCE_MOUNT) / relative)
    paths: list[str] = []
    for line in raw.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 6 or not fields[5].startswith("/"):
            continue
        path = fields[5].removesuffix(" (deleted)")
        require(path.startswith(prefix + "/") or path == prefix,
                f"runtime mapping escaped sealed root: {path}")
        paths.append(path)
    require(paths, "runtime mapping observation contains no sealed files")
    return sorted(set(paths))


def _verify_replayed_mapping_paths(
    checkout: Path,
    paths: Sequence[str],
    root: Path,
    label: str,
) -> None:
    """Translate recorded map paths and prove they remain below the host root."""

    physical_root = root.resolve(strict=True)
    for path in paths:
        translated = translate_source_path(checkout, SOURCE_MOUNT, path)
        try:
            translated.resolve(strict=True).relative_to(physical_root)
        except ValueError as error:
            raise EvidenceError(f"{label}: translated runtime mapping escaped sealed root: {path}") from error


def parse_dynamic_section(raw: str) -> dict[str, Any]:
    """Parse only the dynamic facts that form the supplied-product contract."""

    needed = re.findall(r"\(NEEDED\).*\[([^\]]+)\]", raw)
    runpaths = re.findall(r"\(RUNPATH\).*\[([^\]]*)\]", raw)
    rpaths = re.findall(r"\(RPATH\).*\[([^\]]*)\]", raw)
    hashes: list[str] = []
    if "(HASH)" in raw:
        hashes.append("sysv")
    if "(GNU_HASH)" in raw:
        hashes.append("gnu")
    return {"needed": needed, "runpath": runpaths, "rpath": rpaths, "hashes": hashes}


def parse_program_interpreters(raw: str) -> list[str]:
    """Return the exact PT_INTERP strings reported by readelf, if any."""

    return re.findall(r"Requesting program interpreter:\s*([^\]]+)\]", raw)


def parse_x86_64_dyn_header(raw: str) -> dict[str, str]:
    """Extract the fixed ELF header facts shared by all staged PIE/DSOs."""

    fields: dict[str, str] = {}
    for name in ("Class", "Data", "Type", "Machine"):
        match = re.search(rf"^\s*{re.escape(name)}:\s*(.+?)\s*$", raw, re.MULTILINE)
        require(match is not None, f"ELF header lacks {name}")
        fields[name] = match.group(1)
    require(fields["Class"] == "ELF64" and "little endian" in fields["Data"].lower()
            and fields["Type"].startswith("DYN") and fields["Machine"] == "Advanced Micro Devices X86-64",
            "ELF header is not x86-64 little-endian ET_DYN")
    return fields


def parse_x86_64_static_exec_header(raw: str) -> dict[str, str]:
    """Extract the fixed static ET_EXEC facts for the timing supervisor."""

    fields: dict[str, str] = {}
    for name in ("Class", "Data", "Type", "Machine"):
        match = re.search(rf"^\s*{re.escape(name)}:\s*(.+?)\s*$", raw, re.MULTILINE)
        require(match is not None, f"static ELF header lacks {name}")
        fields[name] = match.group(1)
    require(fields["Class"] == "ELF64" and "little endian" in fields["Data"].lower()
            and fields["Type"].startswith("EXEC") and fields["Machine"] == "Advanced Micro Devices X86-64",
            "static ELF header is not x86-64 little-endian ET_EXEC")
    return fields


def physical_x86_64_static_exec_facts(path: Path) -> dict[str, Any]:
    """Boundedly confirm that the timing supervisor is a static x86 ET_EXEC."""

    require(path.is_file() and not path.is_symlink(), "physical static ELF is not a regular file")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"cannot read physical static ELF: {path}") from error

    def part(offset: int, size: int, label: str) -> bytes:
        require(type(offset) is int and type(size) is int and 0 <= offset <= len(data)
                and 0 <= size <= len(data) - offset,
                f"physical static ELF {label} escapes output bytes")
        return data[offset:offset + size]

    def unpack(fmt: str, offset: int, label: str) -> tuple[Any, ...]:
        return struct.unpack(fmt, part(offset, struct.calcsize(fmt), label))

    require(part(0, 7, "identity") == b"\x7fELF\x02\x01\x01",
            "physical static ELF is not ELF64 little-endian")
    header = unpack("<HHIQQQIHHHHHH", 16, "header")
    kind, machine, version, _entry, program_offset, _section_offset, _flags, header_size, program_size, program_count, _section_size, _section_count, _section_names = header
    require(kind == 2 and machine == 62 and version == 1 and header_size == 64
            and program_size == 56 and 0 < program_count < 65536,
            "physical static ELF header is not x86-64 ET_EXEC")
    require(program_offset <= len(data) and program_count <= (len(data) - program_offset) // program_size,
            "physical static ELF program-header table escapes output bytes")
    interpreters: list[str] = []
    dynamic_segments = 0
    for index in range(program_count):
        program_type, _flags, offset, _virtual, _physical, file_size, _memory_size, _align = unpack(
            "<IIQQQQQQ", program_offset + index * program_size, "program header",
        )
        part(offset, file_size, "program segment")
        if program_type == 3:
            value = part(offset, file_size, "interpreter")
            require(value.endswith(b"\0") and value.count(b"\0") == 1,
                    "physical static ELF interpreter is malformed")
            try:
                interpreters.append(value[:-1].decode("ascii", errors="strict"))
            except UnicodeDecodeError as error:
                raise EvidenceError("physical static ELF interpreter is not ASCII") from error
        elif program_type == 2:
            dynamic_segments += 1
    require(not interpreters and dynamic_segments == 0,
            "timing supervisor is not a static ELF without PT_INTERP/PT_DYNAMIC")
    return {"interpreters": interpreters, "dynamic_segments": dynamic_segments}


def physical_x86_64_dynamic_facts(path: Path) -> dict[str, Any]:
    """Read the selected ELF's loader facts directly from bounded bytes.

    Retained ``readelf`` output explains the tool observation, but its command
    line is not an execution proof during host replay.  This deliberately
    small reader therefore closes that gap for the exact staged output: ELF64
    little-endian x86-64 ET_DYN, PT_INTERP, and the dynamic string tags used
    by this adapter.  It does not try to be a general ELF framework.
    """

    require(path.is_file() and not path.is_symlink(), "physical ELF output is not a regular file")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"cannot read physical ELF output: {path}") from error

    def part(offset: int, size: int, label: str) -> bytes:
        require(type(offset) is int and type(size) is int and 0 <= offset <= len(data)
                and 0 <= size <= len(data) - offset,
                f"physical ELF {label} escapes output bytes")
        return data[offset:offset + size]

    def unpack(fmt: str, offset: int, label: str) -> tuple[Any, ...]:
        return struct.unpack(fmt, part(offset, struct.calcsize(fmt), label))

    require(part(0, 7, "identity") == b"\x7fELF\x02\x01\x01",
            "physical ELF output is not ELF64 little-endian")
    header = unpack("<HHIQQQIHHHHHH", 16, "header")
    kind, machine, version, _entry, program_offset, _section_offset, _flags, header_size, program_size, program_count, _section_size, _section_count, _section_names = header
    require(kind == 3 and machine == 62 and version == 1 and header_size == 64
            and program_size == 56 and 0 < program_count < 65536,
            "physical ELF header is not x86-64 ET_DYN")
    require(program_offset <= len(data) and program_count <= (len(data) - program_offset) // program_size,
            "physical ELF program-header table escapes output bytes")
    programs = [unpack("<IIQQQQQQ", program_offset + index * program_size, "program header")
                for index in range(program_count)]
    loads: list[tuple[int, int, int]] = []
    interpreters: list[str] = []
    dynamic_segments: list[tuple[int, int]] = []
    for program_type, _flags, offset, virtual, _physical, file_size, _memory_size, _align in programs:
        part(offset, file_size, "program segment")
        if program_type == 1:  # PT_LOAD
            loads.append((virtual, offset, file_size))
        elif program_type == 3:  # PT_INTERP
            value = part(offset, file_size, "interpreter")
            require(value.endswith(b"\0") and value.count(b"\0") == 1,
                    "physical ELF interpreter is malformed")
            try:
                interpreters.append(value[:-1].decode("ascii", errors="strict"))
            except UnicodeDecodeError as error:
                raise EvidenceError("physical ELF interpreter is not ASCII") from error
        elif program_type == 2:  # PT_DYNAMIC
            require(file_size % 16 == 0, "physical ELF dynamic segment is not entry-aligned")
            dynamic_segments.append((offset, file_size))
    require(len(dynamic_segments) == 1, "physical ELF has no unique PT_DYNAMIC segment")
    require(loads, "physical ELF has no PT_LOAD mapping for dynamic strings")

    def virtual_part(address: int, size: int, label: str) -> bytes:
        matches = [
            (offset + (address - virtual), file_size - (address - virtual))
            for virtual, offset, file_size in loads
            if address >= virtual and address - virtual <= file_size and size <= file_size - (address - virtual)
        ]
        require(len(matches) == 1, f"physical ELF {label} does not map uniquely into a PT_LOAD segment")
        offset, _remaining = matches[0]
        return part(offset, size, label)

    tags: list[tuple[int, int]] = []
    dynamic_offset, dynamic_size = dynamic_segments[0]
    terminated = False
    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
        tag, value = unpack("<qQ", offset, "dynamic entry")
        if tag == 0:  # DT_NULL
            terminated = True
            break
        tags.append((tag, value))
    require(terminated, "physical ELF dynamic segment lacks DT_NULL")
    values: dict[int, list[int]] = {}
    for tag, value in tags:
        values.setdefault(tag, []).append(value)
    require(len(values.get(5, [])) == 1 and len(values.get(10, [])) == 1,
            "physical ELF dynamic string table is absent or duplicated")
    strings = virtual_part(values[5][0], values[10][0], "dynamic string table")

    def dynamic_string(offset: int, label: str) -> str:
        require(0 <= offset < len(strings), f"physical ELF {label} offset escapes dynamic strings")
        terminator = strings.find(b"\0", offset)
        require(terminator >= 0, f"physical ELF {label} lacks a terminator")
        try:
            return strings[offset:terminator].decode("ascii", errors="strict")
        except UnicodeDecodeError as error:
            raise EvidenceError(f"physical ELF {label} is not ASCII") from error

    needed = [dynamic_string(value, "DT_NEEDED") for value in values.get(1, [])]
    runpath = [dynamic_string(value, "DT_RUNPATH") for value in values.get(29, [])]
    rpath = [dynamic_string(value, "DT_RPATH") for value in values.get(15, [])]
    hashes: list[str] = []
    for tag, _value in tags:
        if tag == 4:
            hashes.append("sysv")
        elif tag == 0x6FFFFEF5:
            hashes.append("gnu")
    return {
        "interpreters": interpreters,
        "needed": needed,
        "runpath": runpath,
        "rpath": rpath,
        "hashes": hashes,
    }


def parse_trace_calls(raw: str) -> dict[str, dict[str, int]]:
    """Count completed and resumed strace calls, including their errors.

    ``strace`` writes an unfinished line at syscall entry and a resumed line
    later.  Counting the latter once avoids silently discarding an error that
    happened after a thread switch.
    """

    calls: dict[str, dict[str, int]] = {}
    ordinary = re.compile(r"^(?:\[pid\s+\d+\]\s+)?(?:\d+\s+)?([A-Za-z_][A-Za-z0-9_]*)\(")
    resumed = re.compile(r"^(?:\[pid\s+\d+\]\s+)?(?:\d+\s+)?<\.\.\.\s+([A-Za-z_][A-Za-z0-9_]*)\s+resumed>")
    for line in raw.splitlines():
        if "<unfinished ...>" in line:
            continue
        match = ordinary.match(line) or resumed.match(line)
        if match is None:
            continue
        name = match.group(1)
        item = calls.setdefault(name, {"calls": 0, "errors": 0})
        item["calls"] += 1
        if re.search(r"=\s+-1(?:\s|$)", line):
            item["errors"] += 1
    return {name: calls[name] for name in sorted(calls)}


def _trace_prefix() -> str:
    return r"(?:\[pid\s+\d+\]\s+)?(?:\d+\s+)?"


def _marker_pattern(marker_fd: int, marker: str) -> re.Pattern[str]:
    return re.compile(rf'^{_trace_prefix()}write\({marker_fd},\s*"{re.escape(marker)}",\s*{len(marker)}\)\s+=\s+{len(marker)}$')


def replay_marker_region(raw: str, marker_fd: int, begin_marker: str, end_marker: str) -> dict[str, Any]:
    """Reconstruct the descriptor-only marked syscall region from raw strace."""

    begin = _marker_pattern(marker_fd, begin_marker)
    end = _marker_pattern(marker_fd, end_marker)
    lines = raw.splitlines()
    begins = [index for index, line in enumerate(lines) if begin.match(line)]
    ends = [index for index, line in enumerate(lines) if end.match(line)]
    if len(begins) != 1 or len(ends) != 1 or ends[0] <= begins[0]:
        return {
            "status": "failed",
            "reason": f"expected one ordered marker pair, got {len(begins)} begin/{len(ends)} end",
            "marker_fd": marker_fd,
        }
    return {
        "status": "ok",
        "marker_fd": marker_fd,
        "begin_trace_line": begins[0] + 1,
        "end_trace_line": ends[0] + 1,
        "calls": parse_trace_calls("\n".join(lines[begins[0] + 1:ends[0]])),
    }


def replay_successful_execve(raw: str, binary: str, arguments: Sequence[str]) -> int | None:
    """Locate the sole successful direct workload execve with its full argv.

    The runner gives strace a large string limit, so this replay can reject a
    trace that launched a cheap alternative mode under a legitimate binary
    path.  The fixture arguments are ASCII contract values and strace's quoted
    representation is therefore exact here.
    """

    argv = ", ".join(json.dumps(value) for value in [binary, *arguments])
    pattern = re.compile(rf'^{_trace_prefix()}execve\("{re.escape(binary)}",\s*\[{re.escape(argv)}\],\s*.*\)\s+=\s+0$')
    matches = [index for index, line in enumerate(raw.splitlines()) if pattern.match(line)]
    return matches[0] if len(matches) == 1 else None


def replay_successful_preexec_chroot(raw: str, root: str) -> int | None:
    """Locate the one successful diagnostic-child chroot into its lane root.

    The trace begins before Python performs descriptor setup and ``chroot``.
    The later ``/app/bin/...`` execve is identical across providers, so its
    argv alone cannot prove which staged runtime root the diagnostic child
    entered.  Bind the successful pre-exec ``chroot`` to the sealed lane root
    before using its syscall counts for either provider.
    """

    require(isinstance(root, str) and root.startswith(SOURCE_MOUNT + "/"),
            "trace chroot root is not a source-mounted staged lane")
    quoted = json.dumps(root)
    pattern = re.compile(rf'^{_trace_prefix()}chroot\({re.escape(quoted)}\)\s+=\s+0$')
    matches = [index for index, line in enumerate(raw.splitlines()) if pattern.match(line)]
    return matches[0] if len(matches) == 1 else None


def replay_whole_process_after_execve(
    raw: str, binary: str, arguments: Sequence[str], marker_fd: int, begin_marker: str, end_marker: str
) -> dict[str, Any]:
    """Count only from the selected successful execve, excluding marker writes."""

    boundary = replay_successful_execve(raw, binary, arguments)
    if boundary is None:
        return {"status": "failed", "reason": "expected exactly one successful workload execve", "calls": {}}
    begin = _marker_pattern(marker_fd, begin_marker)
    end = _marker_pattern(marker_fd, end_marker)
    lines = raw.splitlines()[boundary:]
    return {
        "status": "ok",
        "boundary_trace_line": boundary + 1,
        "calls": parse_trace_calls("\n".join(line for line in lines if not begin.match(line) and not end.match(line))),
    }


@lru_cache(maxsize=None)
def _performance_contract(checkout_text: str) -> Any:
    """Load the frozen 74-row contract without importing the native runner."""

    checkout = Path(checkout_text)
    source = checkout / "compat/perf/run.py"
    spec = importlib.util.spec_from_file_location(f"crabc_perf_contract_{hashlib.sha256(checkout_text.encode()).hexdigest()}", source)
    require(spec is not None and spec.loader is not None, "cannot load performance workload contract")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def canonical_workload_invocations(checkout: Path) -> dict[str, dict[str, Any]]:
    """Return the exact staged binary/argv/iteration contract for all 114 rows."""

    contract = _performance_contract(str(checkout.resolve(strict=True)))
    result: dict[str, dict[str, Any]] = {}
    try:
        rows = performance_profile.performance_rows(checkout, contract.WORKLOADS)
    except performance_profile.ProfileError as error:
        raise EvidenceError(str(error)) from error
    for row in rows:
        if row.legacy:
            workload = row.legacy_workload
            require(workload is not None, f"legacy row lost its frozen workload: {row.name}")
            arguments = contract.workload_arguments(
                workload,
                Path("/app/lib/libsymbols_1.so"),
                Path("/app/lib/libsymbols_128.so"),
                Path("/app/lib/libsymbols_1024.so"),
                Path("/app/lib/libbench_graph_root.so"),
                Path("/app/input/io-fixture.bin"),
                Path("/app/input/span-aligned.bin"),
                Path("/app/input/span-unaligned.bin"),
                Path("/app/input/span-destination.bin"),
                Path("/app/lib"),
            )
            binary = {
                "workload": "/app/bin/workload",
                "constructor": "/app/bin/constructor",
                "graph": "/app/bin/graph",
            }.get(row.timed_artifact)
            require(binary is not None, f"unknown frozen workload binary: {row.name}")
        else:
            binary = f"/app/bin/{row.timed_artifact}"
            arguments = list(row.arguments)
        result[row.name] = {
            "binary": binary,
            "arguments": arguments,
            "fixture_mode": row.fixture_mode,
            "iterations_per_process": row.iterations,
            "operations_per_process": row.operations,
        }
    return result


def canonical_memory_observer_invocations(checkout: Path) -> dict[str, dict[str, Any]]:
    """Return the separate non-timed observer envelope for every row."""

    timed = canonical_workload_invocations(checkout)
    contract = _performance_contract(str(checkout.resolve(strict=True)))
    try:
        rows = performance_profile.performance_rows(checkout, contract.WORKLOADS)
    except performance_profile.ProfileError as error:
        raise EvidenceError(str(error)) from error
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        invocation = timed[row.name]
        result[row.name] = {
            "timed_binary": invocation["binary"],
            "arguments": invocation["arguments"],
            "memory_artifact": row.memory_artifact,
            "observer_binary": f"/app/bin/{row.memory_artifact}",
            "phases": list(row.memory_phases),
            "protocol": performance_profile.OBSERVER_PROTOCOL,
        }
    return result


def syscall_gate(
    reference: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    operations: int | None = None,
    require_difference_classification: bool = False,
) -> dict[str, Any]:
    """Judge exact total calls while retaining per-syscall diagnostics.

    The 2R/reference-zero release rule applies to the summed calls in the
    selected scope.  Per-syscall records remain necessary to expose errors and
    unexplained redistribution, but they are not a hidden stricter 2R gate.
    When supplied, the operation denominator is an exact marked-region
    diagnostic, not a replacement for the total-call comparison.
    """

    reference_calls = reference.get("calls")
    candidate_calls = candidate.get("calls")
    require(isinstance(reference_calls, dict) and isinstance(candidate_calls, dict), "syscall diagnostics lack calls")
    require(operations is None or type(operations) is int and operations > 0,
            "completed operation count is invalid")
    violations: list[str] = []
    differences: dict[str, dict[str, dict[str, int]]] = {}
    names = sorted(set(reference_calls) | set(candidate_calls))
    normalized_reference: dict[str, dict[str, int]] = {}
    normalized_candidate: dict[str, dict[str, int]] = {}
    for name in names:
        ref = reference_calls.get(name, {"calls": 0, "errors": 0})
        cand = candidate_calls.get(name, {"calls": 0, "errors": 0})
        require(isinstance(ref, dict) and isinstance(cand, dict), "syscall entry is not an object")
        require(type(ref.get("calls")) is int and type(cand.get("calls")) is int, "syscall count is not integral")
        require(type(ref.get("errors")) is int and type(cand.get("errors")) is int, "syscall error count is not integral")
        require(ref["calls"] >= 0 and cand["calls"] >= 0 and ref["errors"] >= 0 and cand["errors"] >= 0,
                "syscall count is negative")
        if operations is not None:
            normalized_reference[name] = {
                "calls_numerator": ref["calls"], "errors_numerator": ref["errors"],
                "operations_denominator": operations,
            }
            normalized_candidate[name] = {
                "calls_numerator": cand["calls"], "errors_numerator": cand["errors"],
                "operations_denominator": operations,
            }
        if ref["calls"] != cand["calls"] or ref["errors"] != cand["errors"]:
            differences[name] = {
                "reference": {"calls": ref["calls"], "errors": ref["errors"]},
                "candidate": {"calls": cand["calls"], "errors": cand["errors"]},
            }
        if cand["errors"] != ref["errors"]:
            violations.append(f"{name}: candidate/reference errors differ ({cand['errors']}/{ref['errors']})")
        if require_difference_classification and name in differences:
            violations.append(f"{name}: nonzero candidate/reference difference is unclassified")
    reference_total = sum(entry["calls"] for entry in reference_calls.values())
    candidate_total = sum(entry["calls"] for entry in candidate_calls.values())
    if reference_total == 0:
        total_gate = {
            "reference": 0,
            "candidate": candidate_total,
            "threshold_numerator": 2,
            "threshold_denominator": 1,
            "rule": "reference-zero",
            "release_gate": "pass" if candidate_total == 0 else "fail",
        }
        if candidate_total != 0:
            violations.append(f"total calls: reference-zero but candidate made {candidate_total} calls")
    else:
        total_gate = {
            "reference": reference_total,
            "candidate": candidate_total,
            "threshold_numerator": 2,
            "threshold_denominator": 1,
            "rule": "at-most-2R",
            "release_gate": "pass" if candidate_total <= 2 * reference_total else "fail",
        }
        if candidate_total > 2 * reference_total:
            violations.append(f"total calls: candidate {candidate_total} exceeds 2R={2 * reference_total}")
    result: dict[str, Any] = {
        "status": "pass" if not violations else "fail",
        "violations": violations,
        "differences": differences,
        "total_calls": total_gate,
    }
    if operations is not None:
        result.update({
            "operations_per_process": operations,
            "reference_per_operation": normalized_reference,
            "candidate_per_operation": normalized_candidate,
        })
    return result


def scorecard_syscall_gate(
    reference_diagnostic: Mapping[str, Any],
    candidate_diagnostic: Mapping[str, Any],
    *,
    operations: int,
) -> dict[str, Any]:
    """Judge hot-region and whole-process syscall obligations independently.

    A marker isolates repeated work, but it cannot erase process startup,
    loader, constructor, destructor, or relocation calls.  No native x86
    classification owner has been wired yet, so every nonzero difference is
    retained as an explicit unresolved failure instead of being silently
    treated as a harmless fixed-cost discrepancy.
    """

    marked = syscall_gate(
        reference_diagnostic["marked_region"], candidate_diagnostic["marked_region"],
        operations=operations, require_difference_classification=True,
    )
    whole = syscall_gate(
        reference_diagnostic["whole_process"], candidate_diagnostic["whole_process"],
        require_difference_classification=True,
    )
    violations = [
        *(f"marked_region: {message}" for message in marked["violations"]),
        *(f"whole_process: {message}" for message in whole["violations"]),
    ]
    return {
        "status": "pass" if not violations else "fail",
        "marked_region": marked,
        "whole_process": whole,
        "violations": violations,
    }


def _receipt_contract(checkout: Path) -> Any:
    return _x86_module(checkout, "owned_dynamic_receipt")


def validate_dynamic_direct_receipt(
    *,
    checkout: Path,
    product: Path,
    receipt_path: Path,
    output: Path,
    dynamic_raw: Path,
    expected_direct: Sequence[Path],
    expected_mode: str,
    expected_search_path: str,
    expected_binding: str = "now",
    expected_hash_style: str = "sysv",
) -> dict[str, Any]:
    """Replay one schema-2 installed-driver link receipt.

    A schema-2 receipt is the direct-DSO form: every declared application DSO
    reaches both LLD's input list and its trace.  It is deliberately distinct
    from :func:`validate_dynamic_graph_receipt`, whose schema-3 closure nodes
    may be validation-only.  Keeping these readers separate means the normal
    no-DSO and direct-DSO links cannot accidentally acquire graph semantics.
    """

    record = load_json(receipt_path, "dynamic direct-link receipt")
    contract = _receipt_contract(checkout)
    search = contract.validate(
        record,
        format="crabc-x86-64-owned-dynamic-sysroot-v1",
        label="native performance dynamic direct-link receipt",
        fail=lambda message: (_ for _ in ()).throw(EvidenceError(message)),
    )
    expected_fields = {
        "schema", "format", "mode", "binding", "runtime_imports", "application_runpath", "output_path",
        "output_sha256", "manifest_sha256", "application_dsos", "owned_runtime_inputs", "input_receipts",
        "resolved_linker", "link_command", "link_trace", "campaign_complete", "application_search_kind",
        "application_rpath", "application_hash_style",
    }
    require(record.get("schema") == 2 and set(record) == expected_fields,
            "dynamic direct-link receipt is not exact schema 2")
    require(record["mode"] == expected_mode, "dynamic direct-link mode differs")
    require(record["binding"] == expected_binding, "dynamic direct-link binding differs")
    require(record["runtime_imports"] == [], "dynamic direct-link has undeclared runtime imports")
    require(record["campaign_complete"] is False, "link receipt may not claim campaign completion")
    require((search.schema, search.kind, search.path, search.hash_style)
            == (2, "runpath", expected_search_path, expected_hash_style),
            "dynamic direct-link search/hash contract differs")
    require(_matches_recorded_source_path(checkout, record["output_path"], output),
            "dynamic direct-link receipt output path differs")
    require(record["output_sha256"] == sha256_file(output),
            "dynamic direct-link receipt output hash differs")
    require(record["manifest_sha256"] == sha256_file(product / "share/crabc/manifest.json"),
            "dynamic direct-link receipt product manifest differs")

    direct = list(expected_direct)
    require(len({path.resolve(strict=True) for path in direct}) == len(direct),
            "direct-link expected DSO paths repeat")
    expected_dsos = {path.name: sha256_file(path) for path in direct}
    require(record["application_dsos"] == expected_dsos,
            "dynamic direct-link application DSO roster differs")
    command = record["link_command"]
    trace = record["link_trace"]
    require(isinstance(command, list) and all(isinstance(value, str) for value in command),
            "dynamic direct-link command is invalid")
    require(isinstance(trace, list) and all(isinstance(value, str) for value in trace),
            "dynamic direct-link trace is invalid")
    inputs = record["input_receipts"]
    require(isinstance(inputs, list), "dynamic direct-link input receipts are invalid")
    direct_receipts: dict[str, str] = {}
    for item in inputs:
        require(isinstance(item, dict) and set(item) == {"path", "sha256"}
                and isinstance(item["path"], str) and isinstance(item["sha256"], str),
                "dynamic direct-link input receipt differs")
        for path in direct:
            if _matches_recorded_source_path(checkout, item["path"], path):
                require(path.name not in direct_receipts,
                        "dynamic direct-link repeats an application DSO receipt")
                direct_receipts[path.name] = item["sha256"]
    require(direct_receipts == expected_dsos,
            "dynamic direct-link input receipt DSO identities differ")
    for path in direct:
        recorded = str(path.resolve(strict=True))
        alternate = _recorded_path(checkout, SOURCE_MOUNT, recorded)
        # The live container receipt uses its physical /workspace spelling;
        # host replay sees the translated checkout spelling.  Either is one
        # exact input, never an unbound basename search.
        command_count = command.count(recorded) + (0 if alternate == recorded else command.count(alternate))
        trace_count = trace.count(recorded) + (0 if alternate == recorded else trace.count(alternate))
        require(command_count == 1 and trace_count == 1,
                "dynamic direct-link DSO is not an exact linker/trace input")
    dynamic = parse_dynamic_section(dynamic_raw.read_text(encoding="utf-8", errors="replace"))
    require(dynamic["needed"] == [*(path.name for path in direct), "libc.so"],
            "dynamic direct-link output DT_NEEDED differs")
    require(dynamic["runpath"] == [expected_search_path] and not dynamic["rpath"],
            "dynamic direct-link output search tag differs")
    require(dynamic["hashes"] == ["sysv"], "dynamic direct-link output hash table differs")
    return {
        "receipt": file_identity(receipt_path),
        "output": file_identity(output),
        "dynamic_raw": file_identity(dynamic_raw),
        "direct_dsos": [path.name for path in direct],
    }


def validate_dynamic_graph_receipt(
    *,
    checkout: Path,
    product: Path,
    receipt_path: Path,
    output: Path,
    dynamic_raw: Path,
    expected_direct: Sequence[str],
    expected_needed: Mapping[str, Sequence[str]],
    expected_search_path: str,
    expected_binding: str = "now",
    expected_hash_style: str = "sysv",
) -> dict[str, Any]:
    """Read a schema-3 graph receipt without weakening zero-DSO readers.

    The normal POSIX reader intentionally only recognizes zero-DSO executable
    receipts.  Performance graph links use the driver-owned opt-in schema-3
    reader and insist that closure nodes remain validation-only: direct nodes
    are the only DSO paths admitted to LLD's command and trace.
    """

    record = load_json(receipt_path, "dynamic graph receipt")
    contract = _receipt_contract(checkout)
    try:
        search = contract.validate(
            record,
            format="crabc-x86-64-owned-dynamic-sysroot-v1",
            label="native performance dynamic graph receipt",
            fail=lambda message: (_ for _ in ()).throw(EvidenceError(message)),
            allow_application_dso_closure=True,
        )
    except TypeError as error:
        raise EvidenceError("installed dynamic receipt reader lacks schema-3 application-DSO closure support") from error
    expected_fields = {
        "schema", "format", "mode", "binding", "runtime_imports", "application_runpath", "output_path",
        "output_sha256", "manifest_sha256", "application_dsos", "owned_runtime_inputs", "input_receipts",
        "resolved_linker", "link_command", "link_trace", "campaign_complete", "application_search_kind",
        "application_rpath", "application_hash_style", "application_dso_roles", "application_dso_needed",
    }
    require(record.get("schema") == 3 and set(record) == expected_fields, "dynamic graph receipt is not exact schema 3")
    require(record["binding"] == expected_binding, "dynamic graph binding differs")
    require(record["runtime_imports"] == [], "dynamic graph has undeclared runtime imports")
    require(record["campaign_complete"] is False, "link receipt may not claim campaign completion")
    require((search.kind, search.path, search.hash_style) == ("runpath", expected_search_path, expected_hash_style), "dynamic graph search/hash contract differs")
    require(search.schema == 3 and search.application_dso_closure, "dynamic graph reader did not opt into schema-3 closure")
    require(_matches_recorded_source_path(checkout, record["output_path"], output), "dynamic graph receipt output path differs")
    require(record["output_sha256"] == sha256_file(output), "dynamic graph receipt output hash differs")
    require(record["manifest_sha256"] == sha256_file(product / "share/crabc/manifest.json"), "dynamic graph receipt product manifest differs")

    expected_names = set(expected_needed)
    application_dsos = record["application_dsos"]
    roles = record["application_dso_roles"]
    needed = record["application_dso_needed"]
    require(isinstance(application_dsos, dict) and set(application_dsos) == expected_names, "graph receipt DSO roster differs")
    require(isinstance(roles, dict) and set(roles) == expected_names, "graph receipt DSO roles differ")
    require(isinstance(needed, dict) and set(needed) == expected_names, "graph receipt DSO edges differ")
    direct_set = set(expected_direct)
    require(direct_set <= expected_names or not direct_set, "graph direct DSO is absent from closure")
    for name in sorted(expected_names):
        require(isinstance(application_dsos[name], str) and re.fullmatch(r"[0-9a-f]{64}", application_dsos[name]) is not None, "graph DSO hash is invalid")
        require(roles[name] == ("direct" if name in direct_set else "transitive"), "graph DSO role differs")
        require(needed[name] == list(expected_needed[name]), f"graph DSO edges differ for {name}")
    normalized_closure = {
        node.name: {"path": node.path, "sha256": node.sha256, "role": node.role, "needed": list(node.needed)}
        for node in search.application_dso_closure
    }
    require(set(normalized_closure) == expected_names, "dynamic graph normalized closure differs")
    for name in expected_names:
        require(normalized_closure[name]["sha256"] == application_dsos[name]
                and normalized_closure[name]["role"] == roles[name]
                and normalized_closure[name]["needed"] == needed[name],
                f"dynamic graph normalized closure differs for {name}")

    inputs = record["input_receipts"]
    require(isinstance(inputs, list), "graph receipt inputs are not a list")
    direct_paths: set[str] = set()
    transitive_paths: set[str] = set()
    for item in inputs:
        require(isinstance(item, dict), "graph receipt input is not an object")
        role = item.get("role")
        require(role in {"linker-input", "direct-application-dso", "transitive-application-dso"}, "graph receipt input role differs")
        require(set(item) == {"role", "path", "sha256"} | ({"name"} if role != "linker-input" else set()), "graph receipt input fields differ")
        require(isinstance(item.get("path"), str) and isinstance(item.get("sha256"), str), "graph receipt input lacks identity")
        if role == "direct-application-dso":
            require(item["name"] in direct_set, "unexpected direct graph DSO")
            require(item["sha256"] == application_dsos[item["name"]], "direct graph DSO hash differs")
            direct_paths.add(item["path"])
        elif role == "transitive-application-dso":
            require(item["name"] in expected_names - direct_set, "unexpected transitive graph DSO")
            require(item["sha256"] == application_dsos[item["name"]], "transitive graph DSO hash differs")
            transitive_paths.add(item["path"])
    require(len(direct_paths) == len(direct_set), "graph receipt omits a direct DSO input")
    require(len(transitive_paths) == len(expected_names - direct_set), "graph receipt omits a transitive DSO input")
    command = record["link_command"]
    trace = record["link_trace"]
    require(isinstance(command, list) and all(isinstance(item, str) for item in command), "graph link command is invalid")
    require(isinstance(trace, list) and all(isinstance(item, str) for item in trace), "graph link trace is invalid")
    for path in direct_paths:
        require(command.count(path) == 1, "graph direct DSO is not exactly one linker input")
        require(trace.count(path) == 1, "graph direct DSO is not exactly one trace input")
    for path in transitive_paths:
        require(path not in command and path not in trace, "graph closure was flattened into LLD")
    raw = dynamic_raw.read_text(encoding="utf-8", errors="replace")
    dynamic = parse_dynamic_section(raw)
    require(dynamic["needed"] == [*expected_direct, "libc.so"], "graph output DT_NEEDED differs from direct roots plus libc")
    require(dynamic["runpath"] == [expected_search_path] and not dynamic["rpath"], "graph output search tag differs")
    expected_hashes = ["sysv"] if expected_hash_style == "sysv" else ["gnu"] if expected_hash_style == "gnu" else ["sysv", "gnu"]
    require(dynamic["hashes"] == expected_hashes, "graph output hash table differs")
    return {
        "receipt": file_identity(receipt_path),
        "output": file_identity(output),
        "dynamic_raw": file_identity(dynamic_raw),
        "direct_dsos": list(expected_direct),
        "closure_needed": {name: list(expected_needed[name]) for name in sorted(expected_needed)},
    }


RESOURCE_FIELDS = (
    "user_cpu_ns", "system_cpu_ns", "max_rss_kib", "minor_faults", "major_faults",
    "voluntary_context_switches", "involuntary_context_switches",
)


def validate_timing_launcher_result(value: object) -> Mapping[str, Any]:
    """Validate one raw static-supervisor result before deriving a sample."""

    expected = {"schema", "child_pid", "wait_status", "timed_out", "elapsed_wall_ns", "resources"}
    require(isinstance(value, dict) and set(value) == expected
            and value["schema"] == TIMING_LAUNCHER_SCHEMA,
            "timing launcher result fields differ")
    require(type(value["child_pid"]) is int and value["child_pid"] > 0,
            "timing launcher child PID differs")
    require(type(value["wait_status"]) is int and value["wait_status"] >= 0,
            "timing launcher raw wait status differs")
    require(isinstance(value["timed_out"], bool)
            and type(value["elapsed_wall_ns"]) is int and value["elapsed_wall_ns"] >= 0,
            "timing launcher timeout or wall metric differs")
    require(os.WIFEXITED(value["wait_status"]) or os.WIFSIGNALED(value["wait_status"]),
            "timing launcher did not retain a terminal child wait status")
    resources = value["resources"]
    require(isinstance(resources, dict) and set(resources) == set(RESOURCE_FIELDS)
            and all(type(resources[field]) is int and resources[field] >= 0 for field in RESOURCE_FIELDS),
            "timing launcher resources differ")
    return value


def timing_launcher_status(value: Mapping[str, Any]) -> dict[str, Any]:
    """Derive the ordinary report status from the retained raw wait status."""

    validate_timing_launcher_result(value)
    if value["timed_out"]:
        return {"kind": "timeout"}
    status = value["wait_status"]
    if os.WIFEXITED(status):
        return {"kind": "exit", "code": os.WEXITSTATUS(status)}
    if os.WIFSIGNALED(status):
        return {"kind": "signal", "signal": os.WTERMSIG(status)}
    raise EvidenceError("timing launcher terminal status could not be decoded")


def _verify_peer_context(
    checkout: Path,
    record: object,
    *,
    row: performance_profile.PerformanceRow,
    root_record: str,
    host: Mapping[str, Any],
    invocation_directory: Path,
    label: str,
    seen_records: set[str],
) -> None:
    """Replay one fresh external peer against its exact client invocation.

    ``x86_64_peers`` proves the peer's private lifecycle.  The collector owns
    the other half of that boundary: the peer must use the original controller
    mask, a CPU distinct from the benchmark CPU, the matching staged root, and
    a record path unique to this sample/trace/observer invocation.
    """

    needs_peer = row.requires_loopback_peer or row.requires_hermetic_resolver_files
    if not needs_peer:
        require(record is None, f"{label}: non-network invocation retained a peer")
        return
    require(isinstance(record, dict), f"{label}: private peer evidence is absent")
    try:
        peer = peers.validate_context(checkout, record, require_complete=True)
    except peers.PeerError as error:
        raise EvidenceError(f"{label}: private peer evidence differs: {error}") from error

    peer_cpu = host.get("peer_cpu")
    allowed_affinity = host.get("allowed_affinity_before_pin")
    benchmark_cpu = host.get("benchmark_cpu")
    require(type(peer_cpu) is int and type(benchmark_cpu) is int
            and isinstance(allowed_affinity, list) and peer_cpu != benchmark_cpu
            and peer["affinity"] == {
                "peer_cpu": peer_cpu,
                "allowed_affinity": allowed_affinity,
            }, f"{label}: peer affinity is not bound to the attempt host")
    expected_root = str(Path(root_record).relative_to(SOURCE_MOUNT))
    expected_record = invocation_directory / "peer" / "peer-context.json"
    try:
        expected_record_text = expected_record.relative_to(checkout).as_posix()
    except ValueError as error:
        raise EvidenceError(f"{label}: peer invocation path escapes checkout") from error
    require(peer["row"]["id"] == row.name and peer["row"]["mode"] == row.fixture_mode
            and peer["row"]["client_iterations"] == row.iterations
            and peer["row"]["operations"] == row.operations
            and peer["client"]["execution_root"] == expected_root
            and peer["record_file"] == expected_record_text,
            f"{label}: peer is not bound to its exact row/root/invocation")
    require(peer["record_file"] not in seen_records,
            f"{label}: peer context was reused across client invocations")
    seen_records.add(peer["record_file"])


def _verify_timing_launcher_sample(
    checkout: Path,
    sample: Mapping[str, Any],
    launcher: Mapping[str, Any],
    *,
    launcher_output: Mapping[str, Any],
    root_record: str,
    invocation: Mapping[str, Any],
    label: str,
    invocation_directory: Path,
    seen_artifacts: set[str],
) -> None:
    """Bind a timed sample's derived metrics to one fresh launcher result.

    The static launcher's JSON has no sample-index field.  Its result and
    client/supervisor streams therefore have to occupy the exact fresh output
    directory selected by the recorded warmup/sample plan, and no such raw
    artifact may be referenced by another client invocation.
    """

    expected = {"command", "status", "stdout", "stderr", "result"}
    require(isinstance(launcher, dict) and set(launcher) == expected,
            f"{label}: timing launcher fields differ")
    require(invocation_directory.is_dir() and not invocation_directory.is_symlink(),
            f"{label}: timing launcher invocation directory is absent")

    def bind_artifact(record: object, expected_name: str, artifact_label: str) -> Path:
        require(isinstance(record, dict), f"{label}: {artifact_label} identity is absent")
        expected_path = _recorded_path(checkout, SOURCE_MOUNT, str(invocation_directory / expected_name))
        require(record.get("path") == expected_path,
                f"{label}: {artifact_label} path is not its canonical invocation output")
        path = retained_file_identity(checkout, SOURCE_MOUNT, record, f"{label}: {artifact_label}")
        recorded = str(record["path"])
        require(recorded not in seen_artifacts,
                f"{label}: timing launcher {artifact_label} was reused across client invocations")
        seen_artifacts.add(recorded)
        return path

    result_record = launcher["result"]
    result_path = bind_artifact(result_record, "timing-launcher-result.json", "result")
    bind_artifact(sample["stdout"], "stdout", "client stdout")
    bind_artifact(sample["stderr"], "stderr", "client stderr")
    supervisor_stdout = bind_artifact(launcher["stdout"], "timing-launcher.stdout", "supervisor stdout")
    supervisor_stderr = bind_artifact(launcher["stderr"], "timing-launcher.stderr", "supervisor stderr")
    raw_result = validate_timing_launcher_result(load_json(result_path, f"{label}: timing launcher result"))
    require(launcher["status"] == {"kind": "exit", "code": 0}
            and sample["elapsed_wall_ns"] == raw_result["elapsed_wall_ns"]
            and sample["resources"] == raw_result["resources"]
            and sample["status"] == timing_launcher_status(raw_result),
            f"{label}: sample metrics do not derive from timing launcher")
    require(not supervisor_stdout.read_bytes() and not supervisor_stderr.read_bytes(),
            f"{label}: timing launcher emitted unexpected output")
    command = launcher["command"]
    require(isinstance(command, list) and len(command) >= 8
            and command[0] == launcher_output["path"]
            and command[1] == root_record
            and command[2] == sample["stdout"]["path"]
            and command[3] == sample["stderr"]["path"]
            and command[4] == result_record["path"]
            and isinstance(command[5], str) and command[5].isdecimal() and int(command[5]) > 0
            and command[6] == invocation["binary"]
            and command[7:] == invocation["arguments"],
            f"{label}: timing launcher command differs")
    distinct_outputs = {command[2], command[3], command[4], launcher["stdout"]["path"], launcher["stderr"]["path"]}
    require(len(distinct_outputs) == 5, f"{label}: timing launcher output paths overlap")


def _verify_completed_sample(
    checkout: Path,
    sample: object,
    *,
    label: str,
    index_field: str,
    index: int,
    execution_order: int | None,
    launcher_output: Mapping[str, Any] | None = None,
    root_record: str | None = None,
    invocation: Mapping[str, Any] | None = None,
    row: performance_profile.PerformanceRow | None = None,
    host: Mapping[str, Any] | None = None,
    seen_peers: set[str] | None = None,
    invocation_directory: Path | None = None,
    seen_launcher_artifacts: set[str] | None = None,
) -> Mapping[str, Any]:
    expected = {
        "elapsed_wall_ns", "status", "resources", "stdout", "stderr", "stdout_matches",
        "stderr_bytes", "stdout_sha256", "stderr_sha256", index_field,
    } | ({"execution_order"} if execution_order is not None else set())
    full = launcher_output is not None
    if full:
        expected |= {"launcher", "peer"}
    require(isinstance(sample, dict) and set(sample) == expected, f"{label}: sample fields differ")
    require(sample[index_field] == index, f"{label}: sample index differs")
    if execution_order is not None:
        require(sample["execution_order"] == execution_order, f"{label}: execution order differs")
    require(type(sample["elapsed_wall_ns"]) is int and sample["elapsed_wall_ns"] >= 0,
            f"{label}: elapsed wall metric differs")
    require(sample["status"] == {"kind": "exit", "code": 0}, f"{label}: child status differs")
    resources = sample["resources"]
    require(isinstance(resources, dict) and set(resources) == set(RESOURCE_FIELDS)
            and all(type(resources[field]) is int and resources[field] >= 0 for field in RESOURCE_FIELDS),
            f"{label}: resource metrics differ")
    stdout = retained_file_identity(checkout, SOURCE_MOUNT, sample["stdout"], f"{label}: stdout")
    stderr = retained_file_identity(checkout, SOURCE_MOUNT, sample["stderr"], f"{label}: stderr")
    stdout_bytes = stdout.read_bytes()
    stderr_bytes = stderr.read_bytes()
    require(sample["stdout_matches"] is True and stdout_bytes == b"ok\n", f"{label}: stdout differs")
    require(sample["stderr_bytes"] == 0 and not stderr_bytes, f"{label}: stderr differs")
    require(sample["stdout_sha256"] == hashlib.sha256(stdout_bytes).hexdigest()
            and sample["stderr_sha256"] == hashlib.sha256(stderr_bytes).hexdigest(),
            f"{label}: output hash differs")
    if full:
        require(root_record is not None and invocation is not None and row is not None and host is not None
                and seen_peers is not None and invocation_directory is not None
                and seen_launcher_artifacts is not None,
                f"{label}: full sample replay context is absent")
        require(stdout.parent == invocation_directory and stderr.parent == invocation_directory,
                f"{label}: client outputs are not in their canonical invocation directory")
        _verify_timing_launcher_sample(
            checkout, sample, sample["launcher"], launcher_output=launcher_output,
            root_record=root_record, invocation=invocation, label=label,
            invocation_directory=invocation_directory, seen_artifacts=seen_launcher_artifacts,
        )
        _verify_peer_context(
            checkout, sample["peer"], row=row, root_record=root_record, host=host,
            invocation_directory=invocation_directory, label=label, seen_records=seen_peers,
        )
    return sample


def _verify_diagnostic(
    checkout: Path,
    diagnostic: object,
    invocation: Mapping[str, Any],
    label: str,
    *,
    row: performance_profile.PerformanceRow | None = None,
    root_record: str | None = None,
    host: Mapping[str, Any] | None = None,
    seen_peers: set[str] | None = None,
) -> Mapping[str, Any]:
    expected = {
        "status", "diagnostic", "timing", "child", "resources", "trace", "stdout", "stderr", "markers",
        "strace_stdout", "strace_stderr", "trace_sha256", "whole_process", "marked_region",
        "workload_execve", "successful_workload_execve_trace_lines", "marker_writes_excluded_from_whole_process",
    }
    full = row is not None
    if full:
        expected.add("peer")
    require(isinstance(diagnostic, dict) and set(diagnostic) == expected, f"{label}: diagnostic fields differ")
    require(diagnostic["status"] == "ok" and diagnostic["diagnostic"] is True and diagnostic["timing"] is False,
            f"{label}: diagnostic status differs")
    require(diagnostic["child"] == {"kind": "exit", "code": 0}, f"{label}: diagnostic child differs")
    resources = diagnostic["resources"]
    require(isinstance(resources, dict) and set(resources) == set(RESOURCE_FIELDS)
            and all(type(resources[field]) is int and resources[field] >= 0 for field in RESOURCE_FIELDS),
            f"{label}: diagnostic resources differ")
    trace = retained_file_identity(checkout, SOURCE_MOUNT, diagnostic["trace"], f"{label}: trace")
    stdout = retained_file_identity(checkout, SOURCE_MOUNT, diagnostic["stdout"], f"{label}: stdout")
    stderr = retained_file_identity(checkout, SOURCE_MOUNT, diagnostic["stderr"], f"{label}: stderr")
    retained_file_identity(checkout, SOURCE_MOUNT, diagnostic["markers"], f"{label}: markers")
    retained_file_identity(checkout, SOURCE_MOUNT, diagnostic["strace_stdout"], f"{label}: strace stdout")
    retained_file_identity(checkout, SOURCE_MOUNT, diagnostic["strace_stderr"], f"{label}: strace stderr")
    require(stdout.read_bytes() == b"ok\n" and not stderr.read_bytes(), f"{label}: diagnostic output differs")
    raw = trace.read_text(encoding="utf-8", errors="replace")
    require(diagnostic["trace_sha256"] == sha256_file(trace), f"{label}: trace hash differs")
    contract = _performance_contract(str(checkout.resolve(strict=True)))
    marker_fd = 97
    expected_execve = {"path": invocation["binary"], "argv": [invocation["binary"], *invocation["arguments"]]}
    require(diagnostic["workload_execve"] == expected_execve, f"{label}: diagnostic execve declaration differs")
    marked = replay_marker_region(raw, marker_fd, contract.DIAGNOSTIC_MARKER_BEGIN, contract.DIAGNOSTIC_MARKER_END)
    whole = replay_whole_process_after_execve(
        raw, invocation["binary"], invocation["arguments"], marker_fd,
        contract.DIAGNOSTIC_MARKER_BEGIN, contract.DIAGNOSTIC_MARKER_END,
    )
    require(marked["status"] == "ok" and whole["status"] == "ok", f"{label}: retained trace does not meet marker/execve contract")
    require(diagnostic["marked_region"] == marked, f"{label}: marked syscall region disagrees with trace")
    require(diagnostic["whole_process"] == whole, f"{label}: whole-process syscall region disagrees with trace")
    require(diagnostic["successful_workload_execve_trace_lines"] == [whole["boundary_trace_line"]]
            and diagnostic["marker_writes_excluded_from_whole_process"] is True,
            f"{label}: workload execve boundary differs")
    if full:
        require(root_record is not None and host is not None and seen_peers is not None,
                f"{label}: full diagnostic replay context is absent")
        chroot = replay_successful_preexec_chroot(raw, root_record)
        require(chroot is not None and chroot < whole["boundary_trace_line"] - 1,
                f"{label}: diagnostic chroot does not bind the selected lane root")
        _verify_peer_context(
            checkout, diagnostic["peer"], row=row, root_record=root_record, host=host,
            invocation_directory=stdout.parent, label=label, seen_records=seen_peers,
        )
    return diagnostic


def _verify_memory_snapshot(checkout: Path, snapshot: object, label: str, *, expected_pid: int | None = None) -> None:
    require(isinstance(snapshot, dict) and "raw" in snapshot, f"{label}: memory snapshot is absent")
    raw = snapshot["raw"]
    require(isinstance(raw, dict) and set(raw) == {"status", "smaps_rollup", "smaps"}, f"{label}: memory raw roster differs")
    status = retained_file_identity(checkout, SOURCE_MOUNT, raw["status"], f"{label}: proc status")
    rollup = retained_file_identity(checkout, SOURCE_MOUNT, raw["smaps_rollup"], f"{label}: smaps rollup")
    smaps = retained_file_identity(checkout, SOURCE_MOUNT, raw["smaps"], f"{label}: smaps")
    rebuilt: dict[str, Any] = {}
    observed_pid: int | None = None
    for line in status.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"^(VmRSS|VmHWM|VmSize):\s+(\d+)\s+kB$", line)
        if match is not None:
            rebuilt[match.group(1).lower() + "_kib"] = int(match.group(2))
        pid_match = re.match(r"^Pid:\s+(\d+)$", line)
        if pid_match is not None:
            observed_pid = int(pid_match.group(1))
    for line in rollup.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"^(Rss|Pss|Private_Clean|Private_Dirty):\s+(\d+)\s+kB$", line)
        if match is not None:
            rebuilt[match.group(1).lower() + "_kib"] = int(match.group(2))
    contract = _performance_contract(str(checkout.resolve(strict=True)))
    rebuilt["mapping_attribution"] = contract.smaps_mapping_summary(smaps.read_text(encoding="utf-8", errors="replace"))
    require(snapshot == {**rebuilt, "raw": raw}, f"{label}: memory snapshot disagrees with retained proc bytes")
    require(type(rebuilt.get("pss_kib")) is int, f"{label}: PSS is absent")
    if expected_pid is not None:
        require(observed_pid == expected_pid, f"{label}: retained PSS status PID differs from migrated child")


def _read_decimal_raw(path: Path, label: str) -> int:
    value = path.read_text(encoding="ascii").strip()
    require(value.isdecimal(), f"{label}: raw value is not decimal")
    return int(value)


def _read_memory_stat_raw(path: Path, label: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition(" ")
        if separator and value.isdecimal():
            result[key] = int(value)
    require(result, f"{label}: memory.stat has no metrics")
    return result


def _verify_memory_probe(
    checkout: Path,
    result: object,
    label: str,
    *,
    live: bool,
    expected_root: str | None = None,
    owned_probe_leaves: Iterable[str] | None = None,
) -> None:
    expected = {
        "status", "mode", "live_allocation_bytes", "memory", "cgroup_memory", "migration", "child", "resources",
        "stdout", "stderr", "stdout_sha256", "stderr_sha256", "mappings",
    }
    require(isinstance(result, dict) and set(result) == expected, f"{label}: memory probe fields differ")
    expected_mode = "allocator_live" if live else "allocator_after_ready"
    require(result["status"] == "ok" and result["mode"] == expected_mode and result["live_allocation_bytes"] == 128 * 262144,
            f"{label}: memory probe state differs")
    require(result["child"] == {"kind": "exit", "code": 0}, f"{label}: memory child differs")
    resources = result["resources"]
    require(isinstance(resources, dict) and set(resources) == set(RESOURCE_FIELDS)
            and all(type(resources[field]) is int and resources[field] >= 0 for field in RESOURCE_FIELDS),
            f"{label}: memory resources differ")
    stdout = retained_file_identity(checkout, SOURCE_MOUNT, result["stdout"], f"{label}: stdout")
    stderr = retained_file_identity(checkout, SOURCE_MOUNT, result["stderr"], f"{label}: stderr")
    require(stdout.read_bytes() == b"ok\n" and not stderr.read_bytes(), f"{label}: memory output differs")
    require(result["stdout_sha256"] == sha256_file(stdout) and result["stderr_sha256"] == sha256_file(stderr),
            f"{label}: memory output hashes differ")
    cgroup = result["cgroup_memory"]
    expected_cgroup = {
        "status", "memory_peak_before_ready_bytes", "memory_peak_after_exit_bytes", "memory_stat", "raw", "attribution_limit",
    } | ({"after_ready_self_test"} if live else set())
    require(isinstance(cgroup, dict) and set(cgroup) == expected_cgroup and cgroup["status"] == "ok", f"{label}: cgroup memory fields differ")
    raw = cgroup["raw"]
    expected_raw = {
        "memory_peak_before_ready", "memory_peak_after_exit", "memory_stat_before_continue", "memory_stat_after_exit",
    }
    require(isinstance(raw, dict) and set(raw) == expected_raw, f"{label}: cgroup raw roster differs")
    before_peak = _read_decimal_raw(retained_file_identity(checkout, SOURCE_MOUNT, raw["memory_peak_before_ready"], f"{label}: pre-ready peak"), label)
    after_peak = _read_decimal_raw(retained_file_identity(checkout, SOURCE_MOUNT, raw["memory_peak_after_exit"], f"{label}: post-exit peak"), label)
    before_stat = _read_memory_stat_raw(retained_file_identity(checkout, SOURCE_MOUNT, raw["memory_stat_before_continue"], f"{label}: pre-continue memory.stat"), label)
    after_stat = _read_memory_stat_raw(retained_file_identity(checkout, SOURCE_MOUNT, raw["memory_stat_after_exit"], f"{label}: post-exit memory.stat"), label)
    require(cgroup["memory_peak_before_ready_bytes"] == before_peak and cgroup["memory_peak_after_exit_bytes"] == after_peak,
            f"{label}: cgroup peak values disagree with raw files")
    require(cgroup["memory_stat"] == {"before_continue": before_stat, "after_exit": after_stat},
            f"{label}: cgroup memory.stat differs")
    require(cgroup["attribution_limit"] == "memory.peak can include warm file-cache charges; it is retained as cgroup high-water and is never reset, subtracted, or read from Docker's parent cgroup",
            f"{label}: cgroup attribution boundary differs")
    migration = result["migration"]
    expected_migration = {"pid", "root", "executable", "expected_executable", "threads", "probe", "event", "syscall"}
    require(isinstance(migration, dict) and set(migration) == expected_migration
            and type(migration["pid"]) is int and migration["pid"] > 0
            and isinstance(migration["root"], str) and isinstance(migration["probe"], str)
            and isinstance(migration["executable"], str) and migration["executable"]
            and migration["executable"] == migration["expected_executable"]
            and migration["event"] == "syscall-entry-execve" and migration["threads"] == 1,
            f"{label}: pre-exec migration evidence differs")
    if expected_root is not None:
        require(migration["root"] == expected_root,
                f"{label}: pre-exec child root is not the matching sealed execution root")
    if owned_probe_leaves is not None:
        require(migration["probe"] in set(owned_probe_leaves),
                f"{label}: pre-exec child probe is not an owned cleaned cgroup leaf")
    syscall = migration["syscall"]
    require(syscall == {
        "api": "PTRACE_GET_SYSCALL_INFO", "entry": True, "architecture": "x86_64", "number": 59,
        "path": "/app/bin/workload", "argv": ["/app/bin/workload", expected_mode, "128", "262144", "97", "98"],
    }, f"{label}: pre-exec syscall identity differs")
    if not live:
        require(after_peak > before_peak, f"{label}: after-ready peak did not increase")
        require(result["memory"] == {"raw": {}}, f"{label}: after-ready probe claimed a live PSS snapshot")
        require(result["mappings"] is None, f"{label}: after-ready probe retained mappings")
    else:
        _verify_memory_snapshot(checkout, result["memory"], label, expected_pid=migration["pid"])
        mappings = result["mappings"]
        require(isinstance(mappings, dict) and set(mappings) == {"raw", "paths"}
                and isinstance(mappings["paths"], list), f"{label}: mapping observation differs")
        retained_file_identity(checkout, SOURCE_MOUNT, mappings["raw"], f"{label}: mapping raw")
        require(all(isinstance(path, str) and path.startswith(SOURCE_MOUNT + "/.work/x86_64/")
                    for path in mappings["paths"]), f"{label}: mapping path roster differs")


def _verify_cgroup_lifecycle(checkout: Path, setup: object, cleanup: object) -> None:
    """Check that memory evidence used only an owned private cgroup view."""

    expected_setup = {
        "status", "default_container_cgroup", "private_mount_command", "private_mount_status",
        "private_mount_stdout", "private_mount_stderr", "controller", "control_leaf",
    }
    require(isinstance(setup, dict) and set(setup) == expected_setup and setup["status"] == "ok",
            "private cgroup setup is unavailable or malformed")
    default = setup["default_container_cgroup"]
    require(isinstance(default, dict) and set(default) == {
        "path", "exists", "memory_peak_exists", "subtree_control_writable", "mount_read_only",
    } and default["path"] == "/sys/fs/cgroup"
            and all(type(default[name]) is bool for name in (
                "exists", "memory_peak_exists", "subtree_control_writable", "mount_read_only",
            )), "default container cgroup observation differs")
    command = setup["private_mount_command"]
    require(isinstance(command, list) and len(command) == 5
            and command[:4] == ["mount", "-t", "cgroup2", "none"]
            and isinstance(command[4], str) and command[4].startswith(SOURCE_MOUNT + "/.work/x86_64/"),
            "private cgroup mount command differs")
    require(setup["private_mount_status"] == {"kind": "exit", "code": 0}
            and setup["controller"] == "memory"
            and isinstance(setup["control_leaf"], str)
            and setup["control_leaf"].startswith(command[4] + "/control"),
            "private cgroup controller setup differs")
    retained_file_identity(checkout, SOURCE_MOUNT, setup["private_mount_stdout"], "private cgroup mount stdout")
    retained_file_identity(checkout, SOURCE_MOUNT, setup["private_mount_stderr"], "private cgroup mount stderr")

    expected_cleanup = {
        "owned_leaves", "leaf_results", "remaining_leaves", "unmount_status", "unmount_stdout", "unmount_stderr",
    }
    require(isinstance(cleanup, dict) and set(cleanup) == expected_cleanup
            and isinstance(cleanup["owned_leaves"], list) and cleanup["owned_leaves"]
            and isinstance(cleanup["leaf_results"], list)
            and cleanup["remaining_leaves"] == [] and cleanup["unmount_status"] == 0,
            "private cgroup cleanup differs")
    require(len(cleanup["owned_leaves"]) == len(cleanup["leaf_results"])
            and len(set(cleanup["owned_leaves"])) == len(cleanup["owned_leaves"]),
            "private cgroup cleanup leaf roster differs")
    for owned, result in zip(cleanup["owned_leaves"], cleanup["leaf_results"], strict=True):
        require(isinstance(owned, str) and owned.startswith(command[4] + "/probe-")
                and isinstance(result, dict) and result == {"path": owned, "error": None},
                "private cgroup cleanup retained an occupied or foreign leaf")
    retained_file_identity(checkout, SOURCE_MOUNT, cleanup["unmount_stdout"], "private cgroup unmount stdout")
    retained_file_identity(checkout, SOURCE_MOUNT, cleanup["unmount_stderr"], "private cgroup unmount stderr")


def _verify_observer_mapping(
    checkout: Path,
    mappings: object,
    root: Path,
    root_record: str,
    label: str,
) -> None:
    """Rebuild one observer checkpoint's sealed-root mapping roster."""

    require(isinstance(mappings, dict) and set(mappings) == {"raw", "paths"}
            and isinstance(mappings["paths"], list), f"{label}: mapping observation differs")
    raw = retained_file_identity(checkout, SOURCE_MOUNT, mappings["raw"], f"{label}: maps raw")
    rebuilt = replay_observed_mappings(raw.read_text(encoding="utf-8", errors="replace"), root_record)
    _verify_replayed_mapping_paths(checkout, rebuilt, root, label)
    require(mappings["paths"] == rebuilt
            and all(isinstance(path, str) and path.startswith(root_record + "/") for path in mappings["paths"]),
            f"{label}: mapping observation escapes its sealed root")


def _verify_observer_checkpoint(
    checkout: Path,
    checkpoint: object,
    *,
    index: int,
    phase: str,
    pid: int,
    root: Path,
    root_record: str,
    label: str,
) -> None:
    expected = {"index", "phase", "ready", "continue", "memory", "mappings", "cgroup_memory"}
    require(isinstance(checkpoint, dict) and set(checkpoint) == expected
            and checkpoint["index"] == index and checkpoint["phase"] == phase
            and checkpoint["ready"] == "R" and checkpoint["continue"] == "C",
            f"{label}: observer checkpoint order differs")
    _verify_memory_snapshot(checkout, checkpoint["memory"], f"{label}: PSS", expected_pid=pid)
    _verify_observer_mapping(checkout, checkpoint["mappings"], root, root_record, label)
    cgroup = checkpoint["cgroup_memory"]
    require(isinstance(cgroup, dict) and set(cgroup) == {"memory_peak_bytes", "memory_stat", "raw"}
            and type(cgroup["memory_peak_bytes"]) is int and cgroup["memory_peak_bytes"] >= 0,
            f"{label}: checkpoint cgroup fields differ")
    raw = cgroup["raw"]
    require(isinstance(raw, dict) and set(raw) == {"memory_peak", "memory_stat"},
            f"{label}: checkpoint cgroup raw fields differ")
    peak = _read_decimal_raw(
        retained_file_identity(checkout, SOURCE_MOUNT, raw["memory_peak"], f"{label}: checkpoint memory.peak"),
        label,
    )
    stat_value = _read_memory_stat_raw(
        retained_file_identity(checkout, SOURCE_MOUNT, raw["memory_stat"], f"{label}: checkpoint memory.stat"),
        label,
    )
    require(cgroup["memory_peak_bytes"] == peak and cgroup["memory_stat"] == stat_value,
            f"{label}: checkpoint cgroup values disagree with raw bytes")


def _memory_metric(reference: int, candidate: int) -> dict[str, Any]:
    require(type(reference) is int and reference >= 0 and type(candidate) is int and candidate >= 0,
            "memory comparison value differs")
    if reference == 0:
        return {
            "reference": reference,
            "candidate": candidate,
            "threshold_numerator": 9,
            "threshold_denominator": 10,
            "release_gate": "reference-zero",
        }
    return {
        "reference": reference,
        "candidate": candidate,
        "threshold_numerator": 9,
        "threshold_denominator": 10,
        "release_gate": "pass" if candidate * 10 <= reference * 9 else "fail",
    }


def _verify_memory_observer_result(
    checkout: Path,
    result: object,
    *,
    invocation: Mapping[str, Any],
    row: performance_profile.PerformanceRow,
    lane: str,
    root: Path,
    root_record: str,
    private_mount: str,
    host: Mapping[str, Any],
    seen_peers: set[str],
) -> Mapping[str, Any]:
    """Replay one non-timed observer process from raw checkpoint evidence."""

    expected = {
        "status", "protocol", "observer", "migration", "checkpoints", "cgroup_memory", "child", "resources",
        "stdout", "stderr", "stdout_sha256", "stderr_sha256", "peer",
    }
    require(isinstance(result, dict) and set(result) == expected
            and result["status"] == "ok" and result["protocol"] == performance_profile.OBSERVER_PROTOCOL
            and result["observer"] == invocation,
            f"{row.name}/{lane}: memory observer fields differ")
    migration = result["migration"]
    expected_probe = f"{private_mount}/probe-{lane}-observer-{row.name}"
    expected_migration_fields = {"pid", "root", "executable", "expected_executable", "threads", "probe", "event", "syscall"}
    require(isinstance(migration, dict) and set(migration) == expected_migration_fields
            and type(migration["pid"]) is int and migration["pid"] > 0
            and migration["root"] == root_record and migration["probe"] == expected_probe
            and isinstance(migration["executable"], str) and migration["executable"]
            and migration["executable"] == migration["expected_executable"]
            and migration["threads"] == 1 and migration["event"] == "syscall-entry-execve",
            f"{row.name}/{lane}: observer pre-exec migration differs")
    require(migration["syscall"] == {
        "api": "PTRACE_GET_SYSCALL_INFO", "entry": True, "architecture": "x86_64", "number": 59,
        "path": invocation["observer_binary"],
        "argv": [invocation["observer_binary"], *invocation["arguments"]],
    }, f"{row.name}/{lane}: observer pre-exec argv differs")
    require(result["child"] == {"kind": "exit", "code": 0}, f"{row.name}/{lane}: observer child differs")
    resources = result["resources"]
    require(isinstance(resources, dict) and set(resources) == set(RESOURCE_FIELDS)
            and all(type(resources[field]) is int and resources[field] >= 0 for field in RESOURCE_FIELDS),
            f"{row.name}/{lane}: observer resources differ")
    stdout = retained_file_identity(checkout, SOURCE_MOUNT, result["stdout"], f"{row.name}/{lane}: observer stdout")
    stderr = retained_file_identity(checkout, SOURCE_MOUNT, result["stderr"], f"{row.name}/{lane}: observer stderr")
    require(stdout.read_bytes() == b"ok\n" and not stderr.read_bytes()
            and result["stdout_sha256"] == sha256_file(stdout)
            and result["stderr_sha256"] == sha256_file(stderr),
            f"{row.name}/{lane}: observer output differs")
    checkpoints = result["checkpoints"]
    require(isinstance(checkpoints, list) and len(checkpoints) == len(invocation["phases"]),
            f"{row.name}/{lane}: observer checkpoint roster differs")
    for index, (checkpoint, phase) in enumerate(zip(checkpoints, invocation["phases"], strict=True)):
        _verify_observer_checkpoint(
            checkout, checkpoint, index=index, phase=phase, pid=migration["pid"], root=root,
            root_record=root_record, label=f"{row.name}/{lane}/{phase}",
        )
    cgroup = result["cgroup_memory"]
    expected_cgroup = {"status", "memory_peak_after_exit_bytes", "memory_stat_after_exit", "raw", "attribution_limit"}
    require(isinstance(cgroup, dict) and set(cgroup) == expected_cgroup and cgroup["status"] == "ok"
            and type(cgroup["memory_peak_after_exit_bytes"]) is int
            and cgroup["memory_peak_after_exit_bytes"] >= 0 and isinstance(cgroup["memory_stat_after_exit"], dict),
            f"{row.name}/{lane}: observer post-exit cgroup fields differ")
    raw = cgroup["raw"]
    require(isinstance(raw, dict) and set(raw) == {"memory_peak_after_exit", "memory_stat_after_exit"},
            f"{row.name}/{lane}: observer post-exit raw fields differ")
    peak = _read_decimal_raw(
        retained_file_identity(checkout, SOURCE_MOUNT, raw["memory_peak_after_exit"], f"{row.name}/{lane}: observer post-exit peak"),
        f"{row.name}/{lane}",
    )
    stat_value = _read_memory_stat_raw(
        retained_file_identity(checkout, SOURCE_MOUNT, raw["memory_stat_after_exit"], f"{row.name}/{lane}: observer post-exit stat"),
        f"{row.name}/{lane}",
    )
    require(cgroup["memory_peak_after_exit_bytes"] == peak and cgroup["memory_stat_after_exit"] == stat_value
            and cgroup["attribution_limit"] == "memory.peak can include warm file-cache charges; it is retained as cgroup high-water and is never reset, subtracted, or read from Docker's parent cgroup",
            f"{row.name}/{lane}: observer post-exit values disagree with raw bytes")
    _verify_peer_context(
        checkout, result["peer"], row=row, root_record=root_record, host=host,
        invocation_directory=stdout.parent, label=f"{row.name}/{lane}: observer",
        seen_records=seen_peers,
    )
    return result


def _verify_memory_observer_comparison(
    result: object,
    reference: Mapping[str, Any],
    candidate: Mapping[str, Any],
    label: str,
) -> None:
    require(isinstance(result, dict) and set(result) == {"status", "pss_max_kib", "memory_peak_after_exit_bytes"}
            and result["status"] == "ok", f"{label}: observer memory comparison differs")
    reference_pss = max(checkpoint["memory"]["pss_kib"] for checkpoint in reference["checkpoints"])
    candidate_pss = max(checkpoint["memory"]["pss_kib"] for checkpoint in candidate["checkpoints"])
    require(result["pss_max_kib"] == _memory_metric(reference_pss, candidate_pss)
            and result["memory_peak_after_exit_bytes"] == _memory_metric(
                reference["cgroup_memory"]["memory_peak_after_exit_bytes"],
                candidate["cgroup_memory"]["memory_peak_after_exit_bytes"],
            ), f"{label}: observer memory comparison does not derive from raw checkpoints")


def _verify_probe_assignment(
    memory: Mapping[str, Any],
    observer_memory: Mapping[str, Any],
    rows: Sequence[performance_profile.PerformanceRow],
    owned_probe_leaves: object,
    private_mount: object,
) -> None:
    """Require every old and per-row observer leaf exactly once."""

    require(isinstance(private_mount, str), "private cgroup mount path differs")
    old_expected = {
        f"{private_mount}/probe-{lane}-{phase}"
        for lane in ("musl", "crabc")
        for phase in ("live", "after-ready")
    }
    observer_expected = {
        f"{private_mount}/probe-{lane}-observer-{row.name}"
        for lane in ("musl", "crabc")
        for row in rows
    }
    expected = old_expected | observer_expected
    require(isinstance(owned_probe_leaves, list) and len(owned_probe_leaves) == len(expected)
            and set(owned_probe_leaves) == expected,
            "private cgroup owned-probe roster differs")
    for lane in ("musl", "crabc"):
        live = memory.get(lane)
        require(isinstance(live, dict) and isinstance(live.get("migration"), dict),
                f"{lane}: live migration is absent")
        after = live.get("cgroup_memory", {}).get("after_ready_self_test") if isinstance(live.get("cgroup_memory"), dict) else None
        require(isinstance(after, dict) and isinstance(after.get("migration"), dict),
                f"{lane}: post-ready migration is absent")
        require(live["migration"].get("probe") == f"{private_mount}/probe-{lane}-live"
                and after["migration"].get("probe") == f"{private_mount}/probe-{lane}-after-ready",
                "memory probe lane/phase assignment differs from the owned lifecycle roster")
    for row in rows:
        result = observer_memory.get(row.name)
        require(isinstance(result, dict), f"{row.name}: observer memory result is absent")
        for lane in ("musl", "crabc"):
            lane_result = result.get(lane)
            require(isinstance(lane_result, dict)
                    and lane_result.get("migration", {}).get("probe") == f"{private_mount}/probe-{lane}-observer-{row.name}",
                    f"{row.name}/{lane}: observer probe assignment differs")


def validate_measurement_attempt(checkout: Path, report: Mapping[str, Any], expected_workloads: Sequence[str], *, full: bool) -> list[str]:
    """Rebuild every qualifying metric from retained samples and raw records."""

    reasons: list[str] = []
    try:
        measurement = report.get("measurement")
        expected_measurement = {
            "selected_workloads", "samples", "warmup", "seed", "cgroup_setup", "cgroup_cleanup", "memory", "memory_observers", "workloads",
        }
        require(isinstance(measurement, dict) and set(measurement) == expected_measurement,
                "measurement fields differ")
        selected = measurement.get("selected_workloads")
        require(selected == list(expected_workloads), "selected workload roster differs")
        require(isinstance(selected, list) and len(set(selected)) == len(selected), "selected workload roster repeats a row")
        if full:
            canonical_names = list(canonical_workload_invocations(checkout))
            require(selected == canonical_names and len(selected) == len(canonical_names), "workload subset cannot qualify")
        require(measurement.get("samples") == FULL_SAMPLE_COUNT, "sample count is not 31")
        require(measurement.get("warmup") == FULL_WARMUP_COUNT, "warm-up count is not 3")
        require(type(measurement.get("seed")) is int, "measurement seed is absent")
        _verify_cgroup_lifecycle(checkout, measurement["cgroup_setup"], measurement["cgroup_cleanup"])
        cleanup = measurement["cgroup_cleanup"]
        owned_probe_leaves = cleanup["owned_leaves"]
        execution_roots = report.get("execution", {}).get("roots") if isinstance(report.get("execution"), dict) else None
        require(isinstance(execution_roots, dict) and set(execution_roots) == {"musl", "crabc"},
                "sealed execution roots are absent for memory ownership")
        host: Mapping[str, Any] | None = None
        launcher_output: Mapping[str, Any] | None = None
        if full:
            tools = report.get("tools")
            require(isinstance(tools, dict) and isinstance(tools.get("before"), dict)
                    and isinstance(tools["before"].get("host"), dict),
                    "attempt host record is absent for full sample replay")
            host = tools["before"]["host"]
            build = report.get("build")
            harness = build.get("harness") if isinstance(build, dict) else None
            timing_launcher = harness.get("timing_launcher") if isinstance(harness, dict) else None
            require(isinstance(timing_launcher, dict) and isinstance(timing_launcher.get("output"), dict),
                    "timing launcher harness is absent for full sample replay")
            retained_file_identity(
                checkout, SOURCE_MOUNT, timing_launcher["output"], "timing launcher output for sample replay",
            )
            launcher_output = timing_launcher["output"]
        seen_peers: set[str] = set()
        seen_launcher_artifacts: set[str] = set()
        workloads = measurement.get("workloads")
        require(isinstance(workloads, dict) and set(workloads) == set(selected), "workload metrics roster differs")
        contract = _performance_contract(str(checkout.resolve(strict=True)))
        canonical = canonical_workload_invocations(checkout)
        canonical_observers = canonical_memory_observer_invocations(checkout)
        try:
            rows_by_name = {
                row.name: row
                for row in performance_profile.performance_rows(checkout, contract.WORKLOADS)
            }
        except performance_profile.ProfileError as error:
            raise EvidenceError(str(error)) from error
        for row_index, name in enumerate(selected):
            item = workloads[name]
            require(isinstance(item, dict) and set(item) == {"invocation", "musl", "crabc", "comparison"}, f"{name}: row fields differ")
            invocation = canonical.get(name)
            require(invocation is not None and item["invocation"] == invocation, f"{name}: invocation contract differs")
            seed = measurement["seed"] + row_index
            plan = contract.paired_sample_plan(FULL_SAMPLE_COUNT, seed)
            plan_records = [{"lane": lane, "sample_index": sample_index} for lane, sample_index in plan]
            plan_order = {(lane, sample_index): order for order, (lane, sample_index) in enumerate(plan)}
            for lane in ("musl", "crabc"):
                lane_item = item[lane]
                root_record = execution_roots[lane]
                root_text = root_record.get("root") if isinstance(root_record, dict) else None
                require(isinstance(root_text, str), f"{name}/{lane}: sealed execution root differs")
                attempt_root: Path | None = None
                if full:
                    physical_root = translate_source_path(checkout, SOURCE_MOUNT, root_text)
                    require(physical_root.name == lane and physical_root.parent.name == "roots"
                            and physical_root.parent.parent.name == "execution",
                            f"{name}/{lane}: staged root cannot bind canonical invocation outputs")
                    attempt_root = physical_root.parent.parent.parent
                expected_lane = {
                    "status", "iterations_per_process", "operations_per_process",
                    "warmup_processes", "warmups", "sample_count", "samples", "summary", "syscalls",
                }
                require(isinstance(lane_item, dict) and set(lane_item) == expected_lane and lane_item["status"] == "ok",
                        f"{name}/{lane}: timed lane fields differ")
                require(lane_item["iterations_per_process"] == invocation["iterations_per_process"]
                        and lane_item["operations_per_process"] == invocation["operations_per_process"]
                        and lane_item["warmup_processes"] == FULL_WARMUP_COUNT and lane_item["sample_count"] == FULL_SAMPLE_COUNT,
                        f"{name}/{lane}: row operation, loop, or warm-up contract differs")
                warmups = lane_item["warmups"]
                require(isinstance(warmups, list) and len(warmups) == FULL_WARMUP_COUNT, f"{name}/{lane}: warmup roster differs")
                for warmup_index, warmup in enumerate(warmups):
                    _verify_completed_sample(
                        checkout, warmup, label=f"{name}/{lane}/warmup-{warmup_index}",
                        index_field="warmup_index", index=warmup_index, execution_order=None,
                        launcher_output=launcher_output, root_record=root_text, invocation=invocation,
                        row=rows_by_name[name] if full else None, host=host, seen_peers=seen_peers if full else None,
                        invocation_directory=(
                            attempt_root / "raw" / "execution" / f"warmup-{lane}-{name}-{warmup_index}"
                            if attempt_root is not None else None
                        ),
                        seen_launcher_artifacts=seen_launcher_artifacts if full else None,
                    )
                samples = lane_item["samples"]
                require(isinstance(samples, list) and len(samples) == FULL_SAMPLE_COUNT, f"{name}/{lane}: sample roster differs")
                for sample_index, sample in enumerate(samples):
                    _verify_completed_sample(
                        checkout, sample, label=f"{name}/{lane}/sample-{sample_index}", index_field="sample_index",
                        index=sample_index, execution_order=plan_order[(lane, sample_index)],
                        launcher_output=launcher_output, root_record=root_text, invocation=invocation,
                        row=rows_by_name[name] if full else None, host=host, seen_peers=seen_peers if full else None,
                        invocation_directory=(
                            attempt_root / "raw" / "execution" / f"sample-{lane}-{name}-{sample_index}"
                            if attempt_root is not None else None
                        ),
                        seen_launcher_artifacts=seen_launcher_artifacts if full else None,
                    )
                require(lane_item["summary"] == contract.summarize_samples(samples), f"{name}/{lane}: summary differs")
                _verify_diagnostic(
                    checkout, lane_item["syscalls"], invocation, f"{name}/{lane}",
                    row=rows_by_name[name] if full else None, root_record=root_text,
                    host=host, seen_peers=seen_peers if full else None,
                )
            comparison = item["comparison"]
            require(isinstance(comparison, dict) and set(comparison) == {"status", "seed", "sample_plan", "cpu", "syscall_gate"}
                    and comparison["status"] == "ok" and comparison["seed"] == seed and comparison["sample_plan"] == plan_records,
                    f"{name}: paired sample plan differs")
            reference_cpu = [sample["resources"]["user_cpu_ns"] + sample["resources"]["system_cpu_ns"] for sample in item["musl"]["samples"]]
            candidate_cpu = [sample["resources"]["user_cpu_ns"] + sample["resources"]["system_cpu_ns"] for sample in item["crabc"]["samples"]]
            cpu = contract.bootstrap_cpu_ratio(reference_cpu, candidate_cpu, seed=seed, resamples=CPU_RESAMPLES)
            expected_cpu = {**cpu, "release_gate": "pass" if cpu["one_sided_95_upper"] <= 0.90 else "fail"}
            require(comparison["cpu"] == expected_cpu, f"{name}: bootstrap metric differs")
            expected_gate = scorecard_syscall_gate(
                item["musl"]["syscalls"], item["crabc"]["syscalls"],
                operations=invocation["operations_per_process"],
            )
            require(comparison["syscall_gate"] == expected_gate, f"{name}: syscall gate provenance differs")
        memory = measurement.get("memory")
        require(isinstance(memory, dict) and set(memory) == {"musl", "crabc"}, "allocation memory diagnostics are absent")
        for lane in ("musl", "crabc"):
            root_record = execution_roots.get(lane)
            require(isinstance(root_record, dict) and isinstance(root_record.get("root"), str),
                    f"{lane}: sealed execution root differs")
            _verify_memory_probe(
                checkout, memory[lane], f"{lane}: live allocation", live=True,
                expected_root=root_record["root"], owned_probe_leaves=owned_probe_leaves,
            )
            require(isinstance(root_record, dict)
                    and memory[lane]["mappings"] == execution_roots[lane].get("observed_mappings"),
                    f"{lane}: live mapping observation is not bound to the sealed execution root")
            cgroup = memory[lane]["cgroup_memory"]
            after_ready = cgroup.get("after_ready_self_test")
            require(isinstance(after_ready, dict), f"{lane}: post-ready memory proof is absent")
            # The parent result adds this one nested proof after the live probe;
            # validate its original fields independently.
            _verify_memory_probe(
                checkout, after_ready, f"{lane}: post-ready allocation", live=False,
                expected_root=root_record["root"], owned_probe_leaves=owned_probe_leaves,
            )
        observer_memory = measurement.get("memory_observers")
        if full:
            require(isinstance(observer_memory, dict) and set(observer_memory) == set(selected),
                    "per-workload memory observer metrics are absent")
            private_mount = measurement["cgroup_setup"]["private_mount_command"][4]
            selected_rows: list[performance_profile.PerformanceRow] = []
            for name in selected:
                row = rows_by_name.get(name)
                invocation = canonical_observers.get(name)
                item = observer_memory.get(name) if isinstance(observer_memory, dict) else None
                require(row is not None and invocation is not None and isinstance(item, dict)
                        and set(item) == {"invocation", "musl", "crabc", "comparison"}
                        and item["invocation"] == invocation,
                        f"{name}: observer invocation contract differs")
                selected_rows.append(row)
                for lane in ("musl", "crabc"):
                    root_record = execution_roots[lane]
                    root_text = root_record.get("root") if isinstance(root_record, dict) else None
                    require(isinstance(root_text, str), f"{name}/{lane}: observer root is absent")
                    _verify_memory_observer_result(
                        checkout, item[lane], invocation=invocation, row=row, lane=lane,
                        root=translate_source_path(checkout, SOURCE_MOUNT, root_text),
                        root_record=root_text, private_mount=private_mount,
                        host=host, seen_peers=seen_peers,
                    )
                _verify_memory_observer_comparison(item["comparison"], item["musl"], item["crabc"], name)
            _verify_probe_assignment(memory, observer_memory, selected_rows, owned_probe_leaves, private_mount)
        else:
            require(observer_memory == {}, "partial measurement observer metrics differ")
    except (EvidenceError, peers.PeerError, ValueError, KeyError, TypeError, IndexError) as error:
        reasons.append(str(error))
    return reasons


@dataclass(frozen=True)
class CheckedReport:
    evidence_valid: bool
    release_qualified: bool
    blockers: tuple[str, ...]


def _verify_cpuinfo_diagnostic(checkout: Path, record: object, label: str) -> dict[str, list[str]]:
    """Replay one raw CPU model/frequency observation without freezing it."""

    expected = {"raw", "model_names", "cpu_mhz", "bogomips"}
    require(isinstance(record, dict) and set(record) == expected,
            f"{label} CPU diagnostic fields differ")
    raw = retained_file_identity(checkout, SOURCE_MOUNT, record["raw"], f"{label} raw cpuinfo")
    derived = cpuinfo_diagnostics(raw.read_bytes())
    require(record["model_names"] == derived["model_names"]
            and record["cpu_mhz"] == derived["cpu_mhz"]
            and record["bogomips"] == derived["bogomips"]
            and derived["model_names"] and all(derived["model_names"]),
            f"{label} CPU diagnostic differs from raw cpuinfo")
    return derived


def _verify_stable_cpuinfo_identity(
    checkout: Path,
    host: Mapping[str, Any],
    diagnostics: Mapping[str, Any],
    *,
    index: int,
) -> None:
    """Bind the stable host CPU hash to both retained raw cpuinfo captures."""

    stable_cpu_identity = host.get("cpuinfo_sha256")
    require(isinstance(stable_cpu_identity, str) and re.fullmatch(r"[0-9a-f]{64}", stable_cpu_identity) is not None,
            f"attempt {index} CPU identity is absent")
    before_cpuinfo_raw = retained_file_identity(
        checkout, SOURCE_MOUNT, diagnostics["before"]["raw"], f"attempt {index} before raw cpuinfo",
    )
    after_cpuinfo_raw = retained_file_identity(
        checkout, SOURCE_MOUNT, diagnostics["after"]["raw"], f"attempt {index} after raw cpuinfo",
    )
    require(cpuinfo_identity_sha256(before_cpuinfo_raw.read_bytes()) == stable_cpu_identity
            and cpuinfo_identity_sha256(after_cpuinfo_raw.read_bytes()) == stable_cpu_identity,
            f"attempt {index} stable CPU identity differs from retained cpuinfo")


def _verify_attempt_tools(checkout: Path, attempt: Mapping[str, Any], product: Mapping[str, Any], index: int) -> None:
    tools = attempt["tools"]
    expected = {"before", "after", "host_cpuinfo_diagnostics", "compile_policy", "link_policy"}
    require(isinstance(tools, dict) and set(tools) == expected, f"attempt {index} tool record differs")
    before = tools["before"]
    after = tools["after"]
    snapshot_fields = {
        "candidate_driver", "musl_compiler", "readelf", "strace", "musl_loader", "musl_libc",
        "image_tool_manifest", "host",
    }
    require(isinstance(before, dict) and isinstance(after, dict) and set(before) == snapshot_fields and after == before,
            f"attempt {index} tool/image identity changed during collection")
    diagnostics = tools["host_cpuinfo_diagnostics"]
    require(isinstance(diagnostics, dict) and set(diagnostics) == {"before", "after"},
            f"attempt {index} CPU diagnostic record differs")
    before_cpuinfo = _verify_cpuinfo_diagnostic(checkout, diagnostics["before"], f"attempt {index} before")
    after_cpuinfo = _verify_cpuinfo_diagnostic(checkout, diagnostics["after"], f"attempt {index} after")
    require(before_cpuinfo["model_names"] == after_cpuinfo["model_names"],
            f"attempt {index} CPU model changed during collection")
    candidate_driver = retained_file_identity(checkout, SOURCE_MOUNT, before["candidate_driver"], f"attempt {index} candidate driver")
    require(before["candidate_driver"] == product["driver"], f"attempt {index} candidate driver differs from supplied product")
    _valid_external_identity(before["musl_compiler"], f"attempt {index} musl compiler", FIXED_MUSL_COMPILER)
    _valid_external_identity(before["readelf"], f"attempt {index} readelf", FIXED_READELF)
    _valid_external_identity(before["strace"], f"attempt {index} strace", FIXED_STRACE)
    _valid_external_identity(before["musl_loader"], f"attempt {index} musl loader", FIXED_MUSL_LOADER)
    _valid_external_identity(before["musl_libc"], f"attempt {index} musl libc", FIXED_MUSL_LIBC)
    _verify_image_tool_manifest(checkout, before["image_tool_manifest"], index=index, tools=before)
    require(candidate_driver.name == "crabc-cc-dynamic", f"attempt {index} candidate driver identity is wrong")
    require(tools["compile_policy"] == {
        "flags": list(FIXED_COMPILE_FLAGS),
        "pie": "installed driver --dynamic-pie",
        "pic": "installed driver --dynamic-shared-object",
        "headers": "installed product usr/include",
    }, f"attempt {index} compile policy differs")
    require(tools["link_policy"] == {
        "binding": "now",
        "hash_style": "sysv",
        "runpath": APP_RUNPATH,
        "candidate": "installed bin/crabc-cc-dynamic",
        "reference": FIXED_MUSL_COMPILER,
    }, f"attempt {index} link policy differs")
    host = before["host"]
    expected_host = {
        "system", "machine", "kernel_release", "cpuinfo_sha256", "benchmark_cpu",
        "allowed_affinity_before_pin", "peer_cpu", "affinity", "cache_topology", "governor",
        "environment", "docker_image_id",
    }
    require(isinstance(host, dict) and set(host) == expected_host, f"attempt {index} host record differs")
    require(host["system"] == "Linux" and str(host["machine"]).lower() in {"x86_64", "amd64"}, f"attempt {index} host is not native Linux/x86-64")
    require(isinstance(host["kernel_release"], str) and host["kernel_release"], f"attempt {index} kernel identity is absent")
    _verify_stable_cpuinfo_identity(checkout, host, diagnostics, index=index)
    require(type(host["benchmark_cpu"]) is int and isinstance(host["affinity"], list) and host["affinity"] == [host["benchmark_cpu"]], f"attempt {index} affinity is not pinned")
    allowed_affinity = host["allowed_affinity_before_pin"]
    require(isinstance(allowed_affinity, list) and allowed_affinity
            and all(type(cpu) is int for cpu in allowed_affinity)
            and allowed_affinity == sorted(set(allowed_affinity))
            and host["benchmark_cpu"] in allowed_affinity,
            f"attempt {index} original controller affinity differs")
    peer_cpu = host["peer_cpu"]
    require(peer_cpu is None or (
        type(peer_cpu) is int and peer_cpu in allowed_affinity and peer_cpu != host["benchmark_cpu"]
    ), f"attempt {index} peer CPU differs from the original allowed affinity")
    require(isinstance(host["cache_topology"], dict), f"attempt {index} cache topology is absent")
    require(isinstance(host["governor"], dict) and set(host["governor"]) == {"scaling_governor", "scaling_available_governors"}, f"attempt {index} governor availability differs")
    require(isinstance(host["environment"], dict), f"attempt {index} environment record is absent")
    require(host["environment"].get("CRABC_PERF_CONTAINER_POLICY") == PERFORMANCE_CONTAINER_POLICY, f"attempt {index} container authority differs")
    require(isinstance(host["docker_image_id"], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", host["docker_image_id"]) is not None
            and host["docker_image_id"] == attempt["attempt"]["docker_image_id"], f"attempt {index} image provenance differs")


def _verify_attempt_source(
    checkout: Path,
    attempt: Mapping[str, Any],
    *,
    index: int,
    collector_revision: str,
    collector_digest: str,
) -> None:
    """Require exact before/after source bytes and full-source provenance."""

    source = attempt["source"]
    require(isinstance(source, dict) and set(source) == {
        "before", "after", "source_sha256_before", "source_sha256_after",
    }, f"attempt {index} source fields differ")
    expected_names = {f"source:{name}" for name in FULL_SOURCE_NAMES} | {
        f"header:{name}" for name in FULL_HEADER_PATHS
    }
    require(isinstance(source["before"], dict) and set(source["before"]) == expected_names,
            f"attempt {index} source roster differs")
    verify_file_seal(checkout, SOURCE_MOUNT, source["before"], f"attempt {index} source before")
    verify_file_seal(checkout, SOURCE_MOUNT, source["after"], f"attempt {index} source after")
    require(source["before"] == source["after"], f"attempt {index} source changed during collection")
    for name, relative in FULL_SOURCE_PATHS.items():
        record = source["before"][f"source:{name}"]
        require(record["path"] == f"{SOURCE_MOUNT}/{relative}",
                f"attempt {index} fixed source path differs for {name}")
    for header, relative in FULL_HEADER_PATHS.items():
        record = source["before"][f"header:{header}"]
        require(record["path"] == f"{SOURCE_MOUNT}/{relative}",
                f"attempt {index} header path differs for {header}")
    roster = attempt.get("attempt", {}).get("roster") if isinstance(attempt.get("attempt"), dict) else None
    request = roster.get("request") if isinstance(roster, dict) else None
    work_dir = request.get("work_dir") if isinstance(request, dict) else None
    require(isinstance(work_dir, str) and work_dir.startswith(SOURCE_MOUNT + "/.work/x86_64/"),
            f"attempt {index} source has no immutable work request")
    for name in ("symbols_1", "symbols_1024", *(f"graph:{entry}" for entry in GRAPH_SOURCES)):
        record = source["before"][f"source:{name}"]
        filename = f"{name.removeprefix('graph:')}.c"
        require(record["path"] == f"{work_dir}/build/generated/{filename}",
                f"attempt {index} generated source path differs for {name}")
        generated = retained_file_identity(checkout, SOURCE_MOUNT, record, f"attempt {index} generated source {name}")
        require(generated.read_text(encoding="utf-8") == generated_source_contents(name),
                f"attempt {index} generated source contents differ for {name}")
    for field in ("source_sha256_before", "source_sha256_after"):
        require(isinstance(source[field], str) and re.fullmatch(r"[0-9a-f]{64}", source[field]) is not None,
                f"attempt {index} {field} differs")
    require(source["source_sha256_before"] == source["source_sha256_after"] == collector_digest,
            f"attempt {index} full source digest changed during collection")
    require(attempt["attempt"]["source_revision"] == collector_revision,
            f"attempt {index} source revision differs")


def _verify_collector_roster(
    checkout: Path,
    roster_path: Path,
    collector: Mapping[str, Any],
) -> tuple[Mapping[str, Any], ...]:
    """Replay the immutable request list that prevents favourable selection.

    Retaining a roster-file hash alone only proves that every attempt named the
    same file.  This reader also binds each report to that file's ordered
    request, its exact sibling work directory, and its predecessor chain.
    """

    roster = load_json(roster_path, "collector attempt roster")
    expected = {
        "schema", "kind", "status", "source_mount", "source_revision", "source_sha256", "product",
        "dynamic_product_qualification", "correctness_admission", "attempts",
    }
    require(set(roster) == expected and roster["schema"] == ROSTER_SCHEMA and roster["kind"] == ROSTER_KIND
            and roster["status"] == "planned" and roster["source_mount"] == SOURCE_MOUNT,
            "collector attempt roster fields differ")
    for field in ("source_revision", "source_sha256", "product", "dynamic_product_qualification", "correctness_admission"):
        require(roster[field] == collector[field], f"collector attempt roster {field} differs")
    attempts = roster["attempts"]
    require(isinstance(attempts, list) and len(attempts) == COLLECTOR_ATTEMPTS,
            "collector attempt roster count differs")
    planned: list[Mapping[str, Any]] = []
    for index, request in enumerate(attempts, start=1):
        require(isinstance(request, dict) and set(request) == {"index", "work_dir", "report", "predecessor_report"}
                and request["index"] == index,
                "collector attempt roster request differs")
        work = translate_source_path(checkout, SOURCE_MOUNT, request["work_dir"])
        report = translate_source_path(checkout, SOURCE_MOUNT, request["report"])
        require(work.is_dir() and work == roster_path.parent / f"attempt-{index}"
                and report.is_file() and report == work / "report.json",
                "collector attempt roster paths differ")
        predecessor = None if index == 1 else attempts[index - 2]["report"]
        require(request["predecessor_report"] == predecessor,
                "collector attempt roster predecessor differs")
        planned.append(request)
    return tuple(planned)

def validate_collector_report(checkout: Path, report_path: Path, expected_workloads: Sequence[str]) -> CheckedReport:
    """Replay all retained paths and reject a partial/favourably selected trio."""

    report = load_json(report_path, "native performance collector report")
    expected = {
        "schema", "kind", "status", "source_mount", "collector", "attempts", "release", "absent_scorecard_obligations",
    }
    require(set(report) == expected, "collector report fields drifted")
    require(report["schema"] == SCHEMA and report["kind"] == KIND, "collector report identity differs")
    require(report["source_mount"] == SOURCE_MOUNT, "collector source mount differs")
    require(report["status"] == "complete-evidence", "collector did not retain complete evidence")
    require(report["absent_scorecard_obligations"] == ABSENT_SCORECARD_OBLIGATIONS, "collector scorecard obligations drifted")
    collector = report["collector"]
    require(isinstance(collector, dict) and set(collector) == {
        "attempt_roster", "dynamic_product_qualification", "correctness_admission", "attempt_count",
        "source", "source_revision", "source_sha256", "product",
    }, "collector fields differ")
    require(collector["attempt_count"] == COLLECTOR_ATTEMPTS, "collector did not require three attempts")
    roster = retained_file_identity(checkout, SOURCE_MOUNT, collector["attempt_roster"], "collector attempt roster")
    dynamic = collector["dynamic_product_qualification"]
    require(isinstance(dynamic, dict) and dynamic.get("status") == "validated-product-prerequisite"
            and set(dynamic) == {"status", "receipt", "source_sha256", "products"},
            "collector lacks a validated dynamic-product prerequisite")
    admission = collector["correctness_admission"]
    # No complete correctness-closed predecessor reader exists yet.  A file
    # called "complete" or a generic owner/receipt pair is not authority to
    # turn this adapter into a release collector.  Keep replay fail-closed
    # until that concrete owner is wired here with its own validator.
    correctness_unavailable = admission == {
        "status": "unavailable",
        "required_owner": COMPLETE_CORRECTNESS_OWNER,
        "reason": "no complete correctness-closed predecessor-chain reader is available",
    }
    require(correctness_unavailable,
            "collector correctness admission is self-attested or differs")
    planned_attempts = _verify_collector_roster(checkout, roster, collector)
    verify_file_seal(checkout, SOURCE_MOUNT, collector["source"], "collector source")
    require(isinstance(collector["source_revision"], str) and re.fullmatch(r"[0-9a-f]{40}", collector["source_revision"]) is not None, "collector source revision differs")
    require(isinstance(collector["source_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", collector["source_sha256"]) is not None,
            "collector source digest differs")
    product_path = verify_dynamic_product_identity(checkout, SOURCE_MOUNT, collector["product"])
    verify_dynamic_product_prerequisite(checkout, dynamic, collector["product"], collector["source_sha256"])
    attempts = report["attempts"]
    require(isinstance(attempts, list) and len(attempts) == COLLECTOR_ATTEMPTS, "collector must retain exactly three attempts")
    seen_indices: set[int] = set()
    seen_paths: set[str] = set()
    seen_fingerprints: set[tuple[str, str, str]] = set()
    seen_nonces: set[str] = set()
    image_ids: set[str] = set()
    for expected_order, entry in enumerate(attempts, start=1):
        require(isinstance(entry, dict) and set(entry) == {"index", "report"}, "collector attempt entry differs")
        index = entry["index"]
        require(type(index) is int and 1 <= index <= COLLECTOR_ATTEMPTS and index not in seen_indices, "collector attempt indices are not exact")
        require(index == expected_order, "collector attempts are not in immutable roster order")
        seen_indices.add(index)
        report_record = entry["report"]
        path = retained_file_identity(checkout, SOURCE_MOUNT, report_record, f"collector attempt {index}")
        recorded_path = report_record["path"]
        require(recorded_path not in seen_paths, "collector selected one attempt report more than once")
        seen_paths.add(recorded_path)
        attempt = load_json(path, f"collector attempt {index} report")
        attempt_expected = {
            "schema", "kind", "status", "source_mount", "attempt", "source", "product", "tools", "build", "execution", "measurement", "release",
        }
        require(set(attempt) == attempt_expected, f"attempt {index} fields drifted")
        require(attempt["schema"] == SCHEMA and attempt["kind"] == KIND, f"attempt {index} identity differs")
        require(attempt["source_mount"] == SOURCE_MOUNT and attempt["status"] == "complete-evidence", f"attempt {index} is incomplete")
        attempt_info = attempt["attempt"]
        require(isinstance(attempt_info, dict) and set(attempt_info) == {
            "index", "docker_image_id", "invocation_nonce", "clean_revision", "source_revision", "roster",
        }, f"attempt {index} provenance differs")
        require(attempt_info["index"] == index, f"attempt {index} index differs")
        require(isinstance(attempt_info["docker_image_id"], str) and attempt_info["docker_image_id"], f"attempt {index} lacks Docker image ID")
        require(isinstance(attempt_info["invocation_nonce"], str) and len(attempt_info["invocation_nonce"]) >= 16, f"attempt {index} lacks invocation nonce")
        require(attempt_info["clean_revision"] is True, f"attempt {index} did not start clean")
        require(isinstance(attempt_info["source_revision"], str) and attempt_info["source_revision"] == collector["source_revision"], f"attempt {index} source revision differs")
        roster_binding = attempt_info["roster"]
        require(isinstance(roster_binding, dict) and set(roster_binding) == {"status", "plan", "request", "predecessor"}
                and roster_binding["status"] == "bound" and roster_binding["plan"] == collector["attempt_roster"],
                f"attempt {index} is not bound to the collector's immutable roster")
        request = roster_binding["request"]
        require(request == planned_attempts[index - 1], f"attempt {index} roster request differs")
        require(report_record["path"] == planned_attempts[index - 1]["report"],
                f"attempt {index} report is not the immutable roster report")
        if index == 1:
            require(roster_binding["predecessor"] is None, "first attempt unexpectedly has a predecessor")
        else:
            previous = attempts[index - 2]["report"]
            require(roster_binding["predecessor"] == previous,
                    f"attempt {index} does not bind its immediate ordered predecessor")
        require(attempt_info["invocation_nonce"] not in seen_nonces, "collector reused a favourable attempt")
        seen_nonces.add(attempt_info["invocation_nonce"])
        image_ids.add(attempt_info["docker_image_id"])
        _verify_attempt_source(
            checkout, attempt, index=index,
            collector_revision=collector["source_revision"],
            collector_digest=collector["source_sha256"],
        )
        attempt_product_path = verify_dynamic_product_identity(checkout, SOURCE_MOUNT, attempt["product"]["before"])
        verify_dynamic_product_identity(checkout, SOURCE_MOUNT, attempt["product"]["after"])
        require(attempt["product"]["before"] == attempt["product"]["after"], f"attempt {index} product changed during collection")
        require(attempt_product_path == product_path, f"attempt {index} used a different supplied product")
        # Product identity validation returns a physical path.  Tool replay
        # additionally needs the sealed product record so it can bind the
        # candidate driver's retained identity to ``product[\"driver\"]``.
        _verify_attempt_tools(checkout, attempt, attempt["product"]["before"], index)
        _verify_attempt_build(checkout, attempt, index)
        _verify_attempt_execution(checkout, attempt, index)
        reasons = validate_measurement_attempt(checkout, attempt, expected_workloads, full=True)
        if reasons:
            raise EvidenceError(f"attempt {index} cannot qualify: {reasons[0]}")
        fingerprint = (
            attempt_info["docker_image_id"],
            attempt_info["invocation_nonce"],
            attempt["product"]["before"]["manifest"]["sha256"],
        )
        require(fingerprint not in seen_fingerprints, "collector reused a favourable attempt")
        seen_fingerprints.add(fingerprint)
    require(seen_indices == {1, 2, 3}, "collector omitted an attempt index")
    require(len(image_ids) == 1, "collector attempts used different Docker images")
    release = report["release"]
    require(isinstance(release, dict) and set(release) == {"qualified", "reason"}, "collector release fields differ")
    require(release == {"qualified": False, "reason": "named scorecard obligations remain absent"}, "collector must retain the unresolved release boundary")
    raise EvidenceError(
        "collector cannot qualify while the complete correctness-closed predecessor reader is unavailable"
    )


def _verify_identity_tree(checkout: Path, value: object, label: str) -> None:
    """Replay a tree whose leaves are retained ordinary-file identities."""

    if isinstance(value, dict) and set(value) == IDENTITY_FIELDS:
        retained_file_identity(checkout, SOURCE_MOUNT, value, label)
        return
    require(isinstance(value, dict) and value, f"{label} is not a retained identity tree")
    for name, child in value.items():
        require(isinstance(name, str) and name, f"{label} has an invalid identity-tree name")
        _verify_identity_tree(checkout, child, f"{label}/{name}")


def _expected_link_needed(name: str) -> list[str]:
    if name in GRAPH_NEEDED:
        return GRAPH_NEEDED[name]
    require(name in FULL_LINK_NAMES,
            f"unrecognized native performance link output: {name}")
    return ["libc.so"]


def _expected_graph_record(name: str) -> tuple[list[str], dict[str, list[str]]]:
    """Return the exact direct roots and validation-only closure for each graph link."""

    if name == "libbench_graph_root.so":
        closure_names = (
            "libbench_graph_leaf_left.so", "libbench_graph_leaf_right.so",
            "libbench_graph_mid_left.so", "libbench_graph_mid_right.so",
        )
        return (
            ["libbench_graph_mid_left.so", "libbench_graph_mid_right.so"],
            {entry: list(GRAPH_NEEDED[entry]) for entry in closure_names},
        )
    if name in {"graph", "x86_64_memory_observer_graph"}:
        return (
            ["libbench_graph_root.so"],
            {entry: list(GRAPH_NEEDED[entry]) for entry in sorted(GRAPH_DSO_NAMES)},
        )
    raise EvidenceError(f"unrecognized dynamic graph link output: {name}")


def _verify_readelf_record(
    checkout: Path,
    raw: object,
    output_record: Mapping[str, Any],
    *,
    provider: str,
    name: str,
    index: int,
) -> None:
    """Bind each retained readelf stream to the precise provider output."""

    expected_keys = {"header", "program_headers", "dynamic", "dynamic_symbols", "link_stdout", "link_stderr"}
    if provider == "candidate":
        expected_keys.add("receipt")
    require(isinstance(raw, dict) and set(raw) == expected_keys, f"attempt {index} {provider} raw {name} differs")
    output_path = output_record.get("path")
    require(isinstance(output_path, str), f"attempt {index} {provider} output path differs")
    output = retained_file_identity(checkout, SOURCE_MOUNT, output_record,
                                    f"attempt {index} {provider} output")
    commands = {
        "header": ["-hW"],
        "program_headers": ["-lW"],
        "dynamic": ["-dW"],
        "dynamic_symbols": ["--dyn-syms", "-W"],
    }
    streams: dict[str, Path] = {}
    for kind, arguments in commands.items():
        item = raw[kind]
        require(isinstance(item, dict) and set(item) == {"command", "status", "output", "stderr"},
                f"attempt {index} {provider} readelf {kind} fields differ")
        require(item["command"] == [FIXED_READELF, *arguments, output_path]
                and item["status"] == {"kind": "exit", "code": 0},
                f"attempt {index} {provider} readelf {kind} command differs")
        streams[kind] = retained_file_identity(checkout, SOURCE_MOUNT, item["output"],
                                                f"attempt {index} {provider} readelf {kind} output")
        retained_file_identity(checkout, SOURCE_MOUNT, item["stderr"],
                               f"attempt {index} {provider} readelf {kind} stderr")
    retained_file_identity(checkout, SOURCE_MOUNT, raw["link_stdout"], f"attempt {index} {provider} link stdout")
    retained_file_identity(checkout, SOURCE_MOUNT, raw["link_stderr"], f"attempt {index} {provider} link stderr")
    if provider == "candidate":
        retained_file_identity(checkout, SOURCE_MOUNT, raw["receipt"], f"attempt {index} candidate link receipt")
    parse_x86_64_dyn_header(streams["header"].read_text(encoding="utf-8", errors="replace"))
    dynamic_symbols = streams["dynamic_symbols"].read_text(encoding="utf-8", errors="replace")
    require("Symbol table '.dynsym'" in dynamic_symbols and "libc.so" in streams["dynamic"].read_text(encoding="utf-8", errors="replace"),
            f"attempt {index} {provider} dynamic symbol/raw section differs for {name}")
    dynamic = parse_dynamic_section(streams["dynamic"].read_text(encoding="utf-8", errors="replace"))
    require(dynamic == {
        "needed": _expected_link_needed(name),
        "runpath": [APP_RUNPATH],
        "rpath": [],
        "hashes": ["sysv"],
    }, f"attempt {index} {provider} dynamic ELF contract differs for {name}")
    interpreters = parse_program_interpreters(streams["program_headers"].read_text(encoding="utf-8", errors="replace"))
    physical = physical_x86_64_dynamic_facts(output)
    require(physical == {"interpreters": interpreters, **dynamic},
            f"attempt {index} {provider} retained readelf facts do not match physical ELF output")
    if name.endswith(".so"):
        require(not interpreters, f"attempt {index} {provider} shared DSO has PT_INTERP")
    else:
        expected_interpreter = "/lib/ld-crabc-x86_64.so.1" if provider == "candidate" else FIXED_MUSL_LOADER
        require(interpreters == [expected_interpreter], f"attempt {index} {provider} PT_INTERP differs for {name}")


def _verify_dynamic_graph_record(checkout: Path, attempt: Mapping[str, Any], candidate: Mapping[str, Any], graph: object, index: int, name: str) -> None:
    expected = {"receipt", "output", "dynamic_raw", "direct_dsos", "closure_needed"}
    require(isinstance(graph, dict) and set(graph) == expected, f"attempt {index} {name} dynamic graph record differs")
    receipt = retained_file_identity(checkout, SOURCE_MOUNT, graph["receipt"], f"attempt {index} {name} graph receipt")
    output = retained_file_identity(checkout, SOURCE_MOUNT, graph["output"], f"attempt {index} {name} graph output")
    dynamic_raw = retained_file_identity(checkout, SOURCE_MOUNT, graph["dynamic_raw"], f"attempt {index} {name} graph dynamic raw")
    require(candidate["output"] == graph["output"], f"attempt {index} {name} graph output is not the candidate output")
    raw = candidate["raw"]
    require(isinstance(raw, dict) and raw.get("receipt") == graph["receipt"], f"attempt {index} {name} graph receipt is not candidate link evidence")
    dynamic_raw_record = raw.get("dynamic", {}).get("output") if isinstance(raw.get("dynamic"), dict) else None
    require(dynamic_raw_record == graph["dynamic_raw"], f"attempt {index} {name} graph dynamic section differs")
    direct = graph["direct_dsos"]
    closure = graph["closure_needed"]
    require(isinstance(direct, list) and all(isinstance(value, str) and value for value in direct) and len(set(direct)) == len(direct), f"attempt {index} {name} graph direct roster differs")
    require(isinstance(closure, dict) and closure and all(isinstance(key, str) and isinstance(value, list) and all(isinstance(edge, str) for edge in value) for key, value in closure.items()), f"attempt {index} {name} graph closure differs")
    expected_direct, expected_closure = _expected_graph_record(name)
    require(direct == expected_direct and closure == expected_closure,
            f"attempt {index} {name} graph direct/closure contract differs")
    product = translate_source_path(checkout, SOURCE_MOUNT, str(attempt["product"]["before"]["root"]))
    validate_dynamic_graph_receipt(
        checkout=checkout,
        product=product,
        receipt_path=receipt,
        output=output,
        dynamic_raw=dynamic_raw,
        expected_direct=direct,
        expected_needed=closure,
        expected_search_path=APP_RUNPATH,
    )


def _supplemental_fixture_contract(checkout: Path) -> Mapping[str, performance_profile.SupplementalFixture]:
    """Read the sealed profile's fixed source/flag contract for replay."""

    try:
        return performance_profile.supplemental_fixtures(performance_profile.load_profile(checkout))
    except performance_profile.ProfileError as error:
        raise EvidenceError(str(error)) from error


def _object_source_owner(name: str) -> str:
    if name.startswith("tls_"):
        return "tls_growth"
    return name


def _expected_object_mode(name: str) -> str:
    pie_objects = {
        "workload", "constructor", "startup_graph",
        *(f"supplemental:{artifact}" for artifact in SUPPLEMENTAL_TIMED_LINK_NAMES),
        *(f"memory_observer:{artifact}" for artifact in LEGACY_MEMORY_LINK_NAMES),
        *(f"memory_observer:{artifact}" for artifact in SUPPLEMENTAL_MEMORY_LINK_NAMES),
    }
    return "--dynamic-pie" if name in pie_objects else "--dynamic-shared-object"


def _expected_object_defines(
    checkout: Path,
    name: str,
) -> list[str]:
    if name.startswith("tls_"):
        suffix = name.removeprefix("tls_")
        require(suffix.isdecimal() and 0 <= int(suffix) < 8,
                f"unrecognized TLS object: {name}")
        return [f"-DTLS_GROWTH_INDEX={suffix}"]
    if name.startswith("supplemental:"):
        artifact = name.removeprefix("supplemental:")
        fixture = _supplemental_fixture_contract(checkout).get(artifact)
        require(fixture is not None, f"supplemental compile contract is absent: {artifact}")
        return [f"-D{value}" for value in fixture.compile_defines]
    return []


def _expected_link_flags(checkout: Path, name: str) -> list[str]:
    """Return the profile-owned ordinary C flags for one executable link."""

    if name in SUPPLEMENTAL_TIMED_LINK_NAMES:
        fixture = _supplemental_fixture_contract(checkout).get(name)
        require(fixture is not None, f"supplemental link contract is absent: {name}")
        return list(fixture.link_flags)
    for family, observer in performance_profile.SUPPLEMENTAL_MEMORY_ARTIFACTS.items():
        if observer == name:
            fixture = _supplemental_fixture_contract(checkout).get(family)
            require(fixture is not None, f"supplemental observer link contract is absent: {name}")
            return list(fixture.link_flags)
    return []


def _expected_link_object(name: str) -> str:
    if name == "graph":
        return "startup_graph"
    if name in {"workload", "constructor"}:
        return name
    if name.startswith("libsymbols_"):
        return name.removesuffix(".so").removeprefix("lib")
    if name.startswith("libbench_tls_growth_"):
        suffix = name.removesuffix(".so").removeprefix("libbench_tls_growth_")
        require(suffix.isdecimal() and 0 <= int(suffix) < 8,
                f"unrecognized TLS link output: {name}")
        return f"tls_{suffix}"
    if name.startswith("libbench_graph_"):
        return f"graph:{name}"
    if name in SUPPLEMENTAL_TIMED_LINK_NAMES:
        return f"supplemental:{name}"
    if name in LEGACY_MEMORY_LINK_NAMES or name in SUPPLEMENTAL_MEMORY_LINK_NAMES:
        return f"memory_observer:{name}"
    raise EvidenceError(f"unrecognized native performance link object: {name}")


def _verify_timing_launcher_harness(
    checkout: Path,
    harness: object,
    source_seal: Mapping[str, Any],
    *,
    index: int,
) -> Mapping[str, Any]:
    """Replay the static supervisor without treating it as a provider input."""

    require(isinstance(harness, dict) and set(harness) == {"timing_launcher"},
            f"attempt {index} harness roster differs")
    launcher = harness["timing_launcher"]
    expected = {"source", "output", "compile_command", "compile_raw", "readelf"}
    require(isinstance(launcher, dict) and set(launcher) == expected,
            f"attempt {index} timing launcher fields differ")
    source = retained_file_identity(checkout, SOURCE_MOUNT, launcher["source"],
                                    f"attempt {index} timing launcher source")
    output = retained_file_identity(checkout, SOURCE_MOUNT, launcher["output"],
                                    f"attempt {index} timing launcher output")
    require(launcher["source"] == source_seal["source:timing_launcher"]
            and launcher["source"]["path"] == f"{SOURCE_MOUNT}/{TIMING_LAUNCHER_SOURCE}",
            f"attempt {index} timing launcher source differs")
    command = launcher["compile_command"]
    require(command == [FIXED_MUSL_COMPILER, *TIMING_LAUNCHER_FLAGS, launcher["source"]["path"], "-o", launcher["output"]["path"]],
            f"attempt {index} timing launcher compile command differs")
    raw = launcher["compile_raw"]
    require(isinstance(raw, dict) and set(raw) == {"stdout", "stderr"},
            f"attempt {index} timing launcher compile raw differs")
    retained_file_identity(checkout, SOURCE_MOUNT, raw["stdout"], f"attempt {index} timing launcher compile stdout")
    retained_file_identity(checkout, SOURCE_MOUNT, raw["stderr"], f"attempt {index} timing launcher compile stderr")
    readelf = launcher["readelf"]
    expected_reads = {"header": ["-hW"], "program_headers": ["-lW"]}
    require(isinstance(readelf, dict) and set(readelf) == set(expected_reads),
            f"attempt {index} timing launcher readelf roster differs")
    outputs: dict[str, Path] = {}
    for name, arguments in expected_reads.items():
        record = readelf[name]
        require(isinstance(record, dict) and set(record) == {"command", "status", "output", "stderr"}
                and record["command"] == [FIXED_READELF, *arguments, launcher["output"]["path"]]
                and record["status"] == {"kind": "exit", "code": 0},
                f"attempt {index} timing launcher readelf {name} differs")
        outputs[name] = retained_file_identity(checkout, SOURCE_MOUNT, record["output"],
                                                f"attempt {index} timing launcher readelf {name} output")
        retained_file_identity(checkout, SOURCE_MOUNT, record["stderr"],
                               f"attempt {index} timing launcher readelf {name} stderr")
    parse_x86_64_static_exec_header(outputs["header"].read_text(encoding="utf-8", errors="replace"))
    require(not parse_program_interpreters(outputs["program_headers"].read_text(encoding="utf-8", errors="replace")),
            f"attempt {index} timing launcher has PT_INTERP")
    require(physical_x86_64_static_exec_facts(output) == {"interpreters": [], "dynamic_segments": 0},
            f"attempt {index} timing launcher physical ELF differs")
    return launcher


def _verify_attempt_build(checkout: Path, attempt: Mapping[str, Any], index: int) -> None:
    build = attempt["build"]
    require(isinstance(build, dict) and set(build) == {
        "objects", "links", "harness", "same_object_input_proof", "same_object_input_proof_file",
        "companion_same_object_input_proof",
    }, f"attempt {index} build fields differ")
    objects = build["objects"]
    require(isinstance(objects, dict) and set(objects) == FULL_OBJECT_NAMES,
            f"attempt {index} object roster differs")
    source_seal = attempt.get("source", {}).get("before") if isinstance(attempt.get("source"), dict) else None
    require(isinstance(source_seal, dict), f"attempt {index} source seal is absent")
    tools = attempt.get("tools")
    require(isinstance(tools, dict) and isinstance(tools.get("before"), dict),
            f"attempt {index} tool snapshot is absent")
    driver_path = tools["before"]["candidate_driver"].get("path")
    require(isinstance(driver_path, str), f"attempt {index} candidate driver path is absent")
    _verify_timing_launcher_harness(checkout, build["harness"], source_seal, index=index)
    object_paths: dict[str, Mapping[str, Any]] = {}
    for name, item in objects.items():
        expected_object = {"source", "object", "mode", "compile_command", "raw"}
        require(isinstance(name, str) and isinstance(item, dict) and set(item) == expected_object, f"attempt {index} object record differs")
        source = retained_file_identity(checkout, SOURCE_MOUNT, item["source"], f"attempt {index} source object {name}")
        object_file = retained_file_identity(checkout, SOURCE_MOUNT, item["object"], f"attempt {index} compiled object {name}")
        source_owner = _object_source_owner(name)
        require(item["source"] == source_seal[f"source:{source_owner}"],
                f"attempt {index} object {name} is not bound to its canonical sealed source")
        mode = item["mode"]
        expected_mode = _expected_object_mode(name)
        require(mode == expected_mode, f"attempt {index} object mode differs")
        command = item["compile_command"]
        require(isinstance(command, list) and all(isinstance(value, str) for value in command), f"attempt {index} compile command is absent")
        require(command[:2] == [driver_path, mode], f"attempt {index} object did not use the installed dynamic driver")
        for flag in FIXED_COMPILE_FLAGS:
            require(command.count(flag) == 1, f"attempt {index} object compile policy differs")
        prefix = [driver_path, mode, *FIXED_COMPILE_FLAGS, "--application-quote-include-dir", f"{SOURCE_MOUNT}/compat/perf/fixtures"]
        require(command[:len(prefix)] == prefix and command.count("--application-quote-include-dir") == 1,
                f"attempt {index} object did not use the installed performance headers")
        require(command.count("-c") == 1 and command.count("-o") == 1
                and command[command.index("-c") + 1] == item["source"]["path"]
                and command[command.index("-o") + 1] == item["object"]["path"],
                f"attempt {index} object compile input/output differs")
        extras = command[len(prefix):command.index("-c")]
        require(extras == _expected_object_defines(checkout, name),
                f"attempt {index} object compile defines differ")
        _verify_identity_tree(checkout, item["raw"], f"attempt {index} compile raw {name}")
        object_paths[str(item["object"]["path"])] = item["object"]
    links = build["links"]
    require(isinstance(links, dict) and set(links) == FULL_LINK_NAMES,
            f"attempt {index} link roster differs")
    for name, link in links.items():
        require(isinstance(name, str) and isinstance(link, dict), f"attempt {index} link record differs")
        expected = {"objects", "candidate", "musl"} | ({"dynamic_graph"} if "dynamic_graph" in link else set())
        require(set(link) == expected, f"attempt {index} link fields differ")
        require(("dynamic_graph" in link) == (name in GRAPH_LINK_NAMES),
                f"attempt {index} graph receipt roster differs")
        shared_objects = link["objects"]
        require(isinstance(shared_objects, list) and shared_objects, f"attempt {index} link lacks objects")
        shared_paths: list[str] = []
        for record in shared_objects:
            retained_file_identity(checkout, SOURCE_MOUNT, record, f"attempt {index} shared link object")
            path = record.get("path") if isinstance(record, dict) else None
            require(isinstance(path, str) and path in object_paths and object_paths[path] == record, f"attempt {index} link uses an untracked object")
            shared_paths.append(path)
        require(len(shared_paths) == len(set(shared_paths)), f"attempt {index} link repeats an application object")
        expected_object = objects[_expected_link_object(name)]["object"]
        require(shared_paths == [expected_object["path"]],
                f"attempt {index} link does not use its exact canonical object")
        providers: dict[str, Mapping[str, Any]] = {}
        for provider in ("candidate", "musl"):
            value = link[provider]
            require(isinstance(value, dict) and set(value) == {
                "output", "command", "raw", "direct_inputs", "validated_closure",
            }, f"attempt {index} {provider} link differs")
            retained_file_identity(checkout, SOURCE_MOUNT, value["output"], f"attempt {index} {provider} output")
            command = value["command"]
            require(isinstance(command, list) and all(isinstance(argument, str) for argument in command) and command, f"attempt {index} {provider} command is absent")
            if provider == "candidate":
                require(command[0] == driver_path, f"attempt {index} candidate link bypassed installed driver")
            else:
                require(command[0] == FIXED_MUSL_COMPILER, f"attempt {index} musl link used a different compiler")
            require(command.count("-o") == 1 and command[command.index("-o") + 1] == value["output"]["path"],
                    f"attempt {index} {provider} link output differs")
            expected_link_flags = _expected_link_flags(checkout, name)
            for flag in expected_link_flags:
                require(command.count(flag) == 1,
                        f"attempt {index} {provider} link omitted profile flag {flag}")
            require(command.count("-pthread") == expected_link_flags.count("-pthread"),
                    f"attempt {index} {provider} link pthread policy differs")
            for path in shared_paths:
                require(command.count(path) == 1, f"attempt {index} {provider} link did not receive the exact shared object")
            direct = value["direct_inputs"]
            require(isinstance(direct, list), f"attempt {index} {provider} direct DSO inputs differ")
            direct_paths: list[str] = []
            for record in direct:
                retained_file_identity(checkout, SOURCE_MOUNT, record, f"attempt {index} {provider} direct DSO input")
                require(isinstance(record, dict) and isinstance(record.get("path"), str),
                        f"attempt {index} {provider} direct DSO identity differs")
                direct_paths.append(record["path"])
            require(len(direct_paths) == len(set(direct_paths)),
                    f"attempt {index} {provider} repeats a direct DSO")
            closure = value["validated_closure"]
            require(isinstance(closure, list), f"attempt {index} {provider} closure differs")
            closure_paths: list[str] = []
            for record in closure:
                retained_file_identity(checkout, SOURCE_MOUNT, record, f"attempt {index} {provider} closure input")
                require(isinstance(record, dict) and isinstance(record.get("path"), str), f"attempt {index} {provider} closure identity differs")
                closure_paths.append(record["path"])
            require(len(closure_paths) == len(set(closure_paths)), f"attempt {index} {provider} closure repeats a DSO")
            require(not (set(direct_paths) & set(closure_paths)),
                    f"attempt {index} {provider} confuses direct and validation-only DSOs")
            if provider == "candidate":
                direct_positions = [position for position, value_ in enumerate(command) if value_ == "--application-dso"]
                require(all(position + 1 < len(command) for position in direct_positions),
                        f"attempt {index} candidate direct DSO flag is incomplete")
                require([command[position + 1] for position in direct_positions] == direct_paths,
                        f"attempt {index} candidate direct DSO command differs")
                transitive_positions = [position for position, value_ in enumerate(command) if value_ == "--transitive-application-dso"]
                require(all(position + 1 < len(command) for position in transitive_positions),
                        f"attempt {index} candidate transitive DSO flag is incomplete")
                require([command[position + 1] for position in transitive_positions] == closure_paths,
                        f"attempt {index} candidate validation-only DSO command differs")
            else:
                require("--application-dso" not in command and "--transitive-application-dso" not in command,
                        f"attempt {index} musl link used installed-driver DSO flags")
                for path in direct_paths:
                    require(command.count(path) == 1,
                            f"attempt {index} musl link omitted a direct DSO")
            if provider == "musl":
                # rpath-link names parent directories only; a validation-only
                # DSO itself must never become an ordinary musl linker input.
                require(all(path not in command for path in closure_paths), f"attempt {index} musl link flattened a transitive DSO")
            _verify_readelf_record(checkout, value["raw"], value["output"], provider=provider, name=name, index=index)
            if provider == "candidate" and "dynamic_graph" not in link:
                receipt = retained_file_identity(checkout, SOURCE_MOUNT, value["raw"]["receipt"],
                                                 f"attempt {index} candidate direct receipt")
                dynamic_raw = retained_file_identity(
                    checkout, SOURCE_MOUNT, value["raw"]["dynamic"]["output"],
                    f"attempt {index} candidate direct dynamic raw",
                )
                product = translate_source_path(checkout, SOURCE_MOUNT, str(attempt["product"]["before"]["root"]))
                validate_dynamic_direct_receipt(
                    checkout=checkout,
                    product=product,
                    receipt_path=receipt,
                    output=translate_source_path(checkout, SOURCE_MOUNT, value["output"]["path"]),
                    dynamic_raw=dynamic_raw,
                    expected_direct=[
                        translate_source_path(checkout, SOURCE_MOUNT, path)
                        for path in direct_paths
                    ],
                    expected_mode="shared" if name.endswith(".so") else "pie",
                    expected_search_path=APP_RUNPATH,
                )
            providers[provider] = value
        if "dynamic_graph" in link:
            _verify_dynamic_graph_record(checkout, attempt, providers["candidate"], link["dynamic_graph"], index, name)
    proof = build["same_object_input_proof"]
    require(isinstance(proof, dict) and set(proof) == {"objects", "inputs"}, f"attempt {index} same-object proof differs")
    require(proof["objects"] == {name: item["object"]["sha256"] for name, item in sorted(objects.items())}, f"attempt {index} same-object proof hash differs")
    require(proof["inputs"] == {"io_fixture": hashlib.sha256(bytes(range(256)) * 16).hexdigest()}, f"attempt {index} input proof differs")
    proof_path = retained_file_identity(checkout, SOURCE_MOUNT, build["same_object_input_proof_file"], f"attempt {index} same-object proof file")
    require(load_json(proof_path, f"attempt {index} same-object proof file") == proof, f"attempt {index} same-object proof file differs")
    companion = build["companion_same_object_input_proof"]
    if companion is not None:
        companion_path = retained_file_identity(checkout, SOURCE_MOUNT, companion, f"attempt {index} companion same-object proof")
        require(load_json(companion_path, f"attempt {index} companion same-object proof") == proof, f"attempt {index} companion object/input proof differs")


def _verify_staged_link_inventory(
    inventory: object,
    links: Mapping[str, Any],
    provider: str,
    *,
    index: int,
    lane: str,
) -> None:
    """Bind every `/app/bin` and `/app/lib` file to its provider link output."""

    require(provider in {"musl", "candidate"}, f"attempt {index} {lane} provider differs")
    require(isinstance(inventory, list), f"attempt {index} {lane} inventory differs")
    files = {
        entry["path"]: entry
        for entry in inventory
        if isinstance(entry, dict) and entry.get("kind") == "file" and isinstance(entry.get("path"), str)
    }
    expected_paths = {
        (f"app/lib/{name}" if name.endswith(".so") else f"app/bin/{name}"): name
        for name in links
    }
    staged_paths = {path for path in files if path.startswith("app/bin/") or path.startswith("app/lib/")}
    require(staged_paths == set(expected_paths),
            f"attempt {index} {lane} staged application artifact roster differs")
    for staged_path, name in expected_paths.items():
        staged = files[staged_path]
        output = links[name][provider]["output"]
        require(isinstance(output, dict) and set(output) == IDENTITY_FIELDS,
                f"attempt {index} {lane} {name} provider output identity differs")
        require(staged.get("sha256") == output["sha256"]
                and staged.get("bytes") == output["bytes"]
                and staged.get("mode") == output["mode"],
                f"attempt {index} {lane} staged {name} bytes differ from its provider link output")


def _verify_staged_runtime_inventory(
    inventory: object,
    lane: str,
    product: Mapping[str, Any],
    tools: Mapping[str, Any],
    *,
    index: int,
) -> None:
    """Bind the staged loader/libc closure to product or pinned-musl bytes."""

    require(lane in {"musl", "crabc"} and isinstance(inventory, list),
            f"attempt {index} {lane} runtime inventory differs")
    entries = {
        entry["path"]: entry
        for entry in inventory
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }

    def copied(relative: str, origin: object, label: str) -> None:
        staged = entries.get(relative)
        require(isinstance(staged, dict) and staged.get("kind") == "file"
                and isinstance(origin, dict) and set(origin) == IDENTITY_FIELDS,
                f"attempt {index} {lane} {label} inventory identity differs")
        require(staged.get("sha256") == origin["sha256"]
                and staged.get("bytes") == origin["bytes"]
                and staged.get("mode") == origin["mode"],
                f"attempt {index} {lane} {label} bytes differ from its runtime oracle")

    if lane == "crabc":
        payload = product.get("payload")
        require(isinstance(payload, dict) and payload,
                f"attempt {index} candidate product payload is absent")
        for relative, origin in payload.items():
            require(isinstance(relative, str), f"attempt {index} candidate product payload path differs")
            copied(relative, origin, f"product payload {relative}")
        alias = entries.get("lib/ld-musl-x86_64.so.1")
        require(alias == {"path": "lib/ld-musl-x86_64.so.1", "kind": "symlink", "target": "ld-crabc-x86_64.so.1"},
                f"attempt {index} candidate loader compatibility alias differs")
        return

    copied("lib/ld-musl-x86_64.so.1", tools.get("musl_loader"), "musl loader")
    copied("lib/libc.so", tools.get("musl_libc"), "musl libc")
    copied("usr/lib/libc.so", tools.get("musl_libc"), "musl usr libc")
    for name, target in {
        FIXED_MUSL_LOADER.lstrip("/"): "../../../lib/ld-musl-x86_64.so.1",
        FIXED_MUSL_LIBC.lstrip("/"): "../../../lib/libc.so",
    }.items():
        require(entries.get(name) == {"path": name, "kind": "symlink", "target": target},
                f"attempt {index} musl canonical runtime alias differs")


def _verify_attempt_execution(checkout: Path, attempt: Mapping[str, Any], index: int) -> None:
    execution = attempt["execution"]
    require(isinstance(execution, dict) and set(execution) == {"roots", "raw"}, f"attempt {index} execution fields differ")
    roots = execution["roots"]
    require(isinstance(roots, dict) and set(roots) == {"musl", "crabc"}, f"attempt {index} root roster differs")
    build = attempt.get("build")
    links = build.get("links") if isinstance(build, dict) else None
    require(isinstance(links, dict) and set(links) == FULL_LINK_NAMES,
            f"attempt {index} staged roots lack the exact build link roster")
    product = attempt.get("product", {}).get("before") if isinstance(attempt.get("product"), dict) else None
    tools = attempt.get("tools", {}).get("before") if isinstance(attempt.get("tools"), dict) else None
    require(isinstance(product, dict) and isinstance(tools, dict),
            f"attempt {index} staged roots lack product/tool provenance")
    for lane, root_record in roots.items():
        require(isinstance(root_record, dict) and set(root_record) == {"root", "inventory", "observed_mappings"}, f"attempt {index} {lane} root fields differ")
        root = translate_source_path(checkout, SOURCE_MOUNT, root_record["root"])
        require(root.is_dir(), f"attempt {index} {lane} root is absent")
        verify_inventory(root, root_record["inventory"], f"attempt {index} {lane} root")
        _verify_staged_runtime_inventory(root_record["inventory"], lane, product, tools, index=index)
        _verify_staged_link_inventory(
            root_record["inventory"], links, "candidate" if lane == "crabc" else "musl",
            index=index, lane=lane,
        )
        mappings = root_record["observed_mappings"]
        require(isinstance(mappings, dict) and set(mappings) == {"raw", "paths"}, f"attempt {index} {lane} mapping evidence differs")
        raw_mapping = retained_file_identity(checkout, SOURCE_MOUNT, mappings["raw"], f"attempt {index} {lane} mapping raw")
        require(isinstance(mappings["paths"], list), f"attempt {index} {lane} mapping paths are absent")
        for mapped in mappings["paths"]:
            require(isinstance(mapped, str) and mapped.startswith(str(Path(root_record["root"]))), f"attempt {index} {lane} observed ambient mapping")
        rebuilt_mappings = replay_observed_mappings(
            raw_mapping.read_text(encoding="utf-8", errors="replace"), root_record["root"],
        )
        _verify_replayed_mapping_paths(checkout, rebuilt_mappings, root, f"attempt {index} {lane}")
        require(mappings["paths"] == rebuilt_mappings,
                f"attempt {index} {lane} mapping list disagrees with retained proc maps")
    raw = execution["raw"]
    require(isinstance(raw, dict) and raw, f"attempt {index} raw execution evidence is absent")
    for name, record in raw.items():
        require(isinstance(name, str) and isinstance(record, dict), f"attempt {index} raw execution entry differs")
        retained_file_identity(checkout, SOURCE_MOUNT, record, f"attempt {index} raw {name}")
