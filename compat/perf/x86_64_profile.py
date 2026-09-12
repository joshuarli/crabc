"""Closed native x86-64 performance-row and memory-observer profile.

The native adapter keeps timed artifacts and memory-only observer artifacts
separate.  This module reads the checked-in profile once per caller and turns
its 40 supplemental rows plus the frozen legacy rows supplied by ``run.py``
into one explicit 114-row contract.  It has no execution facility: the runner
owns compilation, staging, peers, cgroups, and measurement; the evidence
reader reuses the same canonical row identity during host replay.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
import tomllib


PROFILE_RELATIVE_PATH = Path("compat/perf/x86_64-profile.toml")
PROFILE_SCHEMA = "crabc.perf.x86_64-profile/v1"
OBSERVER_PROTOCOL = "crabc.perf.observer-r-c/v1"
READY_ENV = "CRABC_PERF_OBSERVER_READY_FD"
CONTINUE_ENV = "CRABC_PERF_OBSERVER_CONTINUE_FD"
READY_FD = 97
CONTINUE_FD = 98

# These are artifact names, not arbitrary executable paths.  The runner builds
# each source family once per provider and stages the selected output under
# ``/app/bin``.  Keeping this mapping here lets a row carry the exact observer
# identity that produced its non-timed PSS checkpoints.
LEGACY_MEMORY_ARTIFACTS = {
    "workload": "x86_64_memory_observer_workload",
    "constructor": "x86_64_memory_observer_constructor",
    "graph": "x86_64_memory_observer_graph",
}
SUPPLEMENTAL_MEMORY_ARTIFACTS = {
    "x86_64_clock_allocator_workload": "x86_64_memory_observer_clock_allocator",
    "x86_64_network_workload": "x86_64_memory_observer_network",
    "x86_64_primitive_boundary_workload": "x86_64_memory_observer_primitive",
}

SUPPLEMENTAL_TIMED_SOURCES = {
    "x86_64_clock_allocator_workload": "compat/perf/x86_64_clock_allocator_workload.c",
    "x86_64_network_workload": "compat/perf/x86_64_network_workload.c",
    "x86_64_primitive_boundary_workload": "compat/perf/x86_64_primitive_boundary_workload.c",
}
SUPPLEMENTAL_MEMORY_SOURCES = {
    "x86_64_clock_allocator_workload": "compat/perf/x86_64_memory_observer_clock_allocator.c",
    "x86_64_network_workload": "compat/perf/x86_64_memory_observer_network.c",
    "x86_64_primitive_boundary_workload": "compat/perf/x86_64_memory_observer_primitive.c",
}
LEGACY_MEMORY_SOURCES = {
    "workload": "compat/perf/x86_64_memory_observer_workload.c",
    "constructor": "compat/perf/x86_64_memory_observer_constructor.c",
    "graph": "compat/perf/x86_64_memory_observer_graph.c",
}


class ProfileError(ValueError):
    """The checked-in row profile is not a closed adapter contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProfileError(message)


@dataclass(frozen=True)
class PerformanceRow:
    """One timed route and its separate memory-observer envelope."""

    name: str
    legacy: bool
    timed_artifact: str
    source_family: str
    arguments: tuple[str, ...]
    fixture_mode: str | None
    iterations: int
    memory_artifact: str
    memory_phases: tuple[str, ...]
    requires_loopback_peer: bool
    requires_hermetic_resolver_files: bool
    legacy_workload: object | None = None


@dataclass(frozen=True)
class SupplementalFixture:
    """The exact source and compile/link inputs for one supplemental family."""

    binary: str
    source: str
    c_standard: str
    compile_defines: tuple[str, ...]
    link_flags: tuple[str, ...]


@dataclass(frozen=True)
class SupplementalRow:
    """Profile-owned supplemental route before it joins the 114-row roster."""

    name: str
    binary: str
    mode: str
    iterations: int
    argv: tuple[str, ...]
    observer_phase: str
    requires_loopback_peer: bool
    requires_hermetic_resolver_files: bool


# The prose checkpoint field in the frozen profile remains useful to readers;
# this exact mapping is the adapter's machine-readable R/C roster.  It prevents
# an implementation from accepting a plausible but shifted plateau.
_LEGACY_CHECKPOINTS = {
    "before and after original main; dependencies and constructor/main state remain live": (
        "main-initial", "main-final",
    ),
    "after final successful selected call with calling frame live": (
        "main-initial", "clock-final-call", "main-final",
    ),
    "before final close with the real descriptor open": (
        "main-initial", "open-before-close", "main-final",
    ),
    "after final verified round trip and before descriptor close": (
        "main-initial", "fd-before-close", "main-final",
    ),
    "before final fclose with the real FILE, buffer, and caller frame live": (
        "main-initial", "stdio-before-fclose", "main-final",
    ),
    "final worker callback result is ready while its real exit/TLS/TSD remain held": (
        "main-initial", "pthread-callback-ready", "main-final",
    ),
    "counter verified while the initialized mutex remains live before destruction": (
        "main-initial", "mutex-before-destroy", "main-final",
    ),
    "final protected counter is complete while worker exit, mutex, and condition remain live": (
        "main-initial", "pingpong-before-worker-exit", "main-final",
    ),
    "loops complete with exactly their original touched static arrays retained": (
        "main-initial", "scalar-arrays-live", "main-final",
    ),
    "before first munmap with exactly the original touched mappings retained; search rows do not prefault an unused destination": (
        "main-initial", "span-before-first-munmap", "main-final",
    ),
    "after original touch and before final free with exactly one allocation live": (
        "main-initial", "allocator-before-final-free", "main-final",
    ),
    "final lookup result is checked before dlclose": (
        "main-initial", "dlsym-before-dlclose", "main-final",
    ),
    "result 31 is checked before handle closure": (
        "main-initial", "graph-before-dlclose", "main-final",
    ),
}
_TLS_CHECKPOINT = "parent after each of eight loads, then worker after all TLS instances are checked before exit and dlclose"


def load_profile(root: Path) -> dict[str, Any]:
    path = root / PROFILE_RELATIVE_PATH
    try:
        with path.open("rb") as stream:
            profile = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ProfileError(f"cannot read native x86 performance profile: {error}") from error
    require(isinstance(profile, dict), "native x86 performance profile is not an object")
    declared = profile.get("profile")
    require(isinstance(declared, dict), "native x86 performance profile metadata is absent")
    require(declared.get("schema") == PROFILE_SCHEMA, "native x86 performance profile schema differs")
    require(declared.get("observer_protocol") == OBSERVER_PROTOCOL, "native x86 observer protocol differs")
    require(declared.get("observer_ready_env") == READY_ENV and declared.get("observer_continue_env") == CONTINUE_ENV,
            "native x86 observer environment contract differs")
    require(declared.get("observer_ready_fd") == READY_FD and declared.get("observer_continue_fd") == CONTINUE_FD,
            "native x86 observer descriptor contract differs")
    require(declared.get("timed_artifact_unchanged") is True
            and declared.get("observer_artifact_separate") is True
            and declared.get("observer_artifact_byte_identical") is False,
            "native x86 timed/observer artifact boundary differs")
    return profile


def supplemental_fixtures(profile: Mapping[str, Any]) -> dict[str, SupplementalFixture]:
    raw = profile.get("fixture")
    require(isinstance(raw, list) and len(raw) == len(SUPPLEMENTAL_TIMED_SOURCES),
            "supplemental fixture roster differs")
    fixtures: dict[str, SupplementalFixture] = {}
    for item in raw:
        require(isinstance(item, dict) and set(item) == {"binary", "source", "c_standard", "compile_defines", "link_flags"},
                "supplemental fixture fields differ")
        binary = item.get("binary")
        source = item.get("source")
        standard = item.get("c_standard")
        defines = item.get("compile_defines")
        flags = item.get("link_flags")
        require(isinstance(binary, str) and binary in SUPPLEMENTAL_TIMED_SOURCES
                and isinstance(source, str) and isinstance(standard, str)
                and isinstance(defines, list) and all(isinstance(value, str) for value in defines)
                and isinstance(flags, list) and all(isinstance(value, str) for value in flags),
                "supplemental fixture values differ")
        require(binary not in fixtures, f"supplemental fixture repeats {binary}")
        require(source == SUPPLEMENTAL_TIMED_SOURCES[binary], f"supplemental fixture source differs for {binary}")
        fixtures[binary] = SupplementalFixture(binary, source, standard, tuple(defines), tuple(flags))
    require(set(fixtures) == set(SUPPLEMENTAL_TIMED_SOURCES), "supplemental fixture names differ")
    return fixtures


def supplemental_rows(profile: Mapping[str, Any]) -> tuple[SupplementalRow, ...]:
    raw = profile.get("supplemental_row")
    require(isinstance(raw, list) and len(raw) == 40, "supplemental row roster is not the closed 40 rows")
    result: list[SupplementalRow] = []
    names: set[str] = set()
    expected_fields = {
        "id", "binary", "mode", "iterations", "argv", "observer_phase",
        "requires_loopback_peer", "requires_hermetic_resolver_files",
        "operations", "result_contract", "geometry",
    }
    for item in raw:
        require(isinstance(item, dict) and set(item) == expected_fields, "supplemental row fields differ")
        name = item.get("id")
        binary = item.get("binary")
        mode = item.get("mode")
        iterations = item.get("iterations")
        argv = item.get("argv")
        phase = item.get("observer_phase")
        loopback = item.get("requires_loopback_peer")
        resolver = item.get("requires_hermetic_resolver_files")
        require(isinstance(name, str) and name and name not in names
                and isinstance(binary, str) and binary in SUPPLEMENTAL_MEMORY_ARTIFACTS
                and isinstance(mode, str) and mode
                and type(iterations) is int and iterations > 0
                and isinstance(argv, list) and all(isinstance(value, str) and value for value in argv)
                and isinstance(phase, str) and phase
                and type(loopback) is bool and type(resolver) is bool,
                "supplemental row values differ")
        names.add(name)
        result.append(SupplementalRow(name, binary, mode, iterations, tuple(argv), phase, loopback, resolver))
    require(len(names) == 40, "supplemental rows repeat an id")
    return tuple(result)


def legacy_memory_phases(profile: Mapping[str, Any], workloads: Sequence[object]) -> dict[str, tuple[str, ...]]:
    """Return the exact phase list for every frozen legacy workload.

    ``workloads`` uses only ``name`` and ``iterations`` attributes, which keeps
    the profile independent from the historical runner's concrete class.
    """

    expected = {
        str(getattr(workload, "name")): int(getattr(workload, "iterations"))
        for workload in workloads
    }
    require(len(expected) == len(workloads) == 74, "legacy workload roster is not the closed 74 rows")
    raw = profile.get("legacy_memory_phase")
    require(isinstance(raw, list) and profile.get("legacy_memory_phase_count") == 74,
            "legacy memory phase roster differs")
    result: dict[str, tuple[str, ...]] = {}
    for item in raw:
        require(isinstance(item, dict) and set(item) == {"rows", "checkpoint", "peak_rule"},
                "legacy memory phase fields differ")
        rows = item.get("rows")
        checkpoint = item.get("checkpoint")
        require(isinstance(rows, list) and rows and all(isinstance(row, str) for row in rows)
                and isinstance(checkpoint, str) and item.get("peak_rule") == "maximum-declared-checkpoints",
                "legacy memory phase values differ")
        if checkpoint == _TLS_CHECKPOINT:
            for name in rows:
                iterations = expected.get(name)
                require(iterations == 8, "dynamic TLS observer requires exactly eight frozen loads")
                phases = (
                    "main-initial", *(f"tls-parent-load-{index}" for index in range(iterations)),
                    "tls-worker-complete", "main-final",
                )
                require(name not in result, f"legacy memory phase repeats {name}")
                result[name] = phases
            continue
        phases = _LEGACY_CHECKPOINTS.get(checkpoint)
        require(phases is not None, f"unknown legacy memory checkpoint: {checkpoint}")
        for name in rows:
            require(name not in result, f"legacy memory phase repeats {name}")
            result[name] = phases
    require(set(result) == set(expected), "legacy memory phases do not cover the frozen 74 rows")
    return result


def performance_rows(root: Path, legacy_workloads: Sequence[object]) -> tuple[PerformanceRow, ...]:
    """Build the closed 74 legacy + 40 supplemental row contract."""

    profile = load_profile(root)
    supplemental_fixtures(profile)
    phases = legacy_memory_phases(profile, legacy_workloads)
    rows: list[PerformanceRow] = []
    names: set[str] = set()
    for workload in legacy_workloads:
        name = str(getattr(workload, "name"))
        source_family = str(getattr(workload, "binary"))
        artifact = LEGACY_MEMORY_ARTIFACTS.get(source_family)
        require(artifact is not None, f"legacy row has no memory observer family: {name}")
        rows.append(PerformanceRow(
            name=name,
            legacy=True,
            timed_artifact=source_family,
            source_family=source_family,
            arguments=(),
            fixture_mode=getattr(workload, "fixture_mode"),
            iterations=int(getattr(workload, "iterations")),
            memory_artifact=artifact,
            memory_phases=phases[name],
            requires_loopback_peer=False,
            requires_hermetic_resolver_files=False,
            legacy_workload=workload,
        ))
        names.add(name)
    for row in supplemental_rows(profile):
        require(row.name not in names, f"supplemental row collides with legacy row: {row.name}")
        rows.append(PerformanceRow(
            name=row.name,
            legacy=False,
            timed_artifact=row.binary,
            source_family=row.binary,
            arguments=(row.mode, str(row.iterations), *row.argv),
            fixture_mode=row.mode,
            iterations=row.iterations,
            memory_artifact=SUPPLEMENTAL_MEMORY_ARTIFACTS[row.binary],
            memory_phases=("main-initial", row.observer_phase, "main-final"),
            requires_loopback_peer=row.requires_loopback_peer,
            requires_hermetic_resolver_files=row.requires_hermetic_resolver_files,
        ))
        names.add(row.name)
    require(len(rows) == 114 and len(names) == len(rows), "native x86 performance row roster is not 114 unique rows")
    return tuple(rows)
