#!/usr/bin/env python3
"""Validate the closed, non-symbol x86-64 runtime-parity ledger.

This is repository test infrastructure, not a runtime dependency.  It records
which AArch64 capability and gate families need independent native x86 proof;
it never treats a source-only foundation slice as public target support.
"""

from __future__ import annotations

import argparse
import tomllib
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
LEDGER_PATH = ROOT / "compat" / "x86_64" / "parity.toml"
HEADER_LAYOUT_MANIFEST_PATH = ROOT / "compat" / "x86_64" / "headers-layouts.toml"
EXPECTED_SCHEMA = "crabc.x86_64-runtime-parity/v3"
EXPECTED_TARGET = "x86_64-unknown-linux-musl"
EXPECTED_PLATFORM = "Linux/x86-64 little-endian"
EXPECTED_KERNEL_MSRV = "5.10"
EXPECTED_HEADER_LAYOUT_SCHEMA = "crabc.x86_64-headers-layouts/v1"

EXPECTED_HEADER_LAYOUT_PROBES = {
    "project": "./scripts/dev-x86_64.sh header-abi-project",
    "sys-reg": "./scripts/dev-x86_64.sh sys-reg-header-abi",
    "types": "./scripts/dev-x86_64.sh types-header-abi",
    "stat": "./scripts/dev-x86_64.sh stat-header-abi",
    "ctype": "./scripts/dev-x86_64.sh ctype-header-abi",
    "integer-arithmetic": "./scripts/dev-x86_64.sh integer-arithmetic-header-abi",
    "integer-parse": "./scripts/dev-x86_64.sh integer-parse-header-abi",
    "intmax-arithmetic": "./scripts/dev-x86_64.sh intmax-arithmetic-header-abi",
    "credential-observation": "./scripts/dev-x86_64.sh credential-observation-header-abi",
    "child-reaping": "./scripts/dev-x86_64.sh child-reaping-header-abi",
    "immediate-termination": "./scripts/dev-x86_64.sh immediate-termination-header-abi",
    "callback-algorithms": "./scripts/dev-x86_64.sh callback-algorithms-header-abi",
    "ffs": "./scripts/dev-x86_64.sh ffs-header-abi",
    "byte-strings": "./scripts/dev-x86_64.sh byte-strings-header-abi",
    "memory-search": "./scripts/dev-x86_64.sh memory-search-header-abi",
    "string-copy": "./scripts/dev-x86_64.sh string-copy-header-abi",
    "random-entropy": "./scripts/dev-x86_64.sh random-entropy-header-abi",
    "time": "./scripts/dev-x86_64.sh time-header-abi",
    "poll": "./scripts/dev-x86_64.sh poll-header-abi",
    "select": "./scripts/dev-x86_64.sh select-header-abi",
    "fcntl": "./scripts/dev-x86_64.sh fcntl-header-abi",
    "unistd": "./scripts/dev-x86_64.sh unistd-header-abi",
    "system": "./scripts/dev-x86_64.sh system-header-abi",
    "syscall": "./scripts/dev-x86_64.sh syscall-header-abi",
    "signal": "./scripts/dev-x86_64.sh signal-header-abi",
    "termios": "./scripts/dev-x86_64.sh termios-header-abi",
    "mman": "./scripts/dev-x86_64.sh mman-header-abi",
    "resource": "./scripts/dev-x86_64.sh resource-header-abi",
    "socket": "./scripts/dev-x86_64.sh socket-header-abi",
}

EXPECTED_HEADER_LAYOUT_SOURCES = {
    "project": (
        "compat/x86_64/project_header_abi_probe.c",
        "compat/x86_64/run_project_header_abi.sh",
    ),
    "sys-reg": (
        "compat/x86_64/sys_reg_header_abi_probe.c",
        "compat/x86_64/run_sys_reg_header_abi.sh",
    ),
    "types": (
        "compat/x86_64/types_header_abi_probe.c",
        "compat/x86_64/types_header_abi_probe.cpp",
        "compat/x86_64/run_types_header_abi.sh",
    ),
    "stat": (
        "compat/x86_64/stat_header_abi_probe.c",
        "compat/x86_64/stat_header_abi_probe.cpp",
        "compat/x86_64/run_stat_header_abi.sh",
    ),
    "ctype": (
        "compat/x86_64/ctype_header_abi_probe.c",
        "compat/x86_64/ctype_header_abi_probe.cpp",
        "compat/x86_64/run_ctype_header_abi.sh",
    ),
    "integer-arithmetic": (
        "compat/x86_64/integer_arithmetic_header_abi_probe.c",
        "compat/x86_64/integer_arithmetic_header_abi_probe.cpp",
        "compat/x86_64/run_integer_arithmetic_header_abi.sh",
    ),
    "integer-parse": (
        "compat/x86_64/integer_parse_header_abi_probe.c",
        "compat/x86_64/integer_parse_header_abi_probe.cpp",
        "compat/x86_64/run_integer_parse_header_abi.sh",
    ),
    "intmax-arithmetic": (
        "compat/x86_64/intmax_arithmetic_header_abi_probe.c",
        "compat/x86_64/intmax_arithmetic_header_abi_probe.cpp",
        "compat/x86_64/run_intmax_arithmetic_header_abi.sh",
    ),
    "credential-observation": (
        "compat/x86_64/credential_observation_header_abi_probe.c",
        "compat/x86_64/credential_observation_header_abi_probe.cpp",
        "compat/x86_64/run_credential_observation_header_abi.sh",
    ),
    "child-reaping": (
        "compat/x86_64/child_reaping_header_abi_probe.c",
        "compat/x86_64/child_reaping_header_abi_probe.cpp",
        "compat/x86_64/run_child_reaping_header_abi.sh",
    ),
    "immediate-termination": (
        "compat/x86_64/immediate_termination_header_abi_probe.c",
        "compat/x86_64/immediate_termination_header_abi_probe.cpp",
        "compat/x86_64/run_immediate_termination_header_abi.sh",
    ),
    "callback-algorithms": (
        "compat/x86_64/callback_algorithms_header_abi_probe.c",
        "compat/x86_64/callback_algorithms_header_abi_probe.cpp",
        "compat/x86_64/run_callback_algorithms_header_abi.sh",
    ),
    "ffs": (
        "compat/x86_64/ffs_header_abi_probe.c",
        "compat/x86_64/ffs_header_abi_probe.cpp",
        "compat/x86_64/run_ffs_header_abi.sh",
    ),
    "byte-strings": (
        "compat/x86_64/byte_strings_header_abi_probe.c",
        "compat/x86_64/byte_strings_header_abi_probe.cpp",
        "compat/x86_64/run_byte_strings_header_abi.sh",
    ),
    "memory-search": (
        "compat/x86_64/memory_search_header_abi_probe.c",
        "compat/x86_64/memory_search_header_abi_probe.cpp",
        "compat/x86_64/run_memory_search_header_abi.sh",
    ),
    "string-copy": (
        "compat/x86_64/string_copy_header_abi_probe.c",
        "compat/x86_64/string_copy_header_abi_probe.cpp",
        "compat/x86_64/run_string_copy_header_abi.sh",
    ),
    "random-entropy": (
        "compat/x86_64/random_entropy_header_abi_probe.c",
        "compat/x86_64/random_entropy_header_abi_probe.cpp",
        "compat/x86_64/run_random_entropy_header_abi.sh",
    ),
    "time": (
        "compat/x86_64/time_header_abi_probe.c",
        "compat/x86_64/time_header_abi_probe.cpp",
        "compat/x86_64/run_time_header_abi.sh",
    ),
    "poll": (
        "compat/x86_64/poll_header_abi_probe.c",
        "compat/x86_64/poll_header_abi_probe.cpp",
        "compat/x86_64/run_poll_header_abi.sh",
    ),
    "select": (
        "compat/x86_64/select_header_abi_probe.c",
        "compat/x86_64/select_header_abi_probe.cpp",
        "compat/x86_64/run_select_header_abi.sh",
    ),
    "fcntl": (
        "compat/x86_64/fcntl_header_abi_probe.c",
        "compat/x86_64/fcntl_header_abi_probe.cpp",
        "compat/x86_64/run_fcntl_header_abi.sh",
    ),
    "unistd": (
        "compat/x86_64/unistd_header_abi_probe.c",
        "compat/x86_64/unistd_header_abi_probe.cpp",
        "compat/x86_64/run_unistd_header_abi.sh",
    ),
    "system": (
        "compat/x86_64/system_header_abi_probe.c",
        "compat/x86_64/system_header_abi_probe.cpp",
        "compat/x86_64/run_system_header_abi.sh",
    ),
    "syscall": (
        "compat/x86_64/x86_syscall_header_probe.c",
        "compat/x86_64/run_x86_syscall_header.sh",
    ),
    "signal": (
        "compat/x86_64/signal_header_abi_probe.c",
        "compat/x86_64/signal_header_posix_abi_probe.c",
        "compat/x86_64/run_signal_header_abi.sh",
    ),
    "termios": (
        "compat/x86_64/termios_header_abi_probe.c",
        "compat/x86_64/termios_header_abi_probe.cpp",
        "compat/x86_64/run_termios_header_abi.sh",
    ),
    "mman": (
        "compat/x86_64/mman_header_abi_probe.c",
        "compat/x86_64/mman_header_abi_probe.cpp",
        "compat/x86_64/run_mman_header_abi.sh",
    ),
    "resource": (
        "compat/x86_64/resource_header_abi_probe.c",
        "compat/x86_64/resource_header_abi_probe.cpp",
        "compat/x86_64/run_resource_header_abi.sh",
    ),
    "socket": (
        "compat/x86_64/socket_header_abi_probe.c",
        "compat/x86_64/socket_header_abi_probe.cpp",
        "compat/x86_64/socket_header_ipv6_macro_probe.c",
        "compat/x86_64/run_socket_header_abi.sh",
    ),
}

EXPECTED_FAMILIES = (
    "oracle.musl-toolchain",
    "core.architecture",
    "facade.direct",
    "facade.record-owning",
    "libc.raw-syscall",
    "libc.errno-tls",
    "libc.headers-layouts",
    "libc.posix-runtime",
    "libc.pthread-tls",
    "libc.text-math-locale-stdio",
    "libc.resolver",
    "libc.c-abi-compat",
    "ldso.relative-relocation",
    "ldso.dynamic-runtime",
    "crt.static-pie",
    "crt.dynamic-startup",
    "sysroot.static-tls",
    "sysroot.owned-artifact",
    "compat.abi-differential",
    "compat.posix-process",
    "compat.resolver-network",
    "compat.loader-corpus",
    "consumer.rust-std-lto",
    "consumer.source-build",
    "capability.accounting",
    "performance.release",
)

ALLOWED_CATEGORIES = {
    "architecture-foundation",
    "rust-facade",
    "c-abi",
    "runtime-artifact",
    "compatibility-gate",
    "consumer-gate",
    "promotion-gate",
}
ALLOWED_STATUSES = {"foundation-verified", "planned"}
ALLOWED_EVIDENCE_STATES = {"verified", "required"}
KNOWN_AARCH64_GATES = {
    "abi-probe",
    "build",
    "compat",
    "corpus",
    "crabc-rs",
    "dashboard",
    "differential",
    "ldso",
    "libc-test",
    "loader-inventory",
    "lto",
    "lto-native-facade",
    "os-test",
    "perf",
    "perf-native",
    "pthread-stress",
    "resolver-network",
    "rust-std",
    "rust-std-dependent",
    "signal-process",
    "static-pthread-tls",
    "symbols",
    "sysroot",
    "sysroot-dist",
    "sysroot-smoke",
    "test",
    "lua",
}

BYTE_STRING_SYMBOLS = (
    "index",
    "rindex",
    "strchr",
    "strchrnul",
    "strcmp",
    "strcspn",
    "strlen",
    "strncmp",
    "strnlen",
    "strpbrk",
    "strrchr",
    "strspn",
    "strstr",
)

RANDOM_ENTROPY_SYMBOLS = ("getrandom", "getentropy")

MEMORY_SEARCH_SYMBOLS = ("memchr", "memrchr", "memmem")

STRING_COPY_SYMBOLS = (
    "stpcpy",
    "stpncpy",
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "strlcpy",
    "strlcat",
)

CTYPE_SYMBOLS = (
    "isalnum",
    "isalpha",
    "isblank",
    "iscntrl",
    "isdigit",
    "isgraph",
    "islower",
    "isprint",
    "ispunct",
    "isspace",
    "isupper",
    "isxdigit",
    "tolower",
    "toupper",
    "isascii",
    "toascii",
)

INTEGER_ARITHMETIC_SYMBOLS = (
    "abs",
    "labs",
    "llabs",
    "div",
    "ldiv",
    "lldiv",
)

INTMAX_ARITHMETIC_SYMBOLS = ("imaxabs", "imaxdiv")

INTEGER_PARSE_SYMBOLS = (
    "atoi",
    "atol",
    "atoll",
    "strtol",
    "strtoul",
    "strtoll",
    "strtoull",
    "strtoimax",
    "strtoumax",
)

CREDENTIAL_OBSERVATION_SYMBOLS = ("getgroups", "getresuid", "getresgid")

CHILD_REAPING_SYMBOLS = ("wait", "waitpid", "waitid")

IMMEDIATE_TERMINATION_SYMBOLS = ("_Exit",)

CALLBACK_ALGORITHM_SYMBOLS = ("bsearch", "__qsort_r", "qsort", "qsort_r")

FFS_SYMBOLS = ("ffs", "ffsl", "ffsll")


class LedgerError(ValueError):
    """The parity ledger does not describe a reviewable closed contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LedgerError(message)


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise LedgerError(f"cannot load {path}: {error}") from error
    require(isinstance(data, dict), "ledger top level must be a table")
    return data


def nonempty_strings(value: Any, location: str) -> list[str]:
    require(isinstance(value, list) and value, f"{location} must be a non-empty array")
    result: list[str] = []
    for index, entry in enumerate(value):
        require(isinstance(entry, str) and entry, f"{location}[{index}] must be a non-empty string")
        result.append(entry)
    return result


def string_list(value: Any, location: str, *, allow_empty: bool = False) -> list[str]:
    """Return a string list while retaining a useful location in failures."""
    require(isinstance(value, list), f"{location} must be an array")
    require(allow_empty or bool(value), f"{location} must be a non-empty array")
    result: list[str] = []
    for index, entry in enumerate(value):
        require(isinstance(entry, str) and entry, f"{location}[{index}] must be a non-empty string")
        result.append(entry)
    return result


def repository_path(path_text: str, location: str) -> Path:
    require(isinstance(path_text, str) and path_text, f"{location} is empty")
    path = Path(path_text)
    require(not path.is_absolute(), f"{location} must be repository-relative: {path_text}")
    resolved = (ROOT / path).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as error:
        raise LedgerError(f"{location} escapes the repository: {path_text}") from error
    require(resolved.exists(), f"{location} does not exist: {path_text}")
    return resolved


def direct_project_headers(source: Path) -> set[str]:
    """Return explicit angle-bracket includes from one C or C++ probe source."""
    headers: set[str] = set()
    for line in source.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("#include <"):
            continue
        header = stripped.removeprefix("#include <").split(">", maxsplit=1)[0]
        if header:
            headers.add(f"include/{header}")
    return headers


def validate_header_layout_manifest(
    family: Mapping[str, Any], manifest: Mapping[str, Any]
) -> dict[str, Any]:
    """Keep selected native header evidence explicit without promoting it.

    The manifest is intentionally an index of direct probe includes only. It
    is not a transitive-include inventory or an assertion that an installed
    header, archive, or runtime is complete.
    """
    require(isinstance(manifest, Mapping), "header-layout manifest must be a table")
    expected_manifest_keys = {
        "schema",
        "family",
        "target",
        "platform",
        "kernel_msrv",
        "status",
        "oracle",
        "policy",
        "probe",
    }
    require(
        set(manifest) == expected_manifest_keys,
        "header-layout manifest top-level keys drifted",
    )
    require(
        manifest["schema"] == EXPECTED_HEADER_LAYOUT_SCHEMA,
        "unexpected header-layout manifest schema",
    )
    require(manifest["family"] == "libc.headers-layouts", "header-layout manifest family drifted")
    require(manifest["target"] == EXPECTED_TARGET, "header-layout manifest target drifted")
    require(manifest["platform"] == EXPECTED_PLATFORM, "header-layout manifest platform drifted")
    require(
        manifest["kernel_msrv"] == EXPECTED_KERNEL_MSRV,
        "header-layout manifest kernel MSRV drifted",
    )
    require(manifest["status"] == "planned", "header-layout manifest must remain planned")
    require(manifest["oracle"] == "Pinned musl 1.2.6", "header-layout manifest oracle drifted")

    policy = manifest["policy"]
    require(isinstance(policy, Mapping), "header-layout manifest policy must be a table")
    require(
        dict(policy)
        == {
            "native_execution_only": True,
            "project_headers_first": True,
            "direct_header_inventory": True,
            "transitive_include_closure": False,
            "aggregate_family_completion": False,
            "public_support": False,
        },
        "header-layout manifest policy drifted",
    )

    require(
        family.get("status") == "planned",
        "libc.headers-layouts must remain planned while its manifest is partial",
    )
    require(
        family.get("capabilities") == [],
        "libc.headers-layouts manifest must not claim baseline capabilities",
    )
    manifest_path = repository_path(
        str(family.get("header_manifest", "")),
        "family[libc.headers-layouts].header_manifest",
    )
    require(
        manifest_path == HEADER_LAYOUT_MANIFEST_PATH,
        "libc.headers-layouts must use the checked-in header-layout manifest",
    )
    source_owners = nonempty_strings(
        family["source_owners"], "family[libc.headers-layouts].source_owners"
    )
    require(
        "compat/x86_64/headers-layouts.toml" in source_owners,
        "libc.headers-layouts must own its header-layout manifest",
    )
    require(
        "include" not in source_owners,
        "libc.headers-layouts must not hide header scope behind the include directory",
    )

    evidence = family["native_evidence"]
    assert isinstance(evidence, list)
    dispatch_source = (ROOT / "scripts" / "dev-x86_64.sh").read_text(encoding="utf-8")
    require(
        tuple(EXPECTED_HEADER_LAYOUT_SOURCES) == tuple(EXPECTED_HEADER_LAYOUT_PROBES),
        "header-layout validator source roster drifted",
    )
    probes = manifest["probe"]
    require(isinstance(probes, list) and probes, "header-layout manifest probe must be a non-empty array")
    require(
        len(probes) == len(EXPECTED_HEADER_LAYOUT_PROBES),
        "header-layout manifest probe count drifted",
    )

    probe_ids: list[str] = []
    for index, entry in enumerate(probes):
        location = f"header-layout manifest probe[{index}]"
        require(isinstance(entry, Mapping), f"{location} must be a table")
        require(
            set(entry) == {"id", "command", "state", "kind", "sources", "headers"},
            f"{location} keys drifted",
        )
        identifier = entry["id"]
        require(isinstance(identifier, str) and identifier, f"{location}.id is empty")
        require(
            identifier == identifier.lower()
            and not identifier.startswith("-")
            and not identifier.endswith("-")
            and all(character in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in identifier),
            f"{location}.id must be lowercase kebab-case",
        )
        require(identifier in EXPECTED_HEADER_LAYOUT_PROBES, f"{location}.id is not a selected header gate")
        command = entry["command"]
        require(isinstance(command, str) and command, f"{location}.command is empty")
        require(
            command == EXPECTED_HEADER_LAYOUT_PROBES[identifier],
            f"{location}.command drifted from its selected header gate",
        )
        require(entry["state"] == "required", f"{location}.state must remain required")
        expected_kind = "macro-runtime" if identifier == "socket" else "compile-only"
        require(entry["kind"] == expected_kind, f"{location}.kind drifted")

        source_names = nonempty_strings(entry["sources"], f"{location}.sources")
        require(
            len(source_names) == len(set(source_names)),
            f"{location}.sources contains a duplicate",
        )
        require(
            tuple(source_names) == EXPECTED_HEADER_LAYOUT_SOURCES[identifier],
            f"{location}.sources drifted from its selected header gate",
        )
        source_paths: list[Path] = []
        for source_index, source_name in enumerate(source_names):
            source_path = repository_path(source_name, f"{location}.sources[{source_index}]")
            require(source_path.is_file(), f"{location}.sources[{source_index}] is not a file")
            require(
                source_name.startswith("compat/x86_64/"),
                f"{location}.sources[{source_index}] must stay in compat/x86_64",
            )
            require(
                source_name in source_owners,
                f"{location}.sources[{source_index}] is not a family source owner",
            )
            source_paths.append(source_path)
        c_sources = [path for path in source_paths if path.suffix in {".c", ".cpp"}]
        runner_sources = [path for path in source_paths if path.suffix == ".sh"]
        require(c_sources, f"{location}.sources must include a C or C++ probe")
        require(len(runner_sources) == 1, f"{location}.sources must include exactly one runner")

        header_names = nonempty_strings(entry["headers"], f"{location}.headers")
        require(
            len(header_names) == len(set(header_names)),
            f"{location}.headers contains a duplicate",
        )
        for header_index, header_name in enumerate(header_names):
            header_path = repository_path(header_name, f"{location}.headers[{header_index}]")
            require(header_path.is_file(), f"{location}.headers[{header_index}] is not a file")
            require(
                header_name.startswith("include/") and header_name.endswith(".h"),
                f"{location}.headers[{header_index}] must be an installed header",
            )
            require(
                header_name in source_owners,
                f"{location}.headers[{header_index}] is not a family source owner",
            )
        direct_headers = set().union(*(direct_project_headers(path) for path in c_sources))
        require(
            set(header_names) == direct_headers,
            f"{location}.headers must exactly match its direct C/C++ includes",
        )

        evidence_matches = [
            record
            for record in evidence
            if isinstance(record, Mapping) and record.get("command") == command
        ]
        require(
            len(evidence_matches) == 1 and evidence_matches[0].get("state") == "required",
            f"{location}.command must map to one required family evidence record",
        )
        subcommand = command.removeprefix("./scripts/dev-x86_64.sh ")
        require(
            subcommand != command
            and (
                f"    {subcommand})" in dispatch_source
                or f"    {subcommand}|" in dispatch_source
                or f"|{subcommand})" in dispatch_source
            ),
            f"{location}.command is absent from the native dispatcher",
        )
        probe_ids.append(identifier)

    require(
        tuple(probe_ids) == tuple(EXPECTED_HEADER_LAYOUT_PROBES),
        "header-layout manifest probe order or roster drifted",
    )
    return {"probe_count": len(probe_ids)}


def require_evidence_state(
    value: Any, location: str, expected_state: str
) -> tuple[list[Mapping[str, Any]], set[str]]:
    """Require one evidence state without promoting its owning family."""
    require(expected_state in ALLOWED_EVIDENCE_STATES, f"{location} has invalid expected state")
    require(isinstance(value, list) and value, f"{location} must be a non-empty array")
    records: list[Mapping[str, Any]] = []
    states: set[str] = set()
    for index, entry in enumerate(value):
        item_location = f"{location}[{index}]"
        require(isinstance(entry, Mapping), f"{item_location} must be a table")
        state = entry.get("state")
        command = entry.get("command")
        scope = entry.get("scope")
        require(state in ALLOWED_EVIDENCE_STATES, f"{item_location}.state is invalid")
        require(isinstance(command, str) and command, f"{item_location}.command is empty")
        require(isinstance(scope, str) and scope, f"{item_location}.scope is empty")
        states.add(state)
        records.append(entry)
    require(states == {expected_state}, f"{location} must be entirely {expected_state}")
    return records, states


def require_evidence(
    value: Any, location: str, status: str
) -> tuple[list[Mapping[str, Any]], set[str]]:
    expected_state = "verified" if status == "foundation-verified" else "required"
    return require_evidence_state(value, location, expected_state)


def require_oracles(value: Any, location: str) -> None:
    require(isinstance(value, list) and value, f"{location} must be a non-empty array")
    for index, entry in enumerate(value):
        item_location = f"{location}[{index}]"
        require(isinstance(entry, Mapping), f"{item_location} must be a table")
        for key in ("kind", "source", "role"):
            item = entry.get(key)
            require(isinstance(item, str) and item, f"{item_location}.{key} is empty")


def require_verified_slices(
    value: Any,
    location: str,
    status: str,
    family_capabilities: list[str],
) -> list[Mapping[str, Any]]:
    """Validate completed vertical slices for a planned or foundation family.

    Planned families may retain independently completed partial slices. A
    foundation family may retain them as the provenance for its aggregate
    evidence; family-specific promotion ratchets below decide when that
    aggregate has accounted for every declared capability.
    """
    if value is None:
        return []
    require(
        status in {"planned", "foundation-verified"},
        f"{location} is allowed only on a planned or foundation-verified family",
    )
    require(isinstance(value, list) and value, f"{location} must be a non-empty array")
    records: list[Mapping[str, Any]] = []
    family_capability_set = set(family_capabilities)
    for index, entry in enumerate(value):
        item_location = f"{location}[{index}]"
        require(isinstance(entry, Mapping), f"{item_location} must be a table")
        for key in (
            "id",
            "description",
            "source_owners",
            "x86_abi_prerequisites",
            "x86_header_prerequisites",
            "native_evidence",
            "oracle",
            "capabilities",
        ):
            require(key in entry, f"{item_location} is missing {key}")
        require(isinstance(entry["id"], str) and entry["id"], f"{item_location}.id is empty")
        require(
            isinstance(entry["description"], str) and entry["description"],
            f"{item_location}.description is empty",
        )
        capabilities = nonempty_strings(entry["capabilities"], f"{item_location}.capabilities")
        require(
            len(capabilities) == len(set(capabilities)),
            f"{item_location}.capabilities contains a duplicate",
        )
        outside_family = sorted(set(capabilities) - family_capability_set)
        require(
            not outside_family,
            f"{item_location}.capabilities escape the owning family: {', '.join(outside_family)}",
        )
        for owner_index, path_text in enumerate(
            nonempty_strings(entry["source_owners"], f"{item_location}.source_owners")
        ):
            repository_path(path_text, f"{item_location}.source_owners[{owner_index}]")
        nonempty_strings(entry["x86_abi_prerequisites"], f"{item_location}.x86_abi_prerequisites")
        nonempty_strings(entry["x86_header_prerequisites"], f"{item_location}.x86_header_prerequisites")
        require_evidence_state(entry["native_evidence"], f"{item_location}.native_evidence", "verified")
        require_oracles(entry["oracle"], f"{item_location}.oracle")
        records.append(entry)
    return records


def require_verified_artifacts(
    value: Any,
    location: str,
    status: str,
) -> list[Mapping[str, Any]]:
    """Validate completed artifact evidence that has no semantic capability ID.

    Header/layout and startup foundations can be real selected binaries before
    they implement one of the baseline facade capabilities. Keep those records
    distinct from ``verified_slice``: they prove a named artifact boundary but
    cannot consume, duplicate, or imply ownership of a capability.
    """
    if value is None:
        return []
    require(status == "planned", f"{location} is allowed only on a planned family")
    require(isinstance(value, list) and value, f"{location} must be a non-empty array")
    records: list[Mapping[str, Any]] = []
    for index, entry in enumerate(value):
        item_location = f"{location}[{index}]"
        require(isinstance(entry, Mapping), f"{item_location} must be a table")
        for key in (
            "id",
            "description",
            "source_owners",
            "x86_abi_prerequisites",
            "x86_header_prerequisites",
            "native_evidence",
            "oracle",
        ):
            require(key in entry, f"{item_location} is missing {key}")
        require(
            "capabilities" not in entry,
            f"{item_location} must not carry capabilities; use verified_slice instead",
        )
        require(isinstance(entry["id"], str) and entry["id"], f"{item_location}.id is empty")
        require(
            isinstance(entry["description"], str) and entry["description"],
            f"{item_location}.description is empty",
        )
        for owner_index, path_text in enumerate(
            nonempty_strings(entry["source_owners"], f"{item_location}.source_owners")
        ):
            repository_path(path_text, f"{item_location}.source_owners[{owner_index}]")
        nonempty_strings(entry["x86_abi_prerequisites"], f"{item_location}.x86_abi_prerequisites")
        nonempty_strings(entry["x86_header_prerequisites"], f"{item_location}.x86_header_prerequisites")
        require_evidence_state(entry["native_evidence"], f"{item_location}.native_evidence", "verified")
        require_oracles(entry["oracle"], f"{item_location}.oracle")
        records.append(entry)
    return records


def require_byte_string_artifact(family: Mapping[str, Any]) -> None:
    """Keep the closed byte-string artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-byte-strings"]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-byte-strings artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in BYTE_STRING_SYMBOLS:
        require(symbol in description, f"static-c-byte-strings description omits {symbol}")
    for phrase in (
        "public `index` and `rindex` forwarding wrappers",
        "private `__strchrnul`/`__memrchr` helpers",
        "scalar fallback",
    ):
        require(phrase in description, f"static-c-byte-strings description omits {phrase}")
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence} == {"./scripts/dev-x86_64.sh libc-byte-strings"},
        "static-c-byte-strings must use the closed libc-byte-strings command",
    )


def require_random_entropy_artifact(family: Mapping[str, Any]) -> None:
    """Keep the direct entropy artifact's cancellation and TLS boundary explicit."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-random-entropy"]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-random-entropy artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in RANDOM_ENTROPY_SYMBOLS:
        require(symbol in description, f"static-c-random-entropy description omits {symbol}")
    for phrase in (
        "pthread cancellation point",
        "disables cancellation",
        "omits pthread cancellation",
        "initial-TLS errno",
    ):
        require(phrase in description, f"static-c-random-entropy description omits {phrase}")
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any("syscall_cp" in item and "cancellation point" in item for item in prerequisites),
        "static-c-random-entropy must record musl getrandom cancellation semantics",
    )
    require(
        any("disables cancellation" in item for item in prerequisites),
        "static-c-random-entropy must record musl getentropy cancellation semantics",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-random-entropy"},
        "static-c-random-entropy must use the closed libc-random-entropy command",
    )


def require_memory_search_artifact(family: Mapping[str, Any]) -> None:
    """Keep the stateless memory-search artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-memory-search"]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-memory-search artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in MEMORY_SEARCH_SYMBOLS:
        require(symbol in description, f"static-c-memory-search description omits {symbol}")
    for phrase in (
        "private `__memrchr` helper",
        "stateless",
        "allocation-free",
    ):
        require(phrase in description, f"static-c-memory-search description omits {phrase}")
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-memory-search"},
        "static-c-memory-search must use the closed libc-memory-search command",
    )


def require_string_copy_artifact(family: Mapping[str, Any]) -> None:
    """Keep the stateless C-string-copy artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-string-copy"]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-string-copy artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in STRING_COPY_SYMBOLS:
        require(symbol in description, f"static-c-string-copy description omits {symbol}")
    for phrase in (
        "private `__stpcpy`/`__stpncpy` helpers",
        "stateless",
        "allocation-free",
        "scalar fallback",
    ):
        require(phrase in description, f"static-c-string-copy description omits {phrase}")
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-string-copy"},
        "static-c-string-copy must use the closed libc-string-copy command",
    )


def require_ctype_artifact(family: Mapping[str, Any]) -> None:
    """Keep the fixed-C-locale ctype artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-ctype"]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-ctype artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in CTYPE_SYMBOLS:
        require(symbol in description, f"static-c-ctype description omits {symbol}")
    for phrase in (
        "fixed-C-locale ctype block",
        "stateless",
        "allocation-free",
        "`EOF` and every `unsigned char` value",
        "locale selection and `_l` entries",
    ):
        require(phrase in description, f"static-c-ctype description omits {phrase}")
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-ctype"},
        "static-c-ctype must use the closed libc-ctype command",
    )


def require_integer_arithmetic_artifact(family: Mapping[str, Any]) -> None:
    """Keep the stateless integer-arithmetic artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-integer-arithmetic"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-integer-arithmetic artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in INTEGER_ARITHMETIC_SYMBOLS:
        require(
            symbol in description,
            f"static-c-integer-arithmetic description omits {symbol}",
        )
    for phrase in (
        "integer-arithmetic block",
        "stateless",
        "allocation-free",
        "unrepresentable absolute value",
        "zero divisor",
        "native signed `idiv`",
    ):
        require(
            phrase in description,
            f"static-c-integer-arithmetic description omits {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-integer-arithmetic"},
        "static-c-integer-arithmetic must use the closed libc-integer-arithmetic command",
    )


def require_integer_parse_artifact(family: Mapping[str, Any]) -> None:
    """Keep the bounded integer-parsing artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-integer-parse"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-integer-parse artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in INTEGER_PARSE_SYMBOLS:
        require(
            symbol in description,
            f"static-c-integer-parse description omits {symbol}",
        )
    for phrase in (
        "integer-parsing block",
        "complete selected byte-string scan",
        "fixed-C-locale",
        "`0x` prefixes",
        "`EINVAL` invalid-base/no-conversion",
        "stale errno on success",
        "`ERANGE` saturation",
        "defined-input",
        "allocation-free",
    ):
        require(
            phrase in description,
            f"static-c-integer-parse description omits {phrase}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any(
            "rdi/rsi/rdx" in item and "intmax_t/uintmax_t" in item
            for item in prerequisites
        ),
        "static-c-integer-parse must record its SysV and LP64 calling contract",
    )
    require(
        any(
            "strtol.c" in item and "intscan.c" in item and "shgetc" in item
            for item in prerequisites
        ),
        "static-c-integer-parse must record its pinned-musl scan mapping",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-integer-parse"},
        "static-c-integer-parse must use the closed libc-integer-parse command",
    )


def require_intmax_arithmetic_artifact(family: Mapping[str, Any]) -> None:
    """Keep the stateless intmax-arithmetic artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-intmax-arithmetic"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-intmax-arithmetic artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in INTMAX_ARITHMETIC_SYMBOLS:
        require(
            symbol in description,
            f"static-c-intmax-arithmetic description omits {symbol}",
        )
    for phrase in (
        "intmax-arithmetic block",
        "stateless",
        "allocation-free",
        "unrepresentable absolute value",
        "zero divisor",
        "native signed `idiv`",
    ):
        require(
            phrase in description,
            f"static-c-intmax-arithmetic description omits {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-intmax-arithmetic"},
        "static-c-intmax-arithmetic must use the closed libc-intmax-arithmetic command",
    )


def require_credential_observation_artifact(family: Mapping[str, Any]) -> None:
    """Keep the read-only credential-observation artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-credential-observation"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-credential-observation artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in CREDENTIAL_OBSERVATION_SYMBOLS:
        require(
            symbol in description,
            f"static-c-credential-observation description omits {symbol}",
        )
    for phrase in (
        "credential-observation block",
        "read-only",
        "query-then-fill race",
        "GNU",
        "initial-TLS",
    ):
        require(
            phrase in description,
            f"static-c-credential-observation description omits {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-credential-observation"},
        "static-c-credential-observation must use the closed libc-credential-observation command",
    )


def require_child_reaping_artifact(family: Mapping[str, Any]) -> None:
    """Keep the complete direct child-reaping artifact boundary durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-child-reaping"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-child-reaping artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in CHILD_REAPING_SYMBOLS:
        require(
            symbol in description,
            f"static-c-child-reaping description omits {symbol}",
        )
    for phrase in (
        "child-reaping block",
        "WNOHANG",
        "WNOWAIT",
        "cancellation",
        "initial-TLS",
    ):
        require(
            phrase in description,
            f"static-c-child-reaping description omits {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-child-reaping"},
        "static-c-child-reaping must use the closed libc-child-reaping command",
    )


def require_immediate_termination_artifact(family: Mapping[str, Any]) -> None:
    """Keep the no-state C11 immediate-termination boundary durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-immediate-termination"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-immediate-termination artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in IMMEDIATE_TERMINATION_SYMBOLS:
        require(
            symbol in description,
            f"static-c-immediate-termination description omits {symbol}",
        )
    for phrase in (
        "immediate-termination block",
        "exit_group=231",
        "exit=60",
        "no errno",
        "quick_exit",
        "initial-TLS",
    ):
        require(
            phrase in description,
            f"static-c-immediate-termination description omits {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-immediate-termination"},
        "static-c-immediate-termination must use the closed libc-immediate-termination command",
    )


def require_callback_algorithms_artifact(family: Mapping[str, Any]) -> None:
    """Keep the stateless musl callback-algorithms boundary durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-callback-algorithms"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-callback-algorithms artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in CALLBACK_ALGORITHM_SYMBOLS:
        require(
            f"`{symbol}`" in description,
            f"static-c-callback-algorithms description omits {symbol}",
        )
    for phrase in (
        "callback-algorithms block",
        "smoothsort",
        "same-address",
        "weak",
        "stateless",
        "allocation-free",
        "no syscall",
        "no errno",
        "no initial-TLS",
        "longjmp",
        "C++ exception",
    ):
        require(
            phrase in description,
            f"static-c-callback-algorithms description omits {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-callback-algorithms"},
        "static-c-callback-algorithms must use the closed libc-callback-algorithms command",
    )


def require_clock_gettime_artifact(family: Mapping[str, Any]) -> None:
    """Keep the normal-C-result clock-observation boundary concrete."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-clock-gettime"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-clock-gettime artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "POSIX clock_gettime block",
        "`clock_gettime`",
        "-1/errno",
        "initial-TLS errno",
        "vDSO resolver",
        "clock_getres",
        "clock_settime",
    ):
        require(
            phrase in description,
            f"static-c-clock-gettime description omits {phrase}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any("clock_gettime=228" in item and "rdi/rsi" in item for item in prerequisites),
        "static-c-clock-gettime must record its two-register syscall ABI",
    )
    require(
        any("vDSO resolver" in item and "dynamic process-lifetime state" in item for item in prerequisites),
        "static-c-clock-gettime must record the vDSO boundary",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-clock-gettime"},
        "static-c-clock-gettime must use the closed libc-clock-gettime command",
    )


def require_system_configuration_artifact(family: Mapping[str, Any]) -> None:
    """Keep the musl-oracle configuration boundary closed and non-promoting."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-system-configuration"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-system-configuration artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "system-configuration block",
        "`sysconf`",
        "`confstr`",
        "`pathconf`",
        "`fpathconf`",
        "`getpagesize`",
        "`getdtablesize`",
        "path- and fd-independent",
        "corresponding AArch64",
        "focused dynamic fixture",
        "full musl sysconf table",
        "startup-owned auxv/getauxval",
    ):
        require(
            phrase in description,
            f"static-c-system-configuration description omits {phrase}",
        )
    owners = set(artifact["source_owners"])
    for owner in (
        "libc/src/c_abi/x86_64/system_configuration.rs",
        "compat/x86_64/libc_system_configuration_probe.c",
        "compat/x86_64/libc_system_configuration_start.S",
        "compat/x86_64/run_libc_system_configuration.sh",
        "compat/x86_64/unistd_header_abi_probe.c",
        "compat/x86_64/unistd_header_abi_probe.cpp",
        "compat/x86_64/run_unistd_header_abi.sh",
        "libc/src/regression_stubs.rs",
        "tests/fixtures/path_configuration_exports_test.c",
        "tests/path_configuration_exports.rs",
    ):
        require(
            owner in owners,
            f"static-c-system-configuration must own {owner}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any("prlimit64=302" in item and "rdi/rsi/rdx/r10" in item for item in prerequisites),
        "static-c-system-configuration must record the prlimit64 four-register ABI",
    )
    require(
        any(
            "path- and fd-independent" in item
            and "corresponding AArch64" in item
            and "focused dynamic fixture" in item
            for item in prerequisites
        ),
        "static-c-system-configuration must record the AArch64 musl pathconf proof",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-system-configuration"},
        "static-c-system-configuration must use the closed libc-system-configuration command",
    )


def require_clock_nanosleep_artifact(family: Mapping[str, Any]) -> None:
    """Keep the direct-positive-error clock sleep boundary durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-clock-nanosleep"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-clock-nanosleep artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "POSIX clock_nanosleep block",
        "`clock_nanosleep`",
        "positive errno",
        "CLOCK_REALTIME",
        "__syscall_cp",
        "omits cancellation",
        "separately selected nanosleep leaf",
        "initial-TLS errno",
    ):
        require(
            phrase in description,
            f"static-c-clock-nanosleep description omits {phrase}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any("clock_nanosleep=230" in item and "rdi/rsi/rdx/r10" in item for item in prerequisites),
        "static-c-clock-nanosleep must record its four-register syscall ABI",
    )
    require(
        any("remaining timespec only on EINTR" in item for item in prerequisites),
        "static-c-clock-nanosleep must record the relative remainder contract",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-clock-nanosleep"},
        "static-c-clock-nanosleep must use the closed libc-clock-nanosleep command",
    )


def require_nanosleep_artifact(family: Mapping[str, Any]) -> None:
    """Keep the normal-C-result nanosleep boundary durable and non-promoting."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-nanosleep"]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-nanosleep artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "POSIX nanosleep block",
        "`nanosleep`",
        "-1/errno",
        "initial-TLS errno",
        "__syscall_cp",
        "omits cancellation",
        "`sleep`/`usleep`",
    ):
        require(
            phrase in description,
            f"static-c-nanosleep description omits {phrase}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any("nanosleep=35" in item and "rdi/rsi" in item for item in prerequisites),
        "static-c-nanosleep must record its two-register syscall ABI",
    )
    require(
        any("remaining timespec only on EINTR" in item for item in prerequisites),
        "static-c-nanosleep must record the EINTR remainder contract",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-nanosleep"},
        "static-c-nanosleep must use the closed libc-nanosleep command",
    )


def require_descriptor_entry_artifact(family: Mapping[str, Any]) -> None:
    """Keep the static C descriptor-entry artifact concrete and non-promoting."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-descriptor-entry"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-descriptor-entry artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "descriptor-entry block",
        "`open`",
        "`openat`",
        "`creat`",
        "O_CLOEXEC",
        "O_LARGEFILE",
        "does not expand C fcntl beyond",
        "cancellation",
    ):
        require(
            phrase in description,
            f"static-c-descriptor-entry description omits {phrase}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any(
            "open=2" in item
            and "openat=257" in item
            and "rdi/rsi/rdx/r10" in item
            for item in prerequisites
        ),
        "static-c-descriptor-entry must record its open/openat register ABI",
    )
    require(
        any(
            "complete O_TMPFILE" in item and "O_LARGEFILE" in item
            for item in prerequisites
        ),
        "static-c-descriptor-entry must record its optional-mode and O_LARGEFILE contract",
    )
    require(
        any(
            "F_SETFD=2/FD_CLOEXEC=1" in item and "omits all __syscall_cp" in item
            for item in prerequisites
        ),
        "static-c-descriptor-entry must record its private O_CLOEXEC and cancellation boundary",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-descriptor-entry"},
        "static-c-descriptor-entry must use the closed libc-descriptor-entry command",
    )


def require_fcntl_status_control_artifact(family: Mapping[str, Any]) -> None:
    """Keep the bounded variadic C fcntl artifact honest and non-promoting."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-fcntl-status-control"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-fcntl-status-control artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "fcntl status-control block",
        "`F_GETFD`",
        "`F_SETFD`",
        "`F_GETFL`",
        "`F_SETFL`",
        "O_LARGEFILE",
        "-1/EINVAL",
        "does not select generic C fcntl",
        "F_SETLKW cancellation",
    ):
        require(
            phrase in description,
            f"static-c-fcntl-status-control description omits {phrase}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any(
            "fcntl=72" in item
            and "rdi/rsi/rdx" in item
            and "F_GETFD=1" in item
            and "F_GETFL=3" in item
            and "F_SETFD=2" in item
            and "F_SETFL=4" in item
            for item in prerequisites
        ),
        "static-c-fcntl-status-control must record its variadic register ABI",
    )
    require(
        any(
            "rdx=0" in item and "F_GETFD=1" in item and "F_GETFL=3" in item
            for item in prerequisites
        ),
        "static-c-fcntl-status-control must record its no-vararg boundary",
    )
    require(
        any("O_LARGEFILE=0x8000" in item and "F_SETFL" in item for item in prerequisites),
        "static-c-fcntl-status-control must record its F_SETFL O_LARGEFILE rule",
    )
    require(
        any(
            "-1/EINVAL" in item and "without observing an absent vararg" in item
            for item in prerequisites
        ),
        "static-c-fcntl-status-control must record its unsupported-command boundary",
    )
    require(
        any(
            "src/fcntl/fcntl.c" in item
            and "__syscall_cp" in item
            and "F_GETOWN" in item
            and "F_DUPFD_CLOEXEC" in item
            for item in prerequisites
        ),
        "static-c-fcntl-status-control must record its pinned-musl differences",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-fcntl-status-control"},
        "static-c-fcntl-status-control must use the closed libc-fcntl-status-control command",
    )


def require_ffs_artifact(family: Mapping[str, Any]) -> None:
    """Keep the stateless find-first-set artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-ffs"]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-ffs artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in FFS_SYMBOLS:
        require(symbol in description, f"static-c-ffs description omits {symbol}")
    for phrase in (
        "find-first-set block",
        "stateless",
        "allocation-free",
        "least-significant set bit",
        "two's-complement",
        "no errno/TLS or syscall boundary",
    ):
        require(phrase in description, f"static-c-ffs description omits {phrase}")
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-ffs"},
        "static-c-ffs must use the closed libc-ffs command",
    )


def baseline_capability_ids(path: Path) -> set[str]:
    """Load the checked-in baseline ledger instead of freezing its ID count here."""
    baseline = load_toml(path)
    capabilities = baseline.get("capability")
    require(isinstance(capabilities, list) and capabilities, "baseline capability ledger has no capability records")
    identifiers: set[str] = set()
    for index, entry in enumerate(capabilities):
        location = f"baseline capability[{index}]"
        require(isinstance(entry, Mapping), f"{location} must be a table")
        identifier = entry.get("id")
        require(isinstance(identifier, str) and identifier, f"{location}.id is empty")
        require(identifier not in identifiers, f"baseline capability ledger has duplicate id: {identifier}")
        identifiers.add(identifier)
    return identifiers


def has_musl_oracle(family: Mapping[str, Any]) -> bool:
    """Whether a parity family names musl as an oracle in its own contract."""
    records = family["oracle"]
    assert isinstance(records, list)
    return any(
        isinstance(record, Mapping)
        and isinstance(record.get("source"), str)
        and "musl" in record["source"].lower()
        for record in records
    )


def validate_ledger(
    data: Mapping[str, Any], *, header_layout_manifest: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    require(data.get("schema") == EXPECTED_SCHEMA, "unexpected x86 parity ledger schema")
    require(data.get("target") == EXPECTED_TARGET, "unexpected x86 parity target")
    require(data.get("platform") == EXPECTED_PLATFORM, "unexpected x86 parity platform")
    require(data.get("kernel_msrv") == EXPECTED_KERNEL_MSRV, "unexpected x86 parity kernel MSRV")
    require(data.get("baseline_platform") == "Linux/AArch64 little-endian", "baseline platform changed")
    baseline_path = repository_path(str(data.get("baseline_capability_ledger", "")), "baseline_capability_ledger")
    repository_path(str(data.get("baseline_gate_dispatch", "")), "baseline_gate_dispatch")

    policy = data.get("policy")
    require(isinstance(policy, Mapping), "policy must be a table")
    expected_policy = {
        "native_execution_only": True,
        "public_support": False,
        "no_emulation": True,
        "no_portability_framework": True,
        "no_symbol_count_claim": True,
    }
    require(dict(policy) == expected_policy, "x86 parity policy drifted")

    meanings = data.get("status_meaning")
    require(isinstance(meanings, Mapping), "status_meaning must be a table")
    require(
        all(
            isinstance(meanings.get(name), str) and meanings[name]
            for name in ("foundation_verified", "planned", "verified_artifact")
        ),
        "status meanings are incomplete",
    )

    promotion = data.get("promotion")
    require(isinstance(promotion, Mapping), "promotion must be a table")
    required_families = nonempty_strings(promotion.get("required_families"), "promotion.required_families")
    require(tuple(required_families) == EXPECTED_FAMILIES, "promotion family roster drifted")

    excluded = data.get("excluded_surface")
    require(isinstance(excluded, list) and len(excluded) == 1, "exactly one excluded surface is required")
    excluded_entry = excluded[0]
    require(isinstance(excluded_entry, Mapping), "excluded_surface[0] must be a table")
    require(excluded_entry.get("id") == "allocator.mimalloc-private", "private allocator exclusion changed")
    require(isinstance(excluded_entry.get("reason"), str) and excluded_entry["reason"], "allocator exclusion needs a reason")
    for index, path_text in enumerate(nonempty_strings(excluded_entry.get("evidence"), "excluded_surface[0].evidence")):
        repository_path(path_text, f"excluded_surface[0].evidence[{index}]")

    families = data.get("family")
    require(isinstance(families, list), "family must be an array")
    require(len(families) == len(EXPECTED_FAMILIES), "family count drifted")
    ids: set[str] = set()
    orders: list[int] = []
    by_id: dict[str, Mapping[str, Any]] = {}
    status_counts = {status: 0 for status in sorted(ALLOWED_STATUSES)}
    verified_slice_ids: set[str] = set()
    verified_artifact_ids: set[str] = set()
    verified_record_ids: set[str] = set()
    for index, entry in enumerate(families):
        location = f"family[{index}]"
        require(isinstance(entry, Mapping), f"{location} must be a table")
        for key in (
            "id",
            "order",
            "depends_on",
            "category",
            "description",
            "aarch64_gates",
            "source_owners",
            "x86_abi_prerequisites",
            "x86_header_prerequisites",
            "native_evidence",
            "oracle",
            "capabilities",
            "status",
        ):
            require(key in entry, f"{location} is missing {key}")
        identifier = entry["id"]
        require(isinstance(identifier, str) and identifier, f"{location}.id is empty")
        require(identifier not in ids, f"duplicate family id: {identifier}")
        require(identifier in EXPECTED_FAMILIES, f"unexpected family id: {identifier}")
        order = entry["order"]
        require(isinstance(order, int) and order > 0, f"{location}.order is invalid")
        category = entry["category"]
        status = entry["status"]
        require(category in ALLOWED_CATEGORIES, f"{location}.category is invalid")
        require(status in ALLOWED_STATUSES, f"{location}.status is invalid")
        require(isinstance(entry["description"], str) and entry["description"], f"{location}.description is empty")
        gates = nonempty_strings(entry["aarch64_gates"], f"{location}.aarch64_gates")
        unknown_gates = sorted(set(gates) - KNOWN_AARCH64_GATES)
        require(not unknown_gates, f"{location} names unknown AArch64 gates: {', '.join(unknown_gates)}")
        for owner_index, path_text in enumerate(nonempty_strings(entry["source_owners"], f"{location}.source_owners")):
            repository_path(path_text, f"{location}.source_owners[{owner_index}]")
        nonempty_strings(entry["x86_abi_prerequisites"], f"{location}.x86_abi_prerequisites")
        nonempty_strings(entry["x86_header_prerequisites"], f"{location}.x86_header_prerequisites")
        require_evidence(entry["native_evidence"], f"{location}.native_evidence", status)
        require_oracles(entry["oracle"], f"{location}.oracle")
        family_capabilities = string_list(
            entry["capabilities"], f"{location}.capabilities", allow_empty=True
        )
        verified_slice_capabilities: set[str] = set()
        for slice_entry in require_verified_slices(
            entry.get("verified_slice"),
            f"{location}.verified_slice",
            status,
            family_capabilities,
        ):
            slice_id = slice_entry["id"]
            assert isinstance(slice_id, str)
            require(slice_id not in verified_record_ids, f"duplicate verified record id: {slice_id}")
            verified_record_ids.add(slice_id)
            verified_slice_ids.add(slice_id)
            for capability in nonempty_strings(
                slice_entry["capabilities"], f"{location}.verified_slice[{slice_id}].capabilities"
            ):
                require(
                    capability not in verified_slice_capabilities,
                    f"{location}.verified_slice duplicates a capability: {capability}",
                )
                verified_slice_capabilities.add(capability)
        if identifier == "facade.record-owning" and status == "foundation-verified":
            family_capability_set = set(family_capabilities)
            missing_slice_capabilities = sorted(
                family_capability_set - verified_slice_capabilities
            )
            unexpected_slice_capabilities = sorted(
                verified_slice_capabilities - family_capability_set
            )
            require(
                not missing_slice_capabilities and not unexpected_slice_capabilities,
                f"{location}.verified_slice must exactly cover the foundation family capabilities; "
                f"missing: {', '.join(missing_slice_capabilities) or 'none'}; "
                f"unexpected: {', '.join(unexpected_slice_capabilities) or 'none'}",
            )
        for artifact_entry in require_verified_artifacts(
            entry.get("verified_artifact"),
            f"{location}.verified_artifact",
            status,
        ):
            artifact_id = artifact_entry["id"]
            assert isinstance(artifact_id, str)
            require(
                artifact_id not in verified_record_ids,
                f"duplicate verified record id: {artifact_id}",
            )
            verified_record_ids.add(artifact_id)
            verified_artifact_ids.add(artifact_id)
        ids.add(identifier)
        orders.append(order)
        by_id[identifier] = entry
        status_counts[status] += 1

    require(tuple(entry["id"] for entry in families) == EXPECTED_FAMILIES, "family table order must equal promotion dependency order")
    require(orders == sorted(orders) and len(orders) == len(set(orders)), "family order values must be unique and ascending")
    require(ids == set(EXPECTED_FAMILIES), "family coverage does not match promotion roster")

    if header_layout_manifest is None:
        header_layout_manifest = load_toml(HEADER_LAYOUT_MANIFEST_PATH)
    header_layout_report = validate_header_layout_manifest(
        by_id["libc.headers-layouts"], header_layout_manifest
    )

    require_byte_string_artifact(by_id["libc.posix-runtime"])
    require_random_entropy_artifact(by_id["libc.posix-runtime"])
    require_memory_search_artifact(by_id["libc.posix-runtime"])
    require_string_copy_artifact(by_id["libc.posix-runtime"])
    require_ctype_artifact(by_id["libc.posix-runtime"])
    require_integer_arithmetic_artifact(by_id["libc.posix-runtime"])
    require_integer_parse_artifact(by_id["libc.posix-runtime"])
    require_intmax_arithmetic_artifact(by_id["libc.posix-runtime"])
    require_credential_observation_artifact(by_id["libc.posix-runtime"])
    require_child_reaping_artifact(by_id["libc.posix-runtime"])
    require_immediate_termination_artifact(by_id["libc.posix-runtime"])
    require_callback_algorithms_artifact(by_id["libc.posix-runtime"])
    require_clock_gettime_artifact(by_id["libc.posix-runtime"])
    require_system_configuration_artifact(by_id["libc.posix-runtime"])
    require_clock_nanosleep_artifact(by_id["libc.posix-runtime"])
    require_nanosleep_artifact(by_id["libc.posix-runtime"])
    require_descriptor_entry_artifact(by_id["libc.posix-runtime"])
    require_fcntl_status_control_artifact(by_id["libc.posix-runtime"])
    require_ffs_artifact(by_id["libc.posix-runtime"])

    musl_oracle = by_id["oracle.musl-toolchain"]
    require(musl_oracle["status"] == "foundation-verified", "musl oracle must remain foundation-verified")
    musl_evidence, _ = require_evidence(
        musl_oracle["native_evidence"], "family[oracle.musl-toolchain].native_evidence", musl_oracle["status"]
    )
    require(
        [entry["command"] for entry in musl_evidence] == ["./scripts/dev-x86_64.sh musl-oracle"],
        "musl oracle must use the closed native musl-oracle command",
    )
    for identifier, family in by_id.items():
        if identifier != "oracle.musl-toolchain" and has_musl_oracle(family):
            dependencies = family["depends_on"]
            assert isinstance(dependencies, list)
            require(
                "oracle.musl-toolchain" in dependencies,
                f"musl-backed family {identifier} must depend on oracle.musl-toolchain",
            )

    baseline_ids = baseline_capability_ids(baseline_path)
    capability_owners: dict[str, str] = {}
    for identifier, family in by_id.items():
        capabilities = string_list(
            family["capabilities"], f"family[{identifier}].capabilities", allow_empty=True
        )
        require(
            len(capabilities) == len(set(capabilities)),
            f"family[{identifier}] maps a capability more than once",
        )
        for capability in capabilities:
            previous = capability_owners.get(capability)
            require(
                previous is None,
                f"baseline capability {capability} is mapped by both {previous} and {identifier}",
            )
            capability_owners[capability] = identifier

    mapped_ids = set(capability_owners)
    stale_ids = sorted(mapped_ids - baseline_ids)
    missing_ids = sorted(baseline_ids - mapped_ids)
    require(not stale_ids, f"parity ledger maps stale baseline capabilities: {', '.join(stale_ids)}")
    require(not missing_ids, f"parity ledger leaves baseline capabilities unmapped: {', '.join(missing_ids)}")

    orders_by_id = {identifier: entry["order"] for identifier, entry in by_id.items()}
    for identifier, entry in by_id.items():
        dependencies = nonempty_strings(entry["depends_on"], f"family[{identifier}].depends_on") if entry["depends_on"] else []
        require(len(dependencies) == len(set(dependencies)), f"family[{identifier}] has duplicate dependencies")
        for dependency in dependencies:
            require(dependency in by_id, f"family[{identifier}] depends on unknown family {dependency}")
            require(orders_by_id[dependency] < orders_by_id[identifier], f"family[{identifier}] dependency {dependency} is not earlier")

    dispatch_source = (ROOT / "scripts" / "dev.sh").read_text(encoding="utf-8")
    used_gates = {gate for family in families for gate in family["aarch64_gates"]}
    missing_dispatch = sorted(gate for gate in used_gates if f"    {gate})" not in dispatch_source and f"    {gate}|" not in dispatch_source)
    require(not missing_dispatch, f"AArch64 gate dispatch does not contain: {', '.join(missing_dispatch)}")

    return {
        "schema": EXPECTED_SCHEMA,
        "family_count": len(families),
        "capability_count": len(baseline_ids),
        "capability_owners": capability_owners,
        "status_counts": status_counts,
        "verified_slice_count": len(verified_slice_ids),
        "verified_artifact_count": len(verified_artifact_ids),
        "header_layout_probe_count": header_layout_report["probe_count"],
        "promotion_ready": all(family["status"] == "foundation-verified" for family in families),
        "public_support": policy["public_support"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate the checked-in ledger (default)")
    arguments = parser.parse_args()
    del arguments
    report = validate_ledger(load_toml(LEDGER_PATH))
    print(
        "x86 parity ledger: PASS "
        f"({report['family_count']} families; "
        f"foundation={report['status_counts']['foundation-verified']}; "
        f"planned={report['status_counts']['planned']}; "
        f"promotion_ready={report['promotion_ready']}; "
        f"public_support={report['public_support']})"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LedgerError as error:
        raise SystemExit(f"x86 parity ledger: ERROR: {error}") from error
