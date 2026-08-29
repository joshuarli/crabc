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
EXPECTED_SCHEMA = "crabc.x86_64-runtime-parity/v3"
EXPECTED_TARGET = "x86_64-unknown-linux-musl"
EXPECTED_PLATFORM = "Linux/x86-64 little-endian"
EXPECTED_KERNEL_MSRV = "5.10"

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
    """Validate completed vertical slices while their aggregate family stays planned."""
    if value is None:
        return []
    require(status == "planned", f"{location} is allowed only on a planned family")
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
        "nanosleep/sleep",
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
        "does not select C fcntl",
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


def validate_ledger(data: Mapping[str, Any]) -> dict[str, Any]:
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

    require_byte_string_artifact(by_id["libc.posix-runtime"])
    require_random_entropy_artifact(by_id["libc.posix-runtime"])
    require_memory_search_artifact(by_id["libc.posix-runtime"])
    require_string_copy_artifact(by_id["libc.posix-runtime"])
    require_ctype_artifact(by_id["libc.posix-runtime"])
    require_integer_arithmetic_artifact(by_id["libc.posix-runtime"])
    require_intmax_arithmetic_artifact(by_id["libc.posix-runtime"])
    require_credential_observation_artifact(by_id["libc.posix-runtime"])
    require_child_reaping_artifact(by_id["libc.posix-runtime"])
    require_immediate_termination_artifact(by_id["libc.posix-runtime"])
    require_callback_algorithms_artifact(by_id["libc.posix-runtime"])
    require_clock_nanosleep_artifact(by_id["libc.posix-runtime"])
    require_descriptor_entry_artifact(by_id["libc.posix-runtime"])
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
