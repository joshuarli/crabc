#!/usr/bin/env python3
"""Frozen workload ownership for the native POSIX runtime family.

The catalog says which 149 frozen spellings belong to ``libc.posix-runtime``.
This module says which executable workload owns each spelling, the retained
source/object roles that must remain stable across product runs, and which
zero-spelling workloads are independently required.  In particular, the
strong dynamic ``fork`` DSO case and the static fork/exec adapter are separate
records: neither global state composition nor a dynamic result supplies the
other one's evidence.

``required_supplementary_sources`` lists independent family inputs retained
beside a primary workload.  They are campaign requirements, not compiler
includes or a claim that the record's runner directly compiles them.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Sequence
import tomllib


ROOT = Path(__file__).resolve().parents[2]

STATIC_PRODUCTS = ("primary", "reproduction", "extracted")
STATIC_LINKAGES = ("et-exec", "pie")
STATIC_CELLS = tuple(
    f"{product}:{linkage}"
    for product in STATIC_PRODUCTS
    for linkage in STATIC_LINKAGES
)

DYNAMIC_PRODUCTS = ("installed", "second", "extracted")
DYNAMIC_LINKAGES = ("pie", "non-pie")
DYNAMIC_ENTRIES = ("kernel", "direct")
DYNAMIC_CELLS = tuple(
    f"{product}:{linkage}:{entry}"
    for product in DYNAMIC_PRODUCTS
    for linkage in DYNAMIC_LINKAGES
    for entry in DYNAMIC_ENTRIES
)

SCOPE_CELLS = MappingProxyType({
    "both": STATIC_CELLS + DYNAMIC_CELLS,
    "static": STATIC_CELLS,
    "dynamic": DYNAMIC_CELLS,
})


class WorkloadMapError(ValueError):
    """The frozen POSIX workload ownership contract is malformed."""


@dataclass(frozen=True)
class SourceObjectRole:
    """One source translation retained as a named leaf-relative object input."""

    role: str
    source: str
    object_path: str


@dataclass(frozen=True)
class Workload:
    """One executable family workload and its primary spelling ownership."""

    id: str
    script: str
    dynamic_case: str | None
    source_object_roles: tuple[SourceObjectRole, ...]
    product_scope: str
    required_supplementary_sources: tuple[str, ...]
    primary_symbols: tuple[str, ...]


def role(role_name: str, source: str, object_path: str) -> SourceObjectRole:
    return SourceObjectRole(role_name, source, object_path)


# Primary spelling lists retain frozen catalog order.  The owner map below is
# deliberately independent of the catalog's capability groups so a complete
# but reassigned partition still fails validation.
_LEGACY_FILESYSTEM = (
    "lchmod",
    "__fxstat", "__fxstatat", "__lxstat", "__xstat",
    "alphasort", "ftw", "nftw", "readdir_r", "scandir", "telldir", "versionsort",
    "mktemp", "name_to_handle_at", "open_by_handle_at", "tempnam", "tmpnam",
)
_CONTROL_RESIDUAL = (
    "execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe", "fexecve",
    "nice",
    "posix_spawnattr_destroy", "posix_spawnattr_getflags", "posix_spawnattr_getpgroup",
    "posix_spawnattr_getschedparam", "posix_spawnattr_getschedpolicy",
    "posix_spawnattr_getsigdefault", "posix_spawnattr_getsigmask", "posix_spawnattr_init",
    "posix_spawnattr_setflags", "posix_spawnattr_setpgroup", "posix_spawnattr_setschedparam",
    "posix_spawnattr_setschedpolicy", "posix_spawnattr_setsigdefault",
    "posix_spawnattr_setsigmask",
    "setpgid", "setpgrp", "setsid", "wait", "wait3", "wait4", "waitid", "waitpid",
)
_CREDENTIALS_PROFILE = (
    "setegid", "seteuid", "setgid", "setgroups", "setregid", "setresgid", "setresuid",
    "setreuid", "setuid",
)
_ENVIRONMENT_LIFECYCLE = ("clearenv", "setenv", "unsetenv")
_SIGNAL_FULL = (
    "__libc_current_sigrtmax", "__libc_current_sigrtmin", "kill", "killpg", "raise",
    "sigaction", "sigaddset", "sigaltstack", "sigandset", "sigdelset", "sigemptyset",
    "sigfillset", "siginterrupt", "sigisemptyset", "sigismember", "sigorset", "sigpause",
    "sigpending", "sigprocmask", "sigqueue", "signal", "signalfd", "sigsuspend",
)
_KERNEL_RESIDUAL = (
    "__sched_cpucount", "confstr", "fpathconf", "getdtablesize", "gethostid", "membarrier",
    "pathconf", "personality", "prctl", "sched_getparam", "sched_getscheduler",
    "sched_setparam", "sched_setscheduler", "setdomainname", "sethostname", "syscall",
    "sysconf", "ulimit",
)
_PROCESS_TRIO = ("clone", "daemon", "vfork")
_SPAWN = (
    "posix_spawn", "posix_spawnp", "posix_spawn_file_actions_addchdir_np",
    "posix_spawn_file_actions_addclose", "posix_spawn_file_actions_adddup2",
    "posix_spawn_file_actions_addfchdir_np", "posix_spawn_file_actions_addopen",
    "posix_spawn_file_actions_destroy", "posix_spawn_file_actions_init",
)
_SIGNAL_HELPERS = (
    "__sysv_signal", "bsd_signal", "psiginfo", "psignal", "sighold", "sigignore", "sigrelse",
    "sigset",
)
_IO_CANCELLATION = ("sigtimedwait", "sigwait", "sigwaitinfo")
_LINUX_CONTROL = (
    "acct", "capget", "capset", "delete_module", "fanotify_init", "fanotify_mark",
    "init_module", "klogctl", "pivot_root", "quotactl", "reboot", "setns", "swapon",
    "swapoff", "unshare", "process_vm_readv", "process_vm_writev", "ptrace",
)
_SYSLOG = ("closelog", "openlog", "setlogmask", "syslog", "vsyslog")

_IO_CANCELLATION_ROLES = (
    role("io-cancellation", "compat/x86_64/owned_io_cancellation_probe.c",
         "owned_io_cancellation.o"),
    role("descriptor-cancellation", "compat/x86_64/owned_descriptor_cancellation_probe.c",
         "owned_descriptor_cancellation.o"),
    role("socket-cancellation", "compat/x86_64/owned_socket_cancellation_probe.c",
         "owned_socket_cancellation.o"),
    role("sleep-wait-cancellation", "compat/x86_64/owned_sleep_wait_cancellation_probe.c",
         "owned_sleep_wait_cancellation.o"),
    role("open-lock-cancellation", "compat/x86_64/owned_open_lock_cancellation_probe.c",
         "owned_open_lock_cancellation.o"),
    role("semaphore-wait-cancellation", "compat/x86_64/owned_semaphore_wait_cancellation_probe.c",
         "owned_semaphore_wait_cancellation.o"),
    role("semaphore-cancellation", "compat/x86_64/owned_semaphore_cancellation_probe.c",
         "owned_semaphore_cancellation.o"),
    role("signal-wait-cancellation", "compat/x86_64/owned_signal_wait_cancellation_probe.c",
         "owned_signal_wait_cancellation.o"),
    role("entropy-cancellation", "compat/x86_64/owned_entropy_cancellation_probe.c",
         "owned_entropy_cancellation.o"),
    role("sysv-message-cancellation", "compat/x86_64/owned_sysv_message_cancellation_probe.c",
         "owned_sysv_message_cancellation.o"),
)

WORKLOADS = (
    Workload(
        "legacy-filesystem", "compat/x86_64/run_owned_posix_filesystem.sh", "posix-filesystem",
        (role("application", "compat/x86_64/owned_posix_filesystem_probe.c", "workload.o"),),
        "both", ("compat/x86_64/owned_filesystem_mechanisms_probe.c",), _LEGACY_FILESYSTEM,
    ),
    Workload(
        "control-residual", "compat/x86_64/run_owned_process_control.sh", "process-control",
        (role("application", "compat/x86_64/owned_process_control_probe.c", "workload.o"),),
        "both", (
            "compat/x86_64/owned_process_trio_probe.c", "compat/x86_64/owned_spawn_probe.c",
            "compat/x86_64/general_dynamic_fork_library.c",
            "compat/x86_64/general_dynamic_fork_consumer.c",
            "compat/x86_64/owned_atfork_registry_probe.c",
            "compat/x86_64/owned_static_posix_probe.c",
        ), _CONTROL_RESIDUAL,
    ),
    Workload(
        "credentials-profile", "compat/x86_64/run_owned_credentials_profile.sh", "credentials-profile",
        (role("application", "compat/x86_64/owned_credentials_profile_probe.c", "workload.o"),),
        "both", (), _CREDENTIALS_PROFILE,
    ),
    Workload(
        "environment-lifecycle", "compat/x86_64/run_owned_environment_lifecycle.sh", "environment-lifecycle",
        (role("application", "compat/x86_64/owned_environment_lifecycle_probe.c", "workload.o"),),
        "both", (), _ENVIRONMENT_LIFECYCLE,
    ),
    Workload(
        "signal-full", "compat/x86_64/run_owned_posix_signals.sh", "signal-full",
        (role("application", "compat/x86_64/owned_posix_signals_probe.c", "workload.o"),),
        "both", (
            "compat/x86_64/owned_signal_helpers_probe.c",
            "compat/x86_64/owned_pthread_signal_probe.c",
            "compat/x86_64/owned_posix_timers_probe.c",
            "compat/x86_64/owned_posix_timers_tls.c",
            "compat/x86_64/owned_io_cancellation_fixtures.sh",
        ), _SIGNAL_FULL,
    ),
    Workload(
        "kernel-residual", "compat/x86_64/run_owned_kernel_residual.sh", "kernel-residual",
        (role("application", "compat/x86_64/owned_kernel_residual_probe.c", "workload.o"),),
        "both", (
            "compat/x86_64/owned_linux_control_probe.c", "compat/x86_64/owned_syslog_probe.c",
            "compat/x86_64/owned_system_cancellation_probe.c",
            "compat/x86_64/owned_system_cancellation_child.c",
        ), _KERNEL_RESIDUAL,
    ),
    Workload(
        "global-state-composition", "compat/x86_64/run_owned_posix_composition.sh", "posix-composition",
        (role("application", "compat/x86_64/owned_posix_composition_probe.c", "workload.o"),),
        "both", (), (),
    ),
    Workload(
        "process-trio", "compat/x86_64/run_owned_process_trio.sh", "process-trio",
        (role("application", "compat/x86_64/owned_process_trio_probe.c", "workload.o"),),
        "both", (), _PROCESS_TRIO,
    ),
    Workload(
        "spawn", "compat/x86_64/run_owned_dynamic_spawn.sh", "spawn",
        (role("application", "compat/x86_64/owned_spawn_probe.c", "workload.o"),),
        "both", (), _SPAWN,
    ),
    Workload(
        "fork", "compat/x86_64/run_general_dynamic_fork.sh", "fork",
        (
            role("initial-dso", "compat/x86_64/general_dynamic_fork_library.c",
                 "objects/libfork-initial.o"),
            role("one-dso", "compat/x86_64/general_dynamic_fork_library.c",
                 "objects/libfork-one.o"),
            role("two-dso", "compat/x86_64/general_dynamic_fork_library.c",
                 "objects/libfork-two.o"),
            role("semantic-consumer", "compat/x86_64/general_dynamic_fork_consumer.c",
                 "objects/semantic-consumer.o"),
            role("owned-layout-consumer", "compat/x86_64/general_dynamic_fork_consumer.c",
                 "objects/owned-layout-consumer.o"),
        ),
        "dynamic", (), ("fork",),
    ),
    Workload(
        "signal-helpers", "compat/x86_64/run_owned_signal_helpers.sh", "signal-helpers",
        (role("application", "compat/x86_64/owned_signal_helpers_probe.c", "workload.o"),),
        "both", (), _SIGNAL_HELPERS,
    ),
    Workload(
        "io-cancellation", "compat/x86_64/run_owned_dynamic_io_cancellation.sh", "io-cancellation",
        _IO_CANCELLATION_ROLES, "both",
        ("compat/x86_64/owned_io_cancellation_fixtures.sh",), _IO_CANCELLATION,
    ),
    Workload(
        "pthread-signal", "compat/x86_64/run_owned_pthread_signal.sh", "pthread-signal",
        (role("application", "compat/x86_64/owned_pthread_signal_probe.c", "workload.o"),),
        "both", (), (),
    ),
    Workload(
        "posix-timers", "compat/x86_64/run_owned_posix_timers.sh", "posix-timers",
        (
            role("application", "compat/x86_64/owned_posix_timers_probe.c", "probe.o"),
            role("timer-tls-dso", "compat/x86_64/owned_posix_timers_tls.c", "tls.o"),
        ),
        "both", (), (),
    ),
    Workload(
        "linux-control", "compat/x86_64/run_owned_linux_control.sh", "linux-control",
        (role("application", "compat/x86_64/owned_linux_control_probe.c", "workload.o"),),
        "both", (), _LINUX_CONTROL,
    ),
    Workload(
        "syslog", "compat/x86_64/run_owned_syslog.sh", "syslog",
        (role("application", "compat/x86_64/owned_syslog_probe.c", "workload.o"),),
        "both", (), _SYSLOG,
    ),
    Workload(
        "system-cancellation", "compat/x86_64/run_owned_system_cancellation.sh", "system-cancellation",
        (
            role("consumer", "compat/x86_64/owned_system_cancellation_probe.c", "consumer.o"),
            role("child", "compat/x86_64/owned_system_cancellation_child.c", "child.o"),
        ),
        "both", (), ("system",),
    ),
    Workload(
        "static-fork", "compat/x86_64/run_owned_posix_static_fork.sh", None,
        (
            role("atfork-registry", "compat/x86_64/owned_atfork_registry_probe.c",
                 "atfork-registry/workload.o"),
            role("static-posix-forkexec", "compat/x86_64/owned_static_posix_probe.c",
                 "static-posix-forkexec/workload.o"),
        ),
        "static", (), (),
    ),
)

_SUPPLEMENTAL_WORKLOADS = frozenset({
    "global-state-composition", "pthread-signal", "posix-timers", "static-fork",
})
# A primary spelling may have a dynamic-only primary owner only when this
# explicit static workload retains its separate static evidence.  The map is
# deliberately keyed by spelling so a coordinator can account for all 149
# names in both product families without assigning ``fork`` to composition.
STATIC_SUPPLEMENTAL_OWNERS = MappingProxyType({"fork": "static-fork"})
_EXPECTED_WORKLOAD_BINDINGS = MappingProxyType({
    "legacy-filesystem": ("compat/x86_64/run_owned_posix_filesystem.sh", "posix-filesystem", "both"),
    "control-residual": ("compat/x86_64/run_owned_process_control.sh", "process-control", "both"),
    "credentials-profile": ("compat/x86_64/run_owned_credentials_profile.sh", "credentials-profile", "both"),
    "environment-lifecycle": ("compat/x86_64/run_owned_environment_lifecycle.sh", "environment-lifecycle", "both"),
    "signal-full": ("compat/x86_64/run_owned_posix_signals.sh", "signal-full", "both"),
    "kernel-residual": ("compat/x86_64/run_owned_kernel_residual.sh", "kernel-residual", "both"),
    "global-state-composition": ("compat/x86_64/run_owned_posix_composition.sh", "posix-composition", "both"),
    "process-trio": ("compat/x86_64/run_owned_process_trio.sh", "process-trio", "both"),
    "spawn": ("compat/x86_64/run_owned_dynamic_spawn.sh", "spawn", "both"),
    "fork": ("compat/x86_64/run_general_dynamic_fork.sh", "fork", "dynamic"),
    "signal-helpers": ("compat/x86_64/run_owned_signal_helpers.sh", "signal-helpers", "both"),
    "io-cancellation": ("compat/x86_64/run_owned_dynamic_io_cancellation.sh", "io-cancellation", "both"),
    "pthread-signal": ("compat/x86_64/run_owned_pthread_signal.sh", "pthread-signal", "both"),
    "posix-timers": ("compat/x86_64/run_owned_posix_timers.sh", "posix-timers", "both"),
    "linux-control": ("compat/x86_64/run_owned_linux_control.sh", "linux-control", "both"),
    "syslog": ("compat/x86_64/run_owned_syslog.sh", "syslog", "both"),
    "system-cancellation": ("compat/x86_64/run_owned_system_cancellation.sh", "system-cancellation", "both"),
    "static-fork": ("compat/x86_64/run_owned_posix_static_fork.sh", None, "static"),
})


def _expected_primary_owners() -> Mapping[str, str]:
    owners: dict[str, str] = {}
    for identifier, symbols in (
        ("legacy-filesystem", _LEGACY_FILESYSTEM),
        ("control-residual", _CONTROL_RESIDUAL),
        ("credentials-profile", _CREDENTIALS_PROFILE),
        ("environment-lifecycle", _ENVIRONMENT_LIFECYCLE),
        ("signal-full", _SIGNAL_FULL),
        ("kernel-residual", _KERNEL_RESIDUAL),
        ("process-trio", _PROCESS_TRIO),
        ("spawn", _SPAWN),
        ("fork", ("fork",)),
        ("signal-helpers", _SIGNAL_HELPERS),
        ("io-cancellation", _IO_CANCELLATION),
        ("linux-control", _LINUX_CONTROL),
        ("syslog", _SYSLOG),
        ("system-cancellation", ("system",)),
    ):
        for symbol in symbols:
            if symbol in owners:
                raise AssertionError(f"duplicate frozen primary owner: {symbol}")
            owners[symbol] = identifier
    return MappingProxyType(owners)


EXPECTED_PRIMARY_OWNERS = _expected_primary_owners()


def load_catalog():
    """Load the existing frozen catalog only when validation is requested."""
    import owned_posix_runtime_catalog as catalog

    with catalog.CATALOG_PATH.open("rb") as source:
        document = tomllib.load(source)
    return catalog.validate_catalog(document, catalog.frozen_family_symbols())


def _physical_source(root: Path, source: object, description: str) -> None:
    if not isinstance(source, str) or not source:
        raise WorkloadMapError(f"{description} must be a nonempty relative path")
    path = Path(source)
    if path.is_absolute() or ".." in path.parts:
        raise WorkloadMapError(f"{description} escapes checkout: {source}")
    target = root / path
    if not target.is_file() or target.resolve() != target:
        raise WorkloadMapError(f"{description} is missing or nonphysical: {source}")


def _relative_object_path(path: object, description: str) -> None:
    if not isinstance(path, str) or not path:
        raise WorkloadMapError(f"{description} must be a nonempty leaf-relative path")
    parsed = Path(path)
    if parsed.is_absolute() or ".." in parsed.parts or parsed == Path("."):
        raise WorkloadMapError(f"{description} escapes workload leaf: {path}")


def _validate_structure(workload: Workload, root: Path) -> None:
    expected = _EXPECTED_WORKLOAD_BINDINGS[workload.id]
    if (workload.script, workload.dynamic_case, workload.product_scope) != expected:
        raise WorkloadMapError(f"workload binding drifted: {workload.id}")
    if not isinstance(workload.source_object_roles, tuple) or not workload.source_object_roles:
        raise WorkloadMapError(f"workload has no source/object roles: {workload.id}")
    names: set[str] = set()
    objects: set[str] = set()
    for source_role in workload.source_object_roles:
        if not isinstance(source_role, SourceObjectRole) or not isinstance(source_role.role, str) or not source_role.role:
            raise WorkloadMapError(f"invalid source/object role: {workload.id}")
        _physical_source(root, source_role.source, f"source/object source for {workload.id}:{source_role.role}")
        _relative_object_path(source_role.object_path, f"source/object path for {workload.id}:{source_role.role}")
        if source_role.role in names:
            raise WorkloadMapError(f"duplicate source/object role: {workload.id}:{source_role.role}")
        if source_role.object_path in objects:
            raise WorkloadMapError(f"duplicate source/object object path: {workload.id}:{source_role.object_path}")
        names.add(source_role.role)
        objects.add(source_role.object_path)
    if not isinstance(workload.required_supplementary_sources, tuple):
        raise WorkloadMapError(f"supplementary source roster must be a tuple: {workload.id}")
    supplementary_sources: set[str] = set()
    for source in workload.required_supplementary_sources:
        _physical_source(root, source, f"supplementary source for {workload.id}")
        if source in supplementary_sources:
            raise WorkloadMapError(f"duplicate supplementary source: {workload.id}")
        supplementary_sources.add(source)


def validate_workloads(
    workloads: Sequence[Workload] = WORKLOADS, *, root: Path = ROOT
) -> tuple[Workload, ...]:
    """Reject any incomplete, duplicate, unknown, or reassigned primary map."""
    if not isinstance(root, Path):
        root = Path(root)
    roster = tuple(workloads)
    if any(not isinstance(workload, Workload) for workload in roster):
        raise WorkloadMapError("invalid workload record")
    identifiers = [workload.id for workload in roster]
    if any(not isinstance(identifier, str) or not identifier for identifier in identifiers):
        raise WorkloadMapError("invalid workload identifier")
    if len(identifiers) != len(set(identifiers)):
        raise WorkloadMapError("duplicate workload identifier")
    actual_ids = set(identifiers)
    expected_ids = set(_EXPECTED_WORKLOAD_BINDINGS)
    for identifier in sorted(_SUPPLEMENTAL_WORKLOADS - actual_ids):
        raise WorkloadMapError(f"missing required supplementary workload: {identifier}")
    unknown_ids = actual_ids - expected_ids
    if unknown_ids:
        raise WorkloadMapError(f"unknown workload: {sorted(unknown_ids)[0]}")
    missing_ids = expected_ids - actual_ids
    if missing_ids:
        raise WorkloadMapError(f"missing required workload: {sorted(missing_ids)[0]}")

    for workload in roster:
        _validate_structure(workload, root)

    catalog = load_catalog()
    frozen_symbols = {
        symbol
        for capability in catalog.capabilities.values()
        for symbol in capability.symbols
    }
    if set(EXPECTED_PRIMARY_OWNERS) != frozen_symbols:
        raise WorkloadMapError("canonical primary owner map differs from frozen catalog")

    owners: dict[str, str] = {}
    for workload in roster:
        if not isinstance(workload.primary_symbols, tuple):
            raise WorkloadMapError(f"primary spelling roster must be a tuple: {workload.id}")
        workload_symbols: set[str] = set()
        for symbol in workload.primary_symbols:
            if not isinstance(symbol, str) or not symbol:
                raise WorkloadMapError(f"invalid primary spelling: {workload.id}")
            if symbol in workload_symbols:
                raise WorkloadMapError(f"duplicate primary spelling within workload: {workload.id}")
            workload_symbols.add(symbol)
            if symbol not in frozen_symbols:
                raise WorkloadMapError(f"unknown primary spelling: {symbol}")
            if symbol in owners:
                raise WorkloadMapError(f"duplicate primary spelling: {symbol}")
            owners[symbol] = workload.id

    for identifier in sorted(_SUPPLEMENTAL_WORKLOADS):
        if next(workload for workload in roster if workload.id == identifier).primary_symbols:
            raise WorkloadMapError(f"supplemental workload cannot own primary spellings: {identifier}")
    missing_symbols = frozen_symbols - set(owners)
    if missing_symbols:
        raise WorkloadMapError(f"omits frozen primary spelling: {sorted(missing_symbols)[0]}")
    for symbol, owner in sorted(owners.items()):
        if owner != EXPECTED_PRIMARY_OWNERS[symbol]:
            raise WorkloadMapError(f"primary spelling owner drifted: {symbol}")
    by_id = {workload.id: workload for workload in roster}
    for symbol, supplemental_id in STATIC_SUPPLEMENTAL_OWNERS.items():
        primary = by_id[owners[symbol]]
        supplemental = by_id[supplemental_id]
        if primary.product_scope != "dynamic" or supplemental.product_scope != "static":
            raise WorkloadMapError(f"static supplementary ownership drifted: {symbol}")
    return roster
