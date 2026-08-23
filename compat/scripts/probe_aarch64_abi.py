#!/usr/bin/env python3
"""Collect comparable AArch64 ABI evidence from musl and crabc.

The probes compile the same source twice, once with the pinned musl headers and
once with the candidate public headers.  The resulting programs are linked
against pinned musl for execution: this makes the values emitted by the
program a measurement of the headers and compiler ABI, not a claim that the
candidate libc runtime works.  Candidate and reference ``libc.a`` archives
are inspected separately, and their selected public symbols are recorded in
the report.

This is deliberately a Python standard-library harness rather than a shell
pipeline.  It is intended to run in the native ``linux/arm64`` development
image, where ``musl-gcc``, ``nm``, and the pinned musl installation are
available.  Missing inputs and non-AArch64 hosts produce a report with an
explicit non-success status instead of an empty or falsely passing result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Sequence


MUSL_VERSION = "1.2.6"
ARCHITECTURE = "aarch64"
DEFAULT_MUSL_ROOT = Path(f"/opt/musl-{MUSL_VERSION}")
DEFAULT_LINUX_UAPI_INCLUDE = Path("/usr/include")
# Keep the generated report durable so a red ABI/static triage result can be
# reviewed by the dashboard and tied to the current candidate archive.  The
# reports directory is ignored, so ad-hoc runs still do not dirty the commit.
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "reports/abi/latest.json"
PROBE_NAMES = (
    "stat",
    "termios",
    "socket",
    "fenv",
    "complex",
    "pthread",
    "signals-ucontext",
    "tls",
    "long-double",
)

# Header compile coverage is kept separate from the selected C layout probes.
# A successful ``#include <header.h>`` syntax check says only that the header
# can be consumed by this compiler configuration; it is not declaration,
# constant, or layout parity.  The selected probes emit and compare values at
# runtime and are the only report section that can claim ABI equality.
HEADER_SYMBOLS: dict[str, tuple[str, ...]] = {
    "arpa/nameser_compat.h": (
        "ns_get16",
        "ns_get32",
        "ns_put16",
        "ns_put32",
        "ns_initparse",
        "ns_parserr",
        "ns_skiprr",
        "ns_name_uncompress",
    ),
    "stdio_ext.h": (
        "_flushlbf",
        "__fsetlocking",
        "__fwriting",
        "__freading",
        "__freadable",
        "__fwritable",
        "__flbf",
        "__fbufsize",
        "__fpending",
        "__fpurge",
        "__freadahead",
        "__freadptr",
        "__freadptrinc",
        "__fseterr",
    ),
    "sys/cachectl.h": ("cachectl", "cacheflush", "_flush_cache"),
    "sys/io.h": ("iopl", "ioperm"),
    "ucontext.h": ("getcontext", "makecontext", "setcontext", "swapcontext"),
}


class ProbeHarnessError(RuntimeError):
    """Raised for an invalid harness configuration or tool invocation."""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _probe_source(header: str, body: str) -> str:
    return f"""\
#include <stddef.h>
#include <stdio.h>
#include <{header}>

{body}
"""


PROBES: dict[str, dict[str, Any]] = {
    "stat": {
        "headers": ("sys/stat.h",),
        "symbols": ("stat", "fstat", "lstat", "fstatat"),
        "source": _probe_source(
            "sys/stat.h",
            """
#include <fcntl.h>
#define VALUE(name, value) printf(name "=%zu\\n", (size_t)(value))
int main(void) {
    VALUE("sizeof_stat", sizeof(struct stat));
    VALUE("alignof_stat", _Alignof(struct stat));
    VALUE("offsetof_st_dev", offsetof(struct stat, st_dev));
    VALUE("offsetof_st_ino", offsetof(struct stat, st_ino));
    VALUE("offsetof_st_mode", offsetof(struct stat, st_mode));
    VALUE("offsetof_st_nlink", offsetof(struct stat, st_nlink));
    VALUE("offsetof_st_uid", offsetof(struct stat, st_uid));
    VALUE("offsetof_st_gid", offsetof(struct stat, st_gid));
    VALUE("offsetof_st_rdev", offsetof(struct stat, st_rdev));
    VALUE("offsetof_st_size", offsetof(struct stat, st_size));
    VALUE("offsetof_st_blksize", offsetof(struct stat, st_blksize));
    VALUE("offsetof_st_blocks", offsetof(struct stat, st_blocks));
    VALUE("offsetof_st_atim", offsetof(struct stat, st_atim));
    VALUE("offsetof_st_mtim", offsetof(struct stat, st_mtim));
    VALUE("offsetof_st_ctim", offsetof(struct stat, st_ctim));
    VALUE("AT_FDCWD", AT_FDCWD);
    VALUE("S_IFMT", S_IFMT);
    return 0;
}
#undef VALUE
""",
        ),
    },
    "termios": {
        "headers": ("termios.h",),
        "symbols": (
            "cfgetispeed",
            "cfgetospeed",
            "cfsetispeed",
            "cfsetospeed",
            "tcgetattr",
            "tcsetattr",
        ),
        "source": _probe_source(
            "termios.h",
            """
#ifdef CRABC_HEADER_PROBE
#define ABI_ISPEED __ispeed
#define ABI_OSPEED __ospeed
#else
#define ABI_ISPEED __c_ispeed
#define ABI_OSPEED __c_ospeed
#endif
#define VALUE(name, value) printf(name "=%zu\\n", (size_t)(value))
int main(void) {
    VALUE("sizeof_termios", sizeof(struct termios));
    VALUE("alignof_termios", _Alignof(struct termios));
    VALUE("offsetof_c_iflag", offsetof(struct termios, c_iflag));
    VALUE("offsetof_c_oflag", offsetof(struct termios, c_oflag));
    VALUE("offsetof_c_cflag", offsetof(struct termios, c_cflag));
    VALUE("offsetof_c_lflag", offsetof(struct termios, c_lflag));
    VALUE("offsetof_c_line", offsetof(struct termios, c_line));
    VALUE("offsetof_c_cc", offsetof(struct termios, c_cc));
    VALUE("offsetof_ispeed", offsetof(struct termios, ABI_ISPEED));
    VALUE("offsetof_ospeed", offsetof(struct termios, ABI_OSPEED));
    VALUE("NCCS", NCCS);
    VALUE("VEOF", VEOF);
    VALUE("VMIN", VMIN);
    VALUE("VTIME", VTIME);
    VALUE("B9600", B9600);
    VALUE("CS8", CS8);
    return 0;
}
#undef VALUE
#undef ABI_ISPEED
#undef ABI_OSPEED
""",
        ),
    },
    "socket": {
        "headers": ("sys/socket.h",),
        "symbols": (
            "socket",
            "socketpair",
            "bind",
            "connect",
            "sendmsg",
            "recvmsg",
        ),
        "source": _probe_source(
            "sys/socket.h",
            """
#define VALUE(name, value) printf(name "=%zu\\n", (size_t)(value))
int main(void) {
    VALUE("sizeof_sockaddr", sizeof(struct sockaddr));
    VALUE("alignof_sockaddr", _Alignof(struct sockaddr));
    VALUE("offsetof_sockaddr_family", offsetof(struct sockaddr, sa_family));
    VALUE("offsetof_sockaddr_data", offsetof(struct sockaddr, sa_data));
    VALUE("sizeof_sockaddr_storage", sizeof(struct sockaddr_storage));
    VALUE("alignof_sockaddr_storage", _Alignof(struct sockaddr_storage));
    VALUE("offsetof_storage_family", offsetof(struct sockaddr_storage, ss_family));
    VALUE("offsetof_storage_padding", offsetof(struct sockaddr_storage, __ss_padding));
    VALUE("offsetof_storage_align", offsetof(struct sockaddr_storage, __ss_align));
    VALUE("sizeof_msghdr", sizeof(struct msghdr));
    VALUE("alignof_msghdr", _Alignof(struct msghdr));
    VALUE("offsetof_msghdr_name", offsetof(struct msghdr, msg_name));
    VALUE("offsetof_msghdr_namelen", offsetof(struct msghdr, msg_namelen));
    VALUE("offsetof_msghdr_iov", offsetof(struct msghdr, msg_iov));
    VALUE("offsetof_msghdr_iovlen", offsetof(struct msghdr, msg_iovlen));
    VALUE("offsetof_msghdr_control", offsetof(struct msghdr, msg_control));
    VALUE("offsetof_msghdr_controllen", offsetof(struct msghdr, msg_controllen));
    VALUE("offsetof_msghdr_flags", offsetof(struct msghdr, msg_flags));
    VALUE("sizeof_cmsghdr", sizeof(struct cmsghdr));
    VALUE("alignof_cmsghdr", _Alignof(struct cmsghdr));
    VALUE("sizeof_linger", sizeof(struct linger));
    VALUE("AF_INET", AF_INET);
    VALUE("AF_INET6", AF_INET6);
    VALUE("SOCK_STREAM", SOCK_STREAM);
    VALUE("CMSG_SPACE_4", CMSG_SPACE(4));
    return 0;
}
#undef VALUE
""",
        ),
    },
    "fenv": {
        "headers": ("fenv.h",),
        "symbols": (
            "feclearexcept",
            "fegetenv",
            "fegetround",
            "fesetenv",
            "fesetround",
        ),
        "source": _probe_source(
            "fenv.h",
            """
#define VALUE(name, value) printf(name "=%zu\\n", (size_t)(value))
int main(void) {
    VALUE("sizeof_fexcept_t", sizeof(fexcept_t));
    VALUE("alignof_fexcept_t", _Alignof(fexcept_t));
    VALUE("sizeof_fenv_t", sizeof(fenv_t));
    VALUE("alignof_fenv_t", _Alignof(fenv_t));
    VALUE("FE_INVALID", FE_INVALID);
    VALUE("FE_DIVBYZERO", FE_DIVBYZERO);
    VALUE("FE_OVERFLOW", FE_OVERFLOW);
    VALUE("FE_UNDERFLOW", FE_UNDERFLOW);
    VALUE("FE_INEXACT", FE_INEXACT);
    VALUE("FE_ALL_EXCEPT", FE_ALL_EXCEPT);
    VALUE("FE_TONEAREST", FE_TONEAREST);
    VALUE("FE_DOWNWARD", FE_DOWNWARD);
    VALUE("FE_UPWARD", FE_UPWARD);
    VALUE("FE_TOWARDZERO", FE_TOWARDZERO);
    return 0;
}
#undef VALUE
""",
        ),
    },
    "complex": {
        "headers": ("complex.h",),
        "symbols": ("cabs", "cacos", "cexp", "cimag", "cpow", "creal"),
        "source": _probe_source(
            "complex.h",
            """
static double complex pass_complex(double complex value) { return value; }
int main(void) {
    double complex value = 1.25 + 2.5 * I;
    double complex result = pass_complex(value);
    printf("sizeof_complex=%zu\\n", sizeof(double complex));
    printf("alignof_complex=%zu\\n", _Alignof(double complex));
    printf("sizeof_float_complex=%zu\\n", sizeof(float complex));
    printf("alignof_float_complex=%zu\\n", _Alignof(float complex));
    printf("sizeof_long_double_complex=%zu\\n", sizeof(long double complex));
    printf("alignof_long_double_complex=%zu\\n", _Alignof(long double complex));
    printf("complex_return_re=%.17g\\n", creal(result));
    printf("complex_return_im=%.17g\\n", cimag(result));
    return 0;
}
""",
        ),
    },
    "pthread": {
        "headers": ("pthread.h",),
        "symbols": (
            "pthread_create",
            "pthread_join",
            "pthread_mutex_lock",
            "pthread_mutex_unlock",
            "pthread_cond_wait",
            "pthread_cond_signal",
            "pthread_key_create",
            "pthread_getspecific",
            "pthread_setspecific",
        ),
        "source": _probe_source(
            "pthread.h",
            """
#define VALUE(name, value) printf(name "=%zu\\n", (size_t)(value))
int main(void) {
    VALUE("sizeof_pthread_t", sizeof(pthread_t));
    VALUE("alignof_pthread_t", _Alignof(pthread_t));
    VALUE("sizeof_pthread_attr_t", sizeof(pthread_attr_t));
    VALUE("alignof_pthread_attr_t", _Alignof(pthread_attr_t));
    VALUE("sizeof_pthread_mutex_t", sizeof(pthread_mutex_t));
    VALUE("alignof_pthread_mutex_t", _Alignof(pthread_mutex_t));
    VALUE("sizeof_pthread_cond_t", sizeof(pthread_cond_t));
    VALUE("alignof_pthread_cond_t", _Alignof(pthread_cond_t));
    VALUE("sizeof_pthread_rwlock_t", sizeof(pthread_rwlock_t));
    VALUE("alignof_pthread_rwlock_t", _Alignof(pthread_rwlock_t));
    VALUE("sizeof_pthread_barrier_t", sizeof(pthread_barrier_t));
    VALUE("alignof_pthread_barrier_t", _Alignof(pthread_barrier_t));
    VALUE("sizeof_pthread_mutexattr_t", sizeof(pthread_mutexattr_t));
    VALUE("alignof_pthread_mutexattr_t", _Alignof(pthread_mutexattr_t));
    VALUE("sizeof_pthread_rwlockattr_t", sizeof(pthread_rwlockattr_t));
    VALUE("alignof_pthread_rwlockattr_t", _Alignof(pthread_rwlockattr_t));
    VALUE("PTHREAD_PROCESS_PRIVATE", PTHREAD_PROCESS_PRIVATE);
    VALUE("PTHREAD_MUTEX_NORMAL", PTHREAD_MUTEX_NORMAL);
    return 0;
}
#undef VALUE
""",
        ),
    },
    "signals-ucontext": {
        "headers": ("signal.h",),
        "symbols": (
            "sigaction",
            "sigprocmask",
            "sigaltstack",
            "sigemptyset",
            "pthread_sigmask",
        ),
        "source": _probe_source(
            "signal.h",
            """
#define VALUE(name, value) printf(name "=%zu\\n", (size_t)(value))
int main(void) {
    VALUE("sizeof_sigset_t", sizeof(sigset_t));
    VALUE("alignof_sigset_t", _Alignof(sigset_t));
    VALUE("sizeof_sigaction", sizeof(struct sigaction));
    VALUE("alignof_sigaction", _Alignof(struct sigaction));
    VALUE("offsetof_sigaction_flags", offsetof(struct sigaction, sa_flags));
    VALUE("offsetof_sigaction_restorer", offsetof(struct sigaction, sa_restorer));
    VALUE("offsetof_sigaction_mask", offsetof(struct sigaction, sa_mask));
    VALUE("sizeof_stack_t", sizeof(stack_t));
    VALUE("alignof_stack_t", _Alignof(stack_t));
    VALUE("offsetof_stack_sp", offsetof(stack_t, ss_sp));
    VALUE("offsetof_stack_flags", offsetof(stack_t, ss_flags));
    VALUE("offsetof_stack_size", offsetof(stack_t, ss_size));
    VALUE("sizeof_mcontext_t", sizeof(mcontext_t));
    VALUE("alignof_mcontext_t", _Alignof(mcontext_t));
    VALUE("sizeof_greg_t", sizeof(greg_t));
    VALUE("sizeof_gregset_t", sizeof(gregset_t));
    VALUE("sizeof_fpregset_t", sizeof(fpregset_t));
    VALUE("offsetof_mcontext_fault_address", offsetof(mcontext_t, fault_address));
    VALUE("offsetof_mcontext_regs", offsetof(mcontext_t, regs));
    VALUE("offsetof_mcontext_sp", offsetof(mcontext_t, sp));
    VALUE("offsetof_mcontext_pc", offsetof(mcontext_t, pc));
    VALUE("offsetof_mcontext_pstate", offsetof(mcontext_t, pstate));
    VALUE("offsetof_mcontext_reserved", offsetof(mcontext_t, __reserved));
    VALUE("sizeof_ucontext_t", sizeof(ucontext_t));
    VALUE("alignof_ucontext_t", _Alignof(ucontext_t));
    VALUE("offsetof_ucontext_flags", offsetof(ucontext_t, uc_flags));
    VALUE("offsetof_ucontext_link", offsetof(ucontext_t, uc_link));
    VALUE("offsetof_ucontext_stack", offsetof(ucontext_t, uc_stack));
    VALUE("offsetof_ucontext_sigmask", offsetof(ucontext_t, uc_sigmask));
    VALUE("offsetof_ucontext_mcontext", offsetof(ucontext_t, uc_mcontext));
    VALUE("MINSIGSTKSZ", MINSIGSTKSZ);
    VALUE("SIGSTKSZ", SIGSTKSZ);
    VALUE("NSIG", NSIG);
    VALUE("SA_SIGINFO", SA_SIGINFO);
    return 0;
}
#undef VALUE
""",
        ),
    },
    "tls": {
        "headers": ("pthread.h",),
        "symbols": (
            "pthread_key_create",
            "pthread_key_delete",
            "pthread_getspecific",
            "pthread_setspecific",
        ),
        "source": _probe_source(
            "pthread.h",
            """
#include <stdint.h>
static _Thread_local struct {
    int value;
    long double wide;
} tls_record;
#define VALUE(name, value) printf(name "=%zu\\n", (size_t)(value))
int main(void) {
    uintptr_t address = (uintptr_t)&tls_record;
    VALUE("sizeof_pthread_key_t", sizeof(pthread_key_t));
    VALUE("alignof_pthread_key_t", _Alignof(pthread_key_t));
    VALUE("sizeof_tls_record", sizeof(tls_record));
    VALUE("alignof_tls_record", _Alignof(__typeof__(tls_record)));
    VALUE("tls_address_alignment", address % _Alignof(__typeof__(tls_record)));
    return 0;
}
#undef VALUE
""",
        ),
    },
    "long-double": {
        "headers": ("float.h", "complex.h"),
        "symbols": ("cabs", "cimag", "creal"),
        "source": _probe_source(
            "float.h",
            """
#include <complex.h>
static long double pass_long_double(long double value) { return value; }
int main(void) {
    long double result = pass_long_double(1.0L / 3.0L);
    printf("sizeof_long_double=%zu\\n", sizeof(long double));
    printf("alignof_long_double=%zu\\n", _Alignof(long double));
    printf("sizeof_long_double_complex=%zu\\n", sizeof(long double complex));
    printf("alignof_long_double_complex=%zu\\n", _Alignof(long double complex));
    printf("LDBL_MANT_DIG=%d\\n", LDBL_MANT_DIG);
    printf("LDBL_MAX_EXP=%d\\n", LDBL_MAX_EXP);
    printf("long_double_return=%.20Lg\\n", result);
    return 0;
}
""",
        ),
    },
}


# Every selected source combines three surfaces: header declarations (the
# named functions in ``symbols``), ABI-bearing layout values, and constants.
# Keeping the dimensions in the generated report makes it clear which
# evidence is present when a future probe is added or narrowed.
PROBE_DIMENSIONS = {
    name: ("declaration", "layout", "constant") for name in PROBES
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def tree_metadata(root: Path) -> dict[str, Any]:
    """Describe a header tree without following symlinks or hiding inputs."""

    if not root.exists():
        return {"path": str(root), "status": "missing", "file_count": 0}
    if not root.is_dir():
        return {"path": str(root), "status": "not_directory", "file_count": 0}

    digest = hashlib.sha256()
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            return {
                "path": str(root),
                "status": "unsupported_symlink",
                "file_count": len(files),
                "symlink": str(path.relative_to(root)),
            }
        if path.is_file():
            files.append(path)
            relative = path.relative_to(root).as_posix().encode("utf-8")
            content_hash = sha256(path).encode("ascii")
            digest.update(relative + b"\0" + content_hash + b"\n")

    return {
        "path": str(root),
        "status": "available",
        "file_count": len(files),
        "tree_sha256": digest.hexdigest(),
    }


def directory_metadata(path: Path) -> dict[str, Any]:
    """Record a required include directory without traversing host headers."""

    if not path.exists():
        return {"path": str(path), "status": "missing"}
    if not path.is_dir():
        return {"path": str(path), "status": "not_directory"}
    return {"path": str(path), "status": "available"}


def run_command(
    command: Sequence[str], *, timeout: float | None = None, max_output: int | None = 4096
) -> dict[str, Any]:
    """Run a tool and retain bounded diagnostics for a machine-readable report."""

    try:
        result = subprocess.run(
            list(command),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        return {
            "status": "missing_tool",
            "returncode": None,
            "stdout": "",
            "stderr": str(error),
        }
    except subprocess.TimeoutExpired as error:
        return {
            "status": "timeout",
            "returncode": None,
            "stdout": (error.stdout or "")[-4096:],
            "stderr": (error.stderr or "")[-4096:],
        }

    stdout = result.stdout if max_output is None else result.stdout[-max_output:]
    stderr = result.stderr if max_output is None else result.stderr[-max_output:]
    return {
        "status": "ok" if result.returncode == 0 else "failed",
        "returncode": result.returncode,
        "stdout": stdout,
        "stderr": stderr,
    }


def parse_probe_output(output: str) -> dict[str, str]:
    """Parse the stable ``key=value`` format emitted by a probe.

    Duplicate or malformed records are rejected.  Treating malformed output
    as a failed probe is important: a truncated program output must never look
    like a successful comparison of a subset of fields.
    """

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(output.splitlines(), 1):
        line = raw_line.strip()
        if not line or "=" not in line:
            raise ProbeHarnessError(f"probe output line {line_number} is not key=value: {raw_line!r}")
        key, value = line.split("=", 1)
        if not key or not value or any(character.isspace() for character in key):
            raise ProbeHarnessError(f"probe output line {line_number} has invalid key/value")
        if key in values:
            raise ProbeHarnessError(f"probe output repeats key {key!r}")
        values[key] = value
    if not values:
        raise ProbeHarnessError("probe produced no key=value records")
    return values


def compare_values(reference: dict[str, str], candidate: dict[str, str]) -> dict[str, Any]:
    """Compare complete probe records and identify missing or changed fields."""

    keys = sorted(set(reference) | set(candidate))
    differences = [
        {
            "key": key,
            "reference": reference.get(key),
            "candidate": candidate.get(key),
        }
        for key in keys
        if reference.get(key) != candidate.get(key)
    ]
    return {
        "status": "match" if not differences else "mismatch",
        "equal": not differences,
        "field_count": len(keys),
        "differences": differences,
    }


def public_header_names(root: Path) -> list[str]:
    """Return public headers from a tree, excluding musl's private ``bits``."""

    if not root.is_dir():
        return []
    names: list[str] = []
    for path in sorted(root.rglob("*.h")):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(root)
        if "bits" in relative.parts:
            continue
        names.append(relative.as_posix())
    return names


def _header_compile_source(header: str) -> str:
    return f"#include <{header}>\nint main(void) {{ return 0; }}\n"


def public_header_probe_manifest(
    pinned_headers: Sequence[str], candidate_headers: Sequence[str]
) -> dict[str, Any]:
    """Describe the generated public-header declaration probe surface.

    The source is generated from the pinned header file names at run time;
    there is no hand-maintained include list that can silently omit a newly
    installed public header.  Compile records remain declaration-consumption
    evidence only.  The named runtime probes carry the separate layout and
    constant evidence below, so a successful include is never mislabeled as
    ABI parity.
    """

    pinned = sorted(set(pinned_headers))
    candidate = sorted(set(candidate_headers))
    return {
        "generator": "pinned-musl-public-header-surface",
        "oracle": f"pinned-musl-{MUSL_VERSION}",
        "declaration_probe": {
            "source_template": "#include <{header}>\\nint main(void) { return 0; }\\n",
            "pinned_headers": pinned,
            "candidate_headers": candidate,
            "pinned_count": len(pinned),
            "candidate_count": len(candidate),
            "candidate_only_headers": sorted(set(candidate) - set(pinned)),
        },
        "layout_constant_probe": {
            "source": "named C probes under probes; each is generated into a temporary source",
            "probe_names": list(PROBE_NAMES),
            "oracle_runtime": "pinned-musl",
        },
    }


def _compile_header(
    *,
    compiler: list[str],
    header: str,
    source: Path,
    include: Path | None,
    musl_root: Path,
    linux_uapi_include: Path,
    timeout: float,
) -> dict[str, Any]:
    command = [*compiler, "-std=c11", "-D_GNU_SOURCE"]
    if include is not None:
        command.extend(("-I", str(include)))
    command.extend(
        (
            "-isystem",
            str(musl_root / "include"),
            "-isystem",
            str(linux_uapi_include),
            "-fsyntax-only",
            str(source),
        )
    )
    result = run_command(command, timeout=timeout)
    return {key: value for key, value in result.items() if key != "stdout"}


def header_compile_coverage(
    *,
    candidate_include: Path,
    musl_root: Path,
    linux_uapi_include: Path,
    compiler: str,
    timeout: float,
    input_status: str,
    input_reason: str,
) -> dict[str, Any]:
    """Compile every pinned public header and its candidate counterpart.

    The inventory is derived from files on disk rather than a hand-maintained
    list.  This is compile coverage only: a ``compile_ok`` record does not
    compare declarations, constants, macros, or structure layouts.  A missing
    counterpart is retained as evidence, while a candidate compile failure is
    ``unsupported`` rather than being silently skipped.
    """

    pinned_names = public_header_names(musl_root / "include")
    candidate_names = public_header_names(candidate_include)
    names = sorted(set(pinned_names) | set(candidate_names))
    pinned_name_set = set(pinned_names)
    records: list[dict[str, Any]] = []
    if input_status != "available":
        records = [
            {
                "header": name,
                "status": input_status if name in pinned_name_set else "candidate_only",
                "evidence": "generated_header_declaration_probe",
                "probe_source_sha256": hashlib.sha256(
                    _header_compile_source(name).encode("utf-8")
                ).hexdigest(),
                "reason": input_reason
                if name in pinned_name_set
                else "candidate public header has no pinned counterpart",
                "candidate": None,
                "reference": None,
            }
            for name in names
        ]
        return _header_compile_coverage_payload(records, pinned_names, candidate_names)

    compiler_prefix = _compiler_prefix(compiler)
    with tempfile.TemporaryDirectory(prefix="crabc-aarch64-headers-") as directory:
        source = Path(directory) / "header.c"
        for name in names:
            source.write_text(_header_compile_source(name), encoding="utf-8")
            candidate_path = candidate_include / name
            reference_path = musl_root / "include" / name
            candidate_result: dict[str, Any]
            reference_result: dict[str, Any]
            if not candidate_path.is_file():
                candidate_result = {"status": "missing", "returncode": None, "stderr": ""}
            else:
                candidate_result = _compile_header(
                    compiler=compiler_prefix,
                    header=name,
                    source=source,
                    include=candidate_include,
                    musl_root=musl_root,
                    linux_uapi_include=linux_uapi_include,
                    timeout=timeout,
                )
            if not reference_path.is_file():
                reference_result = {"status": "missing", "returncode": None, "stderr": ""}
            else:
                reference_result = _compile_header(
                    compiler=compiler_prefix,
                    header=name,
                    source=source,
                    include=None,
                    musl_root=musl_root,
                    linux_uapi_include=linux_uapi_include,
                    timeout=timeout,
                )

            candidate_ok = candidate_result.get("status") == "ok"
            reference_ok = reference_result.get("status") == "ok"
            if name not in pinned_name_set:
                status = "candidate_only" if candidate_ok else "unsupported"
                reason = "candidate public header has no pinned counterpart"
            elif not candidate_ok:
                status = "unsupported" if candidate_result.get("status") != "missing" else "missing_input"
                reason = "candidate header did not compile"
            elif not reference_ok:
                status = "missing_input" if reference_result.get("status") == "missing" else "reference_error"
                reason = "pinned counterpart did not compile"
            else:
                # Both sides accepting an empty include translation unit is
                # useful coverage evidence, but it is not a declaration or
                # layout comparison.
                status = "compile_ok"
                reason = None
            records.append(
                {
                    "header": name,
                    "status": status,
                    "evidence": "generated_header_declaration_probe",
                    "probe_source_sha256": hashlib.sha256(
                        _header_compile_source(name).encode("utf-8")
                    ).hexdigest(),
                    "reason": reason,
                    "candidate": candidate_result,
                    "reference": reference_result,
                }
            )

    return _header_compile_coverage_payload(records, pinned_names, candidate_names)


def _header_compile_coverage_payload(
    records: Sequence[dict[str, Any]], pinned_names: Sequence[str], candidate_names: Sequence[str]
) -> dict[str, Any]:
    """Publish disjoint pinned/candidate inventory counts.

    ``candidate_count`` is the number of candidate files, never the union of
    both trees.  Candidate-only files are useful evidence but are not missing
    pinned counterparts and therefore have their own status and summary.
    """

    pinned_name_set = set(pinned_names)
    candidate_name_set = set(candidate_names)
    pinned_records = [record for record in records if record["header"] in pinned_name_set]
    candidate_only_records = [record for record in records if record["header"] not in pinned_name_set]
    return {
        "pinned_count": len(pinned_names),
        "candidate_count": len(candidate_names),
        "inventory_count": len(set(pinned_names) | candidate_name_set),
        "compiled_count": sum(record.get("status") == "compile_ok" for record in pinned_records),
        "missing_from_candidate_count": len(pinned_name_set - candidate_name_set),
        "candidate_compile_failure_count": sum(
            record.get("status") == "unsupported" for record in pinned_records
        ),
        "pinned_counterpart_count": len(pinned_name_set & candidate_name_set),
        "candidate_only_count": len(candidate_name_set - pinned_name_set),
        "candidate_only_headers": sorted(candidate_name_set - pinned_name_set),
        "records": pinned_records,
        "candidate_only_records": candidate_only_records,
        "summary": _summary(pinned_records),
        "candidate_only_summary": _summary(candidate_only_records),
    }


def _header_compile_coverage_status(records: Sequence[dict[str, Any]]) -> str | None:
    """Classify pinned-header compile coverage without hiding failures.

    A pinned header that cannot compile because the reference installation is
    missing a Linux UAPI file is an explicit reference limitation, not a
    candidate ABI defect. Candidate-side unsupported or missing records keep
    the broader incomplete status when both kinds of evidence are present.
    """

    statuses = {record.get("status") for record in records}
    if statuses & {"unsupported", "missing_input"}:
        return "header_compile_coverage_incomplete"
    if "reference_error" in statuses:
        return "reference_error"
    if statuses - {"compile_ok"}:
        return "header_compile_coverage_incomplete"
    return None


def static_archive_metadata(path: Path, nm: str) -> dict[str, Any]:
    """Record archive identity and defined symbols without linking it.

    Crabc's archive contains loader-facing objects that are not linkable with
    musl's CRT by themselves.  Inspecting the archive is therefore an honest
    and useful input check; the report explicitly keeps this separate from
    the header probe's pinned-musl execution evidence.
    """

    metadata: dict[str, Any] = {"path": str(path)}
    if not path.exists():
        metadata.update({"status": "missing", "defined_symbol_count": 0, "unique_symbol_count": 0})
        return metadata
    if not path.is_file():
        metadata.update({"status": "not_file", "defined_symbol_count": 0, "unique_symbol_count": 0})
        return metadata

    metadata.update({"bytes": path.stat().st_size, "sha256": sha256(path)})
    # ``-A`` is required for archives: without it GNU nm emits a member
    # heading on its own line and the following records are ambiguous.  The
    # archive/member prefix is evidence in its own right and lets the report
    # compare duplicate definitions without collapsing the archive surface.
    result = run_command(
        (nm, "-A", "-g", "--defined-only", "--format=posix", str(path)), max_output=None
    )
    metadata["nm"] = {key: value for key, value in result.items() if key != "stdout"}
    if result["status"] != "ok":
        metadata.update({"status": "tool_error", "defined_symbol_count": 0, "unique_symbol_count": 0})
        return metadata

    symbols: set[str] = set()
    symbol_types: dict[str, set[str]] = {}
    archive_records = 0
    for line in result["stdout"].splitlines():
        fields = line.split()
        # GNU nm --format=posix -A emits:
        #   archive.a[member.o]: name type value [size]
        if len(fields) < 3 or not fields[0].endswith(":"):
            continue
        name, nm_type = fields[1:3]
        archive_records += 1
        symbols.add(name)
        symbol_types.setdefault(name, set()).add(nm_type)
    metadata.update(
        {
            "status": "available",
            "defined_symbol_count": archive_records,
            "unique_symbol_count": len(symbols),
            # Keep parsed names only in the in-memory report while probes are
            # being assembled.  They are removed before publication so the
            # durable report records archive identity/counts and selected
            # coverage without embedding thousands of unrelated names.
            "_defined_symbols": symbols,
            "_symbol_types": symbol_types,
        }
    )
    return metadata


def static_archive_comparison(
    reference: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, Any]:
    """Compare the complete defined-symbol surface of two static archives.

    This is intentionally an archive evidence check, not a link experiment:
    archive extraction is member-driven and crabc's Rust archive may contain
    implementation-only symbols.  Names and nm classes are retained so a
    missing declaration or a class change cannot disappear behind aggregate
    counts.  Allocator internals are not filtered; the report therefore keeps
    the existing mimalloc ownership boundary explicit rather than inventing a
    second allocator oracle.
    """

    def names(metadata: dict[str, Any]) -> set[str]:
        value = metadata.get("_defined_symbols")
        return set(value) if isinstance(value, (set, list, tuple)) else set()

    def types(metadata: dict[str, Any]) -> dict[str, set[str]]:
        value = metadata.get("_symbol_types")
        if not isinstance(value, dict):
            return {}
        return {
            str(name): set(classes)
            for name, classes in value.items()
            if isinstance(classes, (set, list, tuple))
        }

    reference_names = names(reference)
    candidate_names = names(candidate)
    reference_types = types(reference)
    candidate_types = types(candidate)
    common = reference_names & candidate_names
    type_mismatches = [
        {
            "name": name,
            "reference": sorted(reference_types.get(name, ())),
            "candidate": sorted(candidate_types.get(name, ())),
        }
        for name in sorted(common)
        if reference_types.get(name, set()) != candidate_types.get(name, set())
    ]
    complete = reference.get("status") == "available" and candidate.get("status") == "available"
    missing = sorted(reference_names - candidate_names)
    unexpected = sorted(candidate_names - reference_names)
    return {
        "evidence": "complete_static_archive_nm",
        "oracle": f"pinned-musl-{MUSL_VERSION}",
        # A static archive is not a public-symbol parity oracle: musl's
        # internal members and Rust/mimalloc implementation members are
        # expected to differ.  Keep all differences as explicit triage
        # evidence while reserving ``match`` for the unusually exact case.
        "status": (
            "match"
            if complete and not missing and not unexpected and not type_mismatches
            else "triage"
            if complete
            else "incomplete"
        ),
        "gate": "informational-triage",
        "reference_defined_symbol_count": reference.get("defined_symbol_count", 0),
        "candidate_defined_symbol_count": candidate.get("defined_symbol_count", 0),
        "reference_unique_symbol_count": len(reference_names),
        "candidate_unique_symbol_count": len(candidate_names),
        "missing_from_candidate": missing,
        "unexpected_in_candidate": unexpected,
        "nm_type_mismatches": type_mismatches,
    }


def archive_symbol_coverage(
    reference: dict[str, Any], candidate: dict[str, Any], symbols: Iterable[str]
) -> dict[str, Any]:
    """Compare selected ABI function names when archive symbol output exists."""

    wanted = sorted(set(symbols))

    def read_symbols(metadata: dict[str, Any]) -> set[str]:
        symbols = metadata.get("_defined_symbols")
        return set(symbols) if isinstance(symbols, (set, list, tuple)) else set()

    reference_symbols = read_symbols(reference)
    candidate_symbols = read_symbols(candidate)
    return {
        "required": wanted,
        "reference_missing": [name for name in wanted if name not in reference_symbols]
        if reference_symbols
        else None,
        "candidate_missing": [name for name in wanted if name not in candidate_symbols]
        if candidate_symbols
        else None,
        "status": (
            "match"
            if reference_symbols and candidate_symbols
            and all(name in reference_symbols for name in wanted)
            and all(name in candidate_symbols for name in wanted)
            else "incomplete"
        ),
    }


def header_archive_symbol_coverage(
    reference: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    """Compare symbols specifically required by newly surfaced headers."""

    return {
        header: archive_symbol_coverage(reference, candidate, symbols)
        for header, symbols in sorted(HEADER_SYMBOLS.items())
    }


def _compiler_prefix(compiler: str) -> list[str]:
    try:
        prefix = shlex.split(compiler)
    except ValueError as error:
        raise ProbeHarnessError(f"invalid compiler command {compiler!r}: {error}") from error
    if not prefix:
        raise ProbeHarnessError("compiler command is empty")
    return prefix


def _compile_and_run(
    *,
    compiler: list[str],
    source: Path,
    binary: Path,
    include: Path | None,
    candidate_headers: bool,
    musl_root: Path,
    timeout: float,
) -> dict[str, Any]:
    command = [*compiler, "-std=c11", "-D_GNU_SOURCE"]
    if candidate_headers:
        command.append("-DCRABC_HEADER_PROBE")
    if include is not None:
        command.extend(("-I", str(include)))
    command.extend(("-isystem", str(musl_root / "include"), "-fPIE", "-pie", str(source), "-o", str(binary)))
    compile_result = run_command(command, timeout=timeout)
    result: dict[str, Any] = {
        "compile": {key: value for key, value in compile_result.items() if key != "stdout"},
        "runtime": None,
        "values": None,
    }
    if compile_result["status"] != "ok":
        return result

    runtime = run_command((str(binary),), timeout=timeout)
    result["runtime"] = {key: value for key, value in runtime.items() if key != "stdout"}
    if runtime["status"] == "ok":
        try:
            result["values"] = parse_probe_output(runtime["stdout"])
        except ProbeHarnessError as error:
            result["runtime"]["status"] = "invalid_output"
            result["runtime"]["stderr"] = f"{result['runtime'].get('stderr', '')}\n{error}".strip()
    return result


def _input_status(
    *,
    musl_root: Path,
    candidate_include: Path,
    candidate_archive: Path,
    linux_uapi_include: Path,
    machine: str,
) -> tuple[str, list[str]]:
    if machine != ARCHITECTURE:
        return "unsupported", [f"native AArch64 required (platform.machine()={machine!r})"]

    issues: list[str] = []
    required = (
        (musl_root / "include", "pinned musl include directory", True),
        (musl_root / "lib/libc.a", "pinned musl libc.a", False),
        (candidate_include, "candidate public include directory", True),
        (candidate_archive, "candidate libc.a", False),
        (linux_uapi_include, "native Linux UAPI include directory", True),
    )
    for path, label, directory in required:
        if not path.exists():
            issues.append(f"{label} missing: {path}")
        elif directory and not path.is_dir():
            issues.append(f"{label} is not a directory: {path}")
    if issues:
        return "missing_input", issues
    return "available", issues


def _blocked_probe(name: str, status: str, reason: str) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "evidence": "generated_public_header_layout_constant_probe",
        "reason": reason,
        "headers": PROBES[name]["headers"],
        "dimensions": list(PROBE_DIMENSIONS[name]),
        "declarations": list(PROBES[name]["symbols"]),
        "source_sha256": hashlib.sha256(
            PROBES[name]["source"].encode("utf-8")
        ).hexdigest(),
        "reference": None,
        "candidate": None,
        "comparison": None,
        "archive_symbols": None,
    }


def build_report(
    *,
    musl_root: Path,
    candidate_include: Path,
    candidate_archive: Path,
    compiler: str,
    nm: str,
    probes: Sequence[str] = PROBE_NAMES,
    timeout: float = 10.0,
    machine: str | None = None,
    linux_uapi_include: Path = DEFAULT_LINUX_UAPI_INCLUDE,
) -> dict[str, Any]:
    """Generate a report dictionary; writing is kept separate for unit tests."""

    selected = list(dict.fromkeys(probes))
    unknown = sorted(set(selected) - set(PROBE_NAMES))
    if unknown:
        raise ProbeHarnessError(f"unknown probe(s): {', '.join(unknown)}")
    if not selected:
        raise ProbeHarnessError("at least one probe must be selected")
    if timeout <= 0:
        raise ProbeHarnessError("timeout must be positive")

    musl_root = musl_root.expanduser().resolve()
    candidate_include = candidate_include.expanduser().resolve()
    candidate_archive = candidate_archive.expanduser().resolve()
    linux_uapi_include = linux_uapi_include.expanduser().resolve()
    machine = machine or platform.machine()
    input_status, input_issues = _input_status(
        musl_root=musl_root,
        candidate_include=candidate_include,
        candidate_archive=candidate_archive,
        linux_uapi_include=linux_uapi_include,
        machine=machine,
    )

    report: dict[str, Any] = {
        "schema": "crabc.aarch64-abi-probe/v1",
        "architecture": ARCHITECTURE,
        "status": input_status if input_status != "available" else "running",
        "inputs": {
            "machine": machine,
            "musl": {
                "version": MUSL_VERSION,
                "root": str(musl_root),
                "headers": tree_metadata(musl_root / "include"),
                "archive": None,
            },
            "candidate": {
                "headers": tree_metadata(candidate_include),
                "archive": None,
            },
            "linux_uapi": directory_metadata(linux_uapi_include),
            "compiler": compiler,
            "nm": nm,
            "probe_runtime": "pinned-musl",
        },
        "issues": input_issues,
        "probes": [],
        "header_compile_coverage": None,
        "public_header_probe_manifest": None,
        "static_archive_comparison": None,
    }
    report["inputs"]["musl"]["archive"] = static_archive_metadata(musl_root / "lib/libc.a", nm)
    report["inputs"]["candidate"]["archive"] = static_archive_metadata(candidate_archive, nm)
    report["static_archive_comparison"] = static_archive_comparison(
        report["inputs"]["musl"]["archive"], report["inputs"]["candidate"]["archive"]
    )
    for side in ("musl", "candidate"):
        headers = report["inputs"][side]["headers"]
        if headers.get("status") != "available":
            if input_status == "available":
                input_status = "missing_input"
            report["issues"].append(
                f"{side} header tree unavailable: {headers.get('status')}"
            )
    for side in ("musl", "candidate"):
        archive = report["inputs"][side]["archive"]
        if archive.get("status") != "available":
            report["issues"].append(
                f"{side} static archive evidence unavailable: {archive.get('status')}"
            )
    if input_status != "available":
        report["status"] = input_status

    report["header_compile_coverage"] = header_compile_coverage(
        candidate_include=candidate_include,
        musl_root=musl_root,
        linux_uapi_include=linux_uapi_include,
        compiler=compiler,
        timeout=timeout,
        input_status=input_status,
        input_reason="; ".join(input_issues),
    )
    report["public_header_probe_manifest"] = public_header_probe_manifest(
        public_header_names(musl_root / "include"), public_header_names(candidate_include)
    )
    report["header_compile_coverage"]["archive_symbols"] = header_archive_symbol_coverage(
        report["inputs"]["musl"]["archive"], report["inputs"]["candidate"]["archive"]
    )

    if input_status != "available":
        report["probes"] = [
            _blocked_probe(name, input_status, "; ".join(input_issues)) for name in selected
        ]
        report["summary"] = _summary(report["probes"])
        _drop_private_archive_symbols(report)
        return report

    compiler_prefix = _compiler_prefix(compiler)
    with tempfile.TemporaryDirectory(prefix="crabc-aarch64-abi-") as directory:
        work = Path(directory)
        for name in selected:
            definition = PROBES[name]
            missing_headers = [
                str(candidate_include / header)
                for header in definition["headers"]
                if not (candidate_include / header).is_file()
            ]
            if missing_headers:
                report["probes"].append(
                    _blocked_probe(
                        name,
                        "missing_input",
                        "candidate public header(s) missing: " + ", ".join(missing_headers),
                    )
                )
                continue
            source = work / f"{name}.c"
            source.write_text(definition["source"], encoding="utf-8")
            reference = _compile_and_run(
                compiler=compiler_prefix,
                source=source,
                binary=work / f"{name}-musl",
                include=None,
                candidate_headers=False,
                musl_root=musl_root,
                timeout=timeout,
            )
            candidate = _compile_and_run(
                compiler=compiler_prefix,
                source=source,
                binary=work / f"{name}-candidate",
                include=candidate_include,
                candidate_headers=True,
                musl_root=musl_root,
                timeout=timeout,
            )
            probe: dict[str, Any] = {
                "name": name,
                "headers": definition["headers"],
                "evidence": "generated_public_header_layout_constant_probe",
                "dimensions": list(PROBE_DIMENSIONS[name]),
                "declarations": list(definition["symbols"]),
                "source_sha256": hashlib.sha256(
                    definition["source"].encode("utf-8")
                ).hexdigest(),
                "reference": reference,
                "candidate": candidate,
                "comparison": None,
                "archive_symbols": archive_symbol_coverage(
                    report["inputs"]["musl"]["archive"],
                    report["inputs"]["candidate"]["archive"],
                    definition["symbols"],
                ),
            }
            reference_values = reference.get("values")
            candidate_values = candidate.get("values")
            if not isinstance(reference_values, dict):
                probe["status"] = "reference_error"
                probe["reason"] = "pinned musl probe did not compile/run with parseable output"
            elif not isinstance(candidate_values, dict):
                probe["status"] = "unsupported"
                probe["reason"] = "candidate public headers did not compile/run with parseable output"
            else:
                probe["comparison"] = compare_values(reference_values, candidate_values)
                probe["status"] = probe["comparison"]["status"]
            report["probes"].append(probe)

    report["summary"] = _summary(report["probes"])
    _drop_private_archive_symbols(report)
    statuses = {probe["status"] for probe in report["probes"]}
    archive_coverages = [
        probe["archive_symbols"]
        for probe in report["probes"]
        if isinstance(probe.get("archive_symbols"), dict)
    ]
    archive_mismatch = any(
        coverage.get("reference_missing") or coverage.get("candidate_missing")
        for coverage in archive_coverages
    )
    archive_incomplete = any(coverage.get("status") != "match" for coverage in archive_coverages)
    # Candidate-only headers are retained as a separate inventory and are not
    # missing reference counterparts.  Only pinned records determine coverage
    # completeness; their explicit candidate-only evidence remains in report.
    header_status = _header_compile_coverage_status(report["header_compile_coverage"]["records"])
    if "reference_error" in statuses:
        report["status"] = "reference_error"
    elif "mismatch" in statuses:
        report["status"] = "mismatch"
    elif "missing_input" in statuses:
        report["status"] = "missing_input"
    elif "unsupported" in statuses:
        report["status"] = "unsupported"
    elif report["issues"] or archive_mismatch:
        report["status"] = "archive_mismatch" if archive_mismatch else "missing_input"
    elif archive_incomplete:
        report["status"] = "archive_incomplete"
    elif header_status is not None:
        report["status"] = header_status
    else:
        report["status"] = "pass"
    return report


def _summary(probes: Sequence[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for probe in probes:
        status = str(probe.get("status", "unknown"))
        counts[status] = counts.get(status, 0) + 1
    return {"selected": len(probes), "by_status": dict(sorted(counts.items()))}


def _drop_private_archive_symbols(report: dict[str, Any]) -> None:
    """Remove transient nm sets before the report is serialized as JSON."""

    for side in ("musl", "candidate"):
        archive = report["inputs"][side]["archive"]
        archive.pop("_defined_symbols", None)
        archive.pop("_symbol_types", None)


def atomic_write_json(path: Path, report: dict[str, Any]) -> None:
    """Publish complete JSON without leaving a partially written report."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--probe",
        action="append",
        dest="probe_args",
        metavar="NAME[,NAME...]",
        help="probe(s) to run; repeat or comma-separate (default: all selected probes)",
    )
    parser.add_argument("--list-probes", action="store_true", help="list available probes and exit")
    parser.add_argument(
        "--musl-root",
        type=Path,
        default=Path(os.environ.get("MUSL_ROOT", DEFAULT_MUSL_ROOT)),
        help="pinned musl installation (default: MUSL_ROOT or /opt/musl-1.2.6)",
    )
    parser.add_argument(
        "--candidate-include",
        type=Path,
        default=repository_root() / "include",
        help="candidate public headers (default: repository include/)",
    )
    parser.add_argument(
        "--candidate-archive",
        type=Path,
        default=repository_root() / "target/debug/libc.a",
        help="candidate static archive (default: target/debug/libc.a)",
    )
    parser.add_argument(
        "--uapi-include",
        dest="linux_uapi_include",
        type=Path,
        default=Path(os.environ.get("LINUX_UAPI_INCLUDE", DEFAULT_LINUX_UAPI_INCLUDE)),
        help="native Linux UAPI headers (default: LINUX_UAPI_INCLUDE or /usr/include)",
    )
    parser.add_argument(
        "--compiler",
        default=os.environ.get("MUSL_CC", "musl-gcc"),
        help="native musl compiler command (default: MUSL_CC or musl-gcc)",
    )
    parser.add_argument(
        "--nm",
        default=os.environ.get("NM", "nm"),
        help="GNU nm command used for archive evidence (default: NM or nm)",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="per-command timeout in seconds")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(os.environ.get("CRABC_ABI_REPORT", DEFAULT_OUTPUT)),
        help="JSON report destination (default: CRABC_ABI_REPORT or compat/reports/abi/latest.json)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.list_probes:
        print("\n".join(PROBE_NAMES))
        return 0
    try:
        probes = [
            name
            for item in (args.probe_args or [",".join(PROBE_NAMES)])
            for name in item.split(",")
            if name
        ]
        report = build_report(
            musl_root=args.musl_root,
            candidate_include=args.candidate_include,
            candidate_archive=args.candidate_archive,
            linux_uapi_include=args.linux_uapi_include,
            compiler=args.compiler,
            nm=args.nm,
            probes=probes,
            timeout=args.timeout,
        )
        atomic_write_json(args.output, report)
    except (OSError, ProbeHarnessError) as error:
        print(f"ABI probe harness error: {error}", file=sys.stderr)
        return 2

    print(f"AArch64 ABI report: {args.output} ({report['status']})")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
