#!/usr/bin/env python3
"""Focused contracts for native x86 feature-archive provider ownership."""

from __future__ import annotations

import importlib.util
import copy
import tomllib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
ROSTER_PATH = ROOT / "compat" / "x86_64" / "feature_archive_roster.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ROSTER = load_module("feature_archive_roster_test", ROSTER_PATH)


def row(
    identifier: str,
    *,
    state: str = "verified",
    baseline_features: list[str] | None = None,
    additive_callables: list[str] | None = None,
    replacement_callables: list[str] | None = None,
    abi_only_callables: list[str] | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "id": identifier,
        "state": state,
        "runner": f"compat/x86_64/run_{identifier}.sh",
        "baseline_features": [] if baseline_features is None else baseline_features,
        "enabled_features": [identifier],
        "additive_callables": [] if additive_callables is None else additive_callables,
        "replacement_callables": [] if replacement_callables is None else replacement_callables,
        "aliases": [],
    }
    if state == "verified":
        value["evidence_record"] = f"evidence.{identifier}"
        value["dispatch_command"] = identifier
    else:
        value["feature_selection_source"] = f"compat/x86_64/run_{identifier}.sh"
    if abi_only_callables is not None:
        value["abi_only_callables"] = abi_only_callables
    return value


class FeatureArchiveRosterTests(unittest.TestCase):
    def test_checked_roster_covers_every_cargo_x86_feature_once(self) -> None:
        cargo_features = ROSTER.load_cargo_x86_features()
        rows = ROSTER.load_feature_archive_roster()

        self.assertEqual([item.identifier for item in rows], list(cargo_features))
        owned_static = next(item for item in rows if item.identifier == "x86-owned-static-runtime")
        self.assertEqual(owned_static.state, "planned")
        self.assertIsNone(owned_static.evidence_record)
        self.assertIsNone(owned_static.dispatch_command)
        self.assertEqual(owned_static.runner, "compat/x86_64/run_owned_static_sysroot.sh")
        self.assertEqual(
            owned_static.feature_selection_source,
            "scripts/build_x86_64_owned_sysroot.py",
        )
        self.assertEqual(
            owned_static.baseline_features,
            (
                "x86-a64l",
                "x86-allocator-observability",
                "x86-allocator-runtime",
                "x86-allocator-string-duplication",
                "x86-crypt",
                "x86-crypt-allocator-composition",
                "x86-environment-runtime",
                "x86-file-handles",
                "x86-filesystem-traversal",
                "x86-h-errno",
                "x86-interval-timers",
                "x86-io-permissions",
                "x86-kernel-admin",
                "x86-legacy-des-compat",
                "x86-legacy-misc",
                "x86-math-long-double-completion",
                "x86-memory-special",
                "x86-netdb-setent",
                "x86-process-exec",
                "x86-resolver-runtime",
                "x86-scandir",
                "x86-sched-rr-interval",
                "x86-stdio-permanent-format-scan",
                "x86-temporary-names",
                "x86-ualarm",
            ),
        )
        self.assertEqual(
            owned_static.additive_callables,
            (
                "_Fork",
                "__assert_fail",
                "__fpending",
                "__fpurge",
                "__freadahead",
                "__freadptr",
                "__freadptrinc",
                "__fwriting",
                "_flushlbf",
                "abort",
                "acct",
                "acos",
                "acosf",
                "addmntent",
                "adjtime",
                "adjtimex",
                "aio_cancel",
                "aio_fsync",
                "aio_read",
                "aio_return",
                "aio_suspend",
                "aio_write",
                "asctime",
                "asctime_r",
                "asin",
                "asinf",
                "asprintf",
                "at_quick_exit",
                "atan",
                "atan2",
                "atan2f",
                "atanf",
                "brk",
                "capget",
                "capset",
                "chroot",
                "clearerr_unlocked",
                "clone",
                "closelog",
                "cnd_timedwait",
                "ctime",
                "ctime_r",
                "cuserid",
                "daemon",
                "delete_module",
                "dprintf",
                "endgrent",
                "endmntent",
                "endpwent",
                "endspent",
                "endusershell",
                "endutent",
                "endutxent",
                "err",
                "errx",
                "fallocate",
                "fanotify_init",
                "fanotify_mark",
                "fchmodat",
                "fchown",
                "fchownat",
                "fdopen",
                "fflush_unlocked",
                "fgetc_unlocked",
                "fgetgrent",
                "fgetln",
                "fgetpwent",
                "fgets_unlocked",
                "fgetspent",
                "fgetwc",
                "fgetwc_unlocked",
                "fgetws",
                "fgetws_unlocked",
                "flockfile",
                "fma",
                "fmaf",
                "fmemopen",
                "fnmatch",
                "fopencookie",
                "forkpty",
                "fputc_unlocked",
                "fputs_unlocked",
                "fputwc",
                "fputwc_unlocked",
                "fputws",
                "fputws_unlocked",
                "fread_unlocked",
                "freopen",
                "ftrylockfile",
                "funlockfile",
                "fwide",
                "fwprintf",
                "fwrite_unlocked",
                "fwscanf",
                "get_current_dir_name",
                "getc_unlocked",
                "getchar_unlocked",
                "getdate",
                "getdelim",
                "getgrent",
                "getgrgid",
                "getgrgid_r",
                "getgrnam",
                "getgrnam_r",
                "getgrouplist",
                "gethostbyaddr",
                "gethostbyaddr_r",
                "gethostbyname",
                "gethostbyname2",
                "gethostbyname2_r",
                "gethostbyname_r",
                "gethostent",
                "getline",
                "getmntent",
                "getmntent_r",
                "getnetbyaddr",
                "getnetbyname",
                "getnetent",
                "getpwent",
                "getpwnam",
                "getpwnam_r",
                "getpwuid",
                "getpwuid_r",
                "gets",
                "getservbyname",
                "getservbyname_r",
                "getservbyport",
                "getservbyport_r",
                "getspent",
                "getspnam",
                "getspnam_r",
                "getusershell",
                "getutent",
                "getutid",
                "getutline",
                "getutxent",
                "getutxid",
                "getutxline",
                "getw",
                "getwc",
                "getwc_unlocked",
                "getwchar",
                "getwchar_unlocked",
                "glob",
                "globfree",
                "gmtime",
                "herror",
                "hypot",
                "hypotf",
                "init_module",
                "initgroups",
                "isastream",
                "klogctl",
                "lckpwdf",
                "lio_listio",
                "localtime",
                "localtime_r",
                "lockf",
                "log1p",
                "log1pf",
                "login_tty",
                "mbsnrtowcs",
                "mkdtemp",
                "mknod",
                "mknodat",
                "mkostemp",
                "mkostemps",
                "mkstemp",
                "mkstemps",
                "mktime",
                "mount",
                "mq_close",
                "mq_getattr",
                "mq_notify",
                "mq_open",
                "mq_receive",
                "mq_send",
                "mq_timedreceive",
                "mq_timedsend",
                "mq_unlink",
                "mremap",
                "mtx_timedlock",
                "open_memstream",
                "open_wmemstream",
                "openlog",
                "openpty",
                "pclose",
                "perror",
                "popen",
                "posix_openpt",
                "posix_spawn",
                "posix_spawnp",
                "prctl",
                "preadv2",
                "process_vm_readv",
                "process_vm_writev",
                "pthread_cond_timedwait",
                "pthread_getattr_default_np",
                "pthread_getattr_np",
                "pthread_getschedparam",
                "pthread_kill",
                "pthread_mutex_setprioceiling",
                "pthread_mutex_timedlock",
                "pthread_mutexattr_setprotocol",
                "pthread_setattr_default_np",
                "pthread_setschedparam",
                "pthread_setschedprio",
                "pthread_sigmask",
                "pthread_timedjoin_np",
                "pthread_tryjoin_np",
                "ptrace",
                "ptsname",
                "ptsname_r",
                "putc_unlocked",
                "putchar_unlocked",
                "putgrent",
                "putpwent",
                "putspent",
                "pututline",
                "pututxline",
                "putw",
                "putwc",
                "putwc_unlocked",
                "putwchar",
                "putwchar_unlocked",
                "pwritev2",
                "quick_exit",
                "quotactl",
                "rand",
                "realpath",
                "reboot",
                "remap_file_pages",
                "renameat",
                "sbrk",
                "sem_close",
                "sem_open",
                "sem_timedwait",
                "sem_unlink",
                "setbuf",
                "setbuffer",
                "setgrent",
                "setlinebuf",
                "setlogmask",
                "setmntent",
                "setns",
                "setpwent",
                "setspent",
                "settimeofday",
                "setusershell",
                "setutent",
                "setutxent",
                "shm_open",
                "shm_unlink",
                "srand",
                "statx",
                "stime",
                "strfmon",
                "strfmon_l",
                "strftime",
                "strftime_l",
                "strptime",
                "swapoff",
                "swapon",
                "swprintf",
                "swscanf",
                "symlinkat",
                "syscall",
                "syslog",
                "system",
                "tcdrain",
                "tcgetsid",
                "timer_create",
                "times",
                "ttyname",
                "tzset",
                "ulckpwdf",
                "umount",
                "umount2",
                "ungetwc",
                "unshare",
                "updwtmp",
                "updwtmpx",
                "utmpname",
                "utmpxname",
                "vasprintf",
                "vdprintf",
                "verr",
                "verrx",
                "vfork",
                "vfwprintf",
                "vfwscanf",
                "vhangup",
                "vmsplice",
                "vswprintf",
                "vswscanf",
                "vsyslog",
                "vwarn",
                "vwarnx",
                "vwprintf",
                "vwscanf",
                "warn",
                "warnx",
                "wcsdup",
                "wcsftime",
                "wcsftime_l",
                "wcsnrtombs",
                "wordexp",
                "wordfree",
                "wprintf",
                "wscanf",
            ),
        )
        self.assertEqual(
            owned_static.replacement_callables,
            (
                "__fbufsize",
                "__flbf",
                "__freadable",
                "__freading",
                "__fseterr",
                "__fsetlocking",
                "__fwritable",
                "aio_error",
                "clearerr",
                "confstr",
                "fclose",
                "feof",
                "feof_unlocked",
                "ferror",
                "ferror_unlocked",
                "fflush",
                "fgetc",
                "fgetpos",
                "fgets",
                "fileno",
                "fileno_unlocked",
                "fmtmsg",
                "fopen",
                "fpathconf",
                "fputc",
                "fputs",
                "fread",
                "fseek",
                "fseeko",
                "fsetpos",
                "ftell",
                "ftello",
                "fwrite",
                "getaddrinfo",
                "getc",
                "getchar",
                "getdtablesize",
                "getnameinfo",
                "getpagesize",
                "lchmod",
                "pathconf",
                "putc",
                "putchar",
                "puts",
                "regcomp",
                "regerror",
                "regexec",
                "regfree",
                "rewind",
                "setvbuf",
                "sigaltstack",
                "siginterrupt",
                "sigpause",
                "snprintf",
                "sprintf",
                "sscanf",
                "sysconf",
                "timer_delete",
                "timer_getoverrun",
                "timer_gettime",
                "timer_settime",
                "tmpfile",
                "ungetc",
                "vsnprintf",
                "vsprintf",
                "vsscanf",
            ),
        )
        self.assertEqual(
            owned_static.aliases,
            (
                ROSTER.ArchiveAlias("_IO_feof_unlocked", "feof", "weak-same-address"),
                ROSTER.ArchiveAlias("_IO_ferror_unlocked", "ferror", "weak-same-address"),
                ROSTER.ArchiveAlias("_IO_getc", "getc", "weak-same-address"),
                ROSTER.ArchiveAlias("_IO_getc_unlocked", "getc_unlocked", "weak-same-address"),
                ROSTER.ArchiveAlias("_IO_putc", "putc", "weak-same-address"),
                ROSTER.ArchiveAlias("_IO_putc_unlocked", "putc_unlocked", "weak-same-address"),
                ROSTER.ArchiveAlias("__isoc99_fwscanf", "fwscanf", "weak-same-address"),
                ROSTER.ArchiveAlias("__isoc99_swscanf", "swscanf", "weak-same-address"),
                ROSTER.ArchiveAlias("__isoc99_vfwscanf", "vfwscanf", "weak-same-address"),
                ROSTER.ArchiveAlias("__isoc99_vswscanf", "vswscanf", "weak-same-address"),
                ROSTER.ArchiveAlias("__isoc99_vwscanf", "vwscanf", "weak-same-address"),
                ROSTER.ArchiveAlias("__isoc99_wscanf", "wscanf", "weak-same-address"),
                ROSTER.ArchiveAlias("asctime_r", "__asctime_r", "weak-same-address"),
                ROSTER.ArchiveAlias("clearerr_unlocked", "clearerr", "weak-same-address"),
                ROSTER.ArchiveAlias("endpwent", "setpwent", "weak-same-address"),
                ROSTER.ArchiveAlias("endutent", "endutxent", "weak-same-address"),
                ROSTER.ArchiveAlias("fdopen", "__fdopen", "weak-same-address"),
                ROSTER.ArchiveAlias("feof_unlocked", "feof", "weak-same-address"),
                ROSTER.ArchiveAlias("ferror_unlocked", "ferror", "weak-same-address"),
                ROSTER.ArchiveAlias("fflush_unlocked", "fflush", "weak-same-address"),
                ROSTER.ArchiveAlias("fgetc_unlocked", "getc_unlocked", "weak-same-address"),
                ROSTER.ArchiveAlias("fgets_unlocked", "fgets", "weak-same-address"),
                ROSTER.ArchiveAlias("fgetwc_unlocked", "__fgetwc_unlocked", "weak-same-address"),
                ROSTER.ArchiveAlias("fgetws_unlocked", "fgetws", "weak-same-address"),
                ROSTER.ArchiveAlias("fileno_unlocked", "fileno", "weak-same-address"),
                ROSTER.ArchiveAlias("fpurge", "__fpurge", "weak-same-address"),
                ROSTER.ArchiveAlias("fputc_unlocked", "putc_unlocked", "weak-same-address"),
                ROSTER.ArchiveAlias("fputs_unlocked", "fputs", "weak-same-address"),
                ROSTER.ArchiveAlias("fputwc_unlocked", "__fputwc_unlocked", "weak-same-address"),
                ROSTER.ArchiveAlias("fputws_unlocked", "fputws", "weak-same-address"),
                ROSTER.ArchiveAlias("fread_unlocked", "fread", "weak-same-address"),
                ROSTER.ArchiveAlias("fseeko", "__fseeko", "weak-same-address"),
                ROSTER.ArchiveAlias("ftello", "__ftello", "weak-same-address"),
                ROSTER.ArchiveAlias("fwrite_unlocked", "fwrite", "weak-same-address"),
                ROSTER.ArchiveAlias("getutent", "getutxent", "weak-same-address"),
                ROSTER.ArchiveAlias("getutid", "getutxid", "weak-same-address"),
                ROSTER.ArchiveAlias("getutline", "getutxline", "weak-same-address"),
                ROSTER.ArchiveAlias("getwc_unlocked", "__fgetwc_unlocked", "weak-same-address"),
                ROSTER.ArchiveAlias("getwchar_unlocked", "getwchar", "weak-same-address"),
                ROSTER.ArchiveAlias("localtime_r", "__localtime_r", "weak-same-address"),
                ROSTER.ArchiveAlias("mkostemps", "__mkostemps", "weak-same-address"),
                ROSTER.ArchiveAlias(
                    "pthread_cond_timedwait",
                    "__pthread_cond_timedwait",
                    "weak-same-address",
                ),
                ROSTER.ArchiveAlias(
                    "pthread_mutex_timedlock",
                    "__pthread_mutex_timedlock",
                    "weak-same-address",
                ),
                ROSTER.ArchiveAlias(
                    "pthread_timedjoin_np",
                    "__pthread_timedjoin_np",
                    "weak-same-address",
                ),
                ROSTER.ArchiveAlias(
                    "pthread_tryjoin_np",
                    "__pthread_tryjoin_np",
                    "weak-same-address",
                ),
                ROSTER.ArchiveAlias("pututline", "pututxline", "weak-same-address"),
                ROSTER.ArchiveAlias("putwc_unlocked", "__fputwc_unlocked", "weak-same-address"),
                ROSTER.ArchiveAlias("putwchar_unlocked", "putwchar", "weak-same-address"),
                ROSTER.ArchiveAlias("setutent", "setutxent", "weak-same-address"),
                ROSTER.ArchiveAlias("strftime_l", "__strftime_l", "weak-same-address"),
                ROSTER.ArchiveAlias("updwtmp", "updwtmpx", "weak-same-address"),
                ROSTER.ArchiveAlias("utmpxname", "utmpname", "weak-same-address"),
                ROSTER.ArchiveAlias("wcsftime_l", "__wcsftime_l", "weak-same-address"),
            ),
        )
        owned_dynamic = next(item for item in rows if item.identifier == "x86-owned-dynamic-runtime")
        self.assertEqual(owned_dynamic.state, "planned")
        self.assertIsNone(owned_dynamic.evidence_record)
        self.assertIsNone(owned_dynamic.dispatch_command)
        self.assertEqual(
            owned_dynamic.runner,
            "compat/x86_64/run_materialized_dynamic_sysroot.sh",
        )
        self.assertEqual(
            owned_dynamic.feature_selection_source,
            "scripts/build_x86_64_owned_dynamic_sysroot.py",
        )
        self.assertEqual(owned_dynamic.baseline_features, ("x86-owned-static-runtime",))
        self.assertEqual(owned_dynamic.abi_only_callables, ("_dl_debug_state",))
        self.assertEqual(owned_dynamic.additive_callables, ())
        self.assertEqual(owned_dynamic.replacement_callables, ())
        resolver = next(item for item in rows if item.identifier == "x86-resolver-runtime")
        self.assertEqual(resolver.state, "verified")
        self.assertEqual(resolver.evidence_record, "static-c-resolver-runtime")
        self.assertEqual(resolver.dispatch_command, "libc-resolver-runtime")
        self.assertEqual(
            resolver.aliases,
            (
                ROSTER.ArchiveAlias("res_mkquery", "__res_mkquery", "weak-same-address"),
                ROSTER.ArchiveAlias("res_search", "res_query", "weak-same-address"),
                ROSTER.ArchiveAlias("res_send", "__res_send", "weak-same-address"),
            ),
        )
        self.assertEqual(
            next(item for item in rows if item.identifier == "x86-environment-runtime").additive_callables,
            (),
        )
        interval_timers = next(
            item for item in rows if item.identifier == "x86-interval-timers"
        )
        self.assertEqual(interval_timers.evidence_record, "static-c-interval-timers")
        self.assertEqual(interval_timers.dispatch_command, "libc-interval-timers")
        self.assertEqual(interval_timers.additive_callables, ("getitimer", "setitimer"))
        file_handles = next(
            item for item in rows if item.identifier == "x86-file-handles"
        )
        self.assertEqual(file_handles.evidence_record, "static-c-file-handles")
        self.assertEqual(file_handles.dispatch_command, "libc-file-handles")
        self.assertEqual(
            file_handles.additive_callables,
            ("name_to_handle_at", "open_by_handle_at"),
        )
        temporary_names = next(
            item for item in rows if item.identifier == "x86-temporary-names"
        )
        self.assertEqual(
            temporary_names.evidence_record,
            "static-c-temporary-names",
        )
        self.assertEqual(
            temporary_names.dispatch_command,
            "libc-temporary-names",
        )
        self.assertEqual(
            temporary_names.baseline_features,
            ("x86-allocator-runtime", "x86-allocator-string-duplication"),
        )
        self.assertEqual(temporary_names.additive_callables, ("tempnam", "tmpnam"))
        spawn_file_actions = next(
            item
            for item in rows
            if item.identifier == "x86-posix-spawn-file-actions"
        )
        self.assertEqual(
            spawn_file_actions.evidence_record,
            "static-c-posix-spawn-file-actions",
        )
        self.assertEqual(
            spawn_file_actions.dispatch_command,
            "libc-posix-spawn-file-actions",
        )
        self.assertEqual(
            spawn_file_actions.baseline_features,
            ("x86-allocator-runtime",),
        )
        self.assertEqual(
            spawn_file_actions.additive_callables,
            (
                "posix_spawn_file_actions_addchdir_np",
                "posix_spawn_file_actions_addclose",
                "posix_spawn_file_actions_adddup2",
                "posix_spawn_file_actions_addfchdir_np",
                "posix_spawn_file_actions_addopen",
                "posix_spawn_file_actions_destroy",
            ),
        )
        process_exec = next(item for item in rows if item.identifier == "x86-process-exec")
        self.assertEqual(process_exec.state, "verified")
        self.assertEqual(process_exec.evidence_record, "static-c-process-exec")
        self.assertEqual(process_exec.runner, "compat/x86_64/run_libc_process_exec.sh")
        self.assertEqual(process_exec.dispatch_command, "libc-process-exec")
        self.assertEqual(process_exec.baseline_features, ())
        self.assertEqual(
            process_exec.additive_callables,
            ("execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe", "fexecve"),
        )
        self.assertEqual(
            process_exec.aliases,
            (ROSTER.ArchiveAlias("execvpe", "__execvpe", "weak-same-address"),),
        )
        spin_operations = next(
            item
            for item in rows
            if item.identifier == "x86-pthread-spin-operations"
        )
        self.assertEqual(
            spin_operations.evidence_record,
            "static-c-pthread-spin-operations",
        )
        self.assertEqual(
            spin_operations.additive_callables,
            ("pthread_spin_lock", "pthread_spin_trylock", "pthread_spin_unlock"),
        )
        composition = next(
            item
            for item in rows
            if item.identifier == "x86-crypt-allocator-composition"
        )
        self.assertEqual(composition.evidence_record, "static-c-crypt-allocator-composition")
        self.assertEqual(composition.dispatch_command, "libc-crypt-allocator-composition")
        self.assertEqual(
            composition.baseline_features,
            ("x86-allocator-runtime", "x86-crypt"),
        )
        self.assertEqual(composition.additive_callables, ())
        self.assertEqual(composition.replacement_callables, ())

    def test_c_compatibility_entry_provider_ownership_is_explicit(self) -> None:
        """Keep C-compatibility entries in their real default and feature rows."""

        static_exports = tuple(
            line
            for line in (ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt")
            .read_text(encoding="utf-8")
            .splitlines()
            if line and not line.startswith("#")
        )
        expected_default_entries = (
            "__isoc99_sscanf",
            "__isoc99_vsscanf",
            "__strtoimax_internal",
            "__strtol_internal",
            "__strtoll_internal",
            "__strtoul_internal",
            "__strtoull_internal",
            "__strtoumax_internal",
        )
        self.assertEqual(
            tuple(name for name in static_exports if name in expected_default_entries),
            expected_default_entries,
        )

        rows = {row.identifier: row for row in ROSTER.load_feature_archive_roster()}
        permanent_scan = rows["x86-stdio-permanent-format-scan"]
        self.assertEqual(permanent_scan.state, "verified")
        self.assertEqual(permanent_scan.evidence_record, "static-c-stdio-permanent-format-scan")
        self.assertEqual(permanent_scan.baseline_features, ())
        self.assertEqual(
            permanent_scan.additive_callables,
            ("fprintf", "fscanf", "printf", "scanf", "vfprintf", "vfscanf", "vprintf", "vscanf"),
        )
        self.assertEqual(permanent_scan.replacement_callables, ())
        self.assertEqual(
            permanent_scan.aliases,
            (
                ROSTER.ArchiveAlias("__isoc99_fscanf", "fscanf", "weak-same-address"),
                ROSTER.ArchiveAlias("__isoc99_scanf", "scanf", "weak-same-address"),
                ROSTER.ArchiveAlias("__isoc99_vfscanf", "vfscanf", "weak-same-address"),
                ROSTER.ArchiveAlias("__isoc99_vscanf", "vscanf", "weak-same-address"),
            ),
        )

        owned_static = rows["x86-owned-static-runtime"]
        self.assertIn(permanent_scan.identifier, owned_static.baseline_features)
        self.assertEqual(
            owned_static.abi_only_callables,
            ("__xmknod", "__xmknodat", "_fini", "_init"),
        )

    def test_kernel_admin_abi_only_ownership_is_explicit(self) -> None:
        """Keep non-header kernel administration providers out of the default archive."""

        static_exports = tuple(
            line
            for line in (ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt")
            .read_text(encoding="utf-8")
            .splitlines()
            if line and not line.startswith("#")
        )
        archives = ROSTER.load_feature_archive_roster()
        rows = {archive.identifier: archive for archive in archives}
        kernel_admin = rows["x86-kernel-admin"]
        io_permissions = rows["x86-io-permissions"]
        owned_static = rows["x86-owned-static-runtime"]

        self.assertEqual(kernel_admin.state, "planned")
        self.assertIsNone(kernel_admin.evidence_record)
        self.assertIsNone(kernel_admin.dispatch_command)
        self.assertEqual(kernel_admin.runner, "compat/x86_64/run_libc_kernel_admin.sh")
        self.assertEqual(kernel_admin.feature_selection_source, "libc/Cargo.toml")
        self.assertEqual(kernel_admin.baseline_features, ("x86-io-permissions",))
        self.assertEqual(kernel_admin.enabled_features, ("x86-kernel-admin",))
        self.assertEqual(kernel_admin.abi_only_callables, ("arch_prctl",))
        self.assertEqual(kernel_admin.additive_callables, ())
        self.assertEqual(kernel_admin.replacement_callables, ())
        self.assertEqual(kernel_admin.aliases, ())

        self.assertEqual(io_permissions.additive_callables, ("ioperm", "iopl"))
        self.assertIn(io_permissions.identifier, owned_static.baseline_features)
        self.assertIn(kernel_admin.identifier, owned_static.baseline_features)
        self.assertEqual(
            owned_static.abi_only_callables,
            ("__xmknod", "__xmknodat", "_fini", "_init"),
        )

        inherited = ROSTER.selected_baseline_callables(
            owned_static,
            archives,
            static_exports,
        )
        expected_inherited = ("arch_prctl", "ioperm", "iopl")
        self.assertEqual(
            tuple(name for name in expected_inherited if name in inherited),
            expected_inherited,
        )
        self.assertEqual(
            len(inherited.intersection(expected_inherited)),
            len(expected_inherited),
        )
        self.assertEqual(
            tuple(
                name
                for name in static_exports
                if name in {"__xmknod", "__xmknodat", "_fini", "_init", "arch_prctl"}
            ),
            (),
        )

    def test_loader_weak_defaults_have_one_callable_route(self) -> None:
        """Keep loader weak functions planned, ABI-only, and separate from its data object."""

        static_exports = tuple(
            line
            for line in (ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt")
            .read_text(encoding="utf-8")
            .splitlines()
            if line and not line.startswith("#")
        )
        archives = ROSTER.load_feature_archive_roster()
        rows = {archive.identifier: archive for archive in archives}
        owned_static = rows["x86-owned-static-runtime"]
        owned_dynamic = rows["x86-owned-dynamic-runtime"]
        callable_names = {"_dl_debug_state", "_fini", "_init"}
        loader_names = {*callable_names, "_dl_debug_addr"}

        self.assertEqual(owned_static.state, "planned")
        self.assertIsNone(owned_static.evidence_record)
        self.assertIsNone(owned_static.dispatch_command)
        self.assertEqual(
            owned_static.abi_only_callables,
            ("__xmknod", "__xmknodat", "_fini", "_init"),
        )
        self.assertEqual(owned_dynamic.state, "planned")
        self.assertIsNone(owned_dynamic.evidence_record)
        self.assertIsNone(owned_dynamic.dispatch_command)
        self.assertEqual(owned_dynamic.baseline_features, ("x86-owned-static-runtime",))
        self.assertEqual(owned_dynamic.abi_only_callables, ("_dl_debug_state",))
        self.assertEqual(owned_dynamic.additive_callables, ())
        self.assertEqual(owned_dynamic.replacement_callables, ())
        self.assertEqual(owned_dynamic.aliases, ())
        self.assertEqual(
            tuple(
                (archive.identifier, name)
                for archive in archives
                for name in archive.abi_only_callables
                if name in callable_names
            ),
            (
                ("x86-owned-static-runtime", "_fini"),
                ("x86-owned-static-runtime", "_init"),
                ("x86-owned-dynamic-runtime", "_dl_debug_state"),
            ),
        )
        self.assertEqual(
            tuple(
                (archive.identifier, name)
                for archive in archives
                for name in (*archive.additive_callables, *archive.replacement_callables)
                if name in loader_names
            ),
            (),
        )
        self.assertEqual(
            tuple(
                (archive.identifier, name)
                for archive in archives
                for name in archive.abi_only_callables
                if name == "_dl_debug_addr"
            ),
            (),
        )

        inherited = ROSTER.selected_baseline_callables(
            owned_dynamic,
            archives,
            static_exports,
        )
        expected_inherited = (
            "__xmknod",
            "__xmknodat",
            "_fini",
            "_init",
            "arch_prctl",
            "ioperm",
            "iopl",
        )
        self.assertEqual(
            tuple(name for name in expected_inherited if name in inherited),
            expected_inherited,
        )
        self.assertEqual(
            len(inherited.intersection(expected_inherited)),
            len(expected_inherited),
        )
        self.assertEqual(
            tuple(name for name in static_exports if name in loader_names),
            (),
        )
        self.assertEqual(
            tuple(
                (archive.identifier, alias)
                for archive in archives
                for alias in archive.aliases
                if alias.name in loader_names or alias.target in loader_names
            ),
            (),
        )

    def test_planned_provider_runners_route_to_cargo_selection_sources(self) -> None:
        """Keep planned provider evidence distinct from direct feature selection."""
        planned_products = tuple(
            item
            for item in ROSTER.load_feature_archive_roster()
            if item.identifier
            in {
                "x86-kernel-admin",
                "x86-owned-static-runtime",
                "x86-owned-dynamic-runtime",
            }
        )
        self.assertEqual(
            tuple(item.identifier for item in planned_products),
            (
                "x86-owned-static-runtime",
                "x86-owned-dynamic-runtime",
                "x86-kernel-admin",
            ),
        )
        import tomllib
        data = tomllib.loads((ROOT / "compat/x86_64/parity.toml").read_text())
        records = {record["id"]: record for family in data["family"]
                   for key in ("verified_slice", "verified_artifact")
                   for record in family.get(key, [])}
        all_rows = ROSTER.load_feature_archive_roster()
        report = ROSTER.validate_ledger_bindings(
            all_rows,
            static_exports=(ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt")
            .read_text(encoding="utf-8")
            .split(),
            verified_records=records,
            dispatcher_path=ROOT / "scripts" / "dev-x86_64.sh",
        )
        self.assertEqual(
            report,
            {
                "feature_archive_count": 35,
                "planned_feature_archive_count": 6,
                "verified_feature_archive_count": 29,
            },
        )

    def test_native_profiles_preserve_callable_sets_without_inheriting_evidence(self) -> None:
        rows = ROSTER.load_feature_archive_roster()
        by_id = {row.identifier: row for row in rows}
        exports = (ROOT / 'compat/x86_64/static_c_abi_exports.txt').read_text().split()
        for native, c_profile in ROSTER.NATIVE_PROVIDER_PROFILES.items():
            candidate, provider = by_id[native], by_id[c_profile]
            self.assertEqual(candidate.provider_profile, c_profile)
            self.assertEqual(candidate.state, 'planned')
            self.assertIsNone(candidate.evidence_record)
            self.assertIsNone(candidate.dispatch_command)
            expected = ROSTER.selected_baseline_callables(provider, rows, exports)
            expected.update(provider.additive_callables)
            expected.update(provider.abi_only_callables)
            self.assertEqual(ROSTER.selected_baseline_callables(candidate, rows, exports), expected)

    def test_native_profiles_reject_wrong_kind_chains_ownership_and_c_receipts(self) -> None:
        raw = tomllib.loads((ROOT / 'compat/x86_64/parity.toml').read_text())['feature_archive']
        features = ROSTER.load_cargo_x86_features()
        native_id = 'x86-owned-static-native-shadow'
        mutations = [
            {'provider_profile': 'x86-unknown'},
            {'provider_profile': 'x86-owned-dynamic-runtime'},
            {'provider_profile': 'x86-owned-dynamic-native-shadow'},
            {'provider_profile': native_id},
            {'additive_callables': ['malloc']},
            {'replacement_callables': ['malloc']},
            {'abi_only_callables': ['private_native_entry']},
            {'state': 'verified', 'evidence_record': 'static-c-allocator-wrapper',
             'dispatch_command': 'libc-allocator-runtime'},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(raw)
                row = next(row for row in changed if row['id'] == native_id)
                row.update(mutation)
                if row['state'] == 'verified':
                    row.pop('feature_selection_source')
                with self.assertRaises(ROSTER.FeatureArchiveRosterError):
                    ROSTER.parse_feature_archive_roster(changed, features)
        changed = dict(features)
        changed[native_id] = tuple(feature for feature in changed[native_id] if feature != 'x86-memory-special')
        with self.assertRaisesRegex(ROSTER.FeatureArchiveRosterError, 'source capabilities'):
            ROSTER.parse_feature_archive_roster(raw, changed)

    def test_dependent_feature_requires_its_exact_cargo_baseline(self) -> None:
        cargo_features = {
            "x86-base": (),
            "x86-dependent": ("x86-base",),
        }
        rows = [row("x86-base"), row("x86-dependent")]

        with self.assertRaisesRegex(
            ROSTER.FeatureArchiveRosterError,
            "baseline does not match its Cargo feature dependency closure",
        ):
            ROSTER.parse_feature_archive_roster(rows, cargo_features)

    def test_replacement_requires_a_provider_in_the_selected_dependency_baseline(self) -> None:
        cargo_features = {"x86-owned": ("x86-leaf",), "x86-leaf": (), "x86-other": ()}
        rows = ROSTER.parse_feature_archive_roster([
            row("x86-owned", state="planned", baseline_features=["x86-leaf"],
                replacement_callables=["fmtmsg"]),
            row("x86-leaf", additive_callables=["fmtmsg"]),
            row("x86-other", additive_callables=["unrelated"]),
        ], cargo_features)
        partition = ROSTER.partition_candidate_callables(
            rows, candidate_callables={"fmtmsg", "unrelated"}, static_exports=set(),
        )
        self.assertEqual(partition.verified_feature_archives[0][1], ("fmtmsg",))
        self.assertEqual(partition.replacement_variants, ((rows[0], ("fmtmsg",)),))
        self.assertEqual(partition.unprovided, ())
        self.assertEqual(partition.declared_unverified_feature_archives[0][1], ())
        from dataclasses import replace
        invalid = (replace(rows[0], replacement_callables=("unrelated",)), *rows[1:])
        with self.assertRaisesRegex(ROSTER.FeatureArchiveRosterError, "selected baseline"):
            ROSTER.partition_candidate_callables(
                invalid, candidate_callables={"fmtmsg", "unrelated"}, static_exports=set(),
            )

    def test_abi_only_callables_stay_out_of_header_provider_accounting(self) -> None:
        """A real non-header function provider cannot alter header counts."""

        cargo_features = {"x86-abi": ()}
        rows = ROSTER.parse_feature_archive_roster(
            [
                row(
                    "x86-abi",
                    additive_callables=["header_feature"],
                    abi_only_callables=["__strong_private", "strong_private"],
                )
            ],
            cargo_features,
        )

        partition = ROSTER.partition_candidate_callables(
            rows,
            candidate_callables={"header_default", "header_feature", "header_unprovided"},
            static_exports={"header_default"},
        )

        self.assertEqual(rows[0].abi_only_callables, ("__strong_private", "strong_private"))
        self.assertEqual(partition.default_static, ("header_default",))
        self.assertEqual(partition.verified_feature_archives[0][1], ("header_feature",))
        self.assertEqual(partition.unprovided, ("header_unprovided",))
        self.assertNotIn("abi_only_callables", partition.as_report())
        self.assertNotIn(
            "abi_only_callables",
            partition.as_report()["verified_feature_archives"][0],
        )
        self.assertEqual(
            partition.counts(),
            {
                "default_static": 1,
                "verified_feature_archives": 1,
                "declared_unverified_feature_archives": 0,
                "unprovided": 1,
            },
        )

    def test_abi_only_callables_reject_header_default_alias_and_feature_overlaps(self) -> None:
        """Non-header providers have one owner and no weak alias identity."""

        header_rows = ROSTER.parse_feature_archive_roster(
            [row("x86-abi", abi_only_callables=["strong_private"])],
            {"x86-abi": ()},
        )
        with self.assertRaisesRegex(
            ROSTER.FeatureArchiveRosterError,
            "ABI-only callable strong_private is header-declared",
        ):
            ROSTER.partition_candidate_callables(
                header_rows,
                candidate_callables={"strong_private"},
                static_exports=set(),
            )
        with self.assertRaisesRegex(
            ROSTER.FeatureArchiveRosterError,
            "ABI-only callable strong_private is already default-static",
        ):
            ROSTER.partition_candidate_callables(
                header_rows,
                candidate_callables={"header_callable"},
                static_exports={"strong_private"},
            )

        alias_row = row("x86-abi", abi_only_callables=["strong_private"])
        alias_row["aliases"] = [
            {
                "name": "strong_private",
                "target": "provider",
                "binding": "weak-same-address",
            }
        ]
        with self.assertRaisesRegex(
            ROSTER.FeatureArchiveRosterError,
            "ABI-only callable strong_private is also an alias name",
        ):
            ROSTER.parse_feature_archive_roster([alias_row], {"x86-abi": ()})

        target_row = row("x86-abi", abi_only_callables=["strong_private"])
        target_row["aliases"] = [
            {
                "name": "weak_public",
                "target": "strong_private",
                "binding": "weak-same-address",
            }
        ]
        target_rows = ROSTER.parse_feature_archive_roster(
            [target_row], {"x86-abi": ()}
        )
        self.assertEqual(
            ROSTER.partition_candidate_callables(
                target_rows,
                candidate_callables={"header_callable"},
                static_exports=set(),
            ).unprovided,
            ("header_callable",),
        )

        cross_alias_row = row("x86-alias-owner")
        cross_alias_row["aliases"] = [
            {
                "name": "strong_private",
                "target": "provider",
                "binding": "weak-same-address",
            }
        ]
        cross_alias_rows = ROSTER.parse_feature_archive_roster(
            [
                row("x86-abi-owner", abi_only_callables=["strong_private"]),
                cross_alias_row,
            ],
            {"x86-abi-owner": (), "x86-alias-owner": ()},
        )
        with self.assertRaisesRegex(
            ROSTER.FeatureArchiveRosterError,
            "ABI-only callable strong_private is also an alias name",
        ):
            ROSTER.partition_candidate_callables(
                cross_alias_rows,
                candidate_callables={"header_callable"},
                static_exports=set(),
            )

        duplicate_rows = ROSTER.parse_feature_archive_roster(
            [
                row("x86-first", abi_only_callables=["strong_private"]),
                row("x86-second", abi_only_callables=["strong_private"]),
            ],
            {"x86-first": (), "x86-second": ()},
        )
        with self.assertRaisesRegex(
            ROSTER.FeatureArchiveRosterError,
            "ABI-only callable strong_private has multiple feature owners",
        ):
            ROSTER.partition_candidate_callables(
                duplicate_rows,
                candidate_callables={"header_callable"},
                static_exports=set(),
            )

        header_owned_rows = ROSTER.parse_feature_archive_roster(
            [
                row("x86-header-owner", additive_callables=["strong_private"]),
                row("x86-abi-owner", abi_only_callables=["strong_private"]),
            ],
            {"x86-header-owner": (), "x86-abi-owner": ()},
        )
        with self.assertRaisesRegex(
            ROSTER.FeatureArchiveRosterError,
            "ABI-only callable strong_private overlaps header callable ownership",
        ):
            ROSTER.partition_candidate_callables(
                header_owned_rows,
                candidate_callables={"header_callable"},
                static_exports=set(),
            )

    def test_abi_only_callables_are_optional_nonempty_and_transitive(self) -> None:
        cargo_features = {"x86-leaf": (), "x86-parent": ("x86-leaf",)}
        rows = ROSTER.parse_feature_archive_roster(
            [
                row("x86-leaf", abi_only_callables=["strong_leaf"]),
                row("x86-parent", baseline_features=["x86-leaf"]),
            ],
            cargo_features,
        )
        self.assertEqual(rows[1].abi_only_callables, ())
        self.assertEqual(
            ROSTER.selected_baseline_callables(rows[1], rows, set()),
            {"strong_leaf"},
        )

        duplicate_baseline_rows = ROSTER.parse_feature_archive_roster(
            [
                row("x86-leaf", abi_only_callables=["strong_leaf"]),
                row(
                    "x86-parent",
                    baseline_features=["x86-leaf"],
                    abi_only_callables=["strong_leaf"],
                ),
            ],
            cargo_features,
        )
        with self.assertRaisesRegex(
            ROSTER.FeatureArchiveRosterError,
            "ABI-only callable strong_leaf has multiple feature owners",
        ):
            ROSTER.partition_candidate_callables(
                duplicate_baseline_rows,
                candidate_callables={"header_callable"},
                static_exports=set(),
            )

        empty = row("x86-abi", abi_only_callables=[])
        with self.assertRaisesRegex(
            ROSTER.FeatureArchiveRosterError,
            "abi_only_callables must not be empty",
        ):
            ROSTER.parse_feature_archive_roster([empty], {"x86-abi": ()})

        drifted = row("x86-abi")
        drifted["unexpected"] = True
        with self.assertRaisesRegex(ROSTER.FeatureArchiveRosterError, "keys drifted"):
            ROSTER.parse_feature_archive_roster([drifted], {"x86-abi": ()})

    def test_partition_rejects_default_static_additive_ownership(self) -> None:
        cargo_features = {"x86-extra": ()}
        rows = ROSTER.parse_feature_archive_roster(
            [row("x86-extra", additive_callables=["already_default"])],
            cargo_features,
        )

        with self.assertRaisesRegex(
            ROSTER.FeatureArchiveRosterError,
            "not exclusively owned",
        ):
            ROSTER.partition_candidate_callables(
                rows,
                candidate_callables={"already_default"},
                static_exports={"already_default"},
            )

    def test_partition_keeps_declared_unverified_features_out_of_verified_ownership(self) -> None:
        cargo_features = {"x86-planned": ()}
        rows = ROSTER.parse_feature_archive_roster(
            [row("x86-planned", state="planned", additive_callables=["future_callable"])],
            cargo_features,
        )
        partition = ROSTER.partition_candidate_callables(
            rows,
            candidate_callables={"future_callable", "unprovided"},
            static_exports=set(),
        )

        self.assertEqual(partition.counts(), {
            "default_static": 0,
            "verified_feature_archives": 0,
            "declared_unverified_feature_archives": 1,
            "unprovided": 1,
        })


if __name__ == "__main__":
    unittest.main()
