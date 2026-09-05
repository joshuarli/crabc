#!/usr/bin/env python3
"""Focused contracts for native x86 feature-archive provider ownership."""

from __future__ import annotations

import importlib.util
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
                "x86-allocator-observability",
                "x86-allocator-runtime",
                "x86-allocator-string-duplication",
                "x86-environment-runtime",
                "x86-file-handles",
                "x86-filesystem-traversal",
                "x86-h-errno",
                "x86-interval-timers",
                "x86-process-exec",
                "x86-resolver-runtime",
                "x86-scandir",
                "x86-stdio-permanent-format-scan",
                "x86-temporary-names",
                "x86-ualarm",
            ),
        )
        self.assertEqual(
            owned_static.additive_callables,
            (
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
                "adjtime",
                "adjtimex",
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
                "daemon",
                "delete_module",
                "dprintf",
                "endgrent",
                "endpwent",
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
                "localtime",
                "localtime_r",
                "lockf",
                "log1p",
                "log1pf",
                "login_tty",
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
                "putw",
                "putwc",
                "putwc_unlocked",
                "putwchar",
                "putwchar_unlocked",
                "pwritev2",
                "quick_exit",
                "quotactl",
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
                "setns",
                "setpwent",
                "settimeofday",
                "shm_open",
                "shm_unlink",
                "statx",
                "stime",
                "strftime",
                "strftime_l",
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
                "umount",
                "umount2",
                "ungetwc",
                "unshare",
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
                "clearerr",
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
                "fopen",
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
                "getnameinfo",
                "lchmod",
                "putc",
                "putchar",
                "puts",
                "rewind",
                "setvbuf",
                "snprintf",
                "sprintf",
                "sscanf",
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
                ROSTER.ArchiveAlias("clearerr_unlocked", "clearerr", "weak-same-address"),
                ROSTER.ArchiveAlias("endpwent", "setpwent", "weak-same-address"),
                ROSTER.ArchiveAlias("feof_unlocked", "feof", "weak-same-address"),
                ROSTER.ArchiveAlias("ferror_unlocked", "ferror", "weak-same-address"),
                ROSTER.ArchiveAlias("fflush_unlocked", "fflush", "weak-same-address"),
                ROSTER.ArchiveAlias("fgets_unlocked", "fgets", "weak-same-address"),
                ROSTER.ArchiveAlias("fileno_unlocked", "fileno", "weak-same-address"),
                ROSTER.ArchiveAlias("fpurge", "__fpurge", "weak-same-address"),
                ROSTER.ArchiveAlias("fputs_unlocked", "fputs", "weak-same-address"),
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

    def test_planned_owned_product_runners_route_to_cargo_selection_sources(self) -> None:
        """Keep planned product evidence distinct from direct feature selection."""
        planned_products = tuple(
            item
            for item in ROSTER.load_feature_archive_roster()
            if item.identifier in {"x86-owned-static-runtime", "x86-owned-dynamic-runtime"}
        )
        report = ROSTER.validate_ledger_bindings(
            planned_products,
            static_exports=(ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt")
            .read_text(encoding="utf-8")
            .split(),
            verified_records={},
            dispatcher_path=ROOT / "scripts" / "dev-x86_64.sh",
        )
        self.assertEqual(
            report,
            {
                "feature_archive_count": len(planned_products),
                "planned_feature_archive_count": len(planned_products),
                "verified_feature_archive_count": 0,
            },
        )

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
