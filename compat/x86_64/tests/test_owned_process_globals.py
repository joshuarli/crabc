#!/usr/bin/env python3
"""The process.globals provider reader rejects every musl metadata drift."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat" / "x86_64"))

import owned_process_globals as reader  # noqa: E402

RUNNER = ROOT / "compat/x86_64/run_owned_process_globals.sh"
PROBE = ROOT / "compat/x86_64/owned_process_globals_probe.c"
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"

# Pinned musl 1.2.6 x86-64 storage groups: canonical name first.
GROUPS = (
    ("__environ", "environ", "_environ", "___environ"),
    ("__optreset", "optreset"),
    ("__progname", "program_invocation_short_name"),
    ("__progname_full", "program_invocation_name"),
    ("__signgam", "signgam"),
    ("__timezone", "timezone"),
    ("__daylight", "daylight"),
    ("__tzname", "tzname"),
    ("getopt", "__posix_getopt"),
    ("__optpos",), ("h_errno",), ("optarg",), ("opterr",), ("optind",), ("optopt",),
    ("__h_errno_location",), ("getenv",), ("putenv",), ("getopt_long",),
    ("getopt_long_only",),
)
SIZES = {
    "__environ": 8, "__progname": 8, "__progname_full": 8, "__timezone": 8,
    "__tzname": 16, "optarg": 8,
}


def rows(
    *,
    member: str = "",
    binding: dict[str, str] | None = None,
    size: dict[str, int] | None = None,
    value: dict[str, int] | None = None,
    suffix: dict[str, str] | None = None,
    omit: frozenset[str] = frozenset(),
    extra: tuple[str, ...] = (),
) -> str:
    """Render a musl-shaped `readelf --wide` symbol transcript."""
    lines = [f"File: libc.a({member})"] if member else []
    lines.append("   Num:    Value          Size Type    Bind   Vis      Ndx Name")
    index = 1
    for group_index, group in enumerate(GROUPS):
        for position, name in enumerate(group):
            if name in omit:
                continue
            kind = "OBJECT" if name in reader.DATA_NAMES else "FUNC"
            bind = (binding or {}).get(name, "GLOBAL" if position == 0 else "WEAK")
            width = (size or {}).get(name, SIZES.get(group[0], 4) if kind == "OBJECT" else 32)
            address = (value or {}).get(name, 0x1000 + 0x40 * group_index)
            spelling = name + (suffix or {}).get(name, "")
            lines.append(
                f"  {index:4d}: {address:016x} {width:5d} {kind:<7} {bind:<6} DEFAULT   20 {spelling}"
            )
            index += 1
    lines.extend(extra)
    return "\n".join(lines) + "\n"


def armap(member: str, omit: frozenset[str] = frozenset()) -> str:
    return "Archive index:\n" + "".join(
        f"{name} in {member}\n" for name in reader.ROSTER if name not in omit
    )


class ProcessGlobalsReaderTests(unittest.TestCase):
    def test_frozen_ledger_roster_is_the_audited_closure(self) -> None:
        self.assertEqual(reader.frozen_roster(), reader.ROSTER)
        self.assertEqual(len(reader.ROSTER), 31)
        self.assertEqual(set(reader.DATA_NAMES) & set(reader.FUNCTION_NAMES), set())

    def test_matching_shared_and_static_metadata_passes(self) -> None:
        shared = reader.audit_shared(rows(), rows())
        self.assertEqual(shared["names"], 31)
        self.assertIn(["___environ", "__environ", "_environ", "environ"], shared["aliases"])
        static = reader.audit_static(
            rows(member="c.o"), armap("c.o"), rows(member="env.lo"), armap("env.lo")
        )
        self.assertEqual(static["members"], ["c.o"])

    def test_undefined_and_local_rows_are_not_providers(self) -> None:
        extra = (
            "     9: 0000000000000000     0 OBJECT  GLOBAL DEFAULT  UND optind",
            "    10: 0000000000002000     4 OBJECT  LOCAL  DEFAULT   20 optopt",
        )
        self.assertEqual(reader.audit_shared(rows(extra=extra), rows())["names"], 31)

    def test_metadata_drift_is_rejected(self) -> None:
        cases = {
            "binding": rows(binding={"environ": "GLOBAL"}),
            "size": rows(size={"__tzname": 8, "tzname": 8}),
            "alias partition": rows(value={"optreset": 0x9000}),
            "unversioned": rows(suffix={"getenv": "@@CRABC_1"}),
            "does not define": rows(omit=frozenset({"__signgam"})),
            "2 times": rows(extra=(
                "    90: 0000000000009000     4 OBJECT  GLOBAL DEFAULT   20 h_errno",
            )),
        }
        for message, candidate in cases.items():
            with self.subTest(message=message):
                with self.assertRaisesRegex(reader.ProcessGlobalsError, message):
                    reader.audit_shared(candidate, rows())

    def test_static_provider_must_be_archive_extractable(self) -> None:
        with self.assertRaisesRegex(reader.ProcessGlobalsError, "archive index does not extract daylight"):
            reader.audit_static(
                rows(member="c.o"), armap("c.o", frozenset({"daylight"})),
                rows(member="tz.lo"), armap("tz.lo"),
            )

    def test_non_pie_consumer_requires_copy_storage_for_each_group(self) -> None:
        relocations = "\n".join(
            f"0000000000404d60  0000003100000005 R_X86_64_COPY          0000000000404d60 {group[0]} + 0"
            for group in GROUPS if group[0] in reader.DATA_NAMES
        )
        library = rows()
        executable = rows(omit=frozenset(reader.FUNCTION_NAMES))
        report = reader.audit_copy_executable(executable, relocations, library, "fixture")
        self.assertEqual(report["groups"], 14)
        with self.assertRaisesRegex(reader.ProcessGlobalsError, "does not own COPY storage for tzname"):
            reader.audit_copy_executable(
                rows(omit=frozenset(reader.FUNCTION_NAMES) | {"tzname"}), relocations, library, "fixture"
            )
        with self.assertRaisesRegex(reader.ProcessGlobalsError, "no R_X86_64_COPY"):
            reader.audit_copy_executable(
                executable, relocations.replace("optind", "stdout"), library, "fixture"
            )
        with self.assertRaisesRegex(reader.ProcessGlobalsError, "COPY alias partition"):
            reader.audit_copy_executable(
                rows(omit=frozenset(reader.FUNCTION_NAMES), value={"_environ": 0x9000}),
                relocations, library, "fixture",
            )


class ProcessGlobalsRunnerTests(unittest.TestCase):
    def assert_usage(self, *arguments: str) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="owned-process-globals-parser.", dir=scratch) as temporary:
            tools = Path(temporary) / "tools"
            tools.mkdir()
            python = tools / "python3"
            python.write_text("#!/bin/sh\nexit 79\n", encoding="utf-8")
            python.chmod(0o755)
            environment = dict(os.environ)
            environment["PATH"] = f"{tools}{os.pathsep}{environment['PATH']}"
            result = subprocess.run(
                ["bash", str(RUNNER), *arguments], cwd=ROOT, env=environment,
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(
            result.stderr,
            f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n",
        )

    def test_runner_requires_both_products_or_neither(self) -> None:
        self.assert_usage("--static-sysroot", "static")
        self.assert_usage("dynamic")
        self.assert_usage("--static-sysroot")
        self.assert_usage("--unknown")

    def test_runner_links_one_object_per_code_model_through_every_mode(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for fragment in (
            '--dynamic-pie -std=c11 -fno-builtin',
            '--dynamic-non-pie -std=c11 -fno-builtin',
            'validate_sealed_link',
            'compare_class "musl-$mode" "$mode"',
            'compare_class "musl-$mode" "dynamic-$mode" "$work/$mode-root" "$INTERPRETER"',
            '"$AUDIT" static', '"$AUDIT" shared', '"$AUDIT" copy musl-non-pie',
            '"$AUDIT" copy owned-non-pie',
        ):
            self.assertIn(fragment, runner)
        probe = PROBE.read_text(encoding="utf-8")
        for name in reader.ROSTER:
            self.assertRegex(probe, rf"\b{name}\b", name)

    def test_dispatcher_registers_the_native_command(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        self.assertIn("    owned-process-globals) ;;\n", dispatcher)
        self.assertIn(
            "run_in_chroot_cap_container bash /workspace/compat/x86_64/run_owned_process_globals.sh",
            dispatcher,
        )


if __name__ == "__main__":
    unittest.main()
