#!/usr/bin/env python3
"""Focused contracts for the owned x86 wordexp installed-product slice."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "libc/src/c_abi/x86_64/owned_wordexp.rs"
SPAWN = ROOT / "libc/src/c_abi/x86_64/owned_spawn.rs"
SCANNER = ROOT / "libc/src/c_abi/x86_64/owned_wordexp_nocmd.rs"
PROBE = ROOT / "compat/x86_64/owned_wordexp_probe.c"
POSIX_PROBE = ROOT / "compat/x86_64/owned_wordexp_posix_probe.c"
RUNNER = ROOT / "compat/x86_64/run_libc_owned_wordexp.sh"
EVIDENCE = ROOT / "compat/x86_64/owned_wordexp_evidence.py"
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"


class OwnedWordexpContracts(unittest.TestCase):
    def test_probe_has_source_mode_and_allocation_lifecycle_boundaries(self) -> None:
        source = PROBE.read_text(encoding="utf-8")
        for boundary in (
            "WRDE_DOOFFS | WRDE_APPEND", "WRDE_REUSE", "WRDE_NOCMD",
            "WRDE_CMDSUB", "WRDE_BADCHAR", "WRDE_SYNTAX", "WRDE_UNDEF",
            "check_freed", "--shell-unavailable", "unavailable_shell_case",
            "--nocmd-source", "source_nocmd_case", "owned-wordexp-nocmd-source: PASS",
            "$((case $A in a) echo x ;; *) echo y ;; esac))",
            "errno = ERANGE", "errno != ERANGE", "owned-wordexp: PASS",
            "owned-wordexp-shell-unavailable: PASS",
            '#include "owned_wordexp_posix_probe.c"',
        ):
            self.assertIn(boundary, source)

    def test_posix_probe_captures_the_corrections_frames_and_unqualified_boundary(self) -> None:
        source = POSIX_PROBE.read_text(encoding="utf-8")
        for boundary in (
            "posix_quiet_case", "pipe(diagnostics)", "dup2", "read_count",
            "WRDE_SYNTAX", "ERANGE", "posix_nocmd_case", "${FOO}",
            "${X} ${Y}", "${UNSET_X-${UNSET_Y-default}}", "deeply_nested",
            "private lexical depth limit",
            "$(( ${UNSET_X-2} + ${UNSET_Y-3} ))", "\\\\${FOO}",
            "WORDEXP_NOCMD_MARKER", "WRDE_CMDSUB", "WRDE_BADCHAR",
            "posix_nocmd_escaped_brace_control_case",
            "posix_nocmd_arithmetic_command_control_case",
            "posix_nocmd_pattern_control_case",
            "posix_nocmd_arithmetic_delimiter_control_case",
            "posix_nocmd_continuation_command_control_case",
            "posix_nocmd_dollar_single_control_case",
            "posix_nocmd_comment_control_case", "# \\\"\\n",
            "posix_nocmd_positional_case", "${10}", "${#1}", "${#10}",
            "portable wordexp transcript",
            "posix_undef_source_observation", "non-qualifying fixed-source observation",
        ):
            self.assertIn(boundary, source)

    def test_module_uses_existing_spawn_and_stdio_ownership_seams(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        scanner = SCANNER.read_text(encoding="utf-8")
        self.assertIn("pinned musl 1.2.6", source)
        self.assertIn("owned_spawn::spawn", source)
        self.assertIn("stdio_standard::fdopen", source)
        self.assertIn("stdio_standard::getdelim", source)
        self.assertIn("stdio_standard::fclose", source)
        self.assertIn('include!("owned_wordexp_nocmd.rs")', source)
        self.assertNotIn('include!("../../wordexp_nocmd.rs")', source)
        self.assertNotIn("sys_fork", source)
        self.assertNotIn("sys_execve", source)
        self.assertIn("WORDEXP_QUIET_SCRIPT", source)
        self.assertIn("exec 2>/dev/null;", source)
        self.assertIn("show_errors", source)
        self.assertIn("018c97c999cb60966a0376b71f2c8c187179ef31cf5ddde47b959e8f440e08f8", source)
        self.assertIn("wordexp_nocmd_check", scanner)
        self.assertIn("NocmdFrames", scanner)
        self.assertIn("FRAME_PARAMETER", scanner)
        self.assertIn("FRAME_ARITHMETIC", scanner)
        self.assertIn("PARAM_PATTERN", scanner)
        self.assertIn("QUOTE_DOLLAR_SINGLE", scanner)
        self.assertIn("shell_word_start", scanner)
        self.assertIn("comment_has_physical_newline", scanner)
        self.assertIn("NAME_POSITIONAL", scanner)
        self.assertIn("positional_parameter", scanner)
        self.assertIn("logical_next", scanner)
        self.assertIn("skip_line_continuations", scanner)
        self.assertIn("cabi_realloc", scanner)
        self.assertIn("WRDE_NOSPACE", scanner)
        self.assertIn("next == b'{'", scanner)
        self.assertNotIn("escaped_braces", scanner)
        self.assertNotIn("parameter_braces", scanner)
        self.assertNotIn("../../wordexp_nocmd.rs", scanner)
        self.assertIn("if result == WRDE_NOSPACE", source)

    def test_child_spawn_failure_preserves_the_missing_sentinel_result(self) -> None:
        module = MODULE.read_text(encoding="utf-8")
        spawn = SPAWN.read_text(encoding="utf-8")
        self.assertIn("spawn_with_outcome", module)
        self.assertIn("SpawnOutcome::ChildFailure", module)
        self.assertIn("return WRDE_SYNTAX", module)
        self.assertIn("errno_before_spawn", module)
        self.assertIn("pub(super) enum SpawnOutcome", spawn)
        self.assertIn("ParentFailure", spawn)
        self.assertIn("ChildFailure", spawn)
        self.assertIn("pub(super) unsafe fn spawn(", spawn)

    def test_runner_preserves_default_boundary_and_proves_both_installed_modes(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for boundary in (
            "frozen default archive unexpectedly exports",
            "--features x86-owned-static-runtime", "-static-pie",
            "pinned-musl wordexp oracle is not static ET_EXEC",
            "TMPDIR physically escapes checkout .work",
            "retained failure evidence", "run_installed_mode -static et-exec",
            "run_installed_mode -static-pie static-pie",
            "make_private_shell_root", "missing inaccessible invalid",
            "audit_linker_trace", "runtime allowlist or exact application-object receipt drifted",
            "chroot_command", "controlled-shell.sha256", "run_same_object_wordexp_cases",
            "same-object-wordexp", "workload.sha256", "--nocmd-source", "--posix-quiet",
            "--posix-nocmd", "--undef-source-observation", "SOURCE-RED",
            "POSIX_PROBE", "FOO=field X=left Y=right", ".status",
            "SET=1", "mknod", "character device 1:3 mode 666",
            "--posix-nocmd-escaped-control", "--posix-nocmd-dollar-single-control",
            "--posix-nocmd-comment-control", "--posix-nocmd-positional",
            "local audit_root=\"$(dirname \"$candidate\")\"",
        ):
            self.assertIn(boundary, source)
        self.assertNotIn("--wrap=", source)
        self.assertNotIn('env -i CRABC_WORDEXP=\'bar baz\' "$candidate"', source)

    def test_retained_six_mode_evidence_keeps_source_reds_separate_from_positive_cells(self) -> None:
        source = EVIDENCE.read_text(encoding="utf-8")
        for boundary in (
            'crabc.x86_64-owned-wordexp-products/v3', "POSIX_PROBE",
            "WORD_EXP_CASES", "CELL_ENVIRONMENT", "posix-quiet-source-red",
            "posix-nocmd-source-red", "posix-nocmd-arithmetic-source-red",
            "posix-nocmd-continuation-source-red", "posix-nocmd-dollar-single-source-red",
            "posix-nocmd-comment-source-red", "posix-nocmd-positional-source-red",
            "fixture_devices", "char-device", "_null_device_identity", "undef-source-observation",
            "_assert_case_results", "required=False", "SOURCE-RED diagnostic-present",
            "SOURCE-RED parameter-brace-rejected", "SOURCE-RED positional-parameter-rejected",
            "installed header trace omitted the POSIX correction cells",
        ):
            self.assertIn(boundary, source)

    def test_dispatcher_exposes_the_dedicated_native_gate(self) -> None:
        source = DISPATCHER.read_text(encoding="utf-8")
        self.assertIn("libc-owned-wordexp", source)
        self.assertIn("run_libc_owned_wordexp.sh", source)
        self.assertIn("run_in_chroot_cap_container bash /workspace/compat/x86_64/run_libc_owned_wordexp.sh", source)


if __name__ == "__main__":
    unittest.main()
