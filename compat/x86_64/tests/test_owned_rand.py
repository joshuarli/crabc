#!/usr/bin/env python3
"""Focused contracts for native owned rand/srand evidence and state."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "libc/src/c_abi/x86_64/owned_rand.rs"
MANIFEST = ROOT / "libc/Cargo.toml"
LOCK = ROOT / "Cargo.lock"
PROBE = ROOT / "compat/x86_64/owned_rand_probe.c"
HEADER_C = ROOT / "compat/x86_64/owned_rand_header_abi_probe.c"
HEADER_CXX = ROOT / "compat/x86_64/owned_rand_header_abi_probe.cpp"
RUNNER = ROOT / "compat/x86_64/run_owned_rand.sh"
DOCUMENT = ROOT / "compat/x86_64/owned-rand.md"
SYMBOLS = ("rand", "srand")


class OwnedRandContracts(unittest.TestCase):
    def invoke(self, arguments: tuple[str, ...], temporary: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(RUNNER), *arguments],
            cwd=ROOT,
            env={**os.environ, "TMPDIR": temporary},
            capture_output=True,
            text=True,
            check=False,
        )

    def test_target_gated_exact_dependency_graph_is_locked(self) -> None:
        manifest = MANIFEST.read_text(encoding="utf-8")
        self.assertIn('"dep:rand_pcg",', manifest)
        self.assertIn(
            'rand_pcg = { version = "=0.10.2", default-features = false, optional = true }',
            manifest,
        )
        target_start = manifest.index("[target.'cfg(all(target_os = \"linux\", target_arch = \"x86_64\"")
        self.assertGreater(manifest.index("rand_pcg", target_start), target_start)
        lock = tomllib.loads(LOCK.read_text(encoding="utf-8"))
        packages = {item["name"]: item for item in lock["package"]}
        self.assertEqual(
            (packages["rand_pcg"]["version"], packages["rand_pcg"]["checksum"]),
            ("0.10.2", "caa0f4137e1c0a72f4c651489402276c8e8e1cf081f3b0ba156d2cbeef09e86a"),
        )
        self.assertEqual(packages["rand_pcg"]["dependencies"], ["rand_core"])
        self.assertEqual(
            (packages["rand_core"]["version"], packages["rand_core"]["checksum"]),
            ("0.10.1", "63b8176103e19a2643978565ca18b50549f6101881c443590420e4dc998a3c69"),
        )
        self.assertNotIn("dependencies", packages["rand_core"])

    def test_module_owns_atomic_state_but_not_a_local_prng_core(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        for boundary in (
            "AtomicU64", "AtomicU64::new(0)", "seed.wrapping_sub(1)",
            "Ordering::Relaxed", "compare_exchange_weak", "Lcg64Xsh32::from_state(old, 0)",
            "generator.advance(1)", "generator.state()", "next >> 33",
            "83ac507f40f71ce90477290ca255dffb91e4256226616e46fa044ad1b136c24d",
            "racy concurrent schedules",
        ):
            self.assertIn(boundary, source)
        implementation = "\n".join(
            line for line in source.splitlines() if not line.lstrip().startswith("//")
        )
        for forbidden in (
            "6364136223846793005", "next_u32", "SeedableRng", "Lcg64Xsh32::new",
            "Mutex", "getrandom", "thread_local", "errno", "atfork", "alloc::",
        ):
            self.assertNotIn(forbidden, implementation)

    def test_probe_has_oracle_edges_and_candidate_only_transition_case(self) -> None:
        source = PROBE.read_text(encoding="utf-8")
        for boundary in (
            "constructor_default", "srand0-u32-prewiden", "long-13579bdf",
            "broader=64x128", "candidate-concurrency-transitions=", "serialized-workers=",
            "fork-prefix=", "errno-preserved=ok", "0x00000000U", "0xffffffffU",
            "PTHREAD_COND_INITIALIZER", "pthread_cond_broadcast",
        ):
            self.assertIn(boundary, source)
        broader = re.search(
            r"static const unsigned broader_seeds\[\] = \{(?P<body>.*?)\n    \};",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(broader)
        self.assertEqual(len(re.findall(r"0x[0-9a-f]+U", broader.group("body"))), 64)
        self.assertNotIn("6364136223846793005", source)

    def test_headers_check_c_and_cpp_abi(self) -> None:
        for header in (HEADER_C.read_text(encoding="utf-8"), HEADER_CXX.read_text(encoding="utf-8")):
            for boundary in ("RAND_MAX", "rand_signature", "srand_signature", "rand", "srand"):
                self.assertIn(boundary, header)
        self.assertIn("_Static_assert", HEADER_C.read_text(encoding="utf-8"))
        self.assertIn("static_assert", HEADER_CXX.read_text(encoding="utf-8"))

    def test_runner_rejects_raw_symlink_and_parent_components_before_normalization(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="rand-path-target.", dir=scratch) as target:
            link = scratch / "owned-rand-product-link"
            link.symlink_to(target, target_is_directory=True)
            detour = scratch / "owned-rand-parent-component"
            detour.mkdir()
            try:
                raw_parent = f"{detour}/../{Path(target).name}"
                for label, argument in (("symlink", str(link)), ("parent", raw_parent)):
                    with self.subTest(label=label), tempfile.TemporaryDirectory(
                        prefix="rand-parser.", dir=scratch
                    ) as temporary:
                        result = self.invoke((argument,), temporary)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(
                            "owned rand dynamic product must be a checkout .work directory",
                            result.stderr,
                        )
                        self.assertEqual(result.stdout, "")
                        self.assertEqual(list(Path(temporary).iterdir()), [])
            finally:
                link.unlink(missing_ok=True)
                detour.rmdir()

    def test_symbol_judge_counts_all_definitions_not_only_correct_ones(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        function_start = source.index("assert_symbols()")
        script_start = source.index("<<'PY'\n", function_start) + len("<<'PY'\n")
        script_end = source.index("\nPY\n}", script_start)
        for selector, suffix in (("nm", "T"), ("readelf", "FUNC")):
            descriptor, symbol_path = tempfile.mkstemp(
                prefix="owned-rand-symbols.", dir=ROOT / ".work/x86_64/tmp"
            )
            os.close(descriptor)
            symbols = Path(symbol_path)
            try:
                if selector == "nm":
                    text = "".join(f"00000000 T {name}\n" for name in SYMBOLS) + "00000000 W rand\n"
                else:
                    text = "".join(
                        f"  1: 00000000 0 FUNC GLOBAL DEFAULT 1 {name}\n" for name in SYMBOLS
                    ) + "  1: 00000000 0 FUNC WEAK DEFAULT 1 rand\n"
                symbols.write_text(text, encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, "-", str(symbols), selector, *SYMBOLS],
                    input=source[script_start:script_end],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0, suffix)
            finally:
                symbols.unlink(missing_ok=True)

    def test_runner_keeps_receipts_headers_and_racy_oracle_boundary_explicit(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for boundary in (
            "--expect-missing", "compile_header_witnesses oracle ''",
            'compile_header_witnesses source "$ROOT/include"',
            'compile_header_witnesses installed "$installed/usr/include"',
            "write_compile_receipt", "validate_sealed_link", "audit_static_provider_artifact",
            "run_static_concurrency", "run_dynamic_concurrency", "run_dso_shared_stream",
            "ORACLE_SCENARIOS=(core serialized-workers fork)",
            "candidate-concurrency", "rand-provider-rand.objdump", "application_dsos",
            "rand dependency escaped the selected fat-LTO CGU",
        ):
            self.assertIn(boundary, source)
        self.assertNotIn("candidate-concurrency oracle", source)

    def test_document_records_dependency_and_scope_limits(self) -> None:
        document = DOCUMENT.read_text(encoding="utf-8")
        for boundary in (
            "83ac507f40f71ce90477290ca255dffb91e4256226616e46fa044ad1b136c24d",
            "caa0f4137e1c0a72f4c651489402276c8e8e1cf081f3b0ba156d2cbeef09e86a",
            "63b8176103e19a2643978565ca18b50549f6101881c443590420e4dc998a3c69",
            "no_std", "fat LTO", "racy", "candidate-only", "pre-provider",
            "BSD `random`", "mimalloc", "AArch64", "no `rand` or\n`srand` definition",
        ):
            self.assertIn(boundary, document)


if __name__ == "__main__":
    unittest.main()
