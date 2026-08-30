#!/usr/bin/env python3
"""Focused contracts for the native x86 Linux-UAPI and header-closure lane."""

from __future__ import annotations

import stat
import subprocess
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = ROOT / "docker" / "Dockerfile.x86_64"
UPSTREAMS = ROOT / "compat" / "upstreams.toml"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"
UAPI_RUNNER = ROOT / "compat" / "x86_64" / "run_linux_5_10_uapi.sh"
CLOSURE_RUNNER = ROOT / "compat" / "x86_64" / "run_candidate_header_closure.sh"

LINUX_UAPI_SOURCE_SHA256 = (
    "dcdf99e43e98330d925016985bfbc7b83c66d367b714b2de0cbbfcbf83d8ca43"
)
LINUX_UAPI_HEADER_MANIFEST_SHA256 = (
    "00cdc98ceb35926f68dc57dc0d84a989a6df4f60f84b1ae5981b54bb1088eb0e"
)


class CandidateHeaderClosureTests(unittest.TestCase):
    def assert_valid_bash(self, path: Path) -> str:
        result = subprocess.run(
            ["bash", "-n", str(path)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)
        return path.read_text(encoding="utf-8")

    def test_linux_uapi_export_is_fixed_in_image_and_runtime_verifier(self) -> None:
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        verifier = self.assert_valid_bash(UAPI_RUNNER)
        with UPSTREAMS.open("rb") as stream:
            upstreams = tomllib.load(stream)

        self.assertEqual(
            upstreams["linux_5_10_uapi"],
            {
                "version": "5.10",
                "source": "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.10.tar.xz",
                "sha256": LINUX_UAPI_SOURCE_SHA256,
                "architecture": "x86_64",
                "headers_install_arch": "x86",
                "exported_header_count": 935,
                "exported_header_manifest_sha256": LINUX_UAPI_HEADER_MANIFEST_SHA256,
            },
        )

        for phrase in (
            "ARG LINUX_UAPI_VERSION=5.10",
            f"ARG LINUX_UAPI_SHA256={LINUX_UAPI_SOURCE_SHA256}",
            "ARG LINUX_UAPI_HEADER_COUNT=935",
            f"ARG LINUX_UAPI_HEADER_MANIFEST_SHA256={LINUX_UAPI_HEADER_MANIFEST_SHA256}",
            "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-${LINUX_UAPI_VERSION}.tar.xz",
            "make -C \"/tmp/linux-${LINUX_UAPI_VERSION}\" ARCH=x86 headers_install",
            "--http1.1 --continue-at - --retry 5",
            "sha256sum -c -",
        ):
            self.assertIn(phrase, dockerfile)
        self.assertNotIn("RUN --mount=", dockerfile)

        for phrase in (
            "readonly LINUX_UAPI_ROOT=/opt/linux-5.10-uapi",
            f"readonly LINUX_UAPI_SHA256={LINUX_UAPI_SOURCE_SHA256}",
            "readonly LINUX_UAPI_HEADER_COUNT=935",
            f"readonly LINUX_UAPI_HEADER_MANIFEST_SHA256={LINUX_UAPI_HEADER_MANIFEST_SHA256}",
            "header_manifest_sha256=${LINUX_UAPI_HEADER_MANIFEST_SHA256}",
            "sha256sum \"$HEADER_HASHES_PATH\"",
            "sha256sum -c \"$HEADER_HASHES_PATH\"",
        ):
            self.assertIn(phrase, verifier)

    def test_closure_runner_requires_raw_candidate_roots_and_live_full_matrix(self) -> None:
        runner = self.assert_valid_bash(CLOSURE_RUNNER)

        for phrase in (
            "readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "readonly CANDIDATE_CC=/usr/bin/gcc",
            "readonly EXPECTED_PINNED_PUBLIC_HEADER_COUNT=183",
            "readonly EXPECTED_CANDIDATE_PUBLIC_HEADER_COUNT=191",
            "readonly EXPECTED_CANDIDATE_ONLY_HEADER_COUNT=8",
            "readonly EXPECTED_PROFILE_COUNT=7",
            "readonly EXPECTED_RECORD_COUNT=1337",
            "readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)",
            "readonly -a ORACLE_NOT_APPLICABLE_ROWS=(aio.h:c11-strict aio.h:cxx17-strict)",
            "validate_profile_contract",
            "validate_oracle_not_applicable_contract",
            "profile count drifted",
            "profile list contains duplicate",
            "oracle-not-applicable row is duplicated",
            "oracle-not-applicable row uses unknown profile",
            "-nostdinc",
            "-nostdinc++",
            "-U_GNU_SOURCE",
            "run_linux_5_10_uapi.sh",
            "header_cxx_closure.cpp",
            "focused C++ header-closure probe failed",
            "focused C++ header-closure probe did not preprocess project $header",
            "candidate include trace reached pinned musl despite -nostdinc",
            "candidate include trace escaped project/builtin/Linux-5.10 roots",
            "-u GCC_SPECS",
            "grep -Fq 'aio_sigevent'",
            "grep -Fq 'incomplete type'",
            "reference-not-applicable",
            "expected exactly one $row record",
            "observed an undeclared row",
            "[ \"$record_count\" = \"$EXPECTED_RECORD_COUNT\" ]",
            "# schema=crabc.x86_64-candidate-header-closure/v3",
            "# candidate_isolation=-nostdinc for all profiles",
            "header\\tprofile\\tlanguage\\tscope\\tstatus",
            "# scope=empty-TU include closure only; not declaration/layout/linkage/runtime/installed-header/public-support parity",
            "x86 isolated C/C++ candidate header closure: INCOMPLETE",
            "exit 1",
        ):
            self.assertIn(phrase, runner)
        self.assertNotIn("EXPECTED_CXX_FAILURE", runner)
        self.assertNotIn("EXPECTED_REFERENCE_FAILURE", runner)
        self.assertNotIn("--report-only", runner)
        self.assertNotIn("--report-only", DISPATCHER.read_text(encoding="utf-8"))

    def test_dispatcher_exposes_a_pass_required_closure_command(self) -> None:
        dispatcher = self.assert_valid_bash(DISPATCHER)

        for phrase in (
            "linux-5-10-uapi)",
            "candidate-header-closure)",
            "run_linux_5_10_uapi()",
            "run_candidate_header_closure()",
            "run_linux_5_10_uapi",
            "run_candidate_header_closure",
            "linux-5-10-uapi takes no arguments",
            "candidate-header-closure takes no arguments",
        ):
            self.assertIn(phrase, dispatcher)


if __name__ == "__main__":
    unittest.main()
