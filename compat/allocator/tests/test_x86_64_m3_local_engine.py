#!/usr/bin/env python3
"""Fail-closed checks for source-bound local primitive trace coverage."""

from __future__ import annotations

import copy
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("m3_x86_64", ROOT / "compat/allocator/m3_x86_64.py")
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


RETIREMENT_TRACE = """M3R start regular=ABC full= direct=A state=RRR bytes=0 pages=3
M3R retire-head regular=BC full= direct=B state=DRR bytes=0 pages=2
M3R reuse-tail regular=BCA full= direct=B state=RRR bytes=0 pages=3
M3R move-head regular=CBA full= direct=C state=RRR bytes=0 pages=3
M3R full-head regular=BA full=C direct=B state=RRF bytes=256 pages=3
M3R full-next regular=A full=CB direct=A state=RFF bytes=448 pages=3
M3R retire-last-regular regular= full=CB direct=- state=DFF bytes=448 pages=2
M3R reuse-from-full regular=C full=B direct=C state=DFR bytes=192 pages=2
M3R retire-full regular=C full= direct=C state=DDR bytes=0 pages=1
M3R retire-final regular= full= direct=- state=DDD bytes=0 pages=0
"""


class LocalPrimitiveTraceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = gate.load_contract()

    def read_trace(self, trace: str):
        with tempfile.TemporaryDirectory(prefix="m3-reader-", dir=ROOT / ".work") as directory:
            with mock.patch.object(gate, "ARTIFACT_ROOT", Path(directory)):
                with mock.patch.object(gate.run, "command_record", return_value={"status": 0, "stdout": trace, "stderr": ""}):
                    return gate.run_queue_retirement_differential(self.contract)

    def test_one_retirement_sequence_cannot_qualify_bin_and_free_list_parity(self) -> None:
        result = self.read_trace(RETIREMENT_TRACE)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("queue matrix did not execute bin" in item for item in result["unmet"]))
        self.assertTrue(any("free-list matrix did not execute every source mode" in item for item in result["unmet"]))

    def test_a_cache_snapshot_must_match_the_queue_and_unrelated_live_bin(self) -> None:
        trace = RETIREMENT_TRACE + (
            "M3B bin=4 size=32 seed=331572594510 step=0 action=init page=- regular= full= "
            f"direct={'A' * 129} state=DDD bytes=0 pages=1 sentinel=1\n"
        )
        result = self.read_trace(trace)
        self.assertTrue(any("owner/cache/transition invariant" in item for item in result["unmet"]))

    def test_a_free_list_cannot_own_an_allocated_block(self) -> None:
        trace = RETIREMENT_TRACE + "M3F size=32 stage=exhausted capacity=4 reserved=4 used=4 zero=0 free=0 local=-\n"
        result = self.read_trace(trace)
        self.assertTrue(any("initialized ownership/counts" in item for item in result["unmet"]))

    def test_green_local_checks_preserve_incomplete_prerequisites(self) -> None:
        checks = {check: {"status": "passed"} for component in self.contract["components"] for check in component["checks"]}
        checks["prerequisites"] = {"milestones": {}, "unmet": ["M1 and M2 receipts are absent"]}
        result = gate.evaluate_gate(self.contract, checks)
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(all(component["status"] == "complete" for component in result["components"]))

    def test_a_failed_required_check_cannot_be_hidden_by_omitting_its_component(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["components"] = [component for component in contract["components"] if component["id"] != "miri-execution"]
        checks = {check: {"status": "passed"} for component in self.contract["components"] for check in component["checks"]}
        checks["miri"] = {"status": "failed", "unmet": ["undefined behaviour"]}
        checks["prerequisites"] = {"milestones": {}, "unmet": []}
        with self.assertRaisesRegex(gate.GateError, "required checks.*miri"):
            gate.evaluate_gate(contract, checks)


class MiriWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="miri-storage-", dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Path(self.temporary.name)
        self.boundary = self.fixture / "checkout/.work/allocator-x86_64/tmp"
        self.boundary.mkdir(parents=True)
        self.external = self.fixture / "image-cache"
        self.capture = self.fixture / "storage-paths"
        binary = self.fixture / "bin"
        binary.mkdir()
        cargo = binary / "cargo"
        cargo.write_text('''#!/usr/bin/env python3
import os
import sys
from pathlib import Path

arguments = sys.argv[1:]
if arguments == ["miri", "--version"]:
    print("miri fixture")
    sys.exit(0)

def storage(value):
    if value == "/tmp" or value.startswith("/tmp/"):
        return Path(os.environ["MIRI_TEST_TMP_MOUNT"]) / value.removeprefix("/tmp").lstrip("/")
    if value in ("/image-cache", "/image-sysroot"):
        return Path(os.environ["MIRI_TEST_IMAGE_STORAGE"]) / value.lstrip("/")
    raise RuntimeError("unexpected simulated container storage path")

cache = storage(os.environ.get("MIRI_CACHE_DIR", "/image-cache"))
sysroot = storage(os.environ["MIRI_SYSROOT"]) if "MIRI_SYSROOT" in os.environ else cache / "miri"
for directory, marker in ((cache, "cache-write"), (sysroot, "sysroot-write")):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / marker).write_text("initialized")
    with Path(os.environ["MIRI_TEST_CAPTURE"]).open("a") as output:
        output.write(str(directory / marker) + "\\n")
if "--list" in arguments:
    print("fixture::allocation: test")
else:
    print("running 1 test")
    print("test fixture::allocation ... ok")
    print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out")
''')
        cargo.chmod(0o755)
        self.environment = {
            "PATH": f"{binary}:{os.environ['PATH']}",
            "MIRI_TEST_TMP_MOUNT": str(self.boundary),
            "MIRI_TEST_IMAGE_STORAGE": str(self.external),
            "MIRI_TEST_CAPTURE": str(self.capture),
            "MIRI_CACHE_DIR": "/image-cache",
        }
        self.contract = {"miri": {
            "target": "x86_64-unknown-linux-gnu",
            "miriflags": ["-Zmiri-strict-provenance"],
            "module_prefixes": ["fixture::"],
            "required_tests": ["fixture::allocation"],
        }}

    def execute(self, *, inherited_sysroot: bool) -> None:
        environment = dict(self.environment)
        if inherited_sysroot:
            environment["MIRI_CACHE_DIR"] = "/tmp/inherited-cache"
            environment["MIRI_SYSROOT"] = "/image-sysroot"
        with mock.patch.dict(os.environ, environment):
            with mock.patch.object(gate, "ARTIFACT_ROOT", self.boundary / "artifacts"):
                result = gate.run_miri(self.contract)
        self.assertEqual(result["status"], "passed", result)
        for path in self.capture.read_text().splitlines():
            self.assertTrue(Path(path).resolve().is_relative_to(self.boundary), path)

    def test_miri_cache_and_built_sysroot_use_the_checkout_tmp_mount(self) -> None:
        self.execute(inherited_sysroot=False)

    def test_an_inherited_sysroot_cannot_bypass_the_checkout_storage_boundary(self) -> None:
        self.execute(inherited_sysroot=True)


if __name__ == "__main__":
    unittest.main()
