"""Behavior tests for the non-promoting `libc.c-abi-compat` family coordinator."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_c_abi_compat_family as family  # noqa: E402
import owned_c_abi_compat_family_cohort as cohort  # noqa: E402
import owned_posix_family_execution as execution  # noqa: E402


SOURCE = {"revision": "r" * 40, "content_sha256": "c" * 64}
MOUNT = "/workspace"


class RosterTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".work").mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="c-abi-family-roster.", dir=ROOT / ".work"))
        self.addCleanup(shutil.rmtree, self.root)

    def _fake_root(self, roster: str, slices: str) -> Path:
        (self.root / "compat/x86_64").mkdir(parents=True)
        (self.root / "compat/x86_64/run_owned_alpha.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (self.root / "compat/x86_64/run_owned_libc_test.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (self.root / family.ROSTER).write_text(
            f'schema = "{family.ROSTER_SCHEMA}"\nfamily = "{family.FAMILY}"\n' + roster, encoding="utf-8")
        (self.root / family.LEDGER).write_text(
            '[[family]]\nid = "libc.c-abi-compat"\ncapabilities = ["one.cap", "two.cap"]\n' + slices,
            encoding="utf-8")
        return self.root

    ALPHA = ('[[component]]\nid = "alpha"\ncommand = "owned-alpha"\n'
             'runner = "compat/x86_64/run_owned_alpha.sh"\nproducts = "static-and-dynamic"\n'
             'reader = "runner"\ncapabilities = ["one.cap"]\n')
    LIBC_TEST = ('[[component]]\nid = "libc-test"\nrunner = "compat/x86_64/run_owned_libc_test.sh"\n'
                 'products = "dynamic"\nreader = "libc-test"\n'
                 '[[libc_test_unit]]\nid = "functional/two"\ncapabilities = ["two.cap"]\n')
    SLICE = ('[[family.verified_slice]]\nid = "one"\ncapabilities = ["one.cap"]\n'
             'native_evidence = [{ state = "verified", command = "./scripts/dev-x86_64.sh libc-one", scope = "s" },'
             ' { state = "verified", command = "./scripts/dev-x86_64.sh owned-alpha", scope = "s" }]\n')

    def test_checkout_roster_binds_every_family_capability_to_cited_components(self) -> None:
        roster = family.load_roster(ROOT)
        frozen = family.frozen_capabilities(ROOT, roster.capabilities)

        self.assertEqual(set(frozen), set(roster.capabilities))
        for capability in roster.capabilities:
            self.assertTrue(any(capability in component.capabilities for component in roster.components),
                            capability)
        cited = family._slice_commands(family._ledger_family(ROOT))
        commands = {component.command: component for component in roster.components if component.command}
        self.assertEqual(set(cited), set(commands))
        for command, capabilities in cited.items():
            self.assertEqual(set(commands[command].capabilities), capabilities, command)

    def test_roster_accepts_a_joined_ledger_row_and_derives_libc_test_credit(self) -> None:
        root = self._fake_root(self.ALPHA + self.LIBC_TEST, self.SLICE)
        roster = family.load_roster(root)
        self.assertEqual(roster.component("libc-test").capabilities, ("two.cap",))
        self.assertEqual(roster.component("alpha").capabilities, ("one.cap",))

    def test_roster_rejects_an_uncited_or_missing_component_and_an_uncovered_capability(self) -> None:
        cases = {
            "is not a c-abi-compat component": (
                self.LIBC_TEST.replace('"two.cap"', '"one.cap", "two.cap"'), self.SLICE),
            "omits slice capabilities": (
                self.ALPHA + self.LIBC_TEST,
                self.SLICE.replace('capabilities = ["one.cap"]', 'capabilities = ["one.cap", "two.cap"]')),
            "no slice cites": (
                self.ALPHA.replace('["one.cap"]', '["one.cap", "two.cap"]') + self.LIBC_TEST, self.SLICE),
            "has no component": (self.ALPHA + self.LIBC_TEST.replace('"two.cap"', '"one.cap"'), self.SLICE),
            "foreign capability": (self.ALPHA.replace('"one.cap"', '"one.cap", "other.cap"') + self.LIBC_TEST,
                                   self.SLICE),
        }
        for message, (roster, slices) in cases.items():
            with self.subTest(message=message):
                shutil.rmtree(self.root)
                self.root.mkdir()
                with self.assertRaisesRegex(family.CAbiCompatFamilyError, message):
                    family.load_roster(self._fake_root(roster, slices))


class ComponentTests(unittest.TestCase):
    """Replay retained runner evidence written in the dispatcher's layout."""

    def setUp(self) -> None:
        (ROOT / ".work/x86_64").mkdir(parents=True, exist_ok=True)
        self.base = Path(tempfile.mkdtemp(prefix="c-abi-family-test.", dir=ROOT / ".work/x86_64"))
        self.addCleanup(shutil.rmtree, self.base)
        self.work = self.base / "run"
        (self.work / "runs").mkdir(parents=True)
        self.products = {}
        for label in ("primary", "reproduction", "extracted"):
            self.products[label] = {}
            for kind in ("static", "dynamic"):
                path = self.base / "products" / label / kind
                (path / "share/crabc").mkdir(parents=True)
                (path / "share/crabc/manifest.json").write_text(f'{{"{label}": "{kind}"}}\n', encoding="utf-8")
                self.products[label][kind] = {
                    "path": path.relative_to(ROOT).as_posix(),
                    "manifest": cohort.canonical._file_identity(ROOT, path / "share/crabc/manifest.json", "m"),
                }
        self.roster = family.load_roster(ROOT)

    def _host(self, label: str, kind: str) -> Path:
        return ROOT / self.products[label][kind]["path"]

    def _mounted(self, path: Path) -> str:
        return MOUNT + "/" + path.relative_to(ROOT).as_posix()

    def _step(self, component: family.Component, *, status: int = 0, stderr: str = "",
              links: dict[str, Path] | None = None) -> Path:
        step = self.work / "runs" / component.identifier
        leaf = step / "tmp" / f"{component.identifier}.XXXX"
        leaf.mkdir(parents=True)
        (leaf / "raw.stdout").write_text("ok\n", encoding="utf-8")
        for linkage, product in (links or {}).items():
            manifest = product / "share/crabc/manifest.json"
            (leaf / f"{linkage}.link-identity.json").write_text(json.dumps({
                "linkage": linkage, "product": self._mounted(product),
                "product_manifest_sha256": execution.digest(manifest),
            }), encoding="utf-8")
        command = family.component_command(ROOT, component, self.products, MOUNT)
        (step / "invocation.json").write_text(json.dumps(
            execution.invocation(Path(MOUNT), command, execution.case_environment(ROOT, step, MOUNT))),
            encoding="utf-8")
        (step / "stdout").write_text(f"{component.identifier} evidence: {self._mounted(leaf)}\n", encoding="utf-8")
        (step / "stderr").write_text(stderr, encoding="utf-8")
        (step / "status").write_text(f"{status}\n", encoding="ascii")
        return step

    def _result(self, component: family.Component) -> dict[str, object]:
        return family.component_result(ROOT, self.work, component, self.products, MOUNT, self.roster, {})

    def _all_linkages(self) -> dict[str, Path]:
        return {"static": self._host("primary", "static"), "static-pie": self._host("primary", "static"),
                "pie": self._host("primary", "dynamic"), "non-pie": self._host("primary", "dynamic")}

    def test_passing_runner_on_the_primary_pair_is_admitted_and_bound(self) -> None:
        component = self.roster.component("c-abi-compat")
        self._step(component, links=self._all_linkages())

        result = self._result(component)

        self.assertTrue(result["admitted"], result.get("gap"))
        self.assertEqual(result["cohort_binding"]["products"]["static"], self.products["primary"]["static"])
        self.assertEqual(result["cohort_binding"]["products"]["dynamic"], self.products["primary"]["dynamic"])
        self.assertEqual(result["artifacts"]["entries"], 5)

    def test_failed_runner_is_a_named_gap_with_its_raw_condition(self) -> None:
        component = self.roster.component("native-allocator-policy")
        self._step(component, status=1, stderr="allocator_backend is 'accepted-c', not native-shadow\n")

        result = self._result(component)

        self.assertFalse(result["admitted"])
        self.assertEqual(result["gap"]["reason"], "component-run-failed")
        self.assertEqual(result["gap"]["status"], 1)
        self.assertIn("not native-shadow", result["gap"]["stderr_tail"][-1])

    def test_evidence_naming_another_cohort_pair_is_rejected(self) -> None:
        component = self.roster.component("fmtmsg")
        links = self._all_linkages()
        links["non-pie"] = self._host("reproduction", "dynamic")
        self._step(component, links=links)

        result = self._result(component)

        self.assertFalse(result["admitted"])
        self.assertEqual(result["gap"]["reason"], "component-evidence-rejected")
        self.assertIn("not the cohort's primary dynamic product", result["gap"]["detail"])

    def test_link_identities_must_cover_every_scoped_mode(self) -> None:
        component = self.roster.component("process-globals")
        links = self._all_linkages()
        del links["static-pie"]
        self._step(component, links=links)

        result = self._result(component)

        self.assertFalse(result["admitted"])
        self.assertIn("do not cover its product modes", result["gap"]["detail"])

    def test_changed_invocation_or_undeclared_scratch_is_rejected(self) -> None:
        component = self.roster.component("error-reporting")
        step = self._step(component)
        (step / "tmp" / "stray").mkdir()
        self.assertIn("undeclared", self._result(component)["gap"]["detail"])

        shutil.rmtree(step / "tmp" / "stray")
        invocation = json.loads((step / "invocation.json").read_text(encoding="utf-8"))
        invocation["command"].append("--extra")
        (step / "invocation.json").write_text(json.dumps(invocation), encoding="utf-8")
        self.assertIn("invocation differs", self._result(component)["gap"]["detail"])

    def test_component_that_never_ran_is_a_gap(self) -> None:
        result = self._result(self.roster.component("differential"))
        self.assertEqual(result["gap"], {"component": "differential", "reason": "component-not-run"})

    def _complete_run(self) -> Path:
        preparation = self.base / "preparation.json"
        qualification = self.base / "qualification.json"
        for path in (preparation, qualification):
            path.write_text("{}\n", encoding="utf-8")
        execution.static_products.write_new(self.work / "request.json", {
            "schema": family.REQUEST_SCHEMA, "source_mount": MOUNT,
            "static_preparation": preparation.relative_to(ROOT).as_posix(),
            "dynamic_qualification": qualification.relative_to(ROOT).as_posix(),
        })
        seal = family._product_seal(ROOT, self.products)
        for phase in ("before", "after"):
            execution.static_products.write_new(self.work / f"source-{phase}.json", SOURCE)
            execution.static_products.write_new(self.work / f"product-{phase}.json", seal)
        for component in self.roster.components:
            links = self._all_linkages() if component.products == "static-and-dynamic" else {}
            if component.reader != "runner":
                links = {}
            if component.reader == "libc-test":
                step = self._step(component)
                leaf = next((step / "tmp").iterdir())
                renamed = leaf.with_name("owned-libc-test.XXXX")
                leaf.rename(renamed)
                (step / "stdout").write_text(self._mounted(renamed) + "\n", encoding="utf-8")
            else:
                step = self._step(component, links=links)
            execution.static_products.write_new(step / "receipt.json", self._result(component))
        return self.work

    def _patched(self):
        source = {**SOURCE, "static_preparation": {}, "dynamic_qualification": {}}
        return (
            mock.patch.object(cohort, "canonical_products", return_value=(source, self.products)),
            mock.patch.object(execution.static_products, "source_identity", return_value=SOURCE),
            mock.patch.dict(family.READERS, {kind: (lambda **_: {"replayed": True}) for kind in family.READER_KINDS}),
        )

    def test_complete_run_reconstructs_and_rejects_a_changed_receipt(self) -> None:
        patches = self._patched()
        with patches[0], patches[1], patches[2]:
            work = self._complete_run()
            assessment = family.collect(ROOT, work)
            self.assertTrue(assessment["family_complete"], assessment["gaps"])
            self.assertFalse(assessment["promotion_ready"])
            self.assertFalse(assessment["public_support"])
            self.assertTrue(all(record["admitted"] for record in assessment["capabilities"].values()))

            receipt = work / "runs/fmtmsg/receipt.json"
            value = json.loads(receipt.read_text(encoding="utf-8"))
            value["admitted"] = False
            receipt.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(family.CAbiCompatFamilyError, "receipt changed: fmtmsg"):
                family.collect(ROOT, work)

    def test_one_gap_leaves_its_capabilities_and_the_family_unadmitted(self) -> None:
        patches = self._patched()
        with patches[0], patches[1], patches[2]:
            work = self._complete_run()
            (work / "runs/allocator-override/status").write_text("1\n", encoding="ascii")
            (work / "runs/allocator-override/receipt.json").unlink()
            execution.static_products.write_new(
                work / "runs/allocator-override/receipt.json",
                self._result(self.roster.component("allocator-override")))
            assessment = family.collect(ROOT, work)

        self.assertFalse(assessment["family_complete"])
        self.assertEqual([gap["component"] for gap in assessment["gaps"]], ["allocator-override"])
        self.assertFalse(assessment["capabilities"]["memory.allocator-basic"]["admitted"])
        self.assertTrue(assessment["capabilities"]["search.hash-table"]["admitted"])

    def test_admission_facts_accept_only_a_complete_current_assessment(self) -> None:
        patches = self._patched()
        with patches[0], patches[1], patches[2]:
            work = self._complete_run()
            assessment = family.collect(ROOT, work)
        preparation, qualification = (self.base / "preparation.json", self.base / "qualification.json")
        assessment["cohort"]["source"] = {
            **SOURCE,
            "static_preparation": cohort.canonical._file_identity(ROOT, preparation, "p"),
            "dynamic_qualification": cohort.canonical._file_identity(ROOT, qualification, "q"),
        }
        path = work / "assessment.json"
        path.write_text(json.dumps(assessment), encoding="utf-8")

        with patches[1]:
            facts = family.admission_facts(ROOT, path.relative_to(ROOT))
            self.assertEqual(facts["source"], SOURCE)
            self.assertEqual(facts["static_preparation"]["path"], preparation.relative_to(ROOT).as_posix())

            mutations = {
                "completion boundary": lambda value: value.update(family_complete=False),
                "component admission": lambda value: value["components"]["fmtmsg"].update(admitted=False),
                "capability admission": lambda value: value["capabilities"].pop("process.globals"),
                "contract changed": lambda value: value["contract"].update(sha256="0" * 64),
            }
            for message, mutate in mutations.items():
                changed = json.loads(json.dumps(assessment))
                mutate(changed)
                path.write_text(json.dumps(changed), encoding="utf-8")
                with self.subTest(message=message):
                    with self.assertRaisesRegex(family.CAbiCompatFamilyError, message):
                        family.admission_facts(ROOT, path.relative_to(ROOT))
            path.write_text(json.dumps(assessment), encoding="utf-8")
            qualification.write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(family.CAbiCompatFamilyError, "dynamic_qualification receipt changed"):
                family.admission_facts(ROOT, path.relative_to(ROOT))
        with mock.patch.object(execution.static_products, "source_identity",
                               return_value={**SOURCE, "revision": "o" * 40}):
            with self.assertRaisesRegex(family.CAbiCompatFamilyError, "not bound to current source"):
                family.admission_facts(ROOT, path.relative_to(ROOT))


class DispatchTests(unittest.TestCase):
    """Observe the dispatcher's translated, network-isolated family invocation."""

    def test_family_command_translates_receipts_and_runs_without_network(self) -> None:
        import os
        import subprocess

        (ROOT / ".work/x86_64/tmp").mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64/tmp") as temporary:
            work = Path(temporary)
            state = work / "state"
            state.mkdir()
            capture, docker = work / "docker.jsonl", work / "docker"
            docker.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "if sys.argv[1:3] == ['image', 'inspect']: print('linux/amd64')\n"
                "elif sys.argv[1] == 'run':\n"
                "    with open(os.environ['DISPATCH_CAPTURE'], 'a') as output: output.write(json.dumps(sys.argv[1:])+'\\n')\n"
                "else: raise SystemExit('unexpected Docker operation')\n")
            docker.chmod(0o755)
            preparation, qualification = state / "preparation.json", state / "qualification.json"
            for path in (preparation, qualification):
                path.write_text("{}\n", encoding="utf-8")
            environment = {**os.environ, "PATH": f"{work}{os.pathsep}{os.environ['PATH']}",
                           "DISPATCH_CAPTURE": str(capture), "CRABC_X86_64_WORK_DIR": str(state)}
            command = ["bash", str(ROOT / "scripts/dev-x86_64.sh"), "owned-c-abi-compat-family"]
            arguments = ["--static-preparation", str(preparation), "--dynamic-qualification", str(qualification),
                         "--output", str(state / "family")]

            for invalid in (arguments[:4], arguments + ["--output", str(state / "other")],
                            arguments[:-1] + [str(preparation)]):
                result = subprocess.run(command + invalid, cwd=ROOT, env=environment, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, invalid)
            self.assertFalse(capture.exists(), "malformed arguments must fail before any container")

            result = subprocess.run(command + arguments, cwd=ROOT, env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            (invocation,) = [json.loads(line) for line in capture.read_text().splitlines()]
            self.assertIn("--network=none", invocation)
            self.assertIn("--cap-add=SYS_CHROOT", invocation)
            program = invocation.index("/workspace/compat/x86_64/owned_c_abi_compat_family.py")
            self.assertEqual(invocation[program + 1:], [
                "run", "--static-preparation", "/workspace/.work/x86_64/preparation.json",
                "--dynamic-qualification", "/workspace/.work/x86_64/qualification.json",
                "--output", "/workspace/.work/x86_64/family",
            ])


if __name__ == "__main__":
    unittest.main()
