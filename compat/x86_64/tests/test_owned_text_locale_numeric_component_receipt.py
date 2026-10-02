#!/usr/bin/env python3
"""Physical source and product binding for the text/locale/numeric receipt."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))

import owned_dynamic_qualification as qualification
import owned_text_locale_numeric_component_receipt as receipt


class OwnedTextLocaleNumericComponentReceiptTests(unittest.TestCase):
    def test_all_execution_modes_discard_ambient_locale_and_loader_environment(self) -> None:
        work = ROOT / ".work/text-environment-fixture"
        static = work / "static"
        dynamic = work / "dynamic"
        tools = {name: {"path": f"/usr/bin/{name}"}
                 for name in ("linker", "oracle", "static_driver", "dynamic_driver")}
        with mock.patch.object(receipt.providers, "compiler_path", return_value=Path("/usr/bin/gcc")), \
             mock.patch.object(receipt.providers.translation_contract, "hosted_translation_flags", return_value=()):
            plan = receipt.command_plan(ROOT, work, static, dynamic, tools)
        # Replace only the executable boundary, preserving the planned launch
        # environment. The observer stands in for the already linked consumer.
        observer = [sys.executable, "-c", "import json, os; print(json.dumps(dict(os.environ), sort_keys=True))"]
        ambient = {"PATH": "/usr/bin:/bin", "LC_ALL": "unsupported-locale", "LANG": "POSIX",
                   "TZ": "EST5EDT", "LC_CTYPE": "C.UTF-8", "LD_LIBRARY_PATH": "/ambient/provider",
                   "CRABC_TEXT_ENVIRONMENT_SENTINEL": "inherited"}
        expected = {"LC_ALL": "C", "LANG": "C", "TZ": "UTC"}
        for stem, command in plan.items():
            if not stem.endswith(("-run", "-kernel", "-direct")):
                continue
            with self.subTest(stem=stem):
                launch = next((index for index, item in enumerate(command)
                               if Path(item).name == "chroot"), len(command) - 1)
                result = subprocess.run([*command[:launch], *observer], env=ambient,
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                observed = json.loads(result.stdout)
                self.assertEqual(observed, expected)

    def test_rehashed_transplanted_product_source_cannot_reseal(self) -> None:
        (ROOT / ".work").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            checkout = Path(temporary)
            source = checkout / "compat/x86_64/source.c"
            source.parent.mkdir(parents=True)
            source.write_text("int selected_source;\n")
            static = checkout / ".work/products/static"
            dynamic = checkout / ".work/products/dynamic"
            static.mkdir(parents=True)
            dynamic.mkdir(parents=True)
            static_manifest = static / "manifest.json"
            dynamic_manifest = dynamic / "manifest.json"
            static_manifest.write_text("static\n")
            dynamic_manifest.write_text("dynamic\n")
            state_path = dynamic / "share/crabc/dynamic-product-state.json"
            state_path.parent.mkdir(parents=True)
            state = {"schema": "crabc.x86_64-owned-dynamic-materialization/v1",
                     "status": "materialized-unqualified", "source_sha256": "a" * 64}
            state_path.write_bytes(receipt.canonical(state))
            with mock.patch.object(receipt.contract, "direct_sources", return_value=(Path("compat/x86_64/source.c"),)), \
                 mock.patch.object(receipt.product_evidence, "_validate_static_product", return_value=(static_manifest, {})), \
                 mock.patch.object(receipt.product_evidence, "_validate_dynamic_product", return_value=(dynamic_manifest, {})), \
                 mock.patch.object(qualification, "ROOT", checkout), \
                 mock.patch.object(qualification, "source_digest", return_value="a" * 64):
                current = receipt.source_product_seal(checkout, static, dynamic)
                self.assertEqual(current["dynamic"]["tree"], receipt.family.snapshot(dynamic))

                state["source_sha256"] = "b" * 64
                state_path.write_bytes(receipt.canonical(state))
                current["dynamic"]["tree"] = receipt.family.snapshot(dynamic)
                work = checkout / ".work/report"
                work.mkdir()
                for phase in ("before", "after"):
                    seal = work / f"source-product-{phase}.json"
                    seal.write_bytes(receipt.canonical(current))
                    retained = json.loads(seal.read_text())
                    self.assertEqual(retained["dynamic"]["tree"]["share/crabc/dynamic-product-state.json"]["sha256"],
                                     receipt.digest(state_path))

                with self.assertRaisesRegex(receipt.ReceiptError, "dynamic product source differs"):
                    receipt.source_product_seal(checkout, static, dynamic)


if __name__ == "__main__":
    unittest.main()
