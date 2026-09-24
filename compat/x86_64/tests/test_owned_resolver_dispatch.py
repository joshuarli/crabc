#!/usr/bin/env python3
"""Observe the native resolver build and network-isolation boundary."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class OwnedResolverDispatchTests(unittest.TestCase):
    def test_cancellation_prepares_before_isolation_and_reuses_supplied_product(self):
        scratch = ROOT / '.work/x86_64/tmp'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            capture = work / 'docker.jsonl'
            docker = work / 'docker'
            docker.write_text(
                f'#!{sys.executable}\n'
                'import json, os, sys\n'
                "if sys.argv[1:3] == ['image', 'inspect']: print('linux/amd64')\n"
                "elif sys.argv[1] == 'run':\n"
                "    with open(os.environ['DISPATCH_CAPTURE'], 'a') as output: output.write(json.dumps(sys.argv[1:])+'\\n')\n"
                "else: raise SystemExit('unexpected Docker operation')\n")
            docker.chmod(0o755)
            environment = {**os.environ, 'PATH': f"{work}{os.pathsep}{os.environ['PATH']}",
                           'DISPATCH_CAPTURE': str(capture), 'CRABC_X86_64_WORK_DIR': str(work / 'state')}
            command = ['bash', str(ROOT / 'scripts/dev-x86_64.sh'), 'owned-resolver-cancellation']
            result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            prepare, execute = [json.loads(line) for line in capture.read_text().splitlines()]
            leaf = '/workspace/compat/x86_64/run_owned_resolver_cancellation.sh'
            self.assertNotIn('--network', prepare)
            self.assertEqual(prepare[prepare.index(leaf)+1], '--prepare')
            self.assertEqual(execute[execute.index('--network')+1], 'none')
            self.assertIn('--cap-add=SYS_CHROOT', execute)
            self.assertEqual(execute[execute.index(leaf)+1], '--prepared')
            self.assertEqual(prepare[-1], execute[-1])
            supplied = '/workspace/.work/x86_64/preexisting-dynamic-product'
            result = subprocess.run(command+[supplied], cwd=ROOT, env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            invocations = [json.loads(line) for line in capture.read_text().splitlines()]
            self.assertEqual(len(invocations), 3, 'supplied products must not trigger a replacement build')
            self.assertEqual(invocations[-1][-2:], [leaf, supplied])
            self.assertEqual(invocations[-1][invocations[-1].index('--network')+1], 'none')

    def test_products_are_built_before_network_isolated_execution(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            capture = work / "docker.jsonl"
            docker = work / "docker"
            docker.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "if sys.argv[1:3] == ['image', 'inspect']:\n"
                "    print('linux/amd64')\n"
                "elif sys.argv[1] == 'run':\n"
                "    with open(os.environ['DISPATCH_CAPTURE'], 'a') as output:\n"
                "        output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                "else:\n"
                "    raise SystemExit('unexpected Docker operation')\n"
            )
            docker.chmod(0o755)
            environment = dict(os.environ)
            environment.update(
                PATH=f"{work}{os.pathsep}{os.environ['PATH']}",
                DISPATCH_CAPTURE=str(capture),
                CRABC_X86_64_WORK_DIR=str(work / "state"),
            )
            command = ["bash", str(ROOT / "scripts/dev-x86_64.sh"), "owned-resolver-network"]
            invalid = subprocess.run(command + ["unexpected"], cwd=ROOT,
                                     env=environment, capture_output=True, text=True)
            self.assertEqual(invalid.returncode, 2)
            self.assertFalse(capture.exists())
            result = subprocess.run(command, cwd=ROOT, env=environment,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr[:300])
            prepare, execute = [json.loads(line) for line in capture.read_text().splitlines()]
            self.assertNotIn("--network", prepare)
            self.assertNotIn("--cap-add=SYS_CHROOT", prepare)
            self.assertIn("/workspace/compat/resolver-network/prepare_x86_64.py", prepare)
            products = prepare[prepare.index("--output") + 1]
            self.assertTrue(products.startswith("/workspace/.work/x86_64/tmp/owned-resolver-network."))
            self.assertTrue(products.endswith("/products"))
            self.assertEqual(execute[execute.index("--network") + 1], "none")
            self.assertIn("--cap-add=SYS_CHROOT", execute)
            self.assertNotIn("--cap-add=SYS_ADMIN", execute)
            self.assertNotIn("--privileged", execute)
            self.assertIn("/workspace/compat/resolver-network/run_x86_64.py", execute)
            self.assertEqual(execute[execute.index("--static-sysroot") + 1], products + "/static-sysroot")
            self.assertEqual(execute[execute.index("--dynamic-sysroot") + 1], products + "/dynamic-sysroot")
            self.assertEqual(execute[execute.index("--extracted-static-sysroot") + 1], products + "/static-extraction/crabc-x86_64-owned-static-sysroot")
            self.assertEqual(execute[execute.index("--extracted-dynamic-sysroot") + 1], products + "/dynamic-extraction")
            self.assertEqual(execute[execute.index("--work-root") + 1], str(Path(products).parent / "execution"))
            for invocation in (prepare, execute):
                self.assertIn("TMPDIR=/workspace/.work/x86_64/tmp", invocation)

    def test_protocol_database_uses_only_six_supplied_products_and_a_private_receipt_workdir(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            capture = work / "docker.jsonl"
            docker = work / "docker"
            docker.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "if sys.argv[1:3] == ['image', 'inspect']:\n"
                "    print('linux/amd64')\n"
                "elif sys.argv[1] == 'run':\n"
                "    with open(os.environ['DISPATCH_CAPTURE'], 'a') as output:\n"
                "        output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                "else:\n"
                "    raise SystemExit('unexpected Docker operation')\n"
            )
            docker.chmod(0o755)
            state = work / "state"
            roots = {name: state / "products" / name for name in (
                "installed-static", "installed-dynamic", "reproduction-static",
                "reproduction-dynamic", "extracted-static", "extracted-dynamic",
            )}
            for root in roots.values():
                root.mkdir(parents=True)
            environment = {
                **os.environ,
                "PATH": f"{work}{os.pathsep}{os.environ['PATH']}",
                "DISPATCH_CAPTURE": str(capture),
                "CRABC_X86_64_WORK_DIR": str(state),
            }
            command = ["bash", str(ROOT / "scripts/dev-x86_64.sh"), "owned-protocol-database"]
            arguments = [
                "--installed-static-sysroot", str(roots["installed-static"]),
                "--installed-dynamic-sysroot", str(roots["installed-dynamic"]),
                "--reproduction-static-sysroot", str(roots["reproduction-static"]),
                "--reproduction-dynamic-sysroot", str(roots["reproduction-dynamic"]),
                "--extracted-static-sysroot", str(roots["extracted-static"]),
                "--extracted-dynamic-sysroot", str(roots["extracted-dynamic"]),
            ]
            invalid = subprocess.run(command + arguments[:-1], cwd=ROOT,
                                     env=environment, capture_output=True, text=True)
            self.assertEqual(invalid.returncode, 2)
            self.assertFalse(capture.exists())
            result = subprocess.run(command + arguments, cwd=ROOT,
                                    env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr[:300])
            invocation = json.loads(capture.read_text().strip())
            self.assertEqual(invocation[invocation.index("--network") + 1], "none")
            self.assertIn("--cap-add=SYS_CHROOT", invocation)
            self.assertNotIn("--cap-add=SYS_ADMIN", invocation)
            self.assertNotIn("--privileged", invocation)
            self.assertIn("/workspace/compat/x86_64/owned_protocol_database.py", invocation)
            workdir = invocation[invocation.index("--work") + 1]
            self.assertTrue(workdir.startswith("/workspace/.work/x86_64/tmp/owned-protocol-database."))
            expected = {
                "--installed-static-sysroot": "/workspace/.work/x86_64/products/installed-static",
                "--installed-dynamic-sysroot": "/workspace/.work/x86_64/products/installed-dynamic",
                "--reproduction-static-sysroot": "/workspace/.work/x86_64/products/reproduction-static",
                "--reproduction-dynamic-sysroot": "/workspace/.work/x86_64/products/reproduction-dynamic",
                "--extracted-static-sysroot": "/workspace/.work/x86_64/products/extracted-static",
                "--extracted-dynamic-sysroot": "/workspace/.work/x86_64/products/extracted-dynamic",
            }
            for option, product in expected.items():
                self.assertEqual(invocation[invocation.index(option) + 1], product)
            self.assertIn("TMPDIR=/workspace/.work/x86_64/tmp", invocation)

    def test_family_runs_every_component_against_the_planned_cohort(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            capture = work / "docker.jsonl"
            docker = work / "docker"
            # The fake engine records each container and materializes only the
            # two outputs later dispatcher steps read on the host: the plan and
            # the base inventory report named by the ELF-fact collector.
            docker.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                f"sys.path.insert(0, {str(ROOT / 'compat/x86_64')!r})\n"
                "from pathlib import Path\n"
                "import owned_resolver_family as family\n"
                "argv = sys.argv[1:]\n"
                "if argv[:2] == ['image', 'inspect']:\n"
                "    print('sha256:' + 'a' * 64 if '{{.Id}}' in argv else 'linux/amd64')\n"
                "    raise SystemExit(0)\n"
                "if argv[0] != 'run': raise SystemExit('unexpected Docker operation')\n"
                "with open(os.environ['DISPATCH_CAPTURE'], 'a') as output: output.write(json.dumps(argv) + '\\n')\n"
                "state = Path(os.environ['CRABC_X86_64_WORK_DIR'])\n"
                "def host(value): return state / Path(value).relative_to('/workspace/.work/x86_64')\n"
                "if 'plan' in argv and '/workspace/compat/x86_64/owned_resolver_family.py' in argv:\n"
                "    output = Path(argv[argv.index('--output') + 1])\n"
                "    layout = family.execution_layout(output.relative_to('/workspace'))\n"
                "    products = {label: {kind: f'.work/x86_64/cohort/{label}-{kind}' for kind in ('static', 'dynamic')}\n"
                "                for label in ('primary', 'reproduction', 'extracted')}\n"
                "    plan = {'schema': family.PLAN_SCHEMA, 'layout': layout, 'products': products,\n"
                "            'static_preparation': '.work/x86_64/cohort/preparation.json',\n"
                "            'dynamic_qualification': '.work/x86_64/cohort/qualification.json'}\n"
                "    host(str(output) + '/plan.json').write_text(json.dumps(plan))\n"
                "elif '/workspace/compat/x86_64/native_abi_inventory.py' in argv:\n"
                "    report = host(argv[argv.index('--output') + 1])\n"
                "    report.mkdir()\n"
                "    (report / 'report.json').write_text('{}')\n"
            )
            docker.chmod(0o755)
            state = work / "state"
            cohort = state / "cohort"
            for label in ("primary", "reproduction", "extracted"):
                for kind in ("static", "dynamic"):
                    (cohort / f"{label}-{kind}").mkdir(parents=True)
            for name in ("preparation.json", "qualification.json"):
                (cohort / name).write_text("{}\n", encoding="utf-8")
            environment = {
                **os.environ,
                "PATH": f"{work}{os.pathsep}{os.environ['PATH']}",
                "DISPATCH_CAPTURE": str(capture),
                "CRABC_X86_64_WORK_DIR": str(state),
            }
            command = ["bash", str(ROOT / "scripts/dev-x86_64.sh"), "owned-resolver-family"]
            arguments = ["--static-preparation", str(cohort / "preparation.json"),
                         "--dynamic-qualification", str(cohort / "qualification.json"),
                         "--output", str(state / "family")]
            invalid = subprocess.run(command + arguments[:-2], cwd=ROOT, env=environment,
                                     capture_output=True, text=True)
            self.assertEqual(invalid.returncode, 2)
            self.assertFalse(capture.exists())
            outside = subprocess.run(command + arguments[:-1] + [str(ROOT / ".work/resolver-family-outside")],
                                     cwd=ROOT, env=environment, capture_output=True, text=True)
            self.assertNotEqual(outside.returncode, 0)
            self.assertFalse(capture.exists())

            result = subprocess.run(command + arguments, cwd=ROOT, env=environment,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr[-2000:])
            self.assertTrue((state / "family").is_dir(), "the dispatcher owns the user-created output")
            runs = [json.loads(line) for line in capture.read_text().splitlines()]

            def role(invocation):
                for program in (
                    "owned_resolver_family.py", "run_x86_64.py", "owned_classic_netdb.py",
                    "owned_resolver_cancellation.py", "owned_protocol_database.py", "run_loader_debug_abi.sh",
                    "native_abi_inventory.py", "native_abi_elf_facts.py", "run_owned_resolver_alias_contract.sh",
                ):
                    for value in invocation:
                        if value.endswith("/" + program):
                            if program == "owned_resolver_family.py":
                                return invocation[invocation.index(value) + 1]
                            return program
                self.fail(f"unexpected container: {invocation}")

            self.assertEqual([role(run) for run in runs], [
                "plan", "run_x86_64.py", "owned_classic_netdb.py", "owned_resolver_cancellation.py",
                "owned_protocol_database.py", "run_loader_debug_abi.sh", "native_abi_inventory.py",
                "native_abi_elf_facts.py", "run_owned_resolver_alias_contract.sh", "write-assessment", "validate",
            ])
            primary_static = "/workspace/.work/x86_64/cohort/primary-static"
            primary_dynamic = "/workspace/.work/x86_64/cohort/primary-dynamic"
            family_root = "/workspace/.work/x86_64/family"
            network = runs[1]
            self.assertEqual(network[network.index("--static-sysroot") + 1], primary_static)
            self.assertEqual(network[network.index("--extracted-dynamic-sysroot") + 1],
                             "/workspace/.work/x86_64/cohort/extracted-dynamic")
            self.assertEqual(network[network.index("--work-root") + 1], family_root + "/network")
            self.assertEqual(network[network.index("--report") + 1],
                             "/workspace/compat/reports/resolver-network/x86_64/family-family.json")
            protocol = runs[4]
            self.assertEqual(protocol[protocol.index("--reproduction-static-sysroot") + 1],
                             "/workspace/.work/x86_64/cohort/reproduction-static")
            for run in runs[1:6] + [runs[8]]:
                self.assertEqual(run[run.index("--network") + 1], "none")
                self.assertIn("--cap-add=SYS_CHROOT", run)
                self.assertNotIn("--cap-add=SYS_ADMIN", run)
                self.assertNotIn("--privileged", run)
                self.assertIn("ulimit -c 0 && exec \"$@\"", run)
            self.assertIn("CRABC_LOADER_DEBUG_IMAGE_ID=crabc-core-evidence@sha256:" + "a" * 64, runs[5])
            self.assertIn("CRABC_RESOLVER_ALIAS_IMAGE_ID=crabc-core-evidence@sha256:" + "a" * 64, runs[8])
            for run in runs[6:8]:
                self.assertIn("/inputs/static-product", run)
                self.assertIn(f"{cohort / 'primary-static'}:/inputs/static-product:ro", run)
            alias = runs[8]
            self.assertEqual(alias[alias.index("--dynamic-product") + 1], primary_dynamic)
            self.assertEqual(alias[alias.index("--product-report") + 1], family_root + "/loader-debug/report.json")
            self.assertEqual(alias[alias.index("--elf-facts") + 1], family_root + "/native-abi-elf-facts/report.json")
            self.assertEqual(alias[alias.index("--receipt-dir") + 1], family_root + "/alias")
            self.assertEqual(runs[9][-4:], ["--request", ".work/x86_64/family/request.json",
                                            "--output", ".work/x86_64/family/assessment.json"])
            self.assertEqual(runs[10][-2:], ["--assessment", ".work/x86_64/family/assessment.json"])


if __name__ == "__main__":
    unittest.main()
