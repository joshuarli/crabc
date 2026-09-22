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


if __name__ == "__main__":
    unittest.main()
