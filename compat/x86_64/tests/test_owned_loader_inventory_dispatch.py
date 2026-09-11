"""Native loader inventory reads exactly the caller's installed product."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class OwnedLoaderInventoryDispatchTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.state = self.work / "state"
        self.product = self.state / "dynamic product"
        self.product.mkdir(parents=True)
        self.output = self.state / "inventory.json"
        self.capture = self.work / "docker.jsonl"
        docker = self.work / "docker"
        docker.write_text(f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "with open(os.environ['DISPATCH_CAPTURE'], 'a') as out: out.write(json.dumps(sys.argv[1:])+'\\n')\n"
            "if sys.argv[1:3] == ['image', 'inspect']: print('linux/amd64')\n"
            "elif sys.argv[1] != 'run': raise SystemExit('unexpected Docker operation')\n")
        docker.chmod(0o755)
        self.environment = {key: value for key, value in os.environ.items() if not key.startswith("CRABC_X86_64_")}
        self.environment.update(PATH=f"{self.work}{os.pathsep}{os.environ['PATH']}",
            DISPATCH_CAPTURE=str(self.capture), CRABC_X86_64_WORK_DIR=str(self.state))

    def invoke(self, arguments):
        self.capture.unlink(missing_ok=True)
        return subprocess.run(["bash", str(ROOT / "scripts/dev-x86_64.sh"),
            "owned-loader-inventory", *map(str, arguments)], cwd=ROOT, env=self.environment,
            capture_output=True, text=True)

    def test_supplied_product_and_fresh_receipt_reach_one_unprivileged_collector(self):
        for product, output in ((self.product, self.output),
                (self.product.relative_to(ROOT), self.output.relative_to(ROOT)),
                (Path("/workspace/.work/x86_64/dynamic product"), Path("/workspace/.work/x86_64/inventory.json"))):
            with self.subTest(product=product):
                result = self.invoke((product, output))
                self.assertEqual(result.returncode, 0, result.stderr)
                runs = [row for row in map(json.loads, self.capture.read_text().splitlines()) if row[0] == "run"]
                self.assertEqual(len(runs), 1)
                argv = runs[0]
                self.assertEqual(argv[-8:], ["python3", "-B", "/workspace/compat/x86_64/owned_loader_inventory.py",
                    "collect", "--product", "/workspace/.work/x86_64/dynamic product",
                    "--output", "/workspace/.work/x86_64/inventory.json"])
                self.assertFalse(any(item.startswith("--cap-add") or item.startswith("--security-opt")
                                     or item == "--privileged" for item in argv))

    def test_invalid_product_or_output_is_rejected_before_docker(self):
        alias = self.state / "product alias"
        alias.symlink_to(self.product)
        existing = self.state / "existing.json"
        existing.write_text("{}\n")
        for arguments in ((), (self.product,), (self.product, self.output, self.output),
                (alias, self.output), (self.state / "missing", self.output),
                (self.product, existing), (self.product, "/workspace/etc/inventory.json")):
            with self.subTest(arguments=arguments):
                result = self.invoke(arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.capture.exists())


if __name__ == "__main__":
    unittest.main()
