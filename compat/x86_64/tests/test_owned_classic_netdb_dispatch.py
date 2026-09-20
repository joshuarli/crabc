"""Supplied classic-netdb products must bypass product preparation."""
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[3]
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"


class OwnedClassicNetdbDispatchTests(unittest.TestCase):
    def test_supplied_products_reach_network_runner_without_preparation(self) -> None:
        source = DISPATCHER.read_text()
        function = re.search(r"^run_owned_classic_netdb_probe\(\) \{.*?^\}", source, re.M | re.S)
        self.assertIsNotNone(function)
        script = "set -eu\n" + function.group() + "\n" + """
prepare_work_dir() { exit 91; }
run_in_container() { exit 92; }
run_in_resolver_network_container() { printf '%s\\0' "$@"; }
run_owned_classic_netdb_probe "$@"
"""
        for arguments in (("/workspace/.work/dynamic product",),
                          ("--static-sysroot", "/workspace/.work/static product", "/workspace/.work/dynamic product")):
            with self.subTest(arguments=arguments):
                result = subprocess.run(["bash", "-c", script, "dispatch-test", *arguments], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(result.stdout.split(b"\0")[:-1], [
                    b"bash", b"/workspace/compat/x86_64/run_owned_classic_netdb.sh",
                    *(value.encode() for value in arguments),
                ])


if __name__ == "__main__":
    unittest.main()
