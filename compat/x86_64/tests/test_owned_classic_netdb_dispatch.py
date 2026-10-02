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

    def test_network_dispatch_executes_the_observed_immutable_image_and_forwards_its_identity(self) -> None:
        source = DISPATCHER.read_text()
        for name, prefix in (("run_in_resolver_network_container", ""),
                             ("run_in_resolver_family_image_container", "CRABC_RESOLVER_ALIAS_IMAGE_ID ")):
            with self.subTest(dispatch=name):
                self.check_image_dispatch(source, name, prefix)

    def check_image_dispatch(self, source: str, name: str, prefix: str) -> None:
        function = re.search(r"^" + name + r"\(\) \{.*?^\}", source, re.M | re.S)
        self.assertIsNotNone(function)
        script = "set -eu\n" + function.group() + "\n" + """
prepare_work_dir() { :; }
docker() {
    if [ "$1" = image ]; then
        printf '%s\\n' 'sha256:4444444444444444444444444444444444444444444444444444444444444444'
    else
        printf '%s\\0' "$@"
    fi
}
GIT_METADATA_MOUNT=()
IMAGE=mutable-tag
PLATFORM=linux/amd64
ROOT_DIR=/checkout
TMP_DIR=/checkout/.work/tmp
WORK_DIR=/checkout/.work/x86_64
TARGET_VOLUME=/checkout/.work/target
CARGO_VOLUME=/checkout/.work/cargo
""" + name + " " + prefix + "python3 collector.py\n"
        result = subprocess.run(["bash", "-c", script], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        args = result.stdout.split(b"\0")[:-1]
        identity = b"sha256:4444444444444444444444444444444444444444444444444444444444444444"
        self.assertEqual(args[-3:], [identity, b"python3", b"collector.py"])
        self.assertIn(b"CRABC_CLASSIC_NETDB_IMAGE_ID=crabc-core-evidence@" + identity, args)
        self.assertNotIn(b"mutable-tag", args)


if __name__ == "__main__":
    unittest.main()
