from pathlib import Path
import unittest
import hashlib
import importlib.util
import io
import tarfile
import tempfile
from unittest import mock
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts import native_build_tools as tools


class NativeBuildToolsTests(unittest.TestCase):
    def test_environment_rejects_caller_configuration_by_construction(self):
        environment = tools.environment()
        self.assertEqual(environment["RUSTC_WRAPPER"], "/usr/local/bin/kache")
        self.assertEqual(environment["KACHE_CONFIG"], "/dev/null")
        self.assertEqual(environment["KACHE_HOST_CONFIG"], "")
        self.assertEqual(environment["KACHE_LOCAL_ONLY"], "1")
        for name in ("KACHE_AUTO_CLEAN_ORPHANED_TARGETS", "KACHE_AUTO_CLEAN_UNUSED_UNITS_DAYS",
                     "KACHE_AUTO_SHARE_TARGET_FILES", "KACHE_SEED_NEW_TARGETS"):
            self.assertEqual(environment[name], "0")
        self.assertEqual(environment["CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"],
                         "/usr/local/bin/crabc-x86_64-mold-gcc")

    def test_compile_argv_binds_wrapper_and_physical_compiler(self):
        compiler = Path("/opt/rustup/toolchains/nightly-2026-01-01-x86_64-unknown-linux-musl/bin/rustc")
        self.assertEqual(tools.compile_command(compiler), ["/usr/local/bin/kache", str(compiler)])
        with self.assertRaises(ValueError):
            tools.compile_command(Path("/usr/bin/rustc"))


class NativeBuildToolInstallerTests(unittest.TestCase):
    def test_bad_archive_checksum_cannot_replace_installed_wrapper(self):
        root = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location("native_installer", root / "docker/install-native-build-tools.py")
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        scratch = Path(__file__).resolve().parents[2] / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            stage = Path(temporary)
            installed = stage / "kache"
            installed.write_bytes(b"existing wrapper")
            pins = stage / "pins.toml"
            pins.write_text('[kache_native]\nversion="1.0.0"\nsource="https://example.invalid/kache"\nsha256="' + "0" * 64 + '"\n')
            with mock.patch.object(installer.urllib.request, "urlopen", return_value=io.BytesIO(b"untrusted archive")):
                with self.assertRaisesRegex(RuntimeError, "checksum differs"):
                    installer.install(pins, stage / "download", installed)
            self.assertEqual(installed.read_bytes(), b"existing wrapper")

    def test_archive_symlink_cannot_replace_installed_wrapper(self):
        root = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location("native_installer", root / "docker/install-native-build-tools.py")
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as bundle:
            member = tarfile.TarInfo("kache")
            member.type = tarfile.SYMTYPE
            member.linkname = "/host/tool"
            bundle.addfile(member)
        payload = archive.getvalue()
        scratch = Path(__file__).resolve().parents[2] / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            stage = Path(temporary)
            installed = stage / "kache"
            installed.write_bytes(b"existing wrapper")
            pins = stage / "pins.toml"
            pins.write_text('[kache_native]\nversion="1.0.0"\nsource="https://example.invalid/kache"\nsha256="' + hashlib.sha256(payload).hexdigest() + '"\n')
            with mock.patch.object(installer.urllib.request, "urlopen", return_value=io.BytesIO(payload)):
                with self.assertRaisesRegex(RuntimeError, "not a regular archive member"):
                    installer.install(pins, stage / "download", installed)
            self.assertEqual(installed.read_bytes(), b"existing wrapper")
