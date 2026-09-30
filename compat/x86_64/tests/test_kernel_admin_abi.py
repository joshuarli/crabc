#!/usr/bin/env python3
"""Contract for the owned x86 kernel-administration C ABI component."""

from __future__ import annotations

import importlib.util
import hashlib
import os
import tempfile
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "libc" / "Cargo.toml"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
RAW_SYSCALL = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
ARCH_SOURCE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "arch_prctl.rs"
IO_SOURCE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "io_permissions.rs"
PROBE = ROOT / "compat" / "x86_64" / "libc_kernel_admin_probe.c"
RUNNER = ROOT / "compat" / "x86_64" / "run_libc_kernel_admin.sh"
STATIC_PROVIDER_READER = (
    ROOT / "compat" / "x86_64" / "kernel_admin_static_provider_reader.py"
)
DOCUMENT = ROOT / "compat" / "x86_64" / "kernel-admin-abi.md"
README = ROOT / "compat" / "x86_64" / "README.md"


def load_static_provider_reader():
    spec = importlib.util.spec_from_file_location(
        "kernel_admin_static_provider_reader", STATIC_PROVIDER_READER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load static provider reader: {STATIC_PROVIDER_READER}")
    sys.path.insert(0, str(STATIC_PROVIDER_READER.parent))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class KernelAdminAbiTests(unittest.TestCase):
    def test_owned_component_has_a_closed_provider_and_evidence_contract(self) -> None:
        for path in (
            ARCH_SOURCE,
            IO_SOURCE,
            PROBE,
            RUNNER,
            STATIC_PROVIDER_READER,
            DOCUMENT,
        ):
            self.assertTrue(path.is_file(), f"missing kernel-admin input: {path}")
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        manifest = MANIFEST.read_text(encoding="utf-8")
        static_root = STATIC_ROOT.read_text(encoding="utf-8")
        raw_syscall = RAW_SYSCALL.read_text(encoding="utf-8")
        arch_source = ARCH_SOURCE.read_text(encoding="utf-8")
        io_source = IO_SOURCE.read_text(encoding="utf-8")
        probe = PROBE.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        document = DOCUMENT.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")

        self.assertIn('x86-kernel-admin = ["x86-io-permissions"]', manifest)
        owned_start = manifest.index("x86-owned-static-runtime = [")
        owned_end = manifest.index("]\n# Share the owned leaf roster", owned_start)
        self.assertIn("x86-kernel-admin", manifest[owned_start:owned_end])
        self.assertIn(
            '#[cfg(feature = "x86-kernel-admin")]\n'
            '#[path = "arch_prctl.rs"]\n'
            "mod arch_prctl;",
            static_root,
        )
        self.assertIn(
            '#[cfg(any(feature = "x86-io-permissions", feature = "x86-kernel-admin"))]\n'
            '#[path = "io_permissions.rs"]\n'
            "mod io_permissions;",
            static_root,
        )
        self.assertIn("pub(crate) const SYS_ARCH_PRCTL: i64 = 158;", raw_syscall)

        for marker in (
            "src/linux/arch_prctl.c::arch_prctl",
            "syscall(SYS_arch_prctl, code, addr)",
            "SYS_ARCH_PRCTL",
            'pub unsafe extern "C" fn arch_prctl',
            "ARCH_GET_FS",
            "ARCH_GET_GS",
            "# Safety",
            "valid writable `unsigned long *`",
            "TLS and segment-base invariants",
            "performs no validation or recovery",
        ):
            self.assertIn(marker, arch_source)
        self.assertNotIn("ARCH_SET_FS", probe)
        self.assertNotIn("ARCH_SET_GS", probe)
        for marker in (
            "extern int arch_prctl(int, unsigned long);",
            "SYS_arch_prctl == 158",
            "ARCH_GET_FS",
            "ARCH_GET_GS",
            "ARCH_INVALID_OPERATION",
            "arch_prctl(ARCH_GET_FS, 0UL)",
            "arch_prctl(ARCH_GET_GS, 0UL)",
            "iopl_negative = observe_iopl_invalid(-1)",
            "ioperm_start = observe_ioperm_invalid(65536UL, 1UL, 0)",
        ):
            self.assertIn(marker, probe)
        self.assertNotIn("iopl(0)", probe)
        self.assertNotIn("ioperm(0UL, 1UL, 1)", probe)

        for marker in (
            "build_x86_64_owned_sysroot.py",
            "build_x86_64_owned_dynamic_sysroot.py",
            "assert_provider_symbols",
            "assert_provider_instructions",
            "kernel_admin_static_provider_reader.py",
            "readelf --wide --symbols \"$inspection_dir\"/* >\"$report\"",
            "static static-pie",
            "for mode in pie non-pie",
            "dynamic-$mode-kernel",
            "dynamic-$mode-direct",
            '"$work/$label.status"',
            "ARCH_GET_FS/GS",
            "TMPDIR must name checkout-local .work scratch",
            "-nostdinc -isystem",
            "arch_prctl)\n                immediate='\\$0x9e",
            "iopl)\n                immediate='\\$0xac",
            "ioperm)\n                immediate='\\$0xad",
            "raw $raw_helper_suffix helper",
        ):
            self.assertIn(marker, runner)
        for forbidden in ("--cap-add", "seccomp=", "--privileged", "inb", "outb"):
            self.assertNotIn(forbidden, runner)
        self.assertNotIn('"T", "W"', runner)

        for marker in (
            "private native Linux/x86-64 foundation evidence",
            "x86-kernel-admin",
            "src/linux/arch_prctl.c::arch_prctl",
            "ARCH_GET_FS",
            "ARCH_GET_GS",
            "EINVAL`/`EPERM",
            "does not complete `system.kernel-admin`",
        ):
            self.assertIn(marker, document)
        self.assertIn("[kernel-admin-abi.md](kernel-admin-abi.md)", readme)

    def test_supplied_or_invalid_products_never_trigger_builders(self) -> None:
        scratch = ROOT / '.work/x86_64/tmp/kernel-admin-invocation-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            tools = work / 'tools'
            tools.mkdir()
            calls = work / 'python-invocations'
            python = tools / 'python3'
            python.write_text('#!/bin/sh\n'
                              'case "$*" in *build_x86_64_owned*sysroot.py*) '
                              'printf "%s\\n" "$*" >> "$KERNEL_ADMIN_CALLS"; exit 97 ;; esac\n'
                              'exec /usr/bin/python3 "$@"\n')
            python.chmod(0o755)
            static = work / 'static'
            dynamic = work / 'dynamic'
            static.mkdir()
            dynamic.mkdir()
            environment = {**os.environ, 'TMPDIR': str(work), 'KERNEL_ADMIN_CALLS': str(calls),
                           'PATH': str(tools) + ':' + os.environ['PATH']}
            cases = (
                (['--static-sysroot'], 2),
                (['--unknown'], 2),
                ([str(dynamic)], 2),
                (['--static-sysroot', str(static), str(dynamic), str(dynamic)], 2),
                (['--static-sysroot', str(work / 'absent'), str(dynamic)], 1),
                (['--static-sysroot', str(static), str(dynamic)], 1),
            )
            for arguments, expected in cases:
                with self.subTest(arguments=arguments):
                    result = subprocess.run(['bash', str(RUNNER), *arguments], env=environment,
                                            capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    self.assertFalse(calls.exists(), 'supplied or invalid products invoked a sysroot builder')

    @unittest.skipUnless(Path('/usr/local/bin/crabc-x86_64-musl-gcc').is_file(), 'requires pinned musl compiler')
    def test_success_marker_distinguishes_failed_read_from_same_io_fingerprint(self) -> None:
        scratch = ROOT / '.work/x86_64/tmp/kernel-admin-probe-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            model = work / 'providers.c'
            model.write_text('#include <errno.h>\nint model_arch_prctl(int operation, unsigned long address)\n{\n    if ((operation == 0x1003 || operation == 0x1004) && address != 0) {\n#ifdef FAILED_GS_READ\n        if (operation == 0x1004) { errno = EFAULT; return -1; }\n#endif\n        *(unsigned long *)address = 0;\n        return 0;\n    }\n    errno = operation == 0x7fff ? EINVAL : EFAULT;\n    return -1;\n}\nint model_iopl(int level) { errno = level == -1 ? EINVAL : EPERM; return -1; }\nint model_ioperm(unsigned long from, unsigned long count, int enabled)\n{\n    (void)count; (void)enabled;\n    errno = from == 65536UL ? EPERM : EINVAL;\n    return -1;\n}\n')
            outputs = []
            for name, flags in (('complete', []), ('failed-gs-read', ['-DFAILED_GS_READ'])):
                executable = work / name
                command = ['/usr/local/bin/crabc-x86_64-musl-gcc', '-std=c11', '-static', '-fno-pie', '-no-pie',
                           '-nostdinc', '-isystem', '/opt/musl-1.2.6/include',
                           '-Darch_prctl=model_arch_prctl', '-Diopl=model_iopl', '-Dioperm=model_ioperm',
                           *flags, str(PROBE), str(model), '-o', str(executable)]
                compiled = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                result = subprocess.run([str(executable)], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 20)
                self.assertEqual(result.stderr, b'')
                outputs.append(result.stdout)
            self.assertEqual(outputs[0], b'kernel-admin-observations-ok\n')
            self.assertEqual(outputs[1], b'')

    def test_component_reader_rejects_matched_failed_observations_and_missing_cases(self) -> None:
        import test_native_shadow_receipt as generic_tests

        reader = load_static_provider_reader()
        fixture = generic_tests.NativeShadowReceiptTests(methodName='runTest')
        try:
            fixture.setUp()
            root, work = fixture.root, fixture.work
            probe = root / 'compat/x86_64/libc_kernel_admin_probe.c'
            probe.parent.mkdir(parents=True)
            probe.write_bytes(PROBE.read_bytes())
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'probe'], cwd=root, check=True)
            static, dynamic = root / '.work/static', root / '.work/dynamic'
            paths = {
                'probe': probe, 'workload': work / 'workload.o', 'oracle': work / 'root/oracle',
                'static': work / 'root/static', 'static-pie': work / 'root/static-pie',
                'dynamic-pie': work / 'root/dynamic-pie', 'dynamic-non-pie': work / 'root/dynamic-non-pie',
                'static-libc': static / 'usr/lib/libc.a', 'dynamic-libc': dynamic / 'usr/lib/libc.so',
                'dynamic-loader': dynamic / 'lib/ld-crabc-x86_64.so.1',
                'static-provenance': static / 'share/crabc/libc-static.provenance.json',
                'dynamic-provenance': dynamic / 'share/crabc/libc-shared.provenance.json',
            }
            for name, path in paths.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                if name != 'probe':
                    path.write_bytes(name.encode())
            for name, relative in (('dynamic-libc', 'usr/lib/libc.so'), ('dynamic-loader', 'lib/ld-crabc-x86_64.so.1')):
                copied = work / 'root' / relative
                copied.parent.mkdir(parents=True, exist_ok=True)
                copied.write_bytes(paths[name].read_bytes())
            for label in ('oracle', 'static', 'static-pie', 'dynamic-pie-kernel', 'dynamic-pie-direct',
                          'dynamic-non-pie-kernel', 'dynamic-non-pie-direct'):
                (work / (label + '.status')).write_text('20\n')
                (work / (label + '.stdout')).write_bytes(b'kernel-admin-observations-ok\n')
                (work / (label + '.stderr')).write_bytes(b'')
            table = '\n'.join(f'1: 0000000000000000 16 FUNC GLOBAL DEFAULT 1 {name}'
                              for name in ('arch_prctl', 'iopl', 'ioperm'))
            (work / 'static-symbols').write_text(table)
            (work / 'dynamic-symbols').write_text(table)
            (work / 'input.sha256').write_text(''.join(
                f'{hashlib.sha256(paths[name].read_bytes()).hexdigest()}  {paths[name]}\n'
                for name in ('probe', 'workload')))
            (work / 'input-verified.txt').write_text(''.join(f'{paths[name]}: OK\n' for name in ('probe', 'workload')))
            (work / 'header-trace').write_text(''.join(
                f'. {dynamic}/usr/include/{name}\n'
                for name in ('errno.h', 'stdint.h', 'stdio.h', 'sys/io.h', 'sys/syscall.h', 'bits/syscall.h')))
            for label in ('static-archive', 'shared-libc'):
                for provider, number in (('arch_prctl', '9e'), ('iopl', 'ac'), ('ioperm', 'ad')):
                    (work / f'{label}-{provider}.disassembly').write_text(f' mov $0x{number},%eax\n syscall\n')
            provider_logs = [path for path in work.iterdir() if path.is_file()]
            executions = ('static', 'static-pie', 'dynamic-pie-kernel', 'dynamic-pie-direct',
                          'dynamic-non-pie-kernel', 'dynamic-non-pie-direct')
            cases = [('providers', 0, provider_logs)]
            for label in executions:
                cases.append(('compare-' + label, 0, [work / (name + suffix)
                    for name in ('oracle', label) for suffix in ('.status', '.stdout', '.stderr')]))
            parameters = {'CORE_IMAGE': reader.core_image.CORE_IMAGE_ID,
                          'STATIC_PRODUCT': '.work/static', 'DYNAMIC_PRODUCT': '.work/dynamic'}
            def publish(selected=cases):
                return reader.shadow.write_receipt(root, reader.RUNNER, work, paths, selected, parameters, True)
            # Link and ELF inspection have separate owning tests; these seams
            # leave physical receipt, raw-result and source authentication live.
            original_run = subprocess.run
            def inspect(command, *arguments, **options):
                if command[0] == 'readelf':
                    return subprocess.CompletedProcess(command, 0, table, '')
                return original_run(command, *arguments, **options)
            with mock.patch.object(reader, 'validate_link', return_value={}), mock.patch.object(
                    reader.subprocess, 'run', side_effect=inspect):
                publish()
                reader.validate_component(root)
                loaded = work / 'root/usr/lib/libc.so'
                loaded.write_bytes(b'foreign executed runtime')
                with self.assertRaisesRegex(ValueError, 'executed runtime differs'):
                    reader.validate_component(root)
                loaded.write_bytes(paths['dynamic-libc'].read_bytes())
                publish(cases[:-1])
                with self.assertRaisesRegex(ValueError, 'comparison roster'):
                    reader.validate_component(root)
                for label in ('oracle', *executions):
                    (work / (label + '.stdout')).write_bytes(b'')
                publish()
                with self.assertRaisesRegex(ValueError, 'observations did not complete'):
                    reader.validate_component(root)
        finally:
            fixture.tearDown()

    def test_static_provider_reader_rejects_weak_and_hidden_metadata(self) -> None:
        reader = load_static_provider_reader()

        valid = "\n".join(
            f"    1: 0000000000000000    38 FUNC    GLOBAL DEFAULT    1 {provider}"
            for provider in reader.PROVIDERS
        )
        reader.validate_table(valid)

        for provider, binding, visibility in (
            ("iopl", "WEAK", "DEFAULT"),
            ("ioperm", "GLOBAL", "HIDDEN"),
        ):
            rejected = valid.replace(
                f"FUNC    GLOBAL DEFAULT    1 {provider}",
                f"FUNC    {binding:<6} {visibility:<7} 1 {provider}",
            )
            with self.assertRaisesRegex(ValueError, rf"{provider}.*FUNC GLOBAL DEFAULT"):
                reader.validate_table(rejected)


if __name__ == "__main__":
    unittest.main()
