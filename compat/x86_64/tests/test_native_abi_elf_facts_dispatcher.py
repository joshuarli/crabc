#!/usr/bin/env python3
"""ELF fact supplement dispatcher admission, without native inspection."""
from __future__ import annotations

import json
import subprocess
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from compat.x86_64.tests import test_native_abi_inventory_dispatcher as base_dispatcher


class NativeAbiElfFactsDispatcherTests(base_dispatcher.NativeAbiInventoryDispatcherTests):
    def setUp(self):
        super().setUp()
        self.base_inventory = self.inputs / 'base-inventory/report.json'
        self.base_inventory.parent.mkdir()
        self.base_inventory.write_text('{}\n')

    def invoke(self, *arguments):
        return subprocess.run(
            ['bash', str(self.checkout / 'scripts/dev-x86_64.sh'), 'native-abi-elf-facts', *arguments],
            cwd=self.checkout, env=self.environment, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=15,
        )

    def input_arguments(self):
        return [*super().input_arguments(), '--base-inventory', str(self.base_inventory.relative_to(self.checkout))]

    def test_collect_mounts_only_explicit_product_and_static_provenance_inputs_readonly(self):
        super().test_collect_mounts_only_explicit_product_and_static_provenance_inputs_readonly()
        args = self.docker_run()
        self.assertIn(f'{self.base_inventory.parent}:/inputs/base-inventory:ro', args)
        self.assertEqual(args[args.index('--base-inventory') + 1], '/inputs/base-inventory/report.json')
        self.assertIn('/workspace/compat/x86_64/native_abi_elf_facts.py', args)

    def test_validate_report_is_host_replay_without_docker(self):
        report = self.work / 'facts/report.json'
        report.parent.mkdir()
        report.write_text('{}\n')
        runner = self.checkout / 'compat/x86_64/native_abi_elf_facts.py'
        runner.parent.mkdir(parents=True)
        runner.write_text(
            'import json, os, pathlib, sys\n'
            "pathlib.Path(os.environ['ABI_DISPATCH_RUNNER_LOG']).write_text(json.dumps(sys.argv[1:]))\n"
        )
        result = self.invoke('validate-report', str(report.relative_to(self.checkout)), *self.input_arguments())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.docker_log.exists())
        args = json.loads(self.runner_log.read_text())
        self.assertEqual(args[args.index('--base-inventory') + 1], str(self.base_inventory))
        self.assertEqual(args[args.index('--validate-report') + 1], str(report))

    def test_base_inventory_is_mandatory_unique_and_physical(self):
        for args in (
            super().input_arguments(),
            [*self.input_arguments(), '--base-inventory', str(self.base_inventory)],
        ):
            with self.subTest(args=args):
                result = self.invoke('collect', *args, '--output', '.work/x86_64/facts')
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self.docker_log.exists())
        actual = self.base_inventory.with_name('actual.json')
        self.base_inventory.rename(actual)
        self.base_inventory.symlink_to(actual.name)
        result = self.invoke('collect', *self.input_arguments(), '--output', '.work/x86_64/facts')
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.docker_log.exists())


if __name__ == '__main__':
    unittest.main()
