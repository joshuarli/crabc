#!/usr/bin/env python3
"""Separate pinned declaration collection from host retained-evidence replay."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
WORK = ROOT / '.work/x86_64/header-declaration-dispatcher-tests'
IMAGE_ID = 'sha256:' + '6' * 64


class HeaderDeclarationInventoryDispatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        WORK.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=WORK)
        self.addCleanup(temporary.cleanup)
        self.checkout = Path(temporary.name) / 'checkout'
        scripts = self.checkout / 'scripts'
        scripts.mkdir(parents=True)
        shutil.copy2(ROOT / 'scripts/dev-x86_64.sh', scripts / 'dev-x86_64.sh')
        self.work = self.checkout / '.work/x86_64'
        self.evidence = self.work / 'header-declaration-inventory'
        self.evidence.mkdir(parents=True)
        self.docker_log = self.work / 'docker.jsonl'
        self.reader_log = self.work / 'reader.json'
        binaries = self.work / 'bin'
        binaries.mkdir()
        docker = binaries / 'docker'
        docker.write_text(
            '#!/usr/bin/env python3\n'
            'import json, os, pathlib, sys\n'
            'args = sys.argv[1:]\n'
            "with pathlib.Path(os.environ['DECLARATION_DOCKER_LOG']).open('a') as log:\n"
            "    log.write(json.dumps(args) + '\\n')\n"
            "if args[:2] == ['image', 'inspect']:\n"
            "    template = args[args.index('--format') + 1] if '--format' in args else ''\n"
            "    if template == '{{.Os}}/{{.Architecture}}': print('linux/amd64')\n"
            f"    elif template == '{{{{.Id}}}}': print({IMAGE_ID!r})\n"
            "    elif template: sys.exit(3)\n"
            "elif args[:1] != ['run']: sys.exit(3)\n",
            encoding='utf-8',
        )
        docker.chmod(0o755)
        reader = self.checkout / 'compat/x86_64/header_declaration_inventory.py'
        reader.parent.mkdir(parents=True)
        reader.write_text(
            'import json, os, pathlib, sys\n'
            "pathlib.Path(os.environ['DECLARATION_READER_LOG']).write_text(json.dumps(sys.argv[1:]))\n"
            "raise SystemExit(int(os.environ.get('DECLARATION_READER_STATUS', '0')))\n",
            encoding='utf-8',
        )
        self.environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith('CRABC_X86_64_')
        }
        self.environment.update({
            'PATH': str(binaries) + os.pathsep + os.environ['PATH'],
            'DECLARATION_DOCKER_LOG': str(self.docker_log),
            'DECLARATION_READER_LOG': str(self.reader_log),
            'PYTHONDONTWRITEBYTECODE': '1',
        })

    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ['bash', str(self.checkout / 'scripts/dev-x86_64.sh'), 'header-declaration-inventory', *arguments],
            cwd=self.checkout, env=self.environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )

    def test_collection_uses_resolved_pinned_image_and_contained_output(self) -> None:
        result = self.invoke('collect', '--output', '.work/x86_64/header-declaration-inventory/new run',
                             '--workers', '3', '--timeout-seconds', '45')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.docker_log.read_text().splitlines()]
        runs = [call for call in calls if call[0] == 'run']
        self.assertEqual(len(runs), 1)
        args = runs[0]
        self.assertEqual(args[args.index('--network') + 1], 'none')
        self.assertEqual(args[args.index('--user') + 1], f'{os.getuid()}:{os.getgid()}')
        self.assertIn('CRABC_X86_HEADER_DECLARATION_IMAGE_ID=crabc-core-evidence@' + IMAGE_ID, args)
        self.assertNotIn('--privileged', args)
        command = args[args.index(IMAGE_ID) + 1:]
        self.assertEqual(command[:4], ['python3', '-B', '/workspace/compat/x86_64/header_declaration_inventory.py', '--collect'])
        self.assertEqual(command[command.index('--output') + 1], '/workspace/.work/x86_64/header-declaration-inventory/new run')
        self.assertEqual(command[command.index('--workers') + 1], '3')
        self.assertEqual(command[command.index('--timeout-seconds') + 1], '45')
        self.assertFalse(self.reader_log.exists())

    def test_replay_needs_only_retained_report_and_preserves_reader_failure(self) -> None:
        report = self.evidence / 'report.json'
        report.write_text('{}\n')
        self.environment['DECLARATION_READER_STATUS'] = '17'
        result = self.invoke('validate-report', str(report.relative_to(self.checkout)))
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertFalse(self.docker_log.exists())
        self.assertEqual(json.loads(self.reader_log.read_text()), ['--validate-report', str(report)])

    def test_bad_arguments_and_unsafe_paths_fail_before_execution(self) -> None:
        existing = self.evidence / 'existing'
        existing.mkdir()
        alias = self.evidence / 'alias'
        alias.symlink_to(existing, target_is_directory=True)
        cases = [(), ('collect',), ('promote',),
                 ('collect', '--output', str(existing)),
                 ('collect', '--output', str(alias / 'new')),
                 ('collect', '--output', '.work/x86_64/wrong-root'),
                 ('collect', '--output', str(self.evidence / 'new'), '--output', str(self.evidence / 'second')),
                 ('collect', '--output', str(self.evidence / 'new'), '--compiler', 'ambient-clang'),
                 ('validate-report', str(existing)),
                 ('validate-report', str(self.evidence / 'missing.json'))]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.docker_log.exists())
                self.assertFalse(self.reader_log.exists())


if __name__ == '__main__':
    unittest.main()
