#!/usr/bin/env python3
"""Keep public-data execution inputs read-only and retained replay on the host."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
WORK = ROOT / '.work/x86_64/public-data-dispatcher-tests'
IMAGE_ID = 'sha256:' + '6' * 64


class PublicDataOrdinaryLinkDispatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        WORK.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=WORK)
        self.addCleanup(temporary.cleanup)
        self.temporary = Path(temporary.name)
        self.checkout = self.temporary / 'checkout'
        scripts = self.checkout / 'scripts'
        scripts.mkdir(parents=True)
        shutil.copy2(ROOT / 'scripts/dev-x86_64.sh', scripts / 'dev-x86_64.sh')
        self.work = self.checkout / '.work/x86_64'
        self.evidence = self.work / 'public-data-ordinary-link'
        self.evidence.mkdir(parents=True)
        self.products = self.work / 'prepared products'
        self.products.mkdir()
        self.static = self.products / 'static'
        self.dynamic = self.products / 'dynamic'
        self.static.mkdir()
        self.dynamic.mkdir()
        self.preparation = self.products / 'preparation.json'
        self.preparation.write_text('{}\n')
        self.docker_log = self.work / 'docker.jsonl'
        self.reader_log = self.work / 'reader.json'
        binaries = self.work / 'bin'
        binaries.mkdir()
        docker = binaries / 'docker'
        docker.write_text(
            '#!/usr/bin/env python3\n'
            'import json, os, pathlib, sys\n'
            'args = sys.argv[1:]\n'
            "with pathlib.Path(os.environ['DATA_DOCKER_LOG']).open('a') as log:\n"
            "    log.write(json.dumps(args) + '\\n')\n"
            "if args[:2] == ['image', 'inspect']:\n"
            "    template = args[args.index('--format') + 1] if '--format' in args else ''\n"
            "    if template == '{{.Os}}/{{.Architecture}}': print('linux/amd64')\n"
            f"    elif template == '{{{{.Id}}}}': print({IMAGE_ID!r})\n"
            "    elif template: sys.exit(3)\n"
            "elif args[:1] != ['run']: sys.exit(3)\n"
        )
        docker.chmod(0o755)
        reader = self.checkout / 'compat/x86_64/public_data_ordinary_link_evidence.py'
        reader.parent.mkdir(parents=True)
        reader.write_text(
            'import json, os, pathlib, sys\n'
            "pathlib.Path(os.environ['DATA_READER_LOG']).write_text(json.dumps(sys.argv[1:]))\n"
            "raise SystemExit(int(os.environ.get('DATA_READER_STATUS', '0')))\n"
        )
        self.environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith('CRABC_X86_64_')
        }
        self.environment.update({
            'PATH': str(binaries) + os.pathsep + os.environ['PATH'],
            'DATA_DOCKER_LOG': str(self.docker_log),
            'DATA_READER_LOG': str(self.reader_log),
            'PYTHONDONTWRITEBYTECODE': '1',
        })

    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ['bash', str(self.checkout / 'scripts/dev-x86_64.sh'), 'public-data-ordinary-link', *arguments],
            cwd=self.checkout, env=self.environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )

    def inputs(self) -> list[str]:
        return ['--static-product', str(self.static), '--dynamic-product', str(self.dynamic),
                '--static-preparation', str(self.preparation)]

    def test_collection_preserves_product_paths_and_limits_writable_mounts(self) -> None:
        result = self.invoke('collect', *self.inputs(), '--output', str(self.evidence / 'new run'))
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.docker_log.read_text().splitlines()]
        runs = [call for call in calls if call[0] == 'run']
        self.assertEqual(len(runs), 1)
        args = runs[0]
        self.assertEqual(args[args.index('--network') + 1], 'none')
        self.assertEqual([arg for arg in args if arg.startswith('--cap-add')], ['--cap-add=SYS_CHROOT'])
        self.assertNotIn('--privileged', args)
        self.assertFalse(any(arg.startswith('--security-opt') for arg in args))
        volumes = [args[index + 1] for index, arg in enumerate(args) if arg == '--volume']
        self.assertIn(f'{self.checkout}:/workspace:ro', volumes)
        self.assertIn(f'{self.work}:/workspace/.work/x86_64:ro', volumes)
        self.assertIn(f'{self.products}:/workspace/{self.products.relative_to(self.checkout)}:ro', volumes)
        for path in (self.static, self.dynamic, self.preparation):
            self.assertIn(f'{path}:/workspace/{path.relative_to(self.checkout)}:ro', volumes)
        self.assertCountEqual([item for item in volumes if not item.endswith(':ro')], [
            f'{self.work / "tmp"}:/tmp',
            f'{self.work / "tmp"}:/workspace/.work/x86_64/tmp',
            f'{self.evidence}:/workspace/.work/x86_64/public-data-ordinary-link',
        ])
        self.assertIn('CRABC_X86_PUBLIC_DATA_IMAGE_ID=crabc-core-evidence@' + IMAGE_ID, args)
        command = args[args.index(IMAGE_ID) + 1:]
        self.assertEqual(command[:4], ['python3', '-B', '/workspace/compat/x86_64/public_data_ordinary_link_evidence.py', 'collect'])
        self.assertEqual(command[command.index('--static-product') + 1], '/workspace/.work/x86_64/prepared products/static')
        self.assertEqual(command[command.index('--output') + 1], '/workspace/.work/x86_64/public-data-ordinary-link/new run')
        self.assertFalse(self.reader_log.exists())

    def test_host_replay_preserves_failure_and_needs_no_docker(self) -> None:
        report = self.evidence / 'report.json'
        report.write_text('{}\n')
        self.environment['DATA_READER_STATUS'] = '17'
        result = self.invoke('validate-report', '/workspace/.work/x86_64/public-data-ordinary-link/report.json')
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertFalse(self.docker_log.exists())
        self.assertEqual(json.loads(self.reader_log.read_text()), ['validate-report', str(report)])

    def test_invalid_arguments_and_paths_fail_before_execution(self) -> None:
        existing = self.evidence / 'existing'
        existing.mkdir()
        alias = self.evidence / 'alias'
        alias.symlink_to(existing, target_is_directory=True)
        valid = ['collect', *self.inputs(), '--output', str(self.evidence / 'new')]
        cases = [(), ('collect',), ('promote',),
                 (*valid, '--output', str(self.evidence / 'other')),
                 (*valid, '--compiler', 'ambient-cc'),
                 ('collect', *self.inputs(), '--output', str(existing)),
                 ('collect', *self.inputs(), '--output', str(alias / 'new')),
                 ('collect', *self.inputs(), '--output', str(self.work / 'wrong-root')),
                 ('validate-report', str(self.preparation), '--static-product', str(self.static)),
                 ('validate-report', str(self.evidence / 'missing.json'))]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.docker_log.exists())
                self.assertFalse(self.reader_log.exists())

    def test_symlink_product_outside_checkout_is_rejected(self) -> None:
        outside = self.temporary / 'outside'
        outside.mkdir()
        self.dynamic.rmdir()
        self.dynamic.symlink_to(outside, target_is_directory=True)
        result = self.invoke('collect', *self.inputs(), '--output', str(self.evidence / 'new'))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.docker_log.exists())

    def test_output_cannot_make_a_static_preparation_cohort_writable(self) -> None:
        cohort = self.evidence / 'prepared'
        self.static = cohort / 'products/primary'
        self.static.mkdir(parents=True)
        self.preparation = cohort / 'preparation.json'
        self.preparation.write_text('{}\n')
        result = self.invoke('collect', *self.inputs(), '--output', str(cohort / 'new evidence'))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.docker_log.exists())

    def test_nondefault_work_mapping_cannot_change_retained_root_relative_paths(self) -> None:
        for variable in ('CRABC_X86_64_WORK_DIR', 'CRABC_X86_64_CORE_CARGO_VOLUME'):
            with self.subTest(variable=variable):
                self.environment[variable] = str(self.work / 'custom')
                result = self.invoke('collect', *self.inputs(), '--output', str(self.evidence / 'new'))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.docker_log.exists())
                del self.environment[variable]


if __name__ == '__main__':
    unittest.main()
