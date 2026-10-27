#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / 'scripts/dev-x86_64.sh'
COMMANDS = (
    'owned-posix-timers', 'owned-pthread-scheduling', 'owned-pthread-cpuclock',
    'owned-message-queues', 'owned-named-ipc', 'owned-fcntl',
    'owned-static-dl-iterate-phdr', 'owned-pthread-getattr',
)


class NativeImageDispatchTests(unittest.TestCase):
    def test_native_commands_resolve_the_pinned_image_without_an_override(self):
        work = ROOT / '.work/x86_64/tmp'
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            directory = Path(temporary)
            docker = directory / 'docker'
            docker.write_text('''#!/bin/sh
if [ "$1" = image ] && [ "$2" = inspect ]; then
    case "$3" in
        --format) [ -n "$5" ] || exit 2; case "$4" in *Architecture*) printf 'linux/amd64\\n';; *) printf 'sha256:test\\n';; esac ;;
        '') exit 2 ;;
        *) printf 'ok\\n' ;;
    esac
    exit 0
fi
[ "$1" = run ] || exit 2
printf '%s\\n' "$@" > "$TEST_DOCKER_ARGS"
''')
            docker.chmod(0o755)
            env = os.environ.copy()
            env.pop('CRABC_X86_64_CORE_IMAGE', None)
            env['PATH'] = str(directory) + os.pathsep + env['PATH']
            env['TEST_DOCKER_ARGS'] = str(directory / 'args')
            pinned = subprocess.check_output(['python3', '-B', str(ROOT / 'compat/x86_64/core_image.py')], text=True).strip()
            for command in COMMANDS:
                with self.subTest(command=command):
                    result = subprocess.run(['bash', str(RUNNER), command], cwd=ROOT, env=env,
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    args = (directory / 'args').read_text().splitlines()
                    self.assertIn(pinned if command in {'owned-message-queues', 'owned-named-ipc'} else 'sha256:test', args)


if __name__ == '__main__':
    unittest.main()
