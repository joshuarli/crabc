#!/usr/bin/env python3
"""Raw errno, lifecycle, and reply order for the resolver cancellation fixture."""
from __future__ import annotations

import errno
import inspect
import subprocess
import tempfile
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
PROBE = ROOT / 'compat/x86_64/owned_resolver_cancellation_probe.c'
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import owned_resolver_cancellation as cancellation  # noqa: E402
import owned_resolver_cancellation_receipt as receipt  # noqa: E402


BASE_OBSERVATION = {
    'canceled': 0,
    'returned': 1,
    'cleanup': 0,
    'cleanup_fds': 0,
    'leaked': 0,
    'state': 1,
    'transmitted': 0,
    'success': 0,
}


class ResolverCancellationObservationContractTests(unittest.TestCase):
    def compare(self, *, api: str = 'modern-dual', scenario: str = 'masked-dual-mixed-tcp',
                oracle_errno: int = errno.ECANCELED, owned_errno: int = errno.EAGAIN,
                current: dict[str, int] | None = None, stderr: bytes = b'') -> str | None:
        expected = {**BASE_OBSERVATION, 'errno': oracle_errno}
        current = {**BASE_OBSERVATION, 'errno': owned_errno} if current is None else current
        return cancellation.compare_observation(api, scenario, expected, b'', current, stderr)

    def test_only_the_named_dual_cell_allows_the_source_later_errno(self) -> None:
        self.assertIn(cancellation.POST_TCP_LATER_EAGAIN_CASE, cancellation.CASES)
        self.assertNotIn(cancellation.POST_TCP_LATER_EAGAIN_CASE[1], cancellation.SCENARIOS)
        self.assertEqual(self.compare(), 'source-later-syscall')
        self.assertEqual(self.compare(oracle_errno=errno.EAGAIN, owned_errno=errno.ECANCELED),
                         'source-later-syscall')

    def test_named_dual_cell_rejects_every_unlisted_errno(self) -> None:
        with self.assertRaisesRegex(RuntimeError, 'outside source contract'):
            self.compare(owned_errno=errno.EINTR)
        with self.assertRaisesRegex(RuntimeError, 'oracle errno is outside source contract'):
            self.compare(oracle_errno=errno.EINTR, owned_errno=errno.EINTR)

    def test_named_dual_cell_keeps_every_lifecycle_observation_exact(self) -> None:
        for key in BASE_OBSERVATION:
            with self.subTest(key=key):
                changed = {**BASE_OBSERVATION, 'errno': errno.EAGAIN}
                changed[key] += 1
                with self.assertRaisesRegex(RuntimeError, 'observation differs'):
                    self.compare(current=changed)

    def test_other_cells_still_require_an_exact_errno(self) -> None:
        with self.assertRaisesRegex(RuntimeError, 'observation differs'):
            self.compare(api='modern', scenario='masked-dual-mixed-tcp')
        with self.assertRaisesRegex(RuntimeError, 'observation differs'):
            self.compare(scenario='masked-tcp')

    def test_dedicated_post_tcp_case_requires_eagain_exactly(self) -> None:
        with self.assertRaisesRegex(RuntimeError, 'observation differs'):
            self.compare(scenario=cancellation.POST_TCP_LATER_EAGAIN_CASE[1],
                         oracle_errno=errno.EAGAIN, owned_errno=errno.ECANCELED)

    def test_stderr_cannot_drift_with_the_admitted_errno(self) -> None:
        with self.assertRaisesRegex(RuntimeError, 'stderr differs'):
            self.compare(stderr=b'unexpected diagnostic\n')

    def test_dynamic_execution_labels_match_the_public_receipt_matrix(self) -> None:
        """The producer's retained raw names must be replayable by its reader."""

        producer = inspect.getsource(cancellation.run)
        self.assertIn("execute('dynamic-'+mode+'-kernel'", producer)
        self.assertIn("execute('dynamic-'+mode+'-direct'", producer)
        self.assertEqual(receipt.ENTRY_MODES[2:], (
            'dynamic-pie-kernel', 'dynamic-pie-direct',
            'dynamic-non-pie-kernel', 'dynamic-non-pie-direct',
        ))


@unittest.skipUnless(Path('/usr/local/bin/crabc-x86_64-musl-gcc').is_file(),
                     'requires the pinned native musl oracle image')
class ResolverCancellationReplyOrderTests(unittest.TestCase):
    def test_original_masked_dual_cells_send_the_paired_udp_reply_before_tcp_accept(self) -> None:
        cancellation.fixture_module().require_native_loopback_container()
        scratch = ROOT / '.work'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            wrapper = work / 'server-order.c'
            wrapper.write_text(r'''#define _GNU_SOURCE
#include <stdio.h>
#include <sys/socket.h>
ssize_t __real_sendto(int,const void *,size_t,int,const struct sockaddr *,socklen_t);
int __real_accept(int,struct sockaddr *,socklen_t *);
ssize_t __wrap_sendto(int fd,const void *data,size_t n,int flags,const struct sockaddr *peer,socklen_t size) {
    const unsigned char *packet=data;
    ssize_t result=__real_sendto(fd,data,n,flags,peer,size);
    if(result==(ssize_t)n && n>=12 && (packet[2]&0x80))
        dprintf(2,"udp-%s\n",(packet[2]&2)?"truncated":"answer");
    return result;
}
int __wrap_accept(int fd,struct sockaddr *peer,socklen_t *size) {
    dprintf(2,"tcp-accept\n");
    return __real_accept(fd,peer,size);
}
''', encoding='ascii')
            execution = work / 'execution-root'
            (execution / 'etc').mkdir(parents=True)
            command = ['/usr/local/bin/crabc-x86_64-musl-gcc', '-std=c11', '-fno-builtin', '-static',
                       '-fno-pie', '-no-pie', '-pthread', str(PROBE), str(wrapper),
                       '-Wl,--wrap=sendto,--wrap=accept', '-o', str(execution / 'oracle')]
            built = subprocess.run(command, capture_output=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr.decode(errors='replace'))
            for scenario in ('masked-dual-mixed-tcp', 'masked-udp-to-tcp',
                             cancellation.POST_TCP_LATER_EAGAIN_CASE[1]):
                with self.subTest(scenario=scenario):
                    result = subprocess.run([
                        sys.executable, '-B', str(ROOT / 'compat/x86_64/run_pthread_wait_witness.py'),
                        str(execution), '/oracle', scenario, 'modern-dual',
                    ], capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                    dedicated = scenario == cancellation.POST_TCP_LATER_EAGAIN_CASE[1]
                    expected_order = ['udp-truncated', 'tcp-accept'] if dedicated else [
                        'udp-truncated', 'udp-answer', 'tcp-accept',
                    ]
                    self.assertEqual(result.stderr.decode('ascii').splitlines(), expected_order)
                    expected = {**BASE_OBSERVATION,
                                'errno': errno.EAGAIN if dedicated else errno.ECANCELED}
                    cancellation.compare_observation('modern-dual', scenario, expected, b'',
                                                     cancellation.observation(result.stdout), b'')


if __name__ == '__main__':
    unittest.main()
