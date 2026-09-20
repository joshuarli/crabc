#!/usr/bin/env python3
"""Narrow raw-errno contract for the owned resolver cancellation fixture."""
from __future__ import annotations

import errno
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
PROBE = ROOT / 'compat/x86_64/owned_resolver_cancellation_probe.c'
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import owned_resolver_cancellation as cancellation  # noqa: E402


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

    def test_probe_limits_the_original_cell_and_preserves_its_reply_order(self) -> None:
        source = PROBE.read_text(encoding='utf-8')
        self.assertIn('dual_mixed_later_errno_case=!strcmp(scenario,"masked-dual-mixed-tcp") && !strcmp(api,"modern-dual");', source)
        self.assertIn('CHECK(result_errno==ECANCELED || result_errno==EAGAIN);', source)
        paired_reply = source.index('if(!post_tcp_later_eagain_case) {')
        accept = source.index('accepted=accept(tcp,0,0)')
        self.assertLess(paired_reply, accept)


if __name__ == '__main__':
    unittest.main()
