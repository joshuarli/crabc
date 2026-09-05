"""Raw-file regressions for finite POSIX family observations."""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import owned_posix_family_observations as observations


class ObservationsTests(unittest.TestCase):
    def setUp(self):
        scratch = HERE.parents[1] / '.work/x86_64/observation-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        self.leaf = Path(tempfile.mkdtemp(dir=scratch))
        self.addCleanup(shutil.rmtree, self.leaf)

    def fixture(self, case, static=True):
        layout = observations.LAYOUTS[case]
        for scenario in layout.scenarios:
            for mode in ('oracle', *(observations.MODES if static else observations.MODES[2:])):
                stem = observations._stem(case, layout, mode, scenario, oracle=mode == 'oracle')
                for suffix, raw in (('.stdout', b'behavior\n'), (layout.stderr_suffix, b''),
                                    (layout.status_suffix, b'0\n')):
                    (self.leaf / (stem + suffix)).write_bytes(raw)

    def test_exact_raw_observations_have_relative_artifact_identities(self):
        self.fixture('spawn')
        result = observations.collect('spawn', self.leaf, static_required=True)
        self.assertEqual(set(result['scenarios']['normal']['candidates']), set(observations.MODES))
        self.assertEqual(result['scenarios']['normal']['oracle']['stdout']['path'], 'oracle.stdout')

    def test_missing_status_or_empty_stderr_is_not_inferred_from_success(self):
        for suffix in ('.status', '.stderr'):
            with self.subTest(suffix=suffix):
                self.fixture('spawn')
                (self.leaf / ('pie-kernel' + suffix)).unlink()
                with self.assertRaises(observations.ObservationError):
                    observations.collect('spawn', self.leaf, static_required=True)

    def test_changed_stream_bytes_are_not_stripped(self):
        self.fixture('spawn')
        (self.leaf / 'pie-kernel.stdout').write_bytes(b'behavior\n\n')
        with self.assertRaisesRegex(observations.ObservationError, 'raw observation differs'):
            observations.collect('spawn', self.leaf, static_required=True)

    def test_omitted_required_scenario_is_rejected(self):
        self.fixture('signal-helpers')
        for path in self.leaf.glob('*-partial-reporting.*'):
            path.unlink()
        with self.assertRaises(observations.ObservationError):
            observations.collect('signal-helpers', self.leaf, static_required=True)

    def test_extra_or_wrong_mode_is_rejected(self):
        self.fixture('spawn', static=False)
        (self.leaf / 'static.stdout').write_bytes(b'behavior\n')
        with self.assertRaisesRegex(observations.ObservationError, 'roster differs'):
            observations.collect('spawn', self.leaf, static_required=False)

    def test_nonzero_supervisor_status_is_rejected_even_when_every_stream_matches(self):
        self.fixture('spawn')
        for path in self.leaf.glob('*.status'):
            path.write_bytes(b'1\n')
        with self.assertRaisesRegex(observations.ObservationError, 'unsuccessful'):
            observations.collect('spawn', self.leaf, static_required=True)

    def test_fexecve_exception_requires_both_exact_source_owned_outcomes(self):
        self.fixture('control-residual')
        candidate = b'owned-process-control-ok fexecve-seccomp=38\n'
        (self.leaf / 'crabc.expected').write_bytes(candidate)
        for path in self.leaf.glob('*.stdout'):
            path.write_bytes(candidate)
        (self.leaf / 'oracle.stdout').write_bytes(b'owned-process-control-ok fexecve-seccomp=9\n')
        result = observations.collect('control-residual', self.leaf, static_required=True)
        self.assertEqual(result['scenarios']['normal']['kind'], 'fexecve-seccomp-profile-difference')
        (self.leaf / 'pie-direct.stdout').write_bytes(b'owned-process-control-ok fexecve-seccomp=95\n')
        with self.assertRaisesRegex(observations.ObservationError, 'exact profile'):
            observations.collect('control-residual', self.leaf, static_required=True)

    def test_static_fork_requires_both_nested_roles_and_exact_modes(self):
        source_root = self.leaf / 'source-root'
        source = source_root / 'compat/x86_64/run_owned_posix_static_fork.sh'
        source.parent.mkdir(parents=True)
        source.write_text('# synthetic source identity\n')
        evidence = self.leaf / 'evidence'
        for role in ('atfork-registry', 'static-posix-forkexec'):
            for mode in ('musl', 'static', 'static-pie'):
                directory = evidence / role / mode
                directory.mkdir(parents=True)
                for suffix, data in (('stdout', b'fork-ok\n'), ('stderr', b''), ('status', b'0\n')):
                    (directory / ('ordinary.' + suffix)).write_bytes(data)
        result = observations.collect('static-fork', evidence, static_required=True, root=source_root)
        self.assertEqual(set(result['scenarios']), {'atfork-registry', 'static-posix-forkexec'})
        (evidence / 'atfork-registry/dynamic').mkdir()
        (evidence / 'atfork-registry/dynamic/ordinary.stdout').write_bytes(b'fork-ok\n')
        with self.assertRaisesRegex(observations.ObservationError, 'roster differs'):
            observations.collect('static-fork', evidence, static_required=True, root=source_root)

    def test_credentials_deliberate_alias_difference_is_retained_and_validated(self):
        self.fixture('credentials-profile')
        names = ('setreuid-current', 'seteuid-current', 'setregid-current', 'setegid-current')
        for mode in ('oracle', *observations.MODES):
            oracle = mode == 'oracle'
            scenario = 'aliases-musl' if oracle else 'aliases-profile'
            stem = observations._stem('credentials-profile', observations.LAYOUTS['credentials-profile'], mode, 'aliases', oracle=oracle)
            detail = 'musl-success' if oracle else 'crabc-eopnotsupp'
            text = ''.join(f'credentials-profile {scenario} {name}: status={0 if oracle else -1} errno={0 if oracle else 95} before=uid=0/0/0,gid=0/0/0 after=uid=0/0/0,gid=0/0/0 ids=unchanged\n' for name in names)
            text += f'credentials-profile aliases: {detail} IDs-unchanged\n'
            (self.leaf / (stem + '.stdout')).write_text(text)
            observations._credentials_helper(observations.ROOT, scenario, self.leaf / (stem + '.stdout'))
        direct_calls = [('setresuid-current', 0, 0), ('setresgid-current', 0, 0),
                        ('setuid-current', 0, 0), ('setgid-current', 0, 0),
                        ('setresuid-all-ones', 0, 0), ('setresgid-all-ones', 0, 0),
                        ('setuid-unmapped', -1, 22), ('setgid-unmapped', -1, 22),
                        ('setgroups-current', -1, 1)]
        direct = ''.join(f'credentials-profile direct {name}: status={status} errno={error} before=uid=0/0/0,gid=0/0/0 after=uid=0/0/0,gid=0/0/0 ids=unchanged\n' for name, status, error in direct_calls)
        direct += 'credentials-profile direct: successful-current/no-change/rejected IDs-unchanged\n'
        for mode in ('oracle', *observations.MODES):
            stem = observations._stem('credentials-profile', observations.LAYOUTS['credentials-profile'], mode, 'direct', oracle=mode == 'oracle')
            (self.leaf / (stem + '.stdout')).write_text(direct)
        result = observations.collect('credentials-profile', self.leaf, static_required=True)
        self.assertEqual(result['scenarios']['aliases']['kind'], 'credentials-profile-difference')
        self.assertNotEqual(result['scenarios']['aliases']['oracle']['stdout']['base64'], result['scenarios']['aliases']['candidates']['static']['stdout']['base64'])
        path = self.leaf / 'static-aliases-profile.stdout'
        path.write_text(path.read_text().replace('errno=95', 'errno=38'))
        with self.assertRaisesRegex(observations.ObservationError, 'transcript validation failed'):
            observations.collect('credentials-profile', self.leaf, static_required=True)


if __name__ == '__main__':
    unittest.main()
