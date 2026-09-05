"""Read finite POSIX replay observations directly from retained raw files.

This is an observation boundary, not a product/link qualification boundary.
Every ordinary comparison preserves bytes. The named profile exceptions retain
both transcripts; none is a general normalization or successful-log fallback.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
MODES = ('static', 'static-pie', 'pie-kernel', 'pie-direct', 'non-pie-kernel', 'non-pie-direct')
IO_SCENARIOS = tuple('owned_' + name + '_cancellation' for name in (
    'io', 'descriptor', 'socket', 'sleep_wait', 'open_lock', 'semaphore_wait',
    'semaphore', 'signal_wait', 'entropy', 'sysv_message'))
FORK_SCENARIOS = ('main', 'worker', 'kernel-main', 'kernel-worker', 'recursive',
                  'abandoned', 'failure', 'finalizer-single', 'finalizer-held', 'worker-survivor')


class ObservationError(ValueError):
    """The retained files cannot establish the finite replay contract."""


@dataclass(frozen=True)
class Layout:
    runner: str
    scenarios: tuple[str, ...] = ('normal',)
    static: str = '{mode}{scenario_suffix}'
    dynamic: str = '{mode}{scenario_suffix}'
    oracle: str = 'oracle{scenario_suffix}'
    stderr_suffix: str = '.stderr'
    status_suffix: str = '.status'


LAYOUTS = {
    'legacy-filesystem': Layout('posix_filesystem', ('aliases', 'directory', 'traversal', 'temporary', 'handles'), 'static-{mode}-{scenario}', 'dynamic-{mode}-{scenario}', 'oracle-{scenario}'),
    'control-residual': Layout('process_control'),
    'credentials-profile': Layout('credentials_profile', ('direct', 'aliases'), '{mode}-{scenario}', 'dynamic-{mode}-{scenario}', 'oracle-{scenario}', status_suffix='.stdout.status'),
    'environment-lifecycle': Layout('environment_lifecycle', ('normal', 'allocation-failure'), '{mode}-{scenario}', 'dynamic-{mode}-{scenario}', 'oracle-{scenario}', '.stdout.stderr', '.stdout.status'),
    'signal-full': Layout('posix_signals', ('sets', 'actions-masks', 'queue-delivery', 'suspend-delivery', 'sigpause-cancellation', 'sigsuspend-cancellation', 'interrupt-bookkeeping', 'alternate-stack', 'alternate-minimum', 'signalfd'), '{mode}-{scenario}', '{mode}-{scenario}', 'oracle-{scenario}', status_suffix='.status.json'),
    'kernel-residual': Layout('kernel_residual', ('cpucount', 'configuration', 'sysconf-signal-stack', 'hostid-membarrier', 'personality', 'prctl', 'scheduler', 'syscall', 'ulimit', 'uts-namespace', 'uts-seccomp', 'all'), 'static-{mode}-{scenario}', 'dynamic-{mode}-{scenario}', 'oracle-{scenario}'),
    'global-state-composition': Layout('posix_composition'),
    'linux-control': Layout('linux_control', stderr_suffix='.stdout.stderr', status_suffix='.stdout.status', dynamic='dynamic-{mode}'),
    'syslog': Layout('syslog', ('normal', 'worker', 'fork', 'cancellation'), 'static-{mode}-kernel-{scenario}', 'dynamic-{mode}-{scenario}', 'oracle-kernel-{scenario}'),
    'system-cancellation': Layout('system_cancellation', ('normal', 'failure', 'timeout'), 'static-{mode}-{scenario}', 'dynamic-{mode}-{scenario}', 'oracle-{scenario}'),
    'spawn': Layout('dynamic_spawn'),
    'process-trio': Layout('process_trio', ('ordinary', 'errors', 'redirect'), 'static-{mode}-{scenario}', 'dynamic-{mode}-{scenario}', 'oracle-{scenario}'),
    'signal-helpers': Layout('signal_helpers', ('actions', 'interrupt', 'failed-interrupt', 'restart', 'partial-action', 'cancellation', 'reporting', 'partial-reporting'), '{mode}-{scenario}', '{mode}-{scenario}', 'oracle-{scenario}'),
    'pthread-signal': Layout('pthread_signal'),
    'io-cancellation': Layout('dynamic_io_cancellation', IO_SCENARIOS, '{scenario}-{mode}', '{scenario}-{mode}', '{scenario}-oracle'),
    'posix-timers': Layout('posix_timers', ('ordinary',), '{mode}-{scenario}', 'dynamic-{mode}-{scenario}', 'oracle-{scenario}', '.stdout.stderr', '.stdout.status'),
    'fork': Layout('dynamic_fork', FORK_SCENARIOS),
    'static-fork': Layout('posix_static_fork', ('atfork-registry', 'static-posix-forkexec')),
}


def _file(path: Path, base: Path) -> tuple[bytes, dict]:
    try:
        if path.absolute() != path.resolve(strict=True) or not path.is_file():
            raise ObservationError(f'not a physical regular artifact: {path}')
        raw = path.read_bytes()
    except OSError as error:
        raise ObservationError(f'missing or unreadable artifact: {path}') from error
    return raw, {'path': path.relative_to(base).as_posix(), 'size': len(raw),
                 'sha256': hashlib.sha256(raw).hexdigest()}


def _observation(leaf: Path, stem: str, layout: Layout, expected: set[str], *, success=True) -> tuple[dict, dict]:
    raw, record = {}, {}
    for stream, suffix in (('stdout', '.stdout'), ('stderr', layout.stderr_suffix), ('status', layout.status_suffix)):
        name = stem + suffix
        expected.add(name)
        data, identity = _file(leaf / name, leaf)
        raw[stream] = data
        record[stream] = dict(identity, base64=base64.b64encode(data).decode('ascii'))
    if success:
        required = b'{"returncode": 0, "timed_out": false}\n' if layout.status_suffix == '.status.json' else b'0\n'
        if raw['status'] != required:
            raise ObservationError(f'unsuccessful or malformed status: {stem}')
    return raw, record


def _credentials_helper(root: Path, scenario: str, transcript: Path) -> None:
    """Execute only the source-owned transcript validator, never the runner."""
    source = root / 'compat/x86_64/run_owned_credentials_profile.sh'
    text = _file(source, root)[0].decode('utf-8')
    marker = 'validate_transcript() {'
    try:
        helper = text.split(marker, 1)[1].split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
    except IndexError as error:
        raise ObservationError('credentials source transcript helper is absent') from error
    result = subprocess.run([sys.executable, '-B', '-c', helper, scenario, str(transcript)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise ObservationError('credentials source transcript validation failed: ' + result.stderr.decode(errors='replace'))


def _stem(case: str, layout: Layout, mode: str, scenario: str, *, oracle=False) -> str:
    if case == 'credentials-profile' and scenario == 'aliases':
        scenario = 'aliases-musl' if oracle else 'aliases-profile'
    if case == 'system-cancellation' and mode.endswith('-kernel'):
        mode = mode.removesuffix('-kernel')
    if case == 'io-cancellation':
        mode = mode.replace('-direct', '-interpreter')
    if case == 'posix-timers' and not oracle and mode not in MODES[:2]:
        linkage, entry = mode.rsplit('-', 1)
        return f'{"direct" if entry == "direct" else "dynamic"}-{linkage}-{scenario}'
    template = layout.oracle if oracle else layout.static if mode in MODES[:2] else layout.dynamic
    return template.format(mode=mode, scenario=scenario, scenario_suffix='' if layout.scenarios == ('normal',) else '-' + scenario)


def collect(case: str, leaf_root: Path, *, static_required: bool, root: Path = ROOT) -> dict:
    """Require the exact source-defined scenario and entry roster for one replay.

    Paths in returned records are relative to their evidence/source roots. A
    caller must additionally bind the fixture tree, compilation, links and
    products; successful observations alone do not establish those identities.
    """
    if case not in LAYOUTS or type(static_required) is not bool:
        raise ObservationError('unknown workload or non-boolean static requirement')
    leaf, root = Path(leaf_root).absolute(), Path(root).absolute()
    if leaf != leaf.resolve() or not leaf.is_dir():
        raise ObservationError('leaf must be a physical directory')
    layout = LAYOUTS[case]
    modes = MODES if static_required else MODES[2:]
    if case == 'static-fork':
        if not static_required:
            raise ObservationError('static fork requires the static product replay')
        return _static_fork(leaf, root, layout)
    if case == 'fork':
        if static_required:
            raise ObservationError('dynamic fork has no static entries')
        return _fork(leaf, root, layout)
    expected: set[str] = set()
    rows = {}
    for scenario in layout.scenarios:
        oracle_stem = _stem(case, layout, '', scenario, oracle=True)
        oracle_raw, oracle = _observation(leaf, oracle_stem, layout, expected)
        if case == 'credentials-profile':
            _credentials_helper(root, 'aliases-musl' if scenario == 'aliases' else scenario, leaf / (oracle_stem + '.stdout'))
        row = {'kind': 'differential', 'oracle': oracle, 'candidates': {}}
        for mode in modes:
            stem = _stem(case, layout, mode, scenario)
            raw, candidate = _observation(leaf, stem, layout, expected)
            reference = oracle_raw
            if case == 'posix-timers' and mode not in MODES[:2]:
                reference, dynamic_oracle = _observation(leaf, 'oracle-dynamic', layout, expected)
                row['dynamic_oracle'] = dynamic_oracle
            if case == 'credentials-profile' and scenario == 'aliases':
                _credentials_helper(root, 'aliases-profile', leaf / (stem + '.stdout'))
                if raw['stderr'] != b'' or oracle_raw['stderr'] != b'':
                    raise ObservationError('credentials aliases stderr must be empty')
                row['kind'] = 'credentials-profile-difference'
            elif case == 'control-residual':
                _control_difference(root, leaf, oracle_raw, raw)
                row['kind'] = 'fexecve-seccomp-profile-difference'
            elif raw != reference:
                raise ObservationError(f'raw observation differs: {case}/{scenario}/{mode}')
            row['candidates'][mode] = candidate
        rows[scenario] = row
    supplemental = {}
    if case == 'posix-timers':
        supplemental = _timers(leaf, root, layout, modes, expected)
    if case == 'global-state-composition':
        supplemental['logger-wire'] = {}
        for mode in ('oracle', *modes):
            name = mode + '.log-wire'
            expected.add(name)
            _, supplemental['logger-wire'][mode] = _file(leaf / name, leaf)
    _roster(leaf, expected, case)
    sources = _sources(root, layout)
    return {'case': case, 'scenarios': rows, 'supplemental': supplemental, 'sources': sources}


def _control_difference(root, leaf, oracle, candidate):
    oracle_line = b'owned-process-control-ok fexecve-seccomp=9\n'
    candidate_line = b'owned-process-control-ok fexecve-seccomp=38\n'
    source = _file(root / 'compat/x86_64/run_owned_process_control.sh', root)[0]
    if oracle_line.rstrip() not in source or candidate_line.rstrip() not in source:
        raise ObservationError('fexecve source profile expectation changed')
    if _file(leaf / 'crabc.expected', leaf)[0] != candidate_line:
        raise ObservationError('fexecve retained profile expectation changed')
    if oracle != {'stdout': oracle_line, 'stderr': b'', 'status': b'0\n'} or candidate != {'stdout': candidate_line, 'stderr': b'', 'status': b'0\n'}:
        raise ObservationError('fexecve exact profile observation changed')


def _sources(root, layout):
    relative = 'compat/x86_64/run_' + ('general_dynamic_fork' if layout.runner == 'dynamic_fork' else 'owned_' + layout.runner) + '.sh'
    paths = [relative]
    if layout.runner == 'posix_signals':
        paths += ['compat/x86_64/owned_posix_signals.py', 'compat/x86_64/owned-posix-signals.toml']
    if layout.runner == 'posix_timers':
        paths += ['compat/x86_64/owned_posix_timers_probe.c', 'compat/x86_64/owned_posix_timers_tls.c',
                  'ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs',
                  'ldso/src/x86_64_runtime_tls_view.rs', 'ldso/src/x86_64_general_relocation_tests.rs']
    if layout.runner == 'dynamic_fork':
        paths += ['compat/x86_64/owned_dynamic_fork_evidence.py',
                  'compat/x86_64/general_dynamic_fork_consumer.c', 'compat/x86_64/general_dynamic_fork_library.c']
    return {path: _file(root / path, root)[1] for path in paths}


def _roster(leaf, expected, case):
    # Compilation and deliberately rejected audit invocations have their own
    # source-bound artifacts; they are not runtime scenario observations.
    auxiliary = re.compile(r'^(?:.*(?:compile|headers(?:\.i)?|link|build|builtin)|forged-.*|manifest-tamper|compile)\.(?:stdout|stderr|status)(?:\.(?:stderr|status))?$')
    observed = {p.name for p in leaf.iterdir() if re.search(r'\.(?:stdout|stderr|status|status\.json)$', p.name)
                and not auxiliary.fullmatch(p.name)
                and not (case == 'signal-full' and re.fullmatch(r'(?:link-(?:static|static-pie|pie|non-pie)|dynamic-(?:pie|non-pie)\.elf|(?:static|static-pie)\.elf)\.(?:stdout|stderr)', p.name))}
    wanted = {name for name in expected if re.search(r'\.(?:stdout|stderr|status|status\.json)$', name)}
    if observed != wanted:
        raise ObservationError(f'{case} observation roster differs: missing={sorted(wanted-observed)}, extra={sorted(observed-wanted)}')



def _timer_unit_transcript(root, stem, raw):
    """A successful Rust test process must actually execute its named check."""
    source, name = {
        'tls-reset-tests': ('ldso/src/x86_64_runtime_tls_view.rs',
            'x86_64_initial_graph::x86_64_runtime_tls_view::timer_reset_tests::timer_reset_restores_initial_and_runtime_images_without_replacing_tcb_or_dtv'),
        'tls-import-tests': ('ldso/src/x86_64_general_relocation_tests.rs',
            'x86_64_initial_graph::x86_64_general_relocation::tests::installed_runtime_function_imports_validate_shape_before_any_graph_write'),
    }[stem]
    function = name.rsplit('::', 1)[1]
    if ('fn ' + function + '(').encode() not in _file(root / source, root)[0]:
        raise ObservationError('timer named unit-test source changed')
    pattern = (rb'\nrunning 1 test\ntest ' + re.escape(name.encode()) +
               rb' \.\.\. ok\n\ntest result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; '
               rb'[0-9]+ filtered out; finished in [0-9]+\.[0-9]+s\n\n')
    if raw['stderr'] or re.fullmatch(pattern, raw['stdout']) is None:
        raise ObservationError('timer unit transcript did not execute exactly the required test')


def _timers(leaf, root, layout, modes, expected):
    supplemental = {'candidate-reclamation': {}, 'runtime-unit-checks': {}, 'oracle-race-observations': {}}
    for mode in modes:
        stem = _stem('posix-timers', layout, mode, 'failure')
        raw, supplemental['candidate-reclamation'][mode] = _observation(leaf, stem, layout, expected)
        if raw['stdout'] != b'creation failure reclaims detached workers under bounded address space\n' or raw['stderr']:
            raise ObservationError('timer reclamation transcript changed')
    for stem in ('tls-reset-tests', 'tls-import-tests'):
        raw, supplemental['runtime-unit-checks'][stem] = _observation(leaf, stem, layout, expected)
        _timer_unit_transcript(root, stem, raw)
    race_layout = Layout('posix_timers')
    for attempt in range(1, 17):
        stem = f'oracle-failure-{attempt}'
        raw, record = _observation(leaf, stem, race_layout, expected, success=False)
        if raw['status'] not in (b'0\n', b'-9\n'):
            raise ObservationError('timer oracle race has unexpected terminal status')
        proc = leaf / (stem + '.json')
        if raw['status'] == b'-9\n':
            _, record['proc'] = _file(proc, leaf)
        elif proc.exists():
            raise ObservationError('completed timer oracle has a timeout witness')
        supplemental['oracle-race-observations'][str(attempt)] = record
        if raw['status'] == b'-9\n':
            break
    return supplemental



def _fork_survivor(leaf, stem, semantic, expected):
    """Preserve the live child PID; compare only its exact protocol body.

    The runner must observe the child PID before releasing the surviving
    worker. PIDs differ across executions, so they cannot participate in the
    musl byte differential. Every byte outside that one decimal PID remains
    fixed, and the separately retained semantic stream must equal its body.
    """
    name = stem + '.raw.stdout'
    expected.add(name)
    raw, identity = _file(leaf / name, leaf)
    body = b'dynamic fork survives adopted main exit: ok\n'
    match = re.fullmatch(rb'([1-9][0-9]*)\n' + re.escape(body), raw)
    if match is None or semantic['stdout'] != body:
        raise ObservationError('dynamic fork survivor raw protocol or semantic projection differs')
    return {'survivor_pid': int(match.group(1)),
            'raw_stdout': dict(identity, base64=base64.b64encode(raw).decode('ascii'))}


def _fork(leaf, root, layout):
    expected, rows = set(), {}
    for mode in ('pie', 'non-pie'):
        for scenario in FORK_SCENARIOS:
            oracle_raw, oracle = _observation(leaf, f'oracle-{mode}-{scenario}', layout, expected)
            row = {'kind': 'differential', 'oracle': oracle, 'candidates': {}, 'owned-layout-witnesses': {}}
            if scenario == 'worker-survivor':
                oracle['protocol'] = _fork_survivor(leaf, f'oracle-{mode}-{scenario}', oracle_raw, expected)
                row['kind'] = 'pid-protocol-semantic-projection'
            for entry in ('kernel', 'direct'):
                raw, record = _observation(leaf, f'semantic-{mode}-{entry}-{scenario}', layout, expected)
                if raw != oracle_raw:
                    raise ObservationError('dynamic fork semantic observation differs')
                if scenario == 'worker-survivor':
                    record['protocol'] = _fork_survivor(leaf, f'semantic-{mode}-{entry}-{scenario}', raw, expected)
                row['candidates'][entry] = record
                witness_raw, witness = _observation(leaf, f'owned-layout-{mode}-{entry}-{scenario}', layout, expected)
                if scenario == 'worker-survivor':
                    witness['protocol'] = _fork_survivor(leaf, f'owned-layout-{mode}-{entry}-{scenario}', witness_raw, expected)
                row['owned-layout-witnesses'][entry] = witness
            rows[f'{mode}/{scenario}'] = row
    _roster(leaf, expected, 'fork')
    return {'case': 'fork', 'scenarios': rows, 'supplemental': {}, 'sources': _sources(root, layout)}


def _static_fork(leaf, root, layout):
    rows = {}
    for role in layout.scenarios:
        role_root = leaf / role
        if {path.name for path in role_root.iterdir() if path.is_dir()} != {'musl', 'static', 'static-pie'}:
            raise ObservationError(f'static fork mode roster differs: {role}')
        expected = set()
        oracle_raw, oracle = _observation(leaf, f'{role}/musl/ordinary', layout, expected)
        row = {'kind': 'differential', 'oracle': oracle, 'candidates': {}}
        for mode in MODES[:2]:
            raw, record = _observation(leaf, f'{role}/{mode}/ordinary', layout, expected)
            if raw != oracle_raw:
                raise ObservationError(f'static fork raw observation differs: {role}/{mode}')
            row['candidates'][mode] = record
        observed = {path.relative_to(leaf).as_posix() for path in role_root.rglob('*')
                    if re.search(r'\.(?:stdout|stderr|status)$', path.name)}
        if observed != expected:
            raise ObservationError(f'static fork observation roster differs: {role}')
        rows[role] = row
    actual_roles = {path.name for path in leaf.iterdir() if path.is_dir()}
    # The runner owns precisely two nested fixture leaves. Product payloads
    # are supplied inputs and must not appear as an extra execution mode here.
    if actual_roles != set(layout.scenarios):
        raise ObservationError('static fork role roster differs')
    return {'case': 'static-fork', 'scenarios': rows, 'supplemental': {}, 'sources': _sources(root, layout)}
