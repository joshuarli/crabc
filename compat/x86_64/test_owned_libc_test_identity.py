#!/usr/bin/env python3
"""Reject execution identities that bypass the atfork source precondition."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def load(name):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


aggregate = load('owned_libc_test')
identity = load('owned_libc_test_identity')
UNIT = 'regression/pthread_atfork-errno-clobber'
FIXTURE = {
    'kind': 'fixed-unprivileged-identity', 'uid': 65534, 'gid': 65534,
    'supplementary_groups': [],
    'required_zero_capability_sets': ['inheritable', 'permitted', 'effective', 'ambient'],
    'source_requirement': 'RLIMIT_NPROC=0 must reject fork before checking atfork errno preservation',
}


def snapshot(uid=0, gid=0):
    return {
        'resuid': [uid] * 3, 'resgid': [gid] * 3, 'groups': [],
        'proc': {
            'uids': [uid] * 4, 'gids': [gid] * 4, 'groups': [],
            'capabilities': {
                'inheritable': '0000000000000000', 'permitted': '0000000000000000',
                'effective': '0000000000000000', 'bounding': '00000000a80425fb',
                'ambient': '0000000000000000',
            },
        },
    }


class OwnedLibcTestIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.work = Path(self.temporary.name)
        self.root = self.work / 'execution' / UNIT / 'candidate'
        self.source = {'path': str(self.work / 'source-prepared/src' / (UNIT + '.c')), 'sha256': 'a' * 64}
        self.receipt = {
            'schema': 'crabc.x86_64-owned-libc-test-execution-identity/v1',
            'unit': UNIT, 'root': str(self.root), 'fixture': FIXTURE,
            'source': self.source, 'command': ['/runtest', '-w', '', '/' + UNIT],
            'before_drop': snapshot(), 'before_exec': snapshot(65534, 65534),
        }

    def tearDown(self):
        self.temporary.cleanup()

    def validate(self, receipt):
        aggregate.validate_execution_identity_receipt(
            receipt, root=self.root, unit_id=UNIT, source=self.source, parent_before=snapshot(),
        )

    def test_only_atfork_resource_limit_source_selects_fixed_identity(self):
        self.assertEqual(aggregate.execution_identity_fixture_for_unit(UNIT), FIXTURE)
        for unit in ['regression/raise-race', 'functional/pthread_atfork', 'functional/argv', UNIT + '-other']:
            self.assertIsNone(aggregate.execution_identity_fixture_for_unit(unit))
        self.validate(self.receipt)

    def test_receipt_rejects_identity_that_can_bypass_process_limit(self):
        changes = [
            ('real uid', lambda r: r['before_exec']['resuid'].__setitem__(0, 0)),
            ('filesystem uid', lambda r: r['before_exec']['proc']['uids'].__setitem__(3, 0)),
            ('saved gid', lambda r: r['before_exec']['resgid'].__setitem__(2, 0)),
            ('filesystem gid', lambda r: r['before_exec']['proc']['gids'].__setitem__(3, 0)),
            ('supplementary group', lambda r: r['before_exec']['groups'].append(0)),
            ('proc group', lambda r: r['before_exec']['proc']['groups'].append(0)),
            ('effective capability', lambda r: r['before_exec']['proc']['capabilities'].__setitem__('effective', '0000000001000000')),
            ('ambient capability', lambda r: r['before_exec']['proc']['capabilities'].__setitem__('ambient', '0000000001000000')),
            ('bounding mutation', lambda r: r['before_exec']['proc']['capabilities'].__setitem__('bounding', '0000000000000000')),
            ('parent mutation', lambda r: r['before_drop']['groups'].append(0)),
        ]
        for label, change in changes:
            with self.subTest(label=label):
                receipt = copy.deepcopy(self.receipt)
                change(receipt)
                with self.assertRaises(aggregate.EvidenceError):
                    self.validate(receipt)

    def test_receipt_rejects_replaced_source_unit_or_target(self):
        for field, value in [
            ('unit', 'regression/raise-race'), ('root', str(self.root.parent / 'oracle')),
            ('source', {**self.source, 'sha256': 'b' * 64}),
            ('command', ['/runtest', '/' + UNIT]), ('fixture', {**FIXTURE, 'uid': 1}),
        ]:
            with self.subTest(field=field):
                receipt = copy.deepcopy(self.receipt)
                receipt[field] = value
                with self.assertRaises(aggregate.EvidenceError):
                    self.validate(receipt)

    def test_proc_status_parser_requires_all_identity_and_capability_fields(self):
        status = '\n'.join([
            'Uid:\t65534\t65534\t65534\t65534', 'Gid:\t65534\t65534\t65534\t65534',
            'Groups:\t', 'CapInh:\t0000000000000000', 'CapPrm:\t0000000000000000',
            'CapEff:\t0000000000000000', 'CapBnd:\t00000000a80425fb', 'CapAmb:\t0000000000000000',
        ])
        self.assertEqual(identity.parse_proc_identity(status), snapshot(65534, 65534)['proc'])
        for invalid in [status.replace('CapAmb:', 'Missing:'), status + '\nUid:\t0\t0\t0\t0', status.replace('65534\t65534\t65534\t65534', '65534', 1)]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                identity.parse_proc_identity(invalid)

    def run_observation(self, corruption=None, parent_after=None):
        self.root.parent.mkdir(parents=True)
        source = Path(self.source['path'])
        source.parent.mkdir(parents=True)
        source.write_text('unchanged pinned atfork source\n')
        source_record = aggregate.artifact(source, 'test source')
        output = self.root.parent / 'candidate.stdout'
        captured = []

        def capture(command, **arguments):
            captured.append((command, arguments))
            receipt = copy.deepcopy(self.receipt)
            receipt['source'] = source_record
            if corruption == 'identity':
                receipt['before_exec']['proc']['uids'][3] = 0
            if corruption != 'missing':
                output.with_suffix('.identity.json').write_text(json.dumps(receipt))
            if corruption == 'source':
                source.write_text('replaced source\n')
            return {'exit_status': 0, 'command': command}

        with patch.object(aggregate, 'find_control_tool', side_effect=[Path('/usr/bin/timeout'), Path('/usr/bin/python3')]), patch.object(
            aggregate, 'run_capture', side_effect=capture
        ), patch.object(aggregate, 'identity_helper_module', return_value=identity), patch.object(
            identity, 'observe_process_identity', side_effect=[snapshot(), parent_after or snapshot()]
        ):
            record, binding = aggregate.execute_with_identity(root=self.root, unit_id=UNIT, output=output, work=self.work)
        return record, binding, captured

    def test_selected_runtime_retains_controls_and_exact_upstream_invocation(self):
        record, binding, captured = self.run_observation()
        helper = str(aggregate.EXECUTION_IDENTITY_HELPER)
        self.assertEqual(record['exit_status'], 0)
        self.assertEqual(captured[0][0], [
            '/usr/bin/timeout', '20', '/usr/bin/python3', '-B', helper,
            '--root', str(self.root), '--receipt', str(self.root.parent / 'candidate.identity.json'), '--unit', UNIT,
        ])
        self.assertEqual(captured[0][1]['environment'], aggregate.clean_environment())
        self.assertEqual(binding['fixture'], FIXTURE)
        self.assertEqual(binding['source'], binding['source_after'])
        self.assertEqual(binding['parent'], {'before': snapshot(), 'after': snapshot(), 'unchanged': True})
        for name in ('helper', 'python'):
            control = binding[name]
            self.assertEqual(control['source'], control['after'])
            self.assertEqual(Path(control['source']['path']).read_bytes(), Path(control['retained']['path']).read_bytes())

    def test_zero_exit_cannot_hide_missing_identity_receipt(self):
        with self.assertRaises(aggregate.EvidenceError):
            self.run_observation('missing')

    def test_zero_exit_cannot_hide_wrong_filesystem_uid(self):
        with self.assertRaises(aggregate.EvidenceError):
            self.run_observation('identity')

    def test_zero_exit_cannot_hide_changed_source(self):
        with self.assertRaises(aggregate.EvidenceError):
            self.run_observation('source')

    def test_zero_exit_cannot_hide_changed_producer_identity(self):
        changed = snapshot()
        changed['groups'] = [0]
        changed['proc']['groups'] = [0]
        with self.assertRaises(aggregate.EvidenceError):
            self.run_observation(parent_after=changed)

    def test_helper_has_no_caller_selected_identity_or_command(self):
        for arguments in [
            ['--root', str(self.root), '--receipt', str(self.root.parent / 'candidate.identity.json'), '--unit', 'regression/raise-race'],
            ['--root', str(self.root), '--receipt', str(self.root.parent / 'candidate.identity.json'), '--unit', UNIT, '--uid', '0'],
            ['--root', str(self.root), '--receipt', str(self.root.parent / 'candidate.identity.json'), '--unit', UNIT, '/bin/sh'],
        ]:
            with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                identity.parse_arguments(arguments)


if __name__ == '__main__':
    unittest.main()
