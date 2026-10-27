from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import subprocess
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import owned_feature_alias_receipt as receipt
import native_abi_selection as selection
import crabc_cc_owned_dynamic as dynamic_driver

PRODUCT_SPEC = importlib.util.spec_from_file_location("feature_alias_product_fixtures", ROOT / "compat/x86_64/tests/test_owned_posix_product_evidence.py")
PRODUCT_FIXTURE = importlib.util.module_from_spec(PRODUCT_SPEC)
PRODUCT_SPEC.loader.exec_module(PRODUCT_FIXTURE)
POSIX_SPEC = importlib.util.spec_from_file_location("feature_alias_posix_fixtures", ROOT / "compat/x86_64/tests/test_native_abi_posix_sysv_signal_attachment.py")
POSIX_FIXTURE = importlib.util.module_from_spec(POSIX_SPEC)
POSIX_SPEC.loader.exec_module(POSIX_FIXTURE)


def symbol(name, binding='GLOBAL', visibility='DEFAULT', value='0000000000000000', section='2'):
    return {'name': name, 'type': 'FUNC', 'binding': binding, 'visibility': visibility,
            'section_index': section, 'value': value, 'size_bytes': 4, 'version': None, 'version_default': False}


def facts(public='execvpe', target='__execvpe', *, shared=False):
    hidden = target.startswith('__')
    rows = [symbol(public, 'WEAK'), symbol(target, 'LOCAL' if shared and hidden else 'GLOBAL',
                                          'HIDDEN' if hidden else 'DEFAULT')]
    result = {'member_index': None if shared else 0, 'member': None if shared else 'owner.o',
              'sections': [{'index': 2, 'type': 'PROGBITS', 'flags': 'AX'}],
              'symbol_tables': [{'name': '.symtab', 'section_index': 3, 'rows': rows}]}
    if shared:
        result['symbol_tables'].append({'name': '.dynsym', 'section_index': 4, 'rows': [copy.deepcopy(rows[0])]})
    return result if shared else [result]


class FeatureAliasReceiptTests(unittest.TestCase):
    def test_linked_aliases_are_local_and_keep_their_input_visibility(self):
        observed = facts(shared=True)
        observed['symbol_tables'][0]['rows'][0]['binding'] = 'LOCAL'
        receipt.alias_pair(observed, 'execvpe', '__execvpe', placement=receipt.AliasPlacement.EXECUTABLE)
        observed['symbol_tables'][0]['rows'][1]['visibility'] = 'DEFAULT'
        with self.assertRaises(receipt.FeatureAliasError):
            receipt.alias_pair(observed, 'execvpe', '__execvpe', placement=receipt.AliasPlacement.EXECUTABLE)

    def test_override_requires_strong_input_and_local_static_output(self):
        observed = facts()
        override = observed[0]['symbol_tables'][0]['rows'][0]
        override['binding'] = 'GLOBAL'
        receipt.require_override_definitions(observed, 'exec', receipt.OverrideBinding.GLOBAL)
        override['binding'] = 'LOCAL'
        receipt.require_override_definitions(observed, 'exec', receipt.OverrideBinding.LOCAL)
        with self.assertRaises(receipt.FeatureAliasError):
            receipt.require_override_definitions(observed, 'exec', receipt.OverrideBinding.GLOBAL)

    def test_each_current_alias_requirement_retains_its_complete_source_contract(self):
        contract = selection.load_contract()
        expanded = selection.expand_obligations(contract, selection.load_source_inputs(contract, selection.CONTRACT_PATH))
        requirements = receipt.alias_requirements()
        self.assertEqual(set(requirements), {'__sysv_signal', 'bsd_signal', 'endpwent', 'execvpe', 'mkostemps', 'setnetent'})
        for row in expanded:
            name = row['identity']['name']
            if name in requirements:
                self.assertEqual(row['function_alias_requirements'], [requirements[name]])

    def test_equal_zero_values_in_different_member_or_section_are_not_aliases(self):
        receipt.alias_pair(facts(), 'execvpe', '__execvpe')
        for change in ('member', 'section'):
            observed = facts()
            if change == 'member':
                other = copy.deepcopy(observed[0])
                other['member_index'] = 1
                other['symbol_tables'][0]['rows'] = [observed[0]['symbol_tables'][0]['rows'].pop()]
                observed.append(other)
            else:
                observed[0]['sections'].append({'index': 5, 'type': 'PROGBITS', 'flags': 'AX'})
                observed[0]['symbol_tables'][0]['rows'][1]['section_index'] = '5'
            with self.subTest(change=change), self.assertRaisesRegex(receipt.FeatureAliasError, 'definition domain'):
                receipt.alias_pair(observed, 'execvpe', '__execvpe')

    def test_shared_local_hidden_target_is_valid_but_dynamic_leak_is_rejected(self):
        observed = facts(shared=True)
        pair = receipt.alias_pair(observed, 'execvpe', '__execvpe', placement=receipt.AliasPlacement.SHARED)
        self.assertEqual(pair['provider']['row']['binding'], 'LOCAL')
        observed['symbol_tables'][1]['rows'].append(copy.deepcopy(observed['symbol_tables'][0]['rows'][1]))
        with self.assertRaisesRegex(receipt.FeatureAliasError, 'dynamically exported'):
            receipt.alias_pair(observed, 'execvpe', '__execvpe', placement=receipt.AliasPlacement.SHARED)

    def test_alias_metadata_duplicate_and_forwarding_drift_fail(self):
        for field, value in (('binding', 'GLOBAL'), ('visibility', 'HIDDEN'), ('type', 'NOTYPE'), ('value', '0000000000000001')):
            observed = facts()
            observed[0]['symbol_tables'][0]['rows'][0][field] = value
            with self.subTest(field=field), self.assertRaises(receipt.FeatureAliasError):
                receipt.alias_pair(observed, 'execvpe', '__execvpe')
        observed = facts()
        observed[0]['symbol_tables'][0]['rows'].append(copy.deepcopy(observed[0]['symbol_tables'][0]['rows'][0]))
        with self.assertRaisesRegex(receipt.FeatureAliasError, 'ambiguous'):
            receipt.alias_pair(observed, 'execvpe', '__execvpe')

    def test_owned_runtime_reuses_only_exact_prepared_release_feature_command(self):
        command = ['rustup', 'run', 'pinned', 'cargo', 'rustc', '-p', 'crabc-libc',
                   '--no-default-features', '--features', 'x86-owned-static-runtime', '--release']
        record = {'build_profile': 'release', 'commands': {'libc': command}}
        self.assertEqual(receipt.owned_runtime_command(record), command)
        for changed in (command[:-1], command + ['--features', 'x86-crypt'],
                        [arg.replace('x86-owned-static-runtime', 'x86-owned-static-native-shadow') for arg in command],
                        [arg.replace('crabc-libc', 'crabc-builtins') for arg in command]):
            with self.subTest(changed=changed), self.assertRaises(receipt.FeatureAliasError):
                receipt.owned_runtime_command({'build_profile': 'release', 'commands': {'libc': changed}})
        with self.assertRaises(receipt.FeatureAliasError):
            receipt.owned_runtime_command({'build_profile': 'release', 'commands': {}})

    def test_dynamic_product_requires_the_accepted_backend_and_its_exact_feature_route(self):
        command = ['cargo', 'rustc', '--no-default-features', '--release', '--features', 'x86-owned-dynamic-runtime']
        self.assertEqual(receipt.dynamic_runtime_command({'allocator_backend': 'accepted-c', 'libc_command': command}), command)
        for backend, argv in (('native-shadow', command), ('accepted-c', command[:-1] + ['x86-owned-dynamic-native-shadow']),
                              ('accepted-c', command + ['--features', 'x86-owned-dynamic-runtime'])):
            with self.subTest(backend=backend, argv=argv), self.assertRaises(receipt.FeatureAliasError):
                receipt.dynamic_runtime_command({'allocator_backend': backend, 'libc_command': argv})

    def test_selected_source_or_static_product_substitution_fails_before_workload_replay(self):
        static, dynamic, preparation = ROOT / '.work/static', ROOT / '.work/dynamic', ROOT / '.work/preparation.json'
        for source, product in (('stale', '.work/static'), ('current', '.work/another-static')):
            prep = {'source': {'content_sha256': source}, 'products': {'primary': {'path': product}}}
            with self.subTest(source=source, product=product), \
                    mock.patch.object(receipt.static_products, 'validate_receipt', return_value=prep), \
                    mock.patch.object(receipt.qualification, 'source_digest', return_value='current'):
                with self.assertRaises(receipt.FeatureAliasError):
                    receipt.source_product_seal(static, dynamic, preparation)

    def test_copied_payload_rejects_mode_drift_with_unchanged_runtime_bytes(self):
        (ROOT / '.work/tmp').mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work/tmp') as temporary:
            work = Path(temporary)
            dynamic = work / 'dynamic'
            (dynamic / 'lib').mkdir(parents=True)
            loader = dynamic / 'lib/loader'
            loader.write_bytes(b'selected loader')
            loader.chmod(0o755)
            manifest = dynamic / 'manifest.json'
            manifest.write_text('{"symlinks":{}}')
            binary = work / 'binary'
            binary.write_bytes(b'selected consumer')
            binary.chmod(0o755)
            root = work / 'copied'
            with mock.patch.object(receipt.products, '_validate_dynamic_product',
                                   return_value=(manifest, {'lib/loader': receipt.inventory.sha256(loader)})):
                receipt.copied_payload(dynamic, root, binary, capture=True)
                (root / 'lib/loader').chmod(0o644)
                with self.assertRaisesRegex(receipt.FeatureAliasError, 'payload mode differs'):
                    receipt.copied_payload(dynamic, root, binary, capture=False)

    def test_all_collector_compile_commands_pass_the_real_installed_driver_parser(self):
        fixture = PRODUCT_FIXTURE.OwnedPosixProductEvidenceTests('test_accepts_each_sealed_linkage_and_returns_bound_identity')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        headers = ('errno.h', 'signal.h', 'pwd.h', 'fcntl.h', 'pthread.h', 'stdio.h', 'stdlib.h', 'string.h',
                   'sys/prctl.h', 'sys/resource.h', 'sys/stat.h', 'sys/syscall.h', 'sys/wait.h', 'unistd.h',
                   'limits.h', 'sched.h', 'spawn.h', 'stddef.h', 'sys/types.h', 'sys/utsname.h', 'stdint.h', 'netdb.h')
        for header in headers:
            path = fixture.dynamic / 'usr/include' / header
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('controlled installed header\n')
        fixture.refresh_dynamic_manifest()
        calls = []

        class ReachedLink(Exception):
            pass

        class CompileCommands:
            capture = True

            def __init__(self, work):
                self.work = work

            def run(self, label, argv, **_kwargs):
                if not label.endswith('-compile'):
                    raise ReachedLink()
                dynamic_driver.execute(fixture.dynamic, argv[1:])
                (self.work / 'commands' / (label + '.stderr')).write_bytes(b'')
                return b''

        def compile_fixture(command, _temporary):
            calls.append(command)
            output = Path(command[command.index('-o') + 1])
            source = Path(command[command.index('-c') + 1])
            output.write_bytes(b'controlled compiler object\n')
            dependencies = [source, *(fixture.dynamic / 'usr/include' / header for header in headers)]
            Path(command[command.index('-MF') + 1]).write_text(str(output) + ': ' + ' '.join(map(str, dependencies)) + '\n')
            return ''

        for owner in receipt.ALIASES:
            for probe in receipt.probe_specs(owner):
                work = fixture.root / (owner + '-' + probe[0])
                (work / 'commands').mkdir(parents=True)
                commands = CompileCommands(work)
                with self.subTest(owner=owner, probe=probe[0]), \
                     mock.patch.object(receipt, 'probe_specs', return_value=(probe,)), \
                     mock.patch.object(dynamic_driver.shared, 'compiler', return_value='/owned/gcc'), \
                     mock.patch.object(dynamic_driver.shared, 'linker', return_value='/owned/ld.lld'), \
                     mock.patch.object(dynamic_driver, 'run', side_effect=compile_fixture):
                    with self.assertRaises(ReachedLink):
                        receipt.installed_owner(commands, owner, fixture.static, fixture.dynamic, {})
        self.assertEqual(len(calls), 10)

    def test_dependency_file_rejects_wrong_source_target_and_installed_header_closure(self):
        (ROOT / '.work/tmp').mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work/tmp') as temporary:
            work = Path(temporary)
            dynamic = work / 'dynamic'
            include = dynamic / 'usr/include'
            include.mkdir(parents=True)
            headers = [include / name for name in ('errno.h', 'signal.h')]
            for header in headers:
                header.write_text('selected installed header\n')
            source = ROOT / receipt.PROBES['signal']
            obj = work / 'behavior.o'
            dependency = work / 'behavior.d'
            valid = str(obj) + ': ' + ' '.join(map(str, [source, *headers])) + '\n'
            dependency.write_text(valid)
            observed = receipt.probe_dependencies(dependency, source, obj, dynamic)
            self.assertEqual(set(observed['headers']), {'errno.h', 'signal.h'})
            for changed in (valid.replace(str(obj), str(work / 'wrong.o')),
                            valid.replace(str(source), str(ROOT / receipt.PROBES['netdb'])),
                            valid.replace(str(headers[0]), ''),
                            valid.replace(str(headers[0]), str(ROOT / 'include/errno.h')),
                            valid.rstrip() + ' ' + str(headers[0]) + '\n'):
                with self.subTest(dependency=changed):
                    dependency.write_text(changed)
                    with self.assertRaises(receipt.FeatureAliasError):
                        receipt.probe_dependencies(dependency, source, obj, dynamic)

    def test_oracle_and_static_copied_consumers_reject_mode_and_symlink_tampering(self):
        (ROOT / '.work/tmp').mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work/tmp') as temporary:
            work = Path(temporary)
            binary = work / 'binary'
            binary.write_bytes(b'selected executable')
            binary.chmod(0o755)
            for mode in ('oracle', 'static', 'static-pie'):
                with self.subTest(mode=mode):
                    root = work / (mode + '-process-root')
                    root.mkdir()
                    copied = root / 'consumer'
                    copied.write_bytes(binary.read_bytes())
                    copied.chmod(0o755)
                    receipt.copied_consumer(binary, copied)
                    copied.chmod(0o644)
                    with self.assertRaisesRegex(receipt.FeatureAliasError, 'consumer mode differs'):
                        receipt.copied_consumer(binary, copied)
                    copied.unlink()
                    copied.symlink_to(binary)
                    with self.assertRaises(receipt.inventory.InventoryError):
                        receipt.copied_consumer(binary, copied)

    def test_raw_runtime_stream_tampering_and_failure_status_are_rejected(self):
        (ROOT / '.work/tmp').mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work/tmp') as temporary:
            work = Path(temporary)
            (work / 'commands').mkdir()
            for stream, data in (('stdout', b'expected\n'), ('stderr', b''), ('status', b'0\n')):
                (work / 'commands' / ('runtime.' + stream)).write_bytes(data)
            commands = receipt.Commands(work, capture=False)
            commands.runtime('runtime', ['/selected/consumer'], b'expected\n')
            for stream, data in (('stdout', b'forged\n'), ('stderr', b'error'), ('status', b'7\n')):
                path = work / 'commands' / ('runtime.' + stream)
                original = path.read_bytes()
                path.write_bytes(data)
                with self.subTest(stream=stream), self.assertRaises(receipt.FeatureAliasError):
                    commands.runtime('runtime', ['/selected/consumer'], b'expected\n')
                path.write_bytes(original)

    @unittest.skipUnless(receipt.ORACLE_CC.is_file(), 'requires the pinned native oracle image')
    def test_native_tool_seal_rejects_a_different_oracle_source_pin(self):
        with mock.patch.object(receipt.math_receipt, 'expected_tool_seal', return_value={}):
            seal = receipt.tool_seal(ROOT, ROOT)
            self.assertEqual(seal['oracle-pin'], receipt.musl_oracle.load_pin(ROOT / 'compat/upstreams.toml'))
            with mock.patch.object(receipt.musl_oracle, 'manifest', return_value='another source'):
                with self.assertRaisesRegex(receipt.FeatureAliasError, 'oracle source pin differs'):
                    receipt.tool_seal(ROOT, ROOT)

    @unittest.skipUnless(receipt.ORACLE_CC.is_file(), 'requires the pinned native oracle image')
    def test_strong_signal_and_passwd_overrides_leave_the_ordinary_targets_callable(self):
        (ROOT / '.work/tmp').mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work/tmp') as temporary:
            for define in ('CRABC_FEATURE_SIGNAL_OVERRIDE', 'CRABC_FEATURE_PASSWD_OVERRIDE'):
                binary = Path(temporary) / define
                compiled = subprocess.run([str(receipt.ORACLE_CC), '-static', '-fno-pie', '-no-pie', '-std=c11', '-fno-builtin',
                    '-I' + str(ROOT / 'include'), '-D' + define,
                    str(ROOT / 'compat/x86_64/owned_feature_alias_override_probe.c'), '-o', str(binary)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertEqual(compiled.returncode, 0, compiled.stderr.decode())
                executed = subprocess.run([str(binary)], cwd=temporary, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertEqual((executed.returncode, executed.stdout, executed.stderr), (0, b'', b''))

    def test_closed_runtime_matrix_preserves_explicit_exec_oracle_difference(self):
        self.assertEqual(receipt.expected_transcript('exec', 'behavior', True), b'owned-process-control-ok fexecve-seccomp=9\n')
        self.assertEqual(receipt.expected_transcript('exec', 'behavior', False), b'owned-process-control-ok fexecve-seccomp=38\n')
        self.assertEqual(len(receipt.PASSWD_CASES), 16)
        self.assertEqual(receipt.probe_specs('temporary')[1][1], 'compat/x86_64/owned_string_temporary_alias_override_probe.c')

    def test_passwd_range_transcript_preserves_bounded_capacity(self):
        expected = b'owned passwd scenario passed\n'
        receipt.require_runtime_transcript(b'matching allocation capacity 41\n' + expected, expected, passwd_ranges=True)
        for observed in (expected, b'matching allocation capacity 0\n' + expected,
                         b'matching allocation capacity 4096\n' + expected,
                         b'matching allocation capacity 41\nextra\n' + expected):
            with self.assertRaises(receipt.FeatureAliasError):
                receipt.require_runtime_transcript(observed, expected, passwd_ranges=True)


class FeatureAliasSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        contract = selection.load_contract()
        expanded = selection.expand_obligations(contract, selection.load_source_inputs(contract, selection.CONTRACT_PATH))
        cls.records = {row['identity']['name']: row for row in expanded}

    def fixtures(self):
        requirements = receipt.alias_requirements()
        records = [copy.deepcopy(self.records[name]) for name in requirements]
        occurrences, owners = [], {}
        by_name = {}
        for owner, pairs in receipt.ALIASES.items():
            aliases = {'static': [], 'shared': []}
            for product, artifact in (('static', 'candidate-static'), ('shared', 'candidate-shared')):
                for public, target in pairs:
                    proof = {'public': public, 'target': target}
                    for role, name in (('alias', public), ('provider', target)):
                        key = (artifact, name)
                        if key not in by_name:
                            shared = product == 'shared'
                            hidden = name in {'__execvpe', '__mkostemps'}
                            row = symbol(name, 'WEAK' if role == 'alias' else 'LOCAL' if shared and hidden else 'GLOBAL',
                                         'HIDDEN' if hidden else 'DEFAULT')
                            row['size_bytes'] = 4
                            by_name[key] = {'index': len(occurrences), 'artifact_key': artifact, 'table': '.symtab',
                                           'member_index': None if shared else 0, 'member_name': None if shared else 'owner.o',
                                           'member_occurrence': None if shared else 0, 'table_section_index': 3,
                                           'row': row, 'definition_section': {'index': 2, 'type': 'PROGBITS', 'flags': 'AX'}}
                            occurrences.append(by_name[key])
                        selected = by_name[key]
                        proof[role] = {'member_index': selected['member_index'], 'member': selected['member_name'],
                                       'table_section_index': selected['table_section_index'], 'row': selected['row'],
                                       'section': selected['definition_section']}
                    aliases[product].append(proof)
            owners[owner] = {'feature_owner': receipt.FEATURES[owner],
                             'owner_source': receipt.identity(ROOT / receipt.OWNER_SOURCES[owner]), 'aliases': aliases}
        reason = 'unrelated placement blocker'
        for record in records:
            record['unresolved'].append(reason)
        accounting = {'identities': records, 'occurrences': occurrences, 'placement_joins': [],
                      'blockers': [{'code': 'identity-unresolved', 'identity': record['identity'], 'reason': reason}
                                   for record in records for reason in record['unresolved']]}
        companion = {'report': {}, 'owners': owners, 'source_products': {'feature_alias_requirements': requirements}}
        return accounting, companion

    def test_six_feature_receipt_joins_preserve_raw_facts_requirements_and_placement_blockers(self):
        accounting, companion = self.fixtures()
        accounting['occurrences'].append({'index': len(accounting['occurrences']), 'artifact_key': 'candidate-static',
                                         'row': {'name': 'signal', 'section_index': 'UND'}, 'table': '.symtab'})
        before = copy.deepcopy(accounting)
        joins = selection.attach_feature_alias_receipt(accounting, companion)
        self.assertEqual(len(joins), 6)
        self.assertEqual(accounting['occurrences'], before['occurrences'])
        self.assertEqual(accounting['placement_joins'], before['placement_joins'])
        for old, new in zip(before['identities'], accounting['identities']):
            self.assertEqual(new['function_alias_requirements'], old['function_alias_requirements'])
            self.assertEqual(new['unresolved'], ['unrelated placement blocker'])
        self.assertTrue(all(row['reason'] == 'unrelated placement blocker' for row in accounting['blockers']))

    def test_wrong_owner_exact_occurrence_or_source_profile_rejects_the_entire_companion(self):
        for change in ('owner', 'occurrence', 'profile'):
            accounting, companion = self.fixtures()
            if change == 'owner':
                companion['owners']['netdb']['owner_source']['sha256'] = '0' * 64
            elif change == 'occurrence':
                companion['owners']['netdb']['aliases']['shared'][0]['alias'] = copy.deepcopy(companion['owners']['netdb']['aliases']['shared'][0]['alias'])
                companion['owners']['netdb']['aliases']['shared'][0]['alias']['row']['value'] = '1'
            else:
                companion['source_products']['feature_alias_requirements']['setnetent']['enabled_features'] = []
            before = copy.deepcopy(accounting)
            rejected = {}
            joins, admitted = selection._attach(rejected, 'feature_alias_work', accounting, companion,
                lambda: selection.attach_feature_alias_receipt(accounting, companion))
            with self.subTest(change=change):
                self.assertEqual(joins, [])
                self.assertIsNone(admitted)
                self.assertEqual(accounting, before)
                self.assertIn('feature_alias_work', rejected)

    def prior_posix(self, accounting, companion):
        fixture = POSIX_FIXTURE.PosixSysvSignalAttachmentTests('test_attachment_discharges_only_the_exact_alias_requirement')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        prior = fixture._adapter()
        record = next(row for row in accounting['identities'] if row['identity']['name'] == '__sysv_signal')
        record['unresolved'] = [selection.FEATURE_ALIAS_REQUIREMENT]
        accounting['blockers'] = [row for row in accounting['blockers']
                                  if row['identity']['name'] != '__sysv_signal' or row['reason'] == selection.FEATURE_ALIAS_REQUIREMENT]
        rows = accounting['occurrences']
        for name in ('__sysv_signal', 'signal'):
            original = next(row for row in rows if row['artifact_key'] == 'candidate-shared' and row['row']['name'] == name)
            dynamic = copy.deepcopy(original)
            dynamic.update(index=len(rows), table='.dynsym', table_section_index=4, role='definition')
            rows.append(dynamic)
        static = next(row for row in rows if row['artifact_key'] == 'candidate-static' and row['row']['name'] == '__sysv_signal')
        shared = next(row for row in rows if row['artifact_key'] == 'candidate-shared' and row['table'] == '.dynsym' and row['row']['name'] == '__sysv_signal')
        target = next(row for row in rows if row['artifact_key'] == 'candidate-static' and row['row']['name'] == 'signal')
        for row in (static, target):
            row['role'] = 'definition'
        for row in (static, shared):
            accounting['placement_joins'].append({'identity': selection.identity('__sysv_signal'),
                'artifact_key': row['artifact_key'], 'placement_observed': True, 'definition_count': 1,
                'occurrence_indices': [row['index']], 'metadata_differences': [{'occurrence_index': row['index'], 'fields': []}],
                'expected_metadata': {'type': 'FUNC', 'binding': 'WEAK', 'visibility': 'DEFAULT'}})
        accounting['function_alias_observations'] = [{'identity': selection.identity('__sysv_signal'),
            'target': selection.identity('signal'), 'artifact_key': 'candidate-static',
            'same_domain_pairs': [[static['index'], target['index']]],
            'feature_contract': copy.deepcopy(record['function_alias_requirements'][0]),
            'feature_archive_receipt_proven': False, 'runtime_semantics_proven': False}]
        companion['source_products']['source'] = {name: fixture.source[name] for name in ('revision', 'content_sha256')}
        with mock.patch.object(selection, '_posix_sysv_signal_reader', return_value=fixture._reader()):
            joins = selection.attach_posix_sysv_signal_admission(accounting, prior, paths=fixture.paths)
        return fixture, prior, joins

    def test_valid_prior_posix_join_keeps_six_unique_feature_proofs_without_double_discharge(self):
        accounting, companion = self.fixtures()
        fixture, prior, prior_joins = self.prior_posix(accounting, companion)
        before = copy.deepcopy(accounting)
        with mock.patch.object(selection, '_posix_sysv_signal_reader', return_value=fixture._reader()):
            joins = selection.attach_feature_alias_receipt(accounting, companion,
                posix_companion=prior, posix_joins=prior_joins, paths=fixture.paths)
        self.assertEqual(len({row['identity']['name'] for row in joins}), 6)
        sysv = next(row for row in joins if row['identity']['name'] == '__sysv_signal')
        self.assertEqual(sysv['requirements_discharged'], [])
        self.assertEqual(sysv['prior_posix_admission'], {'report': prior['report'], 'join': prior_joins[0]})
        self.assertEqual(sum(bool(row['requirements_discharged']) for row in joins), 5)
        self.assertEqual(accounting['occurrences'], before['occurrences'])
        self.assertEqual(accounting['function_alias_observations'], before['function_alias_observations'])

    def test_prior_posix_overlap_does_not_hide_an_unexpected_missing_other_requirement(self):
        accounting, companion = self.fixtures()
        fixture, prior, prior_joins = self.prior_posix(accounting, companion)
        record = next(row for row in accounting['identities'] if row['identity']['name'] == 'setnetent')
        record['unresolved'].remove(selection.FEATURE_ALIAS_REQUIREMENT)
        before = copy.deepcopy(accounting)
        rejected = {}
        with mock.patch.object(selection, '_posix_sysv_signal_reader', return_value=fixture._reader()):
            joins, admitted = selection._attach(rejected, 'feature_alias_work', accounting, companion,
                lambda: selection.attach_feature_alias_receipt(accounting, companion,
                    posix_companion=prior, posix_joins=prior_joins, paths=fixture.paths))
        self.assertEqual(joins, [])
        self.assertIsNone(admitted)
        self.assertEqual(accounting, before)
        self.assertIn('requirements are absent', rejected['feature_alias_work'])

    def test_missing_sysv_requirement_needs_the_validated_prior_posix_provenance(self):
        accounting, companion = self.fixtures()
        fixture, prior, prior_joins = self.prior_posix(accounting, companion)
        with self.assertRaisesRegex(selection.SelectionError, 'validated prior POSIX join'):
            selection.attach_feature_alias_receipt(accounting, companion)
        bad = copy.deepcopy(prior_joins)
        bad[0]['runtime_semantics_proven'] = False
        with mock.patch.object(selection, '_posix_sysv_signal_reader', return_value=fixture._reader()):
            with self.assertRaisesRegex(selection.SelectionError, 'provenance differs'):
                selection.attach_feature_alias_receipt(accounting, companion,
                    posix_companion=prior, posix_joins=bad, paths=fixture.paths)

    def test_missing_companion_preserves_all_six_receipt_blockers(self):
        accounting, _companion = self.fixtures()
        before = copy.deepcopy(accounting)
        self.assertEqual(selection.attach_feature_alias_receipt(accounting, None), [])
        self.assertEqual(accounting, before)


if __name__ == '__main__':
    unittest.main()
