"""The installed worker token is one lifecycle contract, not seven exports."""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('prepared_worker_tls_evidence_test', ROOT / 'compat/x86_64/prepared_worker_tls_evidence.py')
assert SPEC and SPEC.loader
EVIDENCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EVIDENCE
SPEC.loader.exec_module(EVIDENCE)


class PreparedWorkerTlsEvidenceTests(unittest.TestCase):
    def facts(self):
        rows = [{'row_index': n, 'name': name, 'raw_name': name,
                 'type': 'NOTYPE', 'binding': 'GLOBAL', 'visibility': 'DEFAULT',
                 'section_index': 'UND', 'size_bytes': 0, 'value': '0000000000000000',
                 'version': None, 'version_default': False}
                for n, name in enumerate(EVIDENCE.OPERATIONS, 1)]
        return {'facts': {'candidate-shared': {'symbol_tables': [
                    {'name': '.dynsym', 'rows': copy.deepcopy(rows)},
                    {'name': '.symtab', 'rows': copy.deepcopy(rows)}]},
                'candidate-loader': {'symbol_tables': [{'name': '.dynsym', 'rows': []}]}},
                'artifacts': {'candidate-shared': {'identity': {'sha256': 'a'*64}},
                              'candidate-loader': {'identity': {'sha256': 'b'*64}}}}

    def test_contract_keeps_loader_token_and_frozen_replacements_distinct(self):
        contract = EVIDENCE.load_contract()
        self.assertEqual(len(contract['legacy_replacement']), 7)
        self.assertEqual(contract['worker_token']['size_bytes'], 32)
        self.assertEqual(contract['descriptor']['size_bytes'], 72)
        self.assertFalse(contract['descriptor']['require_installed_import'])
        self.assertTrue(all(value is False for value in contract['limits'].values()))
        broken = copy.deepcopy(contract)
        broken['legacy_replacement'].pop()
        with self.assertRaises(EVIDENCE.PreparedWorkerTlsError):
            EVIDENCE.validate_contract(broken)

    def test_contract_rejects_boolean_geometry_and_unsupported_publication(self):
        for table, field, value in [('worker_token', 'alignment_bytes', 8.0),
                                    ('descriptor', 'initial_generation', True),
                                    ('descriptor', 'require_installed_import', True),
                                    ('limits', 'public_facade_runtime_v1', 0)]:
            contract = EVIDENCE.load_contract()
            contract[table][field] = value
            with self.assertRaises(EVIDENCE.PreparedWorkerTlsError):
                EVIDENCE.validate_contract(contract)

    def test_imports_require_exact_per_table_origins_without_a_loader_export(self):
        result = EVIDENCE.account_elf(self.facts())
        self.assertEqual(set(result['operations']), set(EVIDENCE.OPERATIONS))
        self.assertTrue(all(set(value)=={'.dynsym','.symtab'} for value in result['operations'].values()))
        self.assertEqual(result['operations'][next(iter(EVIDENCE.OPERATIONS))]['.dynsym']['row_index'], 1)
        bad = self.facts()
        tables = bad['facts']['candidate-shared']['symbol_tables']
        tables[0]['rows'] += tables[1]['rows']
        tables[1]['rows'] = []
        with self.assertRaises(EVIDENCE.PreparedWorkerTlsError):
            EVIDENCE.account_elf(bad)
        bad = self.facts()
        bad['facts']['candidate-loader']['symbol_tables'][0]['rows'].append(copy.deepcopy(bad['facts']['candidate-shared']['symbol_tables'][0]['rows'][0]))
        with self.assertRaises(EVIDENCE.PreparedWorkerTlsError):
            EVIDENCE.account_elf(bad)

    def test_imports_do_not_accept_versioned_defined_or_numeric_lookalikes(self):
        for field,value in [('version','PRIVATE_1'),('version_default',0),('section_index','5'),
                            ('size_bytes',False),('binding','WEAK')]:
            bad=self.facts()
            bad['facts']['candidate-shared']['symbol_tables'][0]['rows'][0][field]=value
            with self.assertRaises(EVIDENCE.PreparedWorkerTlsError):
                EVIDENCE.account_elf(bad)

    def test_typed_operation_source_rejects_consumer_pointer_or_return_drift(self):
        source=(ROOT/EVIDENCE.ADAPTER).read_text()
        EVIDENCE.check_operation_signatures(ROOT, source)
        for old,new in [('*mut StaticInitialTlsBlock) -> i32','*const StaticInitialTlsBlock) -> i32'),
                        ('*const StaticInitialTlsBlock) -> i64','*const StaticInitialTlsBlock) -> i32'),
                        ('*const core::ffi::c_void) -> *mut core::ffi::c_void;','usize) -> *mut core::ffi::c_void;')]:
            with self.assertRaises(EVIDENCE.PreparedWorkerTlsError):
                EVIDENCE.check_operation_signatures(ROOT, source.replace(old,new))

    def test_runtime_matrix_retains_owned_reclaim_and_common_oracle_boundaries(self):
        cells=EVIDENCE.runtime_cells()
        self.assertEqual(len(cells),55)
        self.assertEqual(len({cell['label'] for cell in cells}),55)
        self.assertEqual(sum(cell['owner']=='candidate' for cell in cells),30)
        for cell in cells:
            output=EVIDENCE.runtime_stdout(cell)
            self.assertIn(b'reclaimed=owned' if cell['owner']=='candidate' else b'reclaimed=unspecified',output)
        self.assertEqual({c['scenario'] for c in cells},set(EVIDENCE.SCENARIOS))

    def test_command_replay_rejects_rebound_nonzero_status_and_changed_argv(self):
        import tempfile
        import json
        from unittest.mock import patch
        base=ROOT/'.work/x86_64/prepared-worker-tls-development'
        base.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as directory:
            work=Path(directory); (work/'raw').mkdir()
            label='control'; argv=['/usr/bin/true']
            plan={label:{'cwd':'/workspace','argv':argv}}
            row={'label':label,'argv':argv,'cwd':'/workspace','outcome':'ok'}
            for field,suffix,payload in [('command','command.json',json.dumps(argv).encode()),
                                         ('stdout','stdout',b''),('stderr','stderr',b''),('status','status',b'0\n')]:
                path=work/'raw'/(label+'.'+suffix); path.write_bytes(payload)
                row[field]=EVIDENCE.ordinary.work_file_identity(ROOT,path,field)
            with patch.object(EVIDENCE,'command_plan',return_value=plan):
                EVIDENCE.validate_commands(ROOT,work,{}, {}, {},[row])
                path=work/'raw'/'control.status';path.write_bytes(b'1\n')
                row['status']=EVIDENCE.ordinary.work_file_identity(ROOT,path,'status')
                with self.assertRaises(EVIDENCE.PreparedWorkerTlsError):
                    EVIDENCE.validate_commands(ROOT,work,{}, {}, {},[row])
                path.write_bytes(b'0\n');row['status']=EVIDENCE.ordinary.work_file_identity(ROOT,path,'status')
                row['argv']=['/usr/bin/false']
                with self.assertRaises(EVIDENCE.PreparedWorkerTlsError):
                    EVIDENCE.validate_commands(ROOT,work,{}, {}, {},[row])

    def test_actual_capture_writer_replays_complete_serialized_command_plan(self):
        import tempfile
        import json
        from unittest.mock import Mock,patch
        base=ROOT/'.work/x86_64/prepared-worker-tls-development'
        with tempfile.TemporaryDirectory(dir=base) as directory:
            work=Path(directory)
            inputs={'static_preparation':{'primary':{'path':'.work/static'}},'dynamic_product':{'path':'.work/dynamic'}}
            tools={name:{'original':{'path':'/usr/bin/'+name}} for name in EVIDENCE.ordinary.TOOL_ROLES}
            tools['chroot']={'original':{'path':'/bin/coreutils'},'invocation':{'path':'/usr/sbin/chroot','physical_path':'/bin/coreutils'}}
            rust={'compiler':{'original':{'path':'/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/bin/rustc'}}}
            plan=EVIDENCE.command_plan(ROOT,work,inputs,tools,rust)
            capture=EVIDENCE.ordinary.Collector(ROOT,work,work,work,work)
            with patch.object(EVIDENCE.ordinary.subprocess,'Popen',return_value=Mock(wait=Mock(return_value=0))):
                for label,spec in plan.items():
                    capture.run(label,spec['argv'],cwd=ROOT if spec['cwd']=='/workspace' else work)
            rows=json.loads(json.dumps(capture.commands,sort_keys=True))
            EVIDENCE.validate_commands(ROOT,work,inputs,tools,rust,rows)
            self.assertEqual(rows[0]['label'],'rustc-discover')
            self.assertEqual({r['cwd'] for r in rows},{'/workspace',EVIDENCE.ordinary.mounted(ROOT,work)})
            self.assertTrue(all(EVIDENCE.ordinary.mounted(ROOT,work/'probe.o') in plan[name+'-link']['argv']
                                for name in EVIDENCE.ordinary.ALL_EXECUTABLES))
            with self.assertRaises(EVIDENCE.PreparedWorkerTlsError):
                EVIDENCE.validate_commands(ROOT,work,inputs,tools,rust,rows[:-1])

    def test_live_libc_relocation_projection_rejects_duplicate_wrong_kind_or_addend(self):
        from unittest.mock import Mock
        names=list(EVIDENCE.OPERATIONS)
        def fixture():
            elf=Mock()
            elf.sections=[(0,4,0,0,0,72,1,0,0,24)]
            elf.unpack.side_effect=lambda shape,offset:(0x1000+offset,(offset//24+1)<<32|6,0)
            elf.symbol_row.side_effect=lambda table,index:{'name':names[index-1],'type':'0','binding':'GLOBAL',
                'visibility':'DEFAULT','section':0,'value':0,'size':0,'version_index':1}
            return elf
        self.assertEqual(set(EVIDENCE.worker_relocations(fixture())),set(names))
        for kind,addend in [(7,0),(6,1),(6,False)]:
            elf=fixture();elf.unpack.side_effect=lambda shape,offset:(0x1000+offset,(offset//24+1)<<32|kind,addend)
            with self.assertRaises(EVIDENCE.PreparedWorkerTlsError):EVIDENCE.worker_relocations(elf)
        elf=fixture();elf.sections*=2
        with self.assertRaises(EVIDENCE.PreparedWorkerTlsError):EVIDENCE.worker_relocations(elf)

    def test_private_source_layout_requires_repr_c_not_only_field_spelling(self):
        source=(ROOT/EVIDENCE.ADAPTER).read_text()
        self.assertEqual(EVIDENCE._fields(source,'StaticInitialTlsBlock'),EVIDENCE.TOKEN_FIELDS)
        with self.assertRaises(EVIDENCE.PreparedWorkerTlsError):
            EVIDENCE._fields(source.replace('#[repr(C)]',''),'StaticInitialTlsBlock')

    def test_source_account_is_exactly_json_replayable(self):
        import json
        account=EVIDENCE.account_source(ROOT)
        self.assertTrue(EVIDENCE.same(account,json.loads(json.dumps(account))))

    def test_output_overlap_rejects_before_any_directory_creation(self):
        import tempfile
        base=ROOT/'.work/x86_64/prepared-worker-tls-development'
        with tempfile.TemporaryDirectory(dir=base) as directory:
            work=Path(directory)
            paths={}
            for name in EVIDENCE.REPORT_INPUTS:
                target=work/name
                if name.endswith('product'):target.mkdir()
                else:target.mkdir();target=target/'report.json';target.write_text('{}')
                paths[name]=target
            for protected in [paths['static_product'],paths['dynamic_product'],paths['static_preparation'].parent,
                              paths['base_inventory'].parent,paths['elf_report'].parent]:
                output=protected/'new-output'
                with self.assertRaises((EVIDENCE.PreparedWorkerTlsError,EVIDENCE.ordinary.PublicDataEvidenceError)):
                    EVIDENCE.fresh_output(ROOT,output,paths)
                self.assertFalse(output.exists())
            self.assertEqual(EVIDENCE.fresh_output(ROOT,work/'safe',paths),work/'safe')
            self.assertFalse((work/'safe').exists())

    def test_lifecycle_replay_requires_all_cells_and_exact_unit_result(self):
        import tempfile
        base=ROOT/'.work/x86_64/prepared-worker-tls-development'
        with tempfile.TemporaryDirectory(dir=base) as directory:
            work=Path(directory);(work/'raw').mkdir()
            for cell in EVIDENCE.runtime_cells():
                EVIDENCE.ordinary.raw_path(work,cell['label'],'stdout').write_bytes(EVIDENCE.runtime_stdout(cell))
            for index,name in enumerate(EVIDENCE.UNIT_TESTS):
                EVIDENCE.ordinary.raw_path(work,f'unit-{index}','stdout').write_text(
                    '\nrunning 1 test\ntest '+name+' ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 63 filtered out; finished in 0.00s\n\n')
            self.assertEqual(len(EVIDENCE.runtime_observations(work)['application_cells']),55)
            last=EVIDENCE.runtime_cells()[-1];path=EVIDENCE.ordinary.raw_path(work,last['label'],'stdout')
            path.write_bytes(EVIDENCE.runtime_stdout(last).replace(b'cleanup=1',b'cleanup=0'))
            with self.assertRaises(EVIDENCE.PreparedWorkerTlsError):EVIDENCE.runtime_observations(work)
            path.write_bytes(EVIDENCE.runtime_stdout(last))
            EVIDENCE.ordinary.raw_path(work,'unit-6','stdout').write_text('running 0 tests\n')
            with self.assertRaises(EVIDENCE.PreparedWorkerTlsError):EVIDENCE.runtime_observations(work)

    def test_source_account_checks_current_prepared_token_ownership(self):
        account=EVIDENCE.account_source(ROOT)
        self.assertEqual(set(account['operations']),set(EVIDENCE.OPERATIONS))
        self.assertEqual(account['worker_token']['producer_fields'],account['worker_token']['consumer_fields'])
        self.assertIn('before-clone',account['ordering'])
        self.assertIn('after-clear-child-tid-and-withdrawal',account['ordering'])


if __name__ == '__main__':
    unittest.main()
