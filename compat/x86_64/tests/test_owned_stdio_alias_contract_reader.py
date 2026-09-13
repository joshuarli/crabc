#!/usr/bin/env python3
"""Regression coverage for exact ELF stdio alias identity checks."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_DIR))

from owned_stdio_alias_contract_reader import SymbolRow, same_definition


class OwnedStdioAliasContractReaderTests(unittest.TestCase):
    def test_same_member_zero_value_different_sections_is_not_an_alias(self) -> None:
        alias = SymbolRow(
            member="stdio.o",
            value="0000000000000000",
            symbol_type="FUNC",
            binding="WEAK",
            visibility="DEFAULT",
            section="17",
            name="fread_unlocked",
        )
        forwarding_body = alias._replace(
            binding="GLOBAL",
            section="18",
            name="fread",
        )

        self.assertFalse(same_definition(alias, forwarding_body))



class SuppliedStdioReceiptTests(unittest.TestCase):
    def test_real_archive_member_occurrence_and_executable_section_are_required(self):
        import owned_stdio_alias_contract_reader as reader
        left = {'member_index': 1, 'table_section_index': 9, 'row': {'section_index': '3', 'value': '0', 'type': 'FUNC'}, 'section': {'index': 3, 'type': 'PROGBITS', 'flags': 'AX'}}
        right = {**left, 'member_index': 2}
        self.assertFalse(reader.same_physical_definition(left, right))
        right = {**left, 'section': {'index': 3, 'type': 'PROGBITS', 'flags': 'A'}}
        self.assertFalse(reader.same_physical_definition(left, right))
        for section in ('0', 'ABS', 'COM'):
            bad = {**left, 'row': {**left['row'], 'section_index': section}}
            self.assertFalse(reader.same_physical_definition(bad, bad))
        self.assertTrue(reader.same_physical_definition(left, left))

    def test_versioned_or_strong_alias_is_not_the_selected_unversioned_weak_function(self):
        import owned_stdio_alias_contract_reader as reader
        row = {'type': 'FUNC', 'binding': 'WEAK', 'visibility': 'DEFAULT', 'version': None, 'version_default': False}
        reader.require_function_shape(row, 'WEAK', 'DEFAULT')
        for changed in ({'version': 'V1'}, {'binding': 'GLOBAL'}, {'version_default': 0}):
            with self.assertRaises(reader.StdioAliasEvidenceError):
                reader.require_function_shape({**row, **changed}, 'WEAK', 'DEFAULT')

    def test_output_cannot_be_created_inside_supplied_product_or_cohort(self):
        import tempfile
        import owned_stdio_alias_contract_reader as reader
        with tempfile.TemporaryDirectory(dir=SOURCE_DIR.parents[1] / '.work/x86_64/stdio-alias-development') as temporary:
            root = Path(temporary); (root / '.work/inputs/product').mkdir(parents=True)
            inputs = root / '.work/inputs'
            with self.assertRaises(reader.StdioAliasEvidenceError):
                reader.fresh_output(root, inputs / 'product/new', [inputs])
            self.assertFalse((inputs / 'product/new').exists())

    def test_runtime_roster_is_finite_and_requires_oracle_transcript(self):
        import owned_stdio_alias_contract_reader as reader
        cells = reader.runtime_cells()
        self.assertEqual(len(cells), 20)
        self.assertEqual(len({x['label'] for x in cells}), 20)
        self.assertEqual(sum(x['owner'] == 'candidate' for x in cells), 16)
        streams = {x['label']: {'stdout': reader.transcript(x['probe']), 'stderr': b'', 'status': b'0\n'} for x in cells}
        reader.validate_runtime_streams(streams)
        streams[cells[0]['label']]['stdout'] = b'fabricated success\n'
        with self.assertRaises(reader.StdioAliasEvidenceError):
            reader.validate_runtime_streams(streams)

    def fixture(self):
        import copy
        import owned_stdio_alias_contract_reader as reader
        names=sorted(set(reader.ALIASES)|set(reader.ALIASES.values())|set(reader.PROTECTED))
        targets={name:reader.ALIASES.get(name,name) for name in names}
        indexes={name:index+1 for index,name in enumerate(sorted(set(targets.values())))}
        result={}
        for key in ('candidate-static','reference-static','candidate-shared','reference-shared'):
            rows=[]
            sections=[{'index':0,'type':'NULL','flags':''}]+[{'index':i,'type':'PROGBITS','flags':'AX'} for i in range(1,len(indexes)+1)]
            for name in names:
                binding='WEAK' if name in reader.ALIASES else 'GLOBAL'
                visibility='PROTECTED' if name in reader.PROTECTED else 'DEFAULT'
                if name in reader.HIDDEN:
                    binding='GLOBAL' if key.endswith('static') else 'LOCAL'
                    visibility='DEFAULT' if key=='reference-shared' else 'HIDDEN'
                rows.append({'row_index':len(rows)+1,'name':name,'type':'FUNC','binding':binding,'visibility':visibility,
                             'section_index':str(indexes[targets[name]]),'value':'0','version':None,'version_default':False})
            member={'sections':sections,'symbol_tables':[{'name':'.symtab','section_index':90,'rows':rows}]}
            if key.endswith('static'):
                result[key]=[{'member':'same.o','member_index':0,'member_occurrence':0,**member}]
            else:
                member['symbol_tables'].append({'name':'.dynsym','section_index':91,'rows':[copy.deepcopy(x) for x in rows if x['name'] not in reader.HIDDEN]})
                result[key]=member
        return result

    def test_production_shaped_archive_and_shared_facts_keep_local_hidden_targets(self):
        import owned_stdio_alias_contract_reader as reader
        result=reader.account_aliases(self.fixture())
        self.assertEqual(set(result),{'candidate-static','reference-static','candidate-shared','reference-shared'})
        self.assertEqual(len(result['candidate-static']['aliases']),15)
        self.assertEqual(result['candidate-shared']['aliases']['fdopen']['target_occurrence']['row']['visibility'],'HIDDEN')

    def test_duplicate_member_spelling_does_not_merge_alias_domains(self):
        import copy
        import owned_stdio_alias_contract_reader as reader
        facts=self.fixture(); member=facts['candidate-static'][0]
        alias=next(x for x in member['symbol_tables'][0]['rows'] if x['name']=='fdopen')
        member['symbol_tables'][0]['rows'].remove(alias)
        second=copy.deepcopy(member); second['member_index']=1; second['member_occurrence']=1
        second['symbol_tables'][0]['rows']=[alias]; facts['candidate-static'].append(second)
        with self.assertRaisesRegex(reader.StdioAliasEvidenceError,'definition domain'):
            reader.account_aliases(facts)

    def test_hidden_dynamic_leak_and_missing_alias_are_rejected(self):
        import copy
        import owned_stdio_alias_contract_reader as reader
        facts=self.fixture(); member=facts['candidate-shared']
        member['symbol_tables'][1]['rows'].append(copy.deepcopy(next(x for x in member['symbol_tables'][0]['rows'] if x['name']=='__fdopen')))
        with self.assertRaisesRegex(reader.StdioAliasEvidenceError,'leaked'):
            reader.account_aliases(facts)
        facts=self.fixture(); rows=facts['candidate-shared']['symbol_tables'][1]['rows']
        rows[:]=[x for x in rows if x['name']!='fdopen']
        with self.assertRaisesRegex(reader.StdioAliasEvidenceError,'dynsym roster'):
            reader.account_aliases(facts)

    def test_every_plan_uses_original_object_and_static_receipt_is_output_relative(self):
        import owned_stdio_alias_contract_reader as reader
        root=Path('/workspace');work=root/'.work/evidence'
        inputs={'static_preparation':{'primary':{'path':'.work/static'}},'dynamic_product':{'path':'.work/dynamic'}}
        roles=(*reader.ordinary.TOOL_ROLES,'ar')
        tools={name:{'original':{'path':'/tool/'+name}} for name in roles}
        tools['chroot']={'original':{'path':'/bin/coreutils'},'invocation':{'path':'/usr/sbin/chroot','physical_path':'/bin/coreutils'}}
        from unittest.mock import patch
        with patch.object(reader.ordinary,'validate_chroot_invocation',return_value='/usr/sbin/chroot'):
            specs=reader.plan(root,work,inputs,tools)
        links=[x for x in specs if x['label'].endswith('-link')]
        self.assertEqual(len(links),13)
        for spec in links:
            if spec['label'].startswith('candidate-'):
                self.assertNotIn('-Wl,--export-dynamic',spec['argv'])
            probe=spec['label'].removesuffix('-link').rsplit('-',1)[1]
            self.assertEqual(sum(x==str(work/(probe+'.o')) for x in spec['argv']),1)
            if spec['label'].startswith('candidate-static'):
                self.assertEqual(spec['cwd'],str(work))
                receipt=spec['argv'][spec['argv'].index('--link-receipt')+1]
                self.assertEqual(Path(receipt).name,receipt)
        self.assertEqual(len({x['label'] for x in specs}),len(specs))


    def test_actual_command_writer_serialization_replays_and_raw_change_rejects(self):
        import tempfile,json
        from unittest.mock import patch,Mock
        import owned_stdio_alias_contract_reader as reader
        with tempfile.TemporaryDirectory(dir=SOURCE_DIR.parents[1] / '.work/x86_64/stdio-alias-development') as temporary:
            root=Path(temporary); work=root/'.work/receipt'; work.mkdir(parents=True)
            runner=reader.ordinary.Collector(root,work,root,root,root)
            process=Mock(); process.wait.return_value=0
            specs=[{'label':'shape-control','argv':['/usr/bin/true'],'cwd':'/workspace'}]
            with patch.object(reader.ordinary.subprocess,'Popen',return_value=process):
                runner.run('shape-control',['/usr/bin/true'])
            commands=json.loads(json.dumps(runner.commands,sort_keys=True))
            with patch.object(reader,'plan',return_value=specs):
                reader.validate_commands(root,work,{}, {},commands)
                (work/'raw/shape-control.stdout').write_bytes(b'rebound')
                with self.assertRaises(reader.ordinary.PublicDataEvidenceError):
                    reader.validate_commands(root,work,{}, {},commands)

if __name__ == '__main__':
    unittest.main()
