"""Exercise Theap profile execution and observable failure retention."""

import json
import hashlib
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m6_public_theap as theap


class TheapProducerTests(unittest.TestCase):
    def setUp(self):
        root = theap.harness.ROOT / '.work' / 'tmp'
        root.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name)
        self.drivers = {side: self.output / side for side in ('c', 'rust')}

    def observation(self, *, visitor=None, profile='release'):
        trace = dict(theap.SOURCE_TRACE)
        if profile in theap.m4.GUARDED_API_PROFILE_BASES:
            trace.update({f'{context}.guarded_actual':'1,1,1,1,1,1,1,1,1,1'
                          for context in ('main','worker','child','fork')})
        if visitor is not None:
            trace['main.visitor'] = visitor
        return {'status': 0, 'stdout': '\n'.join([theap.BEGIN,
            *(f'{key}={value}' for key, value in trace.items()), theap.END]) + '\n',
            'stderr': '\n'.join(f'source.{context}=1,1,1\nsource.{context}.collect_empty=1'
                for context in ('main', 'worker', 'child', 'fork')) + '\n'}

    def receipt_fixture(self, profile='secure-2'):
        source_seal = {'revision':'1'*40,'worktree_sha256':'2'*64}
        work = self.output / 'work'; work.mkdir()
        output = work / profile; output.mkdir()
        latest = self.output / 'latest'; latest.mkdir()
        products = latest / 'products'; products.mkdir()
        logs = latest / 'logs'; logs.mkdir()
        archive = b'unit oracle archive'
        pin = {'sha256':hashlib.sha256(archive).hexdigest(),'archive_root':'mimalloc-3.5.0'}
        driver = theap.DRIVER.read_bytes()
        adapter = b'unit adapter archive'
        for name,payload in ((f'{profile}-upstream-archive',archive),(f'{profile}-driver.c',driver),
                             (f'{profile}-adapter.a',adapter)):
            (products/name).write_bytes(payload)
        inputs={'profile':profile,'guarded_only':False,'upstream':pin,'archive_sha256':pin['sha256'],
                'driver_sha256':hashlib.sha256(driver).hexdigest(),'source':source_seal,
                'workload_assertions':True,'allocator_flags':list(theap.m4.api_profile_flags(profile)),
                'execution':{'execution_mode':'native','host_architecture':'x86_64','image_id':'sha256:'+'3'*64}}
        (products/f'{profile}-inputs.json').write_text(json.dumps(inputs))
        source=theap.harness.TEMP_ROOT/'crabc-mimalloc-m6-public-theap-removed'/'source'/pin['archive_root']
        compiler,cargo='/tool/musl-gcc','/tool/cargo'
        common=[compiler,'-std=c11','-ftls-model=initial-exec','-DMI_LIBC_MUSL=1',
                *theap.m4.api_profile_flags(profile),'-UNDEBUG','-I',str(source/'include')]
        retained_driver=output/theap.DRIVER.name
        library=output/'cargo-target'/theap.m4.RUST_TARGET/'release'/theap.m4.ADAPTER_STATICLIB
        commands={
            'c-build':[*common,'-DCRABC_M6_SOURCE_INTERNAL=1','-I',str(source/'src'),str(retained_driver),str(source/'src/static.c'),'-pthread','-o',str(output/'public-theap-c')],
            'rust-link':[*common,str(retained_driver),str(library),'-pthread','-o',str(output/'public-theap-rust')],
            'c':[str(output/'public-theap-c')],'rust':[str(output/'public-theap-rust')],
            'adapter-build':[cargo,'build','--locked','--release','--message-format=json','--target',theap.m4.RUST_TARGET,'-p',theap.m4.ADAPTER_PACKAGE,'--target-dir',str(output/'cargo-target'),'--features',','.join(f'crabc-mimalloc/{feature}' for feature in theap.m4.api_profile_features(profile))]}
        ids=[];cases=[]
        labels=['c-build','rust-link','c-run','rust-run','native_theap_contract',*(test.rsplit('::',1)[-1] for test in theap.native_control_tests(profile)[1:])]
        for index,test in enumerate(theap.native_control_tests(profile)):
            label=labels[4+index]
            commands[label]=[cargo,'test','--locked','--offline','--target',theap.m4.RUST_TARGET,'-p','crabc-mimalloc','--no-default-features','--message-format=json','--features',','.join(theap.m4.api_profile_features(profile)),*(('--test','native_theap_contract') if index==0 else ('--lib',)),test,'--','--exact','--nocapture','--test-threads=1']
        for label in labels:
            stem={'c-run':'c','rust-run':'rust'}.get(label,label)
            record=self.observation(profile=profile) if label.endswith('-run') else {'status':0,'stdout':'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;\n','stderr':''}
            record['command']=commands[stem]
            filename=profile+'/'+stem+'.json';(logs/profile).mkdir(exist_ok=True)
            (logs/filename).write_text(json.dumps(record))
            records={filename:{}}
            if label=='rust-link':records[profile+'/adapter-build.json']={}
            ids.append(profile+'-'+label);cases.append({'id':ids[-1],'logs':records,'status':0})
        (logs/profile/'adapter-build.json').write_text(json.dumps({'command':commands['adapter-build'],'status':0,'stdout':'','stderr':'','artifact':{'path':str(library.relative_to(theap.harness.ROOT)),'bytes':len(adapter),'sha256':hashlib.sha256(adapter).hexdigest()}}))
        (latest/'receipt.json').write_text(json.dumps({'work':str(work.relative_to(theap.harness.ROOT))}))
        receipt=SimpleNamespace(path=latest/'receipt.json',source=source_seal,cases=cases,
            parameters=theap.parameters((profile,),False),
            products={profile+'-adapter.a':{'sha256':hashlib.sha256(adapter).hexdigest(),'size':len(adapter)}},
            case_ids=lambda prefix='':[name for name in ids if name.startswith(prefix)])
        return receipt,pin,commands

    def test_reader_rejects_changed_middle_compiler_or_profile_inputs(self):
        receipt,pin,commands=self.receipt_fixture()
        changed=[]
        source=receipt.path.parent/'products/secure-2-inputs.json'
        original=json.loads(source.read_text())
        for field,value in (('profile','secure-1'),('allocator_flags',list(theap.m4.api_profile_flags('secure-1'))),
                            ('archive_sha256','0'*64),('guarded_only',True)):
            item=dict(original);item[field]=value;changed.append((source,json.dumps(item)))
        for label in ('c-build','rust-link','adapter-build'):
            path=receipt.path.parent/'logs/secure-2'/f'{label}.json'
            data=json.loads(path.read_text())
            argv=list(data['command'])
            if label=='c-build':argv[-4]=argv[-4].replace('static.c','other.c')
            elif label=='rust-link':argv[-4]=str(self.output/'another-provider.a')
            else:argv[-1]='crabc-mimalloc/mi-secure-1'
            item=dict(data,command=argv);changed.append((path,json.dumps(item)))
            mutations=[]
            if label=='c-build':
                for index,replacement in ((argv.index('-DMI_SECURE=2'),'-DMI_SECURE=1'),(-5,str(self.output/'different-driver.c')),(-1,str(self.output/'different-c'))):
                    variant=list(data['command']);variant[index]=replacement;mutations.append(variant)
                variant=list(data['command']);index=variant.index('-I');variant[index+1]=str(self.output/'different-headers');mutations.append(variant)
            elif label=='rust-link':
                variant=list(data['command']);variant[-1]=str(self.output/'different-rust');mutations.append(variant)
            else:
                variant=list(data['command']);variant[variant.index('--target-dir')+1]=str(self.output/'different-target');mutations.append(variant)
                mutations.append(list(data['command'])[:-2])
            for variant in mutations:
                changed.append((path,json.dumps(dict(data,command=variant))))
        artifact_path=receipt.path.parent/'logs/secure-2/adapter-build.json'
        artifact_record=json.loads(artifact_path.read_text())
        altered=dict(artifact_record,artifact=dict(artifact_record['artifact'],path='another-provider.a'))
        changed.append((artifact_path,json.dumps(altered)))
        for path,contents in changed:
            saved=path.read_text();path.write_text(contents)
            with mock.patch.object(theap.receipts,'read_receipt',return_value=receipt), \
                 mock.patch.object(theap.harness,'load_pin',return_value=pin), \
                 mock.patch.object(theap.harness,'require_tool',side_effect=lambda name: '/tool/'+name):
                with self.subTest(path=path),self.assertRaises(theap.harness.HarnessError):
                    theap.cli(['--profiles','secure-2','--read'])
            path.write_text(saved)

    def test_reader_accepts_complete_bound_compiler_products_without_old_temp_sources(self):
        receipt,pin,_=self.receipt_fixture()
        with mock.patch.object(theap.receipts,'read_receipt',return_value=receipt), \
             mock.patch.object(theap.harness,'load_pin',return_value=pin), \
             mock.patch.object(theap.harness,'require_tool',side_effect=AssertionError('retained reading requires no installed compiler')):
            self.assertEqual(theap.cli(['--profiles','secure-2','--read']),0)

    def test_reader_requires_original_c_owner_and_empty_collection_observations(self):
        receipt,pin,_=self.receipt_fixture()
        path=receipt.path.parent/'logs/secure-2/c.json'
        original=json.loads(path.read_text())
        for context in ('main','worker','child','fork'):
            for witness in (f'source.{context}=1,1,1', f'source.{context}.collect_empty=1'):
                for changed in ('', witness.replace('=1', '=0', 1), witness+'\n'+witness):
                    record=dict(original,stderr=original['stderr'].replace(witness,changed))
                    path.write_text(json.dumps(record))
                    with mock.patch.object(theap.receipts,'read_receipt',return_value=receipt), \
                         mock.patch.object(theap.harness,'load_pin',return_value=pin), \
                         mock.patch.object(theap.harness,'require_tool',side_effect=lambda name: '/tool/'+name):
                        with self.subTest(witness=witness,changed=changed),self.assertRaises(theap.harness.HarnessError):
                            theap.cli(['--profiles','secure-2','--read'])

    def test_reader_accepts_original_commands_after_checkout_relocation(self):
        receipt,pin,_=self.receipt_fixture()
        original_root=str(theap.harness.ROOT)
        for path in (receipt.path.parent/'logs/secure-2').glob('*.json'):
            record=json.loads(path.read_text())
            record['command']=[argument.replace(original_root,'/removed/original-checkout')
                               for argument in record['command']]
            path.write_text(json.dumps(record))
        with mock.patch.object(theap.receipts,'read_receipt',return_value=receipt), \
             mock.patch.object(theap.harness,'load_pin',return_value=pin), \
             mock.patch.object(theap.harness,'require_tool',side_effect=lambda name: '/tool/'+name):
            self.assertEqual(theap.cli(['--profiles','secure-2','--read']),0)

    def test_actual_guarded_reader_requires_both_compilers_and_protected_clients(self):
        receipt,pin,_=self.receipt_fixture('guarded-secure-3')
        with mock.patch.object(theap.receipts,'read_receipt',return_value=receipt), \
             mock.patch.object(theap.harness,'load_pin',return_value=pin), \
             mock.patch.object(theap.harness,'require_tool',side_effect=lambda name: '/tool/'+name):
            self.assertEqual(theap.cli(['--profiles','guarded-secure-3','--read']),0)
            for label,original,replacement in (
                    ('c-build','-DMI_GUARDED=1','-DMI_GUARDED=0'),
                    ('adapter-build','crabc-mimalloc/mi-guarded,crabc-mimalloc/mi-secure-3','crabc-mimalloc/mi-secure-3'),
                    ('native_theap_contract','mi-guarded,mi-secure-3','mi-guarded')):
                path=receipt.path.parent/'logs/guarded-secure-3'/f'{label}.json'
                saved=path.read_text();data=json.loads(saved)
                data['command'][data['command'].index(original)]=replacement
                path.write_text(json.dumps(data))
                with self.subTest(label=label),self.assertRaises(theap.harness.HarnessError):
                    theap.cli(['--profiles','guarded-secure-3','--read'])
                path.write_text(saved)
            for side in ('c','rust'):
                path=receipt.path.parent/'logs/guarded-secure-3'/f'{side}.json'
                saved=path.read_text();data=json.loads(saved)
                data['stdout']=data['stdout'].replace('main.guarded_actual=1,1,1', 'main.guarded_actual=1,0,1')
                path.write_text(json.dumps(data))
                with self.subTest(side=side),self.assertRaises(theap.harness.HarnessError):
                    theap.cli(['--profiles','guarded-secure-3','--read'])
                path.write_text(saved)

    def test_guarded_debug_reader_rejects_lower_source_or_native_debug(self):
        receipt,pin,_=self.receipt_fixture('guarded-debug-3')
        with mock.patch.object(theap.receipts,'read_receipt',return_value=receipt), \
             mock.patch.object(theap.harness,'load_pin',return_value=pin), \
             mock.patch.object(theap.harness,'require_tool',side_effect=lambda name: '/tool/'+name):
            self.assertEqual(theap.cli(['--profiles','guarded-debug-3','--read']),0)
            for label,original,replacement in (
                    ('c-build','-DMI_DEBUG=3','-DMI_DEBUG=2'),
                    ('adapter-build','crabc-mimalloc/mi-guarded,crabc-mimalloc/mi-debug-3','crabc-mimalloc/mi-guarded,crabc-mimalloc/mi-debug-2'),
                    ('native_theap_contract','mi-guarded,mi-debug-3','mi-guarded,mi-debug-2')):
                path=receipt.path.parent/'logs/guarded-debug-3'/f'{label}.json'
                saved=path.read_text();data=json.loads(saved)
                data['command'][data['command'].index(original)]=replacement
                path.write_text(json.dumps(data))
                with self.subTest(label=label),self.assertRaises(theap.harness.HarnessError):
                    theap.cli(['--profiles','guarded-debug-3','--read'])
                path.write_text(saved)

    def test_numeric_debug_reader_rejects_lower_c_or_native_selector(self):
        receipt,pin,_=self.receipt_fixture('debug-3')
        with mock.patch.object(theap.receipts,'read_receipt',return_value=receipt), \
             mock.patch.object(theap.harness,'load_pin',return_value=pin), \
             mock.patch.object(theap.harness,'require_tool',side_effect=lambda name: '/tool/'+name):
            self.assertEqual(theap.cli(['--profiles','debug-3','--read']),0)
            for label,original,replacement in (
                    ('c-build','-DMI_DEBUG=3','-DMI_DEBUG=2'),
                    ('adapter-build','crabc-mimalloc/mi-debug-3','crabc-mimalloc/mi-debug-2'),
                    ('native_theap_contract','mi-debug-3','mi-debug-2')):
                path=receipt.path.parent/'logs/debug-3'/f'{label}.json'
                saved=path.read_text();data=json.loads(saved)
                data['command'][data['command'].index(original)]=replacement
                path.write_text(json.dumps(data))
                with self.subTest(label=label),self.assertRaises(theap.harness.HarnessError):
                    theap.cli(['--profiles','debug-3','--read'])
                path.write_text(saved)

    def test_secure_three_reader_requires_executed_configuration_and_null_controls(self):
        receipt,pin,_=self.receipt_fixture('secure-3')
        ids=receipt.case_ids()
        with mock.patch.object(theap.receipts,'read_receipt',return_value=receipt), \
             mock.patch.object(theap.harness,'load_pin',return_value=pin), \
             mock.patch.object(theap.harness,'require_tool',side_effect=lambda name: '/tool/'+name):
            self.assertEqual(theap.cli(['--profiles','secure-3','--read']),0)
            for test in theap.SECURE_THREE_UNIT_TESTS:
                label=test.rsplit('::',1)[-1]
                omitted='secure-3-'+label
                receipt.case_ids=lambda prefix='': [name for name in ids
                    if name!=omitted and name.startswith(prefix)]
                with self.subTest(omitted=label),self.assertRaises(theap.harness.HarnessError):
                    theap.cli(['--profiles','secure-3','--read'])
                receipt.case_ids=lambda prefix='': [name for name in ids if name.startswith(prefix)]
                path=receipt.path.parent/'logs/secure-3'/f'{label}.json'
                saved=path.read_text();data=json.loads(saved)
                data['stdout']='test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;\n'
                path.write_text(json.dumps(data))
                with self.subTest(unexecuted=label),self.assertRaises(theap.harness.HarnessError):
                    theap.cli(['--profiles','secure-3','--read'])
                path.write_text(saved)

    def test_debug_entry_selects_opt0_legal_clients_without_publishing_release_receipt(self):
        with mock.patch.object(theap, 'run_cohort') as run:
            self.assertEqual(theap.cli(['--debug']), 0)
        run.assert_called_once_with(('release',), False, debug=True)

    def test_debug_reader_binds_opt0_core_and_ordinary_driver_compilers(self):
        receipt, pin, commands = self.receipt_fixture('release')
        latest = receipt.path.parent
        products, logs = latest / 'products', latest / 'logs'
        work = Path(theap.harness.ROOT / json.loads(receipt.path.read_text())['work'])
        original_output = work / 'release'
        flags = list(theap.compiler_flags('release', True))
        inputs = json.loads((products / 'release-inputs.json').read_text())
        inputs.update(allocator_flags=flags, build_profile='debug', scope='legal-public-theap-debug')
        (products / 'release-inputs.json').write_text(json.dumps(inputs))
        runtime_path = theap.harness.ROOT / 'compat/x86_64/native_static_source_runtime_closure.py'
        import importlib.util
        spec = importlib.util.spec_from_file_location('theap_test_core', runtime_path)
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        core_flags = list(runtime.runtime_flags('pic'))
        provenance = {'flags':core_flags, 'environment': {
            'CARGO_ENCODED_RUSTFLAGS':'\x1f'.join(core_flags), 'CARGO_PROFILE_DEV_OPT_LEVEL':'0'}}
        core = products / 'release-source-runtime.json'
        core.write_text(json.dumps(provenance))
        library = work / 'cargo-target' / theap.m4.RUST_TARGET / 'debug' / theap.m4.ADAPTER_STATICLIB
        adapter_command = [str(runtime.PINNED_RUSTUP_FRONTEND), 'run', runtime.TOOLCHAIN, 'cargo',
            '-Zbuild-std=core,compiler_builtins', 'build', '--locked', '--offline', '--message-format=json',
            '--target', theap.m4.RUST_TARGET, '-p', theap.m4.ADAPTER_PACKAGE,
            '--target-dir', str(work / 'cargo-target')]
        raw_adapter = json.loads((logs / 'release/adapter-build.json').read_text())
        raw_adapter.update(command=adapter_command, stdout='\n'.join(json.dumps({
            'reason':'compiler-artifact','target':{'name':name},'profile':{'opt_level':'0'}})
            for name in ('core','compiler_builtins','crabc_mimalloc_native_mi_adapter')))
        raw_adapter['artifact']['path'] = library.relative_to(theap.harness.ROOT).as_posix()
        (logs / 'adapter-build.json').write_text(json.dumps(raw_adapter))
        selected = receipt.cases[:4]
        for case in selected:
            label = case['id'].removeprefix('release-')
            stem = {'c-run':'c','rust-run':'rust'}.get(label, label)
            record = json.loads((logs / 'release' / (stem+'.json')).read_text())
            argv = [argument.replace(str(original_output), str(work)) for argument in record['command']]
            if label in ('c-build','rust-link'):
                argv = [argument for argument in argv if not argument.startswith('-O')]
                argv.insert(argv.index('-UNDEBUG'), '-O0')
                if label == 'rust-link':
                    argv[-4] = str(library)
            record['command'] = argv
            (logs / (stem+'.json')).write_text(json.dumps(record))
            case['logs'] = {stem+'.json':{}}
            if label == 'rust-link':
                case['logs']['adapter-build.json'] = {}
        receipt.cases = selected
        receipt.case_ids = lambda prefix='':[case['id'] for case in selected]
        receipt.parameters = theap.parameters(('release',), False, True)
        with mock.patch.object(theap.receipts, 'read_receipt', return_value=receipt), \
             mock.patch.object(theap.harness, 'load_pin', return_value=pin):
            self.assertEqual(theap.cli(['--debug','--read']), 0)
            for field, changed in (('flags', core_flags[:-1]), ('environment',
                    {**provenance['environment'], 'CARGO_PROFILE_DEV_OPT_LEVEL':'1'})):
                altered = {**provenance, field:changed}
                core.write_text(json.dumps(altered))
                with self.subTest(field=field), self.assertRaises(theap.harness.HarnessError):
                    theap.cli(['--debug','--read'])
                core.write_text(json.dumps(provenance))
            for target in ('core','compiler_builtins'):
                changed = dict(raw_adapter, stdout='\n'.join(line for line in raw_adapter['stdout'].splitlines()
                    if json.loads(line)['target']['name'] != target))
                (logs / 'adapter-build.json').write_text(json.dumps(changed))
                with self.subTest(target=target), self.assertRaises(theap.harness.HarnessError):
                    theap.cli(['--debug','--read'])
                (logs / 'adapter-build.json').write_text(json.dumps(raw_adapter))

    def test_successful_process_with_wrong_visitor_geometry_is_retained_and_rejected(self):
        changed = self.observation(visitor='0,0,1,1,1,1,1,1')
        with mock.patch.object(theap.harness, 'command_record',
             side_effect=[self.observation(), changed]):
            with self.assertRaises(theap.harness.HarnessError):
                theap.observe(self.drivers, self.output, 'debug-1', False, [])
        self.assertEqual(json.loads((self.output / 'rust.json').read_text()), changed)
        self.assertEqual((self.output / 'rust.log').read_text(), changed['stdout'] + changed['stderr'])
        self.assertEqual(json.loads((self.output / 'c.json').read_text())['status'], 0)

    def test_matrix_stops_at_callback_mismatch_without_publishing_a_receipt(self):
        def run(profile, guarded, cases):
            directory = self.output / profile
            directory.mkdir()
            records = [self.observation(), self.observation(
                visitor='0,0,1,1,1,1,1,1' if profile == 'debug-1' else None)]
            with mock.patch.object(theap.harness, 'command_record', side_effect=records):
                count = theap.observe(self.drivers, directory, profile, guarded, cases)
            return count, {}
        with mock.patch.object(theap.receipts, 'source_seal', return_value={}), \
             mock.patch.object(theap, 'run_profile', side_effect=run) as execute, \
             mock.patch.object(theap.receipts, 'write_receipt') as publish:
            with self.assertRaises(theap.harness.HarnessError):
                theap.cli(['--matrix'])
        self.assertEqual([call.args[0] for call in execute.call_args_list], ['release', 'debug-1'])
        publish.assert_not_called()
        self.assertTrue((self.output / 'release/c.json').is_file())
        self.assertTrue((self.output / 'debug-1/rust.json').is_file())

    def test_guarded_only_receipt_cannot_replay_as_full_allocation_contract(self):
        receipt = SimpleNamespace(parameters=theap.parameters(theap.PROFILES, True))
        with mock.patch.object(theap.receipts, 'read_receipt', return_value=receipt), \
             mock.patch.object(theap.harness, 'command_record') as execute:
            with self.assertRaises(theap.harness.HarnessError):
                theap.cli(['--matrix', '--replay'])
        execute.assert_not_called()

    def test_successful_cargo_exit_with_zero_executed_tests_is_rejected(self):
        record = {'status': 0, 'stdout': 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;\n',
                  'stderr': ''}
        with mock.patch.object(theap.harness, 'require_tool', return_value='cargo'), \
             mock.patch.object(theap.harness, 'command_record', return_value=record) as execute:
            with self.assertRaises(theap.harness.HarnessError):
                theap.native_controls(self.output, 'stat-2', [])
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(json.loads((self.output / 'native_theap_contract.json').read_text()), record)

    def test_secure_three_executes_configuration_and_encoded_null_controls(self):
        executable=self.output/'unit-executable';executable.write_bytes(b'unit test artifact')
        extras=('config::tests::secure_three_uses_encoded_padding_without_debug_or_statistics',
                'free_list::tests::encoded_links_use_both_source_keys_and_page_null_sentinel')
        for profile in (*theap.PROFILES, 'secure-1', 'secure-2', 'debug-2', 'debug-3', 'secure-3', *theap.m4.GUARDED_API_PROFILE_BASES):
            executed=[]
            def run(output,label,argv,cwd):
                executed.append(argv)
                target='native_theap_contract' if '--test' in argv else 'crabc_mimalloc'
                stdout=json.dumps({'reason':'compiler-artifact','target':{'name':target},
                    'executable':str(executable)})+'\n'
                stdout+='test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;\n'
                return {'status':0,'stdout':stdout,'stderr':''},[]
            with self.subTest(profile=profile),mock.patch.object(theap,'command',side_effect=run), \
                 mock.patch.object(theap.harness,'require_tool',return_value='cargo'):
                theap.native_controls(self.output,profile,[])
                tests=[argv[argv.index('--')-1] for argv in executed]
                for extra in extras:
                    self.assertEqual(extra in tests,profile=='secure-3')
                for argv in executed:
                    if profile=='release':self.assertNotIn('--features',argv)
                    else:self.assertEqual(argv[argv.index('--features')+1],','.join(theap.m4.api_profile_features(profile)))


class TheapProfileSelectionTests(unittest.TestCase):
    def test_internal_debug_selection_is_explicit_and_ordered(self):
        with mock.patch.object(theap, 'run_cohort') as run:
            self.assertEqual(theap.cli(['--profiles', 'debug-3', 'debug-2']), 0)
            run.assert_called_once_with(('debug-3', 'debug-2'), False)

    def test_secure_selection_is_explicit_and_ordered(self):
        with mock.patch.object(theap, 'run_cohort') as run:
            self.assertEqual(theap.cli(['--profiles', 'secure-3', 'secure-1', 'secure-2']), 0)
            run.assert_called_once_with(('secure-3', 'secure-1', 'secure-2'), False)

    def test_default_and_matrix_remain_release_and_four_profiles(self):
        for arguments, profiles in (([], ('release',)), (['--matrix'], theap.PROFILES)):
            with mock.patch.object(theap, 'run_cohort') as run:
                self.assertEqual(theap.cli(arguments), 0)
                run.assert_called_once_with(profiles, False)

    def test_empty_unknown_or_duplicate_cohort_stops_before_source_or_execution(self):
        for profiles in ((), ('secure-4',), ('release', 'release')):
            with mock.patch.object(theap.receipts, 'source_seal', return_value={}) as source, \
                 mock.patch.object(theap, 'run_profile', return_value=(1, {})) as run, \
                 mock.patch.object(theap.receipts, 'write_receipt'), \
                 mock.patch.object(theap.receipts, 'read_receipt'):
                with self.assertRaises(theap.harness.HarnessError):
                    theap.run_cohort(profiles)
                source.assert_not_called()
                run.assert_not_called()

    def test_unknown_duplicate_or_conflicting_cli_selection_stops_before_work(self):
        for arguments in (['--profiles'], ['--profiles', 'secure-4'],
                          ['--profiles', 'secure-1', 'secure-1'],
                          ['--profiles', 'secure-1', '--matrix']):
            with mock.patch.object(theap, 'run_cohort') as run, mock.patch('sys.stderr'):
                with self.assertRaises(SystemExit) as stopped:
                    theap.cli(arguments)
                self.assertEqual(stopped.exception.code, 2)
                run.assert_not_called()

    def test_reader_rejects_extra_unselected_profile_cases(self):
        labels = ['c-build', 'rust-link', 'c-run', 'rust-run', 'native_theap_contract',
                  *(test.rsplit('::',1)[-1] for test in theap.UNIT_TESTS)]
        ids = [f'{profile}-{label}' for profile in theap.PROFILES for label in labels]
        ids += ['secure-1-c-run']
        receipt = SimpleNamespace(parameters=theap.parameters(theap.PROFILES, False),
            case_ids=lambda prefix='': [name for name in ids if name.startswith(prefix)])
        with mock.patch.object(theap.receipts, 'read_receipt', return_value=receipt):
            with self.assertRaises(theap.harness.HarnessError):
                theap.cli(['--matrix', '--read'])

    def test_reader_rejects_partial_selected_cohort_before_replay(self):
        profiles = ('secure-1', 'secure-2')
        receipt = SimpleNamespace(parameters=theap.parameters(profiles, False),
            case_ids=lambda prefix='': [prefix + 'c-build', prefix + 'rust-link', prefix + 'c-run'])
        with mock.patch.object(theap.receipts,'read_receipt',return_value=receipt), \
             mock.patch.object(theap.harness,'command_record') as execute:
            with self.assertRaises(theap.harness.HarnessError):
                theap.cli(['--profiles', *profiles, '--replay'])
            execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
