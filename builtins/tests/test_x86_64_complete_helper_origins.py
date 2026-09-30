"""Replay complete owned helper bodies, local edges, and compiler consumers."""
from pathlib import Path
import importlib.util
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
PINNED=Path('/opt/rustup/toolchains/nightly-2026-09-15-x86_64-unknown-linux-musl')

@unittest.skipUnless((PINNED/'bin/rustc').is_file(),'requires the pinned native x86 environment')
class CompleteHelperOriginPhysicalTests(unittest.TestCase):
    def test_complete_helpers_execute_and_reject_counterfeit_private_dependencies(self):
        parent=ROOT/'.work/x86_64/complete-helper-origins';parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            work=Path(directory)
            spec=importlib.util.spec_from_file_location('owned_builder_complete',ROOT/'builtins/build_x86_64.py')
            builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
            archive=work/'libcrabc-builtins.a'
            subprocess.run(['python3','-B',str(ROOT/'builtins/build_x86_64.py'),'--output',str(archive)],check=True,capture_output=True)
            compiler='/usr/local/bin/crabc-x86_64-musl-gcc'
            obj=work/'aggregate.o';start=work/'start.o'
            subprocess.run([compiler,'-O2','-ffreestanding','-fno-builtin','-fno-stack-protector',
                            '-fno-asynchronous-unwind-tables','-fno-unwind-tables','-DCRABC_BUILTINS_FREESTANDING',
                            '-c',str(ROOT/'builtins/fixtures/x86_64_compiler_helper_aggregate_probe.c'),'-o',str(obj)],check=True,capture_output=True)
            subprocess.run([compiler,'-c',str(ROOT/'builtins/fixtures/x86_64_compiler_helper_aggregate_start.S'),'-o',str(start)],check=True,capture_output=True)
            sys.path.insert(0,str(ROOT/'compat/x86_64'))
            import compiler_helper_evidence as reader
            names=set(reader.helper_names(reader.load_contract(ROOT)))
            undefined=subprocess.check_output(['nm','--undefined-only',str(obj)],text=True)
            self.assertEqual({line.split()[-1] for line in undefined.splitlines()},names)
            for mode in ('static','pie'):
                binary=work/mode;map_path=work/(mode+'.map');trace=work/(mode+'.trace')
                linked=subprocess.run([builder.tool('ld.lld'),'-static',*(['-pie'] if mode=='pie' else []),
                                       '--no-dynamic-linker','--no-undefined','-Map',str(map_path),'-t',str(start),str(obj),str(archive),'-o',str(binary)],capture_output=True)
                self.assertEqual(linked.returncode,0,linked.stderr.decode());trace.write_bytes(linked.stdout)
                executed=subprocess.run([str(binary)],check=True,capture_output=True)
                self.assertEqual(executed.stdout,b'compiler-helper-aggregate-ok\n')
                arguments=dict(root=ROOT,archive=archive,workload=obj,executable=binary,map_path=map_path,trace_path=trace)
                observed=reader._compiler_helper_transfers(**arguments)
                self.assertEqual(set(observed['transfers']),names)
                original_map=map_path.read_text()
                with self.assertRaisesRegex(reader.CompilerHelperEvidenceError,'selected provider roster'):
                    reader._compiler_helper_transfers(**arguments,names=['__foreign_helper'])
                original=binary.read_bytes();elf=reader.Elf(binary)
                division=observed['transfers']['__divti3']['provider_closure']
                private=next(row for row in division['code'] if row['section']!='.text.__divti3')
                constant=observed['transfers']['__muldc3']['provider_closure']['constants'][0]
                for address in (private['address'],constant['address']):
                    program=next(p for p in elf.programs if p[0]==1 and p[3]<=address<p[3]+p[5])
                    offset=program[2]+address-program[3]
                    counterfeit=bytearray(original);counterfeit[offset]^=1;binary.write_bytes(counterfeit)
                    with self.assertRaisesRegex(reader.CompilerHelperEvidenceError,'provider (code|constant) bytes'):
                        reader._compiler_helper_transfers(**arguments)
                    binary.write_bytes(original)
                private_suffix=':('+private['section']+')'
                map_path.write_text('\n'.join(line for line in original_map.splitlines() if not line.rstrip().endswith(private_suffix))+'\n')
                with self.assertRaisesRegex(reader.CompilerHelperEvidenceError,'contribution is missing'):
                    reader._compiler_helper_transfers(**arguments)
                map_path.write_text(original_map)
                edge=division['code'][0]['relocations'][0]
                address=division['code'][0]['address']+edge['offset']
                program=next(p for p in elf.programs if p[0]==1 and p[3]<=address<p[3]+p[5])
                offset=program[2]+address-program[3]
                counterfeit=bytearray(original);counterfeit[offset:offset+4]=b'\0'*4;binary.write_bytes(counterfeit)
                with self.assertRaisesRegex(reader.CompilerHelperEvidenceError,'branch resolves to foreign code'):
                    reader._compiler_helper_transfers(**arguments)
                binary.write_bytes(original)
