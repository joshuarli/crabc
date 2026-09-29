"""Execute compiler-emitted binary64/integer128 calls through owned ELF inputs."""
from pathlib import Path
import importlib.util
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
PINNED=Path('/opt/rustup/toolchains/nightly-2026-09-15-x86_64-unknown-linux-musl')

@unittest.skipUnless((PINNED/'bin/rustc').is_file(),'requires the pinned native x86 environment')
class Int128CastPhysicalTests(unittest.TestCase):
    def test_compiler_emitted_casts_link_and_execute_in_static_and_pie(self):
        parent=ROOT/'.work/x86_64/int128-casts';parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            work=Path(directory)
            spec=importlib.util.spec_from_file_location('owned_builder',ROOT/'builtins/build_x86_64.py')
            builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
            archive=work/'libcrabc-builtins.a'
            subprocess.run(['python3','-B',str(ROOT/'builtins/build_x86_64.py'),'--output',str(archive)],check=True,capture_output=True)
            compiler='/usr/local/bin/crabc-x86_64-musl-gcc'
            source=ROOT/'builtins/fixtures/x86_64_int128_casts_probe.c'
            obj=work/'casts.o'
            subprocess.run([compiler,'-O2','-ffreestanding','-fno-builtin','-fno-stack-protector',
                            '-fno-asynchronous-unwind-tables','-fno-unwind-tables','-c',str(source),'-o',str(obj)],check=True,capture_output=True)
            undefined=subprocess.check_output(['nm','--undefined-only',str(obj)],text=True)
            self.assertEqual({line.split()[-1] for line in undefined.splitlines()},
                             {'__floattidf','__floatuntidf','__fixdfti','__fixunsdfti'})
            start=work/'start.S'
            start.write_text((ROOT/'builtins/fixtures/x86_64_compiler_helper_aggregate_start.S').read_text()
                             .replace('crabc_x86_64_compiler_helper_aggregate_probe','crabc_x86_64_int128_casts_probe'))
            start_obj=work/'start.o'
            subprocess.run([compiler,'-c',str(start),'-o',str(start_obj)],check=True,capture_output=True)
            linker=builder.tool('ld.lld')
            import sys
            sys.path.insert(0,str(ROOT/'compat/x86_64'))
            import compiler_helper_evidence as reader
            for mode in ('static','pie'):
                binary=work/mode
                map_path=work/(mode+'.map');trace_path=work/(mode+'.trace')
                linked=subprocess.run([linker,'-static',*(['-pie'] if mode=='pie' else []),'--no-dynamic-linker',
                                '--no-undefined','-Map',str(map_path),'-t','-e','_start',str(start_obj),str(obj),str(archive),'-o',str(binary)],capture_output=True)
                self.assertEqual(linked.returncode,0,linked.stderr.decode())
                trace_path.write_bytes(linked.stdout)
                result=subprocess.run([str(binary)],check=True,capture_output=True)
                self.assertEqual(result.stdout,b'compiler-helper-aggregate-ok\n')
                arguments=dict(root=ROOT,archive=archive,workload=obj,executable=binary,
                               map_path=map_path,trace_path=trace_path)
                observations=reader._integer128_cast_transfers(**arguments)
                self.assertEqual(set(observations['transfers']),set(reader.INT128_CAST_NAMES))
                original_map=map_path.read_text()
                map_path.write_text(original_map.replace(str(archive)+'(crabc-builtins.o)',str(work/'libgcc.a')+'(crabc-builtins.o)'))
                with self.assertRaisesRegex(reader.CompilerHelperEvidenceError,'owned archive'):
                    reader._integer128_cast_transfers(**arguments)
                map_path.write_text(original_map)
                original_trace=trace_path.read_text()
                trace_path.write_text(original_trace.replace(str(archive)+'(crabc-builtins.o)',''))
                with self.assertRaisesRegex(reader.CompilerHelperEvidenceError,'exact owned member'):
                    reader._integer128_cast_transfers(**arguments)
                trace_path.write_text(original_trace)
                call=observations['transfers']['__floattidf']['resolved_calls'][0]['call_address']
                elf=reader.Elf(binary)
                program=next(p for p in elf.programs if p[0]==1 and p[3]<=call< p[3]+p[5])
                offset=program[2]+call-program[3]
                original=binary.read_bytes();counterfeit=bytearray(original)
                counterfeit[offset+1:offset+5]=b'\0'*4
                binary.write_bytes(counterfeit)
                with self.assertRaisesRegex(reader.CompilerHelperEvidenceError,'foreign provider'):
                    reader._integer128_cast_transfers(**arguments)
                binary.write_bytes(original)
                provider=observations['transfers']['__floattidf']['provider_address']
                program=next(p for p in elf.programs if p[0]==1 and p[3]<=provider< p[3]+p[5])
                provider_offset=program[2]+provider-program[3]
                counterfeit=bytearray(original);counterfeit[provider_offset]^=1
                binary.write_bytes(counterfeit)
                with self.assertRaisesRegex(reader.CompilerHelperEvidenceError,'provider bytes'):
                    reader._integer128_cast_transfers(**arguments)
                binary.write_bytes(original)
