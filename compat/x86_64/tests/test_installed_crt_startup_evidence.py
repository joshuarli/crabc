"""Exact installed CRT ownership and finite startup receipt regressions."""
import copy
import hashlib
import json
import subprocess
from unittest import mock
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import installed_crt_startup_evidence as reader

class InstalledCrtStartupTests(unittest.TestCase):
    _FROZEN_0E_REPORT = (
        Path(__file__).resolve().parents[4] / 'native_abi_protocol_integration/.work/x86_64/'
        'crt-startup-evidence/clean-0e7af481/report.json'
    )

    def test_retained_main_image_descriptor_transport_has_exact_owned_boundary(self):
        """Project actual v1 facts only; it is never a v3 admission waiver."""
        if not self._FROZEN_0E_REPORT.is_file():
            self.skipTest('requires retained 0e startup receipt')
        self.assertEqual(hashlib.sha256(self._FROZEN_0E_REPORT.read_bytes()).hexdigest(),
                         'e53fe18993303b6ea290773298fcc66ee198477431aaf57da39deb0358195bd6')
        report=json.loads(self._FROZEN_0E_REPORT.read_text())
        handoff=reader.descriptor_handoff(
            report['observations']['product_relocations'], report['observations']['executables'])
        self.assertEqual(handoff['source_artifact'],'dynamic-crabc-dynamic-attach.o')
        slots=handoff['executables']
        self.assertEqual({name for name,row in slots.items() if row['slot']},
                         {'owned-pie-normal','owned-pie-empty',
                          'owned-non-pie-normal','owned-non-pie-empty'})
        self.assertTrue(all(not row['slot'] for name,row in slots.items()
                            if not name.startswith(('owned-pie-','owned-non-pie-'))))
        def without_source(value):
            rows=value['observations']['product_relocations']['dynamic-crabc-dynamic-attach.o']
            rows[:]=[row for row in rows if row['name']!=reader.DESCRIPTOR]
        def static_slot(value):
            source=next(row for row in value['observations']['executables']['owned-pie-normal']['relocations']
                        if row['name']==reader.DESCRIPTOR)
            value['observations']['executables']['static-normal']['relocations'].append(copy.deepcopy(source))
        def wrong_owned_kind(value):
            slot=next(row for row in value['observations']['executables']['owned-pie-normal']['relocations']
                      if row['name']==reader.DESCRIPTOR)
            slot['kind']=7
        for mutate in (without_source,static_slot,wrong_owned_kind):
            with self.subTest(mutate=mutate):
                changed=copy.deepcopy(report)
                mutate(changed)
                with self.assertRaises(reader.StartupEvidenceError):
                    reader.descriptor_handoff(changed['observations']['product_relocations'],
                                              changed['observations']['executables'])

    def test_probe_rejects_a_weak_handoff_with_the_wrong_symbol_type(self):
        """The live main-image observer must not accept a weak non-OBJECT slot."""
        parent=reader.ROOT/'.work/x86_64/crt-startup-development';parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            work=Path(directory);source=work/'wrong-handoff-type.c';binary=work/'wrong-handoff-type'
            source.write_text(r'''
#define CRABC_STARTUP_PROBE_WIRE_HARNESS 1
#define EMPTY_ARRAYS 1
#define main installed_crt_startup_probe_main
#include "compat/x86_64/installed_crt_startup_probe.c"
#undef main
#include <sys/wait.h>
uintptr_t __stack_chk_guard;
int main(void) {
    static const char strings[]="\0__crabc_x86_64_owned_crt_handoff";
    Elf64_Sym symbols[2]={0}; Elf64_Rela relocation={0}; Elf64_Dyn dynamic[5]={0};
    Elf64_Phdr program[2]={0}; struct dl_phdr_info info={0}; uintptr_t slot=0;
    symbols[1].st_name=1;
    symbols[1].st_info=ELF64_ST_INFO(STB_WEAK,STT_FUNC);
    symbols[1].st_other=STV_DEFAULT; symbols[1].st_shndx=SHN_UNDEF;
    relocation.r_offset=(Elf64_Addr)(uintptr_t)&slot;
    relocation.r_info=ELF64_R_INFO(1,R_X86_64_GLOB_DAT);
    dynamic[0]=(Elf64_Dyn){.d_tag=DT_SYMTAB,.d_un.d_ptr=(Elf64_Addr)(uintptr_t)symbols};
    dynamic[1]=(Elf64_Dyn){.d_tag=DT_STRTAB,.d_un.d_ptr=(Elf64_Addr)(uintptr_t)strings};
    dynamic[2]=(Elf64_Dyn){.d_tag=DT_RELA,.d_un.d_ptr=(Elf64_Addr)(uintptr_t)&relocation};
    dynamic[3]=(Elf64_Dyn){.d_tag=DT_RELASZ,.d_un.d_val=sizeof relocation};
    program[0]=(Elf64_Phdr){.p_type=PT_LOAD,.p_flags=PF_X,
                            .p_vaddr=(Elf64_Addr)(uintptr_t)(void *)&wires,.p_memsz=1};
    program[1]=(Elf64_Phdr){.p_type=PT_DYNAMIC,.p_vaddr=(Elf64_Addr)(uintptr_t)dynamic};
    info.dlpi_phdr=program; info.dlpi_phnum=2; info.dlpi_name="";
    pid_t child=fork(); if (child<0) return 2;
    if (!child) { struct wire_state state={0}; wires(&info,0,&state); _Exit(0); }
    int status=0;
    return waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status)!=102;
}
''',encoding='utf-8')
            subprocess.run(['cc','-std=c11','-I',str(reader.ROOT),str(source),'-o',str(binary)],
                           cwd=reader.ROOT,check=True,capture_output=True,text=True)
            subprocess.run([str(binary)],cwd=reader.ROOT,check=True,capture_output=True,text=True)

    def test_probe_keeps_conventional_shared_slot_outside_main_descriptor_scope(self):
        """The descriptor transport is main-only; the legacy snapshot remains graph-wide."""
        parent=reader.ROOT/'.work/x86_64/crt-startup-development';parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            work=Path(directory);source=work/'wire-scopes.c';binary=work/'wire-scopes'
            source.write_text(r'''
#define CRABC_STARTUP_PROBE_WIRE_HARNESS 1
#define EMPTY_ARRAYS 1
#define main installed_crt_startup_probe_main
#include "compat/x86_64/installed_crt_startup_probe.c"
#undef main
uintptr_t __stack_chk_guard;
static const char strings[]="\0__crabc_x86_64_owned_crt_handoff\0__crabc_x86_64_loader_tls_runtime_v1\0__crabc_x86_64_loader_conventional_startup_v1";
static void import(Elf64_Sym *symbol,size_t offset,int type) {
    *symbol=(Elf64_Sym){.st_name=offset,.st_info=ELF64_ST_INFO(STB_WEAK,type),
                         .st_other=STV_DEFAULT,.st_shndx=SHN_UNDEF};
}
static struct dl_phdr_info image(const char *name,Elf64_Phdr *program,Elf64_Dyn *dynamic,int owns_probe) {
    if (owns_probe) {
        program[0]=(Elf64_Phdr){.p_type=PT_LOAD,.p_flags=PF_X,
                                 .p_vaddr=(Elf64_Addr)(uintptr_t)(void *)&wires,.p_memsz=1};
        program[1]=(Elf64_Phdr){.p_type=PT_DYNAMIC,.p_vaddr=(Elf64_Addr)(uintptr_t)dynamic};
    } else program[0]=(Elf64_Phdr){.p_type=PT_DYNAMIC,.p_vaddr=(Elf64_Addr)(uintptr_t)dynamic};
    return (struct dl_phdr_info){.dlpi_phdr=program,.dlpi_phnum=(ElfW(Half))(owns_probe ? 2 : 1),.dlpi_name=name};
}
int main(void) {
    enum { H=1, D=1+sizeof "__crabc_x86_64_owned_crt_handoff",
           C=1+sizeof "__crabc_x86_64_owned_crt_handoff"+sizeof "__crabc_x86_64_loader_tls_runtime_v1" };
    Elf64_Sym main_symbols[3]={0},shared_symbols[4]={0};
    Elf64_Rela main_relocations[2]={0},shared_relocations[3]={0};
    Elf64_Dyn main_dynamic[5]={0},shared_dynamic[5]={0}; Elf64_Phdr main_program[2],shared_program[1];
    uintptr_t handoff=0x100,descriptor=0x200,snapshot=0,rogue_handoff=0x300,rogue_descriptor=0x400;
    import(&main_symbols[1],H,STT_OBJECT); import(&main_symbols[2],D,STT_NOTYPE);
    import(&shared_symbols[1],C,STT_OBJECT); import(&shared_symbols[2],H,STT_OBJECT); import(&shared_symbols[3],D,STT_NOTYPE);
    main_relocations[0]=(Elf64_Rela){.r_offset=(Elf64_Addr)(uintptr_t)&handoff,.r_info=ELF64_R_INFO(1,R_X86_64_GLOB_DAT)};
    main_relocations[1]=(Elf64_Rela){.r_offset=(Elf64_Addr)(uintptr_t)&descriptor,.r_info=ELF64_R_INFO(2,R_X86_64_GLOB_DAT)};
    shared_relocations[0]=(Elf64_Rela){.r_offset=(Elf64_Addr)(uintptr_t)&snapshot,.r_info=ELF64_R_INFO(1,R_X86_64_GLOB_DAT)};
    shared_relocations[1]=(Elf64_Rela){.r_offset=(Elf64_Addr)(uintptr_t)&rogue_handoff,.r_info=ELF64_R_INFO(2,R_X86_64_GLOB_DAT)};
    shared_relocations[2]=(Elf64_Rela){.r_offset=(Elf64_Addr)(uintptr_t)&rogue_descriptor,.r_info=ELF64_R_INFO(3,R_X86_64_GLOB_DAT)};
    main_dynamic[0]=(Elf64_Dyn){.d_tag=DT_SYMTAB,.d_un.d_ptr=(Elf64_Addr)(uintptr_t)main_symbols};
    main_dynamic[1]=(Elf64_Dyn){.d_tag=DT_STRTAB,.d_un.d_ptr=(Elf64_Addr)(uintptr_t)strings};
    main_dynamic[2]=(Elf64_Dyn){.d_tag=DT_RELA,.d_un.d_ptr=(Elf64_Addr)(uintptr_t)main_relocations};
    main_dynamic[3]=(Elf64_Dyn){.d_tag=DT_RELASZ,.d_un.d_val=sizeof main_relocations};
    shared_dynamic[0]=(Elf64_Dyn){.d_tag=DT_SYMTAB,.d_un.d_ptr=(Elf64_Addr)(uintptr_t)shared_symbols};
    shared_dynamic[1]=(Elf64_Dyn){.d_tag=DT_STRTAB,.d_un.d_ptr=(Elf64_Addr)(uintptr_t)strings};
    shared_dynamic[2]=(Elf64_Dyn){.d_tag=DT_RELA,.d_un.d_ptr=(Elf64_Addr)(uintptr_t)shared_relocations};
    shared_dynamic[3]=(Elf64_Dyn){.d_tag=DT_RELASZ,.d_un.d_val=sizeof shared_relocations};
    struct dl_phdr_info shared=image("/usr/lib/libc.so",shared_program,shared_dynamic,0);
    struct dl_phdr_info main=image("",main_program,main_dynamic,1); struct wire_state state={0};
    wires(&shared,0,&state); wires(&main,0,&state);
    return state.main_images!=1 || state.handoffs!=1 || state.handoff!=handoff
        || state.descriptors!=1 || state.descriptor!=descriptor
        || state.conventional!=1 || state.snapshot!=snapshot;
}
''',encoding='utf-8')
            subprocess.run(['cc','-std=c11','-I',str(reader.ROOT),str(source),'-o',str(binary)],
                           cwd=reader.ROOT,check=True,capture_output=True,text=True)
            subprocess.run([str(binary)],cwd=reader.ROOT,check=True,capture_output=True,text=True)

    def test_probe_identifies_the_named_direct_main_by_its_own_code_load(self):
        """The source object anchors the direct main without auxv or name fallback."""
        parent=reader.ROOT/'.work/x86_64/crt-startup-development';parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            work=Path(directory);source=work/'direct-main.c';binary=work/'direct-main'
            source.write_text(r'''
#define CRABC_STARTUP_PROBE_WIRE_HARNESS 1
#define EMPTY_ARRAYS 1
#define main installed_crt_startup_probe_main
#include "compat/x86_64/installed_crt_startup_probe.c"
#undef main
uintptr_t __stack_chk_guard;
static void import(Elf64_Sym *symbol,size_t offset,int type) {
    *symbol=(Elf64_Sym){.st_name=offset,.st_info=ELF64_ST_INFO(STB_WEAK,type),
                         .st_other=STV_DEFAULT,.st_shndx=SHN_UNDEF};
}
int main(void) {
    static const char strings[]="\0__crabc_x86_64_owned_crt_handoff\0__crabc_x86_64_loader_tls_runtime_v1";
    enum { H=1, D=1+sizeof "__crabc_x86_64_owned_crt_handoff" };
    Elf64_Sym symbols[3]={0}; Elf64_Rela relocations[2]={0}; Elf64_Dyn dynamic[5]={0};
    Elf64_Phdr expected_program[2]={0},spoof_program[2]={0}; uintptr_t handoff=0x100,descriptor=0x200;
    import(&symbols[1],H,STT_OBJECT); import(&symbols[2],D,STT_NOTYPE);
    relocations[0]=(Elf64_Rela){.r_offset=(Elf64_Addr)(uintptr_t)&handoff,.r_info=ELF64_R_INFO(1,R_X86_64_GLOB_DAT)};
    relocations[1]=(Elf64_Rela){.r_offset=(Elf64_Addr)(uintptr_t)&descriptor,.r_info=ELF64_R_INFO(2,R_X86_64_GLOB_DAT)};
    dynamic[0]=(Elf64_Dyn){.d_tag=DT_SYMTAB,.d_un.d_ptr=(Elf64_Addr)(uintptr_t)symbols};
    dynamic[1]=(Elf64_Dyn){.d_tag=DT_STRTAB,.d_un.d_ptr=(Elf64_Addr)(uintptr_t)strings};
    dynamic[2]=(Elf64_Dyn){.d_tag=DT_RELA,.d_un.d_ptr=(Elf64_Addr)(uintptr_t)relocations};
    dynamic[3]=(Elf64_Dyn){.d_tag=DT_RELASZ,.d_un.d_val=sizeof relocations};
    expected_program[0]=(Elf64_Phdr){.p_type=PT_LOAD,.p_flags=PF_X,
                                     .p_vaddr=(Elf64_Addr)(uintptr_t)(void *)&wires,.p_memsz=1};
    expected_program[1]=(Elf64_Phdr){.p_type=PT_DYNAMIC,.p_vaddr=(Elf64_Addr)(uintptr_t)dynamic};
    spoof_program[0]=expected_program[0]; spoof_program[0].p_vaddr++;
    spoof_program[1]=expected_program[1];
    struct dl_phdr_info direct={.dlpi_phdr=expected_program,.dlpi_phnum=2,.dlpi_name="/owned-pie-normal"};
    struct dl_phdr_info spoof={.dlpi_phdr=spoof_program,.dlpi_phnum=2,.dlpi_name=""};
    struct wire_state direct_state={0},spoof_state={0}; wires(&direct,0,&direct_state); wires(&spoof,0,&spoof_state);
    return direct_state.main_images!=1 || direct_state.handoffs!=1 || direct_state.handoff!=handoff
        || direct_state.descriptors!=1 || direct_state.descriptor!=descriptor
        || spoof_state.main_images || spoof_state.handoffs || spoof_state.descriptors;
}
''',encoding='utf-8')
            subprocess.run(['cc','-std=c11','-I',str(reader.ROOT),str(source),'-o',str(binary)],
                           cwd=reader.ROOT,check=True,capture_output=True,text=True)
            subprocess.run([str(binary)],cwd=reader.ROOT,check=True,capture_output=True,text=True)

    def test_duplicate_report_spellings_reject_before_replay(self):
        for options in (['--report=one','--report=two'],['--report','one','--report=two']):
            with self.subTest(options=options), mock.patch.object(reader,'validate_report',
                    side_effect=AssertionError('duplicate option reached replay')):
                with self.assertRaisesRegex(reader.StartupEvidenceError,'duplicate startup option'):
                    reader.main(['validate-report',*options])

    def test_descriptor_command_replay_rejects_a_self_sealed_true_command(self):
        """The canonical plan, rather than its retained command JSON, owns argv."""
        parent=reader.ROOT/'.work/x86_64/crt-startup-development';parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            root=Path(directory);work=root/'.work/receipt';raw=work/'raw';raw.mkdir(parents=True)
            label='descriptor-wrong-addend-kernel'
            spec={'label':label,'argv':['/usr/bin/env','-i','CRABC_STARTUP=yes','/usr/sbin/chroot',
                                         '/workspace/.work/receipt/candidate-root','/descriptor-wrong-addend','owned'],
                  'cwd':'/workspace','expected_status':127,'expected_stdout':b'','expected_stderr':b'reloc\n'}
            paths={suffix:reader.ordinary.raw_path(work,label,suffix) for suffix in ('command.json','stdout','stderr','status')}
            paths['command.json'].write_text(json.dumps(spec['argv'])+'\n')
            paths['stdout'].write_bytes(b'');paths['stderr'].write_bytes(b'reloc\n');paths['status'].write_bytes(b'127\n')
            row={'label':label,'argv':list(spec['argv']),'cwd':'/workspace','outcome':'ok',
                 'command':reader.ordinary.work_file_identity(root,paths['command.json'],'command'),
                 'stdout':reader.ordinary.work_file_identity(root,paths['stdout'],'stdout'),
                 'stderr':reader.ordinary.work_file_identity(root,paths['stderr'],'stderr'),
                 'status':reader.ordinary.work_file_identity(root,paths['status'],'status')}
            with mock.patch.object(reader,'plan',return_value=[spec]):
                reader.validate_commands(root,work,{}, {},[row])
                row['argv']=['/bin/true','--not-the-retained-chroot-command']
                paths['command.json'].write_text(json.dumps(row['argv'])+'\n')
                row['command']=reader.ordinary.work_file_identity(root,paths['command.json'],'forged command')
                with self.assertRaises(reader.StartupEvidenceError):
                    reader.validate_commands(root,work,{}, {},[row])

    def test_collector_stdout_default_still_rejects_unexpected_stderr(self):
        """Descriptor rejection support must not relax every existing stdout control."""
        parent=reader.ROOT/'.work/x86_64/crt-startup-development';parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            root=Path(directory);work=root/'.work/collector';work.mkdir(parents=True)
            collector=reader.ordinary.Collector(root,work,Path('preparation'),Path('static'),Path('dynamic'))
            with self.assertRaises(reader.ordinary.PublicDataEvidenceError):
                collector.run('stdout-default',['/bin/sh','-c','printf expected; printf unexpected >&2'],
                              stdout=b'expected')

    def test_collector_accepts_the_explicit_descriptor_rejection_stream(self):
        """The new finite rejection cells may seal their nonzero status and stderr."""
        parent=reader.ROOT/'.work/x86_64/crt-startup-development';parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            root=Path(directory);work=root/'.work/collector';work.mkdir(parents=True)
            collector=reader.ordinary.Collector(root,work,Path('preparation'),Path('static'),Path('dynamic'))
            row=collector.run('descriptor-rejection',['/bin/sh','-c','printf reloc >&2; exit 127'],
                              stdout=b'',stderr=b'reloc',expected_status=127)
            self.assertEqual(row['outcome'],'ok')
            self.assertEqual((work/'raw/descriptor-rejection.status').read_bytes(),b'127\n')

    def test_retained_fed_main_supplies_the_exact_four_canonical_mutations(self):
        """This observes fed placement only; it deliberately does not admit its old loader."""
        main=reader.ROOT.parent/'native_crt_main_anchor_integration/.work/x86_64/crt-startup-evidence/clean-fed397b0/owned-pie-normal'
        if not main.is_file():self.skipTest('requires retained fed owned PIE main')
        self.assertEqual(hashlib.sha256(main.read_bytes()).hexdigest(),'5cdfa442f1d96018a797f18c24e38862f229425fed093469f95822df273d4b97')
        parent=reader.ROOT/'.work/x86_64/crt-startup-development';parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            work=Path(directory);before=main.read_bytes();symbol,relocation,info=reader.descriptor_slot(before)
            for label,(field,value) in reader.DESCRIPTOR_MUTATIONS.items():
                output=work/label;mutation=reader.mutate_descriptor_main(main,output,label)
                self.assertEqual((mutation['symbol_file_offset'],mutation['rela_file_offset'],mutation['field'],mutation['value']),
                                 (symbol,relocation,field,value))
                changed=output.read_bytes()
                if field=='symbol-info':self.assertEqual(changed[symbol+4],value)
                elif field=='relocation-kind':self.assertEqual(changed[relocation+8:relocation+16],((info&~0xffffffff)|value).to_bytes(8,'little'))
                else:self.assertEqual(changed[relocation+16:relocation+24],value.to_bytes(8,'little',signed=True))
            self.assertEqual(main.read_bytes(),before)

    def test_candidate_root_rejects_self_sealed_loader_and_control_substitution(self):
        """The selected product tree and linked control determine execution bytes."""
        parent=reader.ROOT/'.work/x86_64/crt-startup-development';parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            work=Path(directory);policy=reader.expected_contract()['descriptor_handoff']['admission']
            main=work/'owned-pie-normal';main.write_bytes(b'linked control');main.chmod(0o755)
            for label in policy['mutations']:
                path=work/('descriptor-'+label);path.write_bytes(label.encode());path.chmod(0o755)
            for name in (policy['dso']['endpoint'],policy['dso']['shared_object']):
                path=work/name;path.write_bytes(name.encode());path.chmod(0o755)
            runtime=work/'qualification-oracle/runtime';runtime.parent.mkdir();runtime.write_bytes(b'oracle');runtime.chmod(0o755)
            selected={'lib':{'kind':'directory','mode':0o755},
                      'lib/ld-crabc-x86_64.so.1':{'kind':'file','mode':0o755,'size':8,'sha256':'selected'},
                      'usr':{'kind':'directory','mode':0o755},'usr/lib':{'kind':'directory','mode':0o755}}
            candidate=copy.deepcopy(selected)
            def record(path):return {'kind':'file','mode':0o755,'size':path.stat().st_size,'sha256':reader.ordinary.digest(path)}
            candidate['owned-pie-normal']=record(main)
            for label in policy['mutations']:candidate['descriptor-'+label]=record(work/('descriptor-'+label))
            candidate[policy['dso']['endpoint']]=record(work/policy['dso']['endpoint'])
            candidate['usr/lib/'+policy['dso']['shared_object']]=record(work/policy['dso']['shared_object'])
            oracle={'lib':{'kind':'directory','mode':0o755},
                    'lib/libc.so':{'kind':'symlink','mode':0o777,'target':'ld-musl-x86_64.so.1'},
                    'lib/ld-musl-x86_64.so.1':record(runtime)}
            case=[{'mode':'owned-pie','variant':'normal','name':'owned-pie-normal'}]
            for key in ('lib/ld-crabc-x86_64.so.1','owned-pie-normal'):
                forged=copy.deepcopy(candidate);forged[key]['sha256']='self-sealed-replacement'
                with self.subTest(replacement=key),mock.patch.object(reader,'cases',return_value=case), \
                        mock.patch.object(reader.ordinary,'execution_tree',side_effect=[forged,oracle]):
                    with self.assertRaises(reader.StartupEvidenceError):reader.roots(reader.ROOT,work,{'dynamic_tree':selected})

    def test_crt_caller_relocations_are_required_per_object(self):
        # Exact raw rows from pinned b525 product bytes, retained by the e434
        # startup receipt. Calling artifact_relocations keeps this regression
        # at the owning public observation boundary, not a new helper alone.
        rows=json.loads(Path(__file__).with_name('installed_crt_startup_relocations.json').read_text())
        paths={role:Path(role) for role in rows}
        def observe(value):
            with mock.patch.object(reader,'product_paths',return_value=paths), \
                 mock.patch.object(reader,'relocations',side_effect=lambda path:copy.deepcopy(value[str(path)])):
                return reader.artifact_relocations(reader.ROOT,Path('.'),{})
        observe(rows)
        for role,values in rows.items():
            if not role.endswith('.o'):
                continue
            for index,row in enumerate(values):
                changes=[('removed',None),('duplicate','duplicate'),('kind',7),('addend',0),
                         ('binding','LOCAL'),('symbol_type','TLS'),('symbol_section',False)]
                for field,value in changes:
                    with self.subTest(role=role,name=row['name'],mutation=field):
                        changed=copy.deepcopy(rows)
                        if field=='removed':del changed[role][index]
                        elif field=='duplicate':changed[role].append(copy.deepcopy(row))
                        else:changed[role][index][field]=value
                        with self.assertRaises(reader.StartupEvidenceError):observe(changed)

    def test_oracle_crt_capture_survives_actual_readability_cleanup(self):
        parent=reader.ROOT/'.work/x86_64/crt-startup-development';parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            root=Path(directory);source=root/'original.o';source.write_bytes(b'retained CRT fixture')
            source.chmod(0o644);work=root/'evidence';work.mkdir()
            record=reader.retain_oracle_crt(work,source,'crt1.o')
            reader.static_products.make_retained_evidence_readable(work)
            reader.inventory._validate_snapshot(work,record,'oracle CRT fixture',
                expected_original_path=str(source),expected_retained_path='inputs/oracle-crt/crt1.o')
            self.assertEqual(record['retained']['mode'],0o644)
            self.assertEqual(source.read_bytes(),b'retained CRT fixture')

    def test_contract_is_closed_and_flags_are_booleans(self):
        contract=reader.expected_contract()
        self.assertEqual(len(contract['identities']),12)
        admission=contract['descriptor_handoff']['admission']
        self.assertEqual(set(admission['mutations']),set(reader.DESCRIPTOR_MUTATIONS))
        self.assertEqual(admission['rejection'],{'status':127,'stdout':'','stderr':'reloc\n'})
        reader.validate_contract(contract)
        for bad in ({**contract,'public_support':0},{**contract,'identities':contract['identities'][:-1]},
                    {**contract,'extra':True}):
            with self.assertRaises(reader.StartupEvidenceError):reader.validate_contract(bad)

    def test_exact_weak_object_requires_defined_table_origin_and_zero_addend(self):
        row={'name':reader.CONVENTIONAL,'binding':'WEAK','visibility':'DEFAULT','type':'OBJECT',
             'section_index':'UND','version':None,'version_default':False,'size_bytes':0}
        reader.require_import(row,'OBJECT','WEAK','DEFAULT')
        for mutation in ({'binding':'GLOBAL'},{'section_index':'3'},{'version_default':0},{'size_bytes':0.0}):
            with self.assertRaises(reader.StartupEvidenceError):reader.require_import({**row,**mutation},'OBJECT','WEAK','DEFAULT')
        relocation={'name':reader.CONVENTIONAL,'kind':6,'addend':0,'symbol_type':'OBJECT','binding':'WEAK','visibility':'DEFAULT','symbol_section':0}
        reader.require_handoff_relocation(relocation,reader.CONVENTIONAL)
        for mutation in ({'kind':7},{'addend':1},{'addend':False},{'symbol_section':3}):
            with self.assertRaises(reader.StartupEvidenceError):reader.require_handoff_relocation({**relocation,**mutation},reader.CONVENTIONAL)

    def test_linker_array_empty_bounds_are_valid_but_wrong_range_is_not(self):
        reader.require_array_bounds(0x3000,0x3000,None)
        section={'address':'0000000000003000','size':'000010','alignment':8,'type':'INIT_ARRAY'}
        reader.require_array_bounds(0x3000,0x3010,section)
        for start,end in ((0x3001,0x3010),(0x3000,0x3008),(0x3010,0x3000),(False,0x3000)):
            with self.assertRaises(reader.StartupEvidenceError):reader.require_array_bounds(start,end,section)

    def test_empty_application_arrays_preserve_only_exact_static_runtime_entries(self):
        names={'__crabc_x86_owned_mimalloc_process_initializer':0x3000}
        reader.require_array_entries('static','empty','init',0x3000,0x3008,names)
        reader.require_array_entries('owned-pie','empty','init',0,0,{})
        reader.require_array_entries('static','normal','init',0x3000,0x3010,
            {'i':0x3000,'__crabc_x86_owned_mimalloc_process_initializer':0x3008})
        for changed in ({},{'i':0x3000},{**names,'extra':0x3008},
                        {'__crabc_x86_owned_mimalloc_process_initializer':0x3001}):
            with self.assertRaises(reader.StartupEvidenceError):
                reader.require_array_entries('static','empty','init',0x3000,0x3008,changed)

    def test_runtime_roster_and_owned_conventional_pointer_decisions_are_not_interchangeable(self):
        rows=reader.runtime_cells()
        self.assertEqual(len({x['label'] for x in rows}),len(rows))
        streams={x['label']:reader.expected_stdout(x) for x in rows}
        reader.validate_streams(streams)
        owned=next(x for x in rows if x['mode']=='owned-pie' and x['variant']=='normal')
        conventional=next(x for x in rows if x['mode']=='conventional-pie')
        streams[owned['label']]=reader.expected_stdout(conventional)
        with self.assertRaises(reader.StartupEvidenceError):reader.validate_streams(streams)

    def test_definitions_require_positive_executable_section(self):
        row={'type':'FUNC','binding':'GLOBAL','visibility':'HIDDEN','version':None,'version_default':False,'section_index':'3'}
        section={'index':3,'type':'PROGBITS','flags':'AX'}
        reader.require_function(row,section,'HIDDEN')
        for ndx in ('UND','0','ABS','COM'):
            with self.assertRaises(reader.StartupEvidenceError):reader.require_function({**row,'section_index':ndx},section,'HIDDEN')
        with self.assertRaises(reader.StartupEvidenceError):reader.require_function(row,{**section,'flags':'A'},'HIDDEN')

    def fixture(self):
        def row(name,kind='NOTYPE',binding='GLOBAL',visibility='DEFAULT',section='UND'):
            return {'row_index':1,'name':name,'type':kind,'binding':binding,'visibility':visibility,
                    'section_index':section,'version':None,'version_default':False,'size_bytes':0,'value':'0000000000000000'}
        def member(values):
            return {'sections':[{'index':0,'type':'NULL','flags':''},{'index':1,'type':'PROGBITS','flags':'AX'}],
                    'symbol_tables':[{'name':'.symtab','section_index':2,'rows':values}]}
        facts={}
        for key in ('static-crt1.o','static-Scrt1.o','static-rcrt1.o','dynamic-crt1.o','dynamic-Scrt1.o'):
            values=[row(x) for x in reader.ARRAYS]
            if key in ('static-crt1.o','static-rcrt1.o'):values.append(row(reader.BOOTSTRAP,visibility='HIDDEN'))
            else:values.append(row(reader.HANDOFF,'OBJECT','WEAK'))
            if key.startswith('dynamic'):values.append(row(reader.ATTACH))
            facts[key]=member(values)
        facts['candidate-static']=[{**member([row(reader.BOOTSTRAP,'FUNC',visibility='HIDDEN',section='1')]),'member':'runtime.o','member_index':0,'member_occurrence':0},
                                  {**member([row('_GLOBAL_OFFSET_TABLE_')]),'member':'producer.o','member_index':1,'member_occurrence':0}]
        facts['candidate-shared']=member([row(reader.CONVENTIONAL,'OBJECT','WEAK')])
        facts['candidate-shared']['symbol_tables'].append({'name':'.dynsym','section_index':3,'rows':[row(reader.CONVENTIONAL,'OBJECT','WEAK')]})
        facts['candidate-loader']=member([])
        facts['dynamic-crabc-dynamic-attach.o']=member([row(reader.ATTACH,'FUNC',section='1'),row(reader.RECORD,'FUNC',visibility='HIDDEN',section='1')])
        return facts

    def test_actual_shaped_product_tables_cannot_collapse_import_origins(self):
        facts=self.fixture();result=reader.account_products(facts)
        self.assertEqual(set(result['candidate-shared']),{'.dynsym','.symtab'})
        facts['candidate-shared']['symbol_tables'][0]['rows']=[]
        facts['candidate-shared']['symbol_tables'][1]['rows']*=2
        with self.assertRaises(reader.StartupEvidenceError):reader.account_products(facts)

    def test_actual_shaped_crt_roster_cannot_omit_hidden_bootstrap_or_replace_it_with_common(self):
        for section in ('UND','COM','ABS','0'):
            facts=self.fixture();facts['candidate-static'][0]['symbol_tables'][0]['rows'][0]['section_index']=section
            with self.assertRaises(reader.StartupEvidenceError):reader.account_products(facts)
        facts=self.fixture();facts['dynamic-crt1.o']['symbol_tables'][0]['rows']=[x for x in facts['dynamic-crt1.o']['symbol_tables'][0]['rows'] if x['name']!=reader.HANDOFF]
        with self.assertRaises(reader.StartupEvidenceError):reader.account_products(facts)

    def test_private_startup_names_cannot_gain_public_loader_or_shared_definitions(self):
        facts=self.fixture()
        rogue=copy.deepcopy(facts['dynamic-crabc-dynamic-attach.o']['symbol_tables'][0]['rows'][0])
        facts['candidate-loader']['symbol_tables'].append({'name':'.dynsym','section_index':3,'rows':[rogue]})
        with self.assertRaises(reader.StartupEvidenceError):reader.account_products(facts)
        facts=self.fixture()
        facts['candidate-shared']['symbol_tables'][1]['rows'].append(rogue)
        with self.assertRaises(reader.StartupEvidenceError):reader.account_products(facts)

    def test_final_link_plan_keeps_same_object_and_exact_conventional_crt_owner(self):
        from unittest.mock import patch
        root=Path('/workspace');work=root/'.work/receipt'
        inputs={'static_preparation':{'primary':{'path':'.work/static'}},'dynamic_product':{'path':'.work/dynamic'}}
        tools={name:{'original':{'path':'/tool/'+name}} for name in (*reader.ordinary.TOOL_ROLES,'ar')}
        tools['chroot']['invocation']={}
        with patch.object(reader.ordinary,'validate_chroot_invocation',return_value='/usr/sbin/chroot'):
            plan=reader.plan(root,work,inputs,tools)
        for compilation in [x for x in plan if x['label'].endswith('-compile')]:
            self.assertNotIn('-fPIC',compilation['argv'])
            self.assertNotIn('-fno-stack-protector',compilation['argv'])
            self.assertNotIn('-ftls-model=initial-exec',compilation['argv'])
            self.assertEqual(compilation['argv'][1],'--dynamic-shared-object')
        self.assertEqual(len(plan),len({x['label'] for x in plan}))
        for spec in plan:
            reader.ordinary.raw_path(work,spec['label'],'stdout')
        links=[x for x in plan if x['label'].endswith('-link')]
        for case in reader.cases():
            row=next(x for x in links if x['label']==case['name']+'-link')
            self.assertEqual(row['argv'].count(str(work/(case['variant']+'.o'))),1)
            if case['mode'] in ('default-pie','oracle-pie','oracle-non-pie'):
                self.assertIn('-l:libc.so',row['argv'])
                self.assertNotIn(str(work/'qualification-oracle/runtime'),row['argv'])
            if case['mode'].startswith('conventional'):
                self.assertIn(str(work/'inputs/oracle-crt'/('Scrt1.o' if case['mode']=='conventional-pie' else 'crt1.o')),row['argv'])
                self.assertIn(str(root/'.work/dynamic/usr/lib/libc.so'),row['argv'])
                self.assertNotIn(str(root/'.work/dynamic/usr/lib/crabc-dynamic-attach.o'),row['argv'])

if __name__=='__main__':unittest.main()
