#!/usr/bin/env python3
"""Supplied installed CRT/startup ownership; no qualification authority."""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tomllib
sys.path.insert(0,str(Path(__file__).resolve().parent))
import owned_stdio_alias_contract_reader as substrate
import public_data_ordinary_link_evidence as ordinary
import native_abi_inventory as inventory
import owned_dynamic_receipt as dynamic_receipt
import owned_posix_product_evidence as products
import owned_posix_static_products as static_products
import owned_dynamic_qualification as qualification
import owned_static_link_authority as static_authority
from loader_debug_abi_evidence import Elf
ROOT=Path(__file__).resolve().parents[2]
SCHEMA='crabc.x86_64-installed-crt-startup/v4'
CONVENTIONAL='__crabc_x86_64_loader_conventional_startup_v1'
HANDOFF='__crabc_x86_64_owned_crt_handoff'
ATTACH='__crabc_x86_loader_tls_runtime_v1_attach'
RECORD='__crabc_x86_loader_tls_runtime_v1_record'
BOOTSTRAP='__crabc_x86_static_tls_bootstrap'
DESCRIPTOR='__crabc_x86_64_loader_tls_runtime_v1'
DESCRIPTOR_DSO='descriptor-rogue-dso.so'
DESCRIPTOR_ENDPOINT='descriptor-dso-endpoint'
DESCRIPTOR_RUNTIME_VALUE_CASES=(
    'bad-magic','bad-version','bad-abi-size','bad-mode','bad-owner','unpublished','publishing',
    'unexpected-state','nonzero-reserved','bad-generation','null-tp','null-dtv','unaligned-tp',
    'unaligned-dtv','zero-module-count','short-dtv-words','module-count-overflow','fs-mismatch',
    'self-word-mismatch','dtv-slot-mismatch','dtv-count-mismatch',
)
DESCRIPTOR_RUNTIME_CONSUMER_BODIES=(
    {
        'source_function':'validate_loader_tls_runtime_v1',
        'symbol':'_RNvNtCs3Tpd2S587Z6_24crabc_dynamic_attachment21loader_tls_runtime_v130validate_loader_tls_runtime_v1',
        'source_binding':'LOCAL','source_visibility':'DEFAULT',
        'final_binding':'LOCAL','final_visibility':'DEFAULT',
    },
    {
        'source_function':'current_thread_pointer',
        'symbol':'_RNvNtCs3Tpd2S587Z6_24crabc_dynamic_attachment21loader_tls_runtime_v122current_thread_pointer',
        'source_binding':'LOCAL','source_visibility':'DEFAULT',
        'final_binding':'LOCAL','final_visibility':'DEFAULT',
    },
    {
        'source_function':'observe_validated_loader_tls',
        'symbol':'_RNvNtCs3Tpd2S587Z6_24crabc_dynamic_attachment21loader_tls_runtime_v128observe_validated_loader_tls',
        'source_binding':'LOCAL','source_visibility':'DEFAULT',
        'final_binding':'LOCAL','final_visibility':'DEFAULT',
    },
)
DESCRIPTOR_RUNTIME_SOURCE_FILES=(
    'scripts/build_x86_64_owned_dynamic_sysroot.py','ldso/Cargo.toml','ldso/build.rs',
    'crt/build_x86_64.py','crt/src/x86_64_dynamic_startup.rs',
    'ldso/src/x86_64_general_initial_graph.rs','ldso/src/x86_64_general_initial_tls_state.rs',
    'libc/src/c_abi/x86_64/owned_dynamic_attachment.rs',
    'libc/src/c_abi/x86_64/loader_tls_runtime_v1.rs',
)
DESCRIPTOR_RUNTIME_PROBE='compat/x86_64/installed_crt_startup_descriptor_runtime_probe.c'
DESCRIPTOR_MUTATIONS={
    'wrong-symbol-type':('symbol-info',0x21),
    'wrong-binding':('symbol-info',0x10),
    'wrong-relocation-kind':('relocation-kind',7),
    'wrong-addend':('addend',1),
}
ARRAYS=tuple('__'+a+'_array_'+b for a in ('preinit','init','fini') for b in ('start','end'))
NAMES=('_GLOBAL_OFFSET_TABLE_',CONVENTIONAL,HANDOFF,ATTACH,RECORD,BOOTSTRAP,*ARRAYS)
MODES=('static','static-pie','owned-pie','owned-non-pie','conventional-pie','conventional-non-pie','default-pie','oracle-static','oracle-static-pie','oracle-pie','oracle-non-pie')
STATUS={'component':'verified','family_completion':False,'runtime_qualification':False,'selection_closure':False,'public_support':False}
class StartupEvidenceError(ValueError):pass

def require(condition,message):
    if not condition:raise StartupEvidenceError(message)
from prepared_worker_tls_evidence import same
ident=substrate.ident
read=substrate.read
def raw(work,label):return substrate.raw(work,label.replace('.','-').lower())

def expected_contract():
    return {'schema':SCHEMA,'identities':list(NAMES),'modes':list(MODES),'variants':['normal','empty'],
            'record_sizes':{'owned_handoff':32,'conventional_snapshot':88},
            'roles':{'linker_boundaries':['_GLOBAL_OFFSET_TABLE_',*ARRAYS],
                     'private_static_bootstrap':BOOTSTRAP,'main_attachment':[ATTACH,RECORD],
                     'private_loader_handoffs':[HANDOFF,CONVENTIONAL]},
            # The descriptor is a private loader-to-main-image weak-GOT wire.
            # It is deliberately separate from the twelve CRT identity rows:
            # those rows prove CRT callers, while this account proves the
            # final main-image transport they use.
            'descriptor_handoff':{
                'name':DESCRIPTOR,'source_artifact':'dynamic-crabc-dynamic-attach.o',
                'source_relocation':{'kind':9,'addend':-4,'symbol_type':'0','binding':'WEAK',
                                     'visibility':'DEFAULT','symbol_section':0,'symbol_value':0},
                'main_slot_relocation':{'kind':6,'addend':0,'symbol_type':'0','binding':'WEAK',
                                        'visibility':'DEFAULT','symbol_section':0,'symbol_value':0},
                'owned_modes':['owned-pie','owned-non-pie'],
                'geometry':{'size_bytes':72,'alignment_bytes':8,
                            'magic':'43524142435f5451','version':1,'process_mode':2,
                            'owner':1,'ready_state':2,'generation':1},
                # Mutation files are derived from the linked owned main, then
                # run through the selected product loader in `candidate-root`.
                # They are not a second interpreter/product authority.
                'admission':{
                    'main_case':'owned-pie-normal',
                    'mutations':{
                        'wrong-symbol-type':{'field':'symbol-info','value':0x21},
                        'wrong-binding':{'field':'symbol-info','value':0x10},
                        'wrong-relocation-kind':{'field':'relocation-kind','value':7},
                        'wrong-addend':{'field':'addend','value':1},
                    },
                    'dso':{'source':'compat/x86_64/installed_crt_startup_descriptor_dso.c',
                            'shared_object':DESCRIPTOR_DSO,'endpoint':DESCRIPTOR_ENDPOINT},
                    'source_object':{'relocation':{'kind':42,'addend':-4,'symbol_type':'0',
                                                    'binding':'WEAK','visibility':'DEFAULT',
                                                    'symbol_section':0,'symbol_value':0}},
                    'entry_modes':['kernel','direct'],
                    'rejection':{'status':127,'stdout':'','stderr':'reloc\n'},
                },
                # This is a selected-object execution account. Its freestanding
                # endpoints deliberately use controlled storage and a strong
                # test record where present; it neither changes nor replaces
                # the separate main-image weak-GOT transport account above.
                'runtime_admission':{
                    'probe':{'source':DESCRIPTOR_RUNTIME_PROBE,
                             'attachment_artifact':'dynamic-crabc-dynamic-attach.o',
                             'static_artifact':'candidate-static',
                             'mode':'static-freestanding-selected-object'},
                    'value_cases':list(DESCRIPTOR_RUNTIME_VALUE_CASES),
                    'consumer_bodies':list(DESCRIPTOR_RUNTIME_CONSUMER_BODIES),
                    'cells':[
                        {'name':'descriptor-runtime-matrix','define':''},
                        {'name':'descriptor-runtime-absent','define':'CRABC_RUNTIME_CASE_ABSENT'},
                        {'name':'descriptor-runtime-unaligned-record','define':'CRABC_RUNTIME_CASE_UNALIGNED_RECORD'},
                    ],
                },
            },
            'descriptor_import_required':False,'family_completion':False,'public_support':False}

def validate_contract(value):require(same(value,expected_contract()),'startup contract differs')
def contract(root):
    value=tomllib.loads((root/'compat/x86_64/installed-crt-startup.toml').read_text());validate_contract(value);return value

def require_import(row,kind,binding,visibility):
    expected={'type':kind,'binding':binding,'visibility':visibility,'section_index':'UND','version':None,'version_default':False,'size_bytes':0}
    require(same({k:row.get(k) for k in expected},expected),'startup import metadata differs')

def require_function(row,section,visibility,binding='GLOBAL'):
    expected={'type':'FUNC','binding':binding,'visibility':visibility,'version':None,'version_default':False}
    require(same({k:row.get(k) for k in expected},expected),'startup function metadata differs')
    ndx=row.get('section_index')
    require(type(ndx) is str and ndx.isdigit() and int(ndx)>0 and section is not None
            and type(section['index']) is int and section['index']==int(ndx)
            and section['type']=='PROGBITS' and 'X' in section['flags'],'startup definition lacks executable section')

def require_handoff_relocation(row,name):
    expected={'name':name,'kind':6,'addend':0,'symbol_type':'OBJECT','binding':'WEAK','visibility':'DEFAULT','symbol_section':0}
    require(same({k:row.get(k) for k in expected},expected),'private handoff relocation differs')

def require_array_bounds(start,end,section):
    require(type(start) is int and type(end) is int and 0<=start<=end and start%8==end%8==0,'invalid linker array bounds')
    if section is None:require(start==end,'nonempty linker array has no section')
    else:require(start==int(section['address'],16) and end-start==int(section['size'],16) and section['alignment']>=8,'linker array does not match defining section')

def array_entry_names(mode,variant,kind):
    names=[] if variant=='empty' else [{'preinit':'p','init':'i','fini':'f'}[kind]]
    # Source-owned libc array transport remains present in static images even
    # when the application contributes no arrays. No allocator-body claim is
    # inferred from this exact slot/source-object placement.
    if mode in ('static','static-pie') and kind!='preinit':
        names.append('__crabc_x86_owned_mimalloc_process_'+('initializer' if kind=='init' else 'finalizer'))
    return names

def require_array_entries(mode,variant,kind,start,end,entries):
    names=array_entry_names(mode,variant,kind)
    require(set(entries)==set(names) and end-start==8*len(names)
            and all(type(value) is int for value in entries.values())
            and sorted(entries.values())==list(range(start,end,8)),
            'startup array contribution differs')

def cases():
    return [{'mode':mode,'variant':variant,'name':mode+'-'+variant} for mode in MODES
            for variant in (('normal','empty') if mode in MODES[:4] else ('normal',))]

def runtime_cells():
    return [{**case,'entry':entry,'label':case['name']+'-'+entry} for case in cases()
            for entry in (('process',) if 'static' in case['mode'] else ('kernel','direct'))]

def descriptor_admission_cells():
    policy=expected_contract()['descriptor_handoff']['admission']
    binaries=['descriptor-'+label for label in policy['mutations']]+[policy['dso']['endpoint']]
    return [{'binary':binary,'entry':entry,'label':binary+'-'+entry}
            for binary in binaries for entry in policy['entry_modes']]

def descriptor_runtime_cells():
    policy=expected_contract()['descriptor_handoff']['runtime_admission']
    cells=[]
    for row in policy['cells']:
        cells.append({'label':row['name'],'define':row['define'],'status':0,'stdout':b'','stderr':b''})
    validate_descriptor_runtime_cells(cells)
    return cells


def validate_descriptor_runtime_cells(cells):
    policy=expected_contract()['descriptor_handoff']['runtime_admission']
    expected=[{'label':row['name'],'define':row['define'],'status':0,'stdout':b'','stderr':b''}
              for row in policy['cells']]
    require(same(cells,expected),'descriptor runtime cell roster differs')


def descriptor_runtime_source_bytes(root):
    require(set(DESCRIPTOR_RUNTIME_SOURCE_FILES)<=set(RUNTIME_SOURCES),
            'descriptor runtime source roster is not selected')
    return {name:(root/name).read_bytes() for name in DESCRIPTOR_RUNTIME_SOURCE_FILES}


def _runtime_source_text(sources,name):
    require(type(sources) is dict and set(sources)==set(DESCRIPTOR_RUNTIME_SOURCE_FILES),
            'descriptor runtime source roster differs')
    value=sources[name]
    require(type(value) is bytes,'descriptor runtime source bytes differ: '+name)
    try:return value.decode('utf-8')
    except UnicodeDecodeError as error:raise StartupEvidenceError('descriptor runtime source encoding differs: '+name) from error


PUBLISHER_SOURCE_TEMPLATE=(
    'unsafefnpublish_reserved_loader_tls_runtime_v1(installed:InstalledInitialTls){'
    'letrecord=core::ptr::addr_of_mut!(__crabc_x86_64_loader_tls_runtime_v1);'
    '#[cfg(crabc_general_loader_libc_tls_runtime_v1_poisoned_dtv)]'
    'letdescriptor_dtv=1usizeas*constusize;'
    '#[cfg(not(crabc_general_loader_libc_tls_runtime_v1_poisoned_dtv))]'
    'letdescriptor_dtv=installed.dtv.cast_const();unsafe{'
    '(*record).thread_pointer=installed.thread_pointer.cast_const();'
    '(*record).dtv=descriptor_dtv;(*record).dtv_words=installed.dtv_words;'
    '(*record).module_count=installed.module_count;'
    '(*record).state.store(GENERAL_LOADER_TLS_RUNTIME_V1_STATE_READY,Ordering::Release);}}'
)


def _runtime_region(text,signature,end_marker,label):
    require(text.count(signature)==1,label+' signature differs')
    begin=text.index(signature);end=text.find(end_marker,begin+len(signature))
    require(end>=0 and text.find(end_marker,end+len(end_marker))<0,label+' boundary differs')
    return text[begin:end]


def _runtime_order(text,anchors,label):
    positions=[]
    for anchor in anchors:
        require(text.count(anchor)==1,label+' anchor differs: '+anchor)
        positions.append(text.index(anchor))
    require(positions==sorted(positions),label+' operation order differs')


def _runtime_python_definition(text,signature,label):
    require(text.count(signature)==1,label+' signature differs')
    begin=text.index(signature);end=text.find('\ndef ',begin+1)
    require(end>=0,label+' body is unterminated')
    return text[begin:end]


def _runtime_source_code(text):
    return re.sub(r'\s+','',re.sub(r'//[^\n]*','',text))



def descriptor_runtime_source_order(sources):
    """Account only selected lexical Release/Acquire and CRT-call order.

    This bounded source account is intentionally not a compiler-lowering or
    concurrent-scheduling proof. The selected object execution account below
    independently checks the consumer's current behavior.
    """
    builder=_runtime_source_text(sources,'scripts/build_x86_64_owned_dynamic_sysroot.py')
    cargo=_runtime_source_text(sources,'ldso/Cargo.toml')
    build=_runtime_source_text(sources,'ldso/build.rs')
    crt_build=_runtime_source_text(sources,'crt/build_x86_64.py')
    crt=_runtime_source_text(sources,'crt/src/x86_64_dynamic_startup.rs')
    graph=_runtime_source_text(sources,'ldso/src/x86_64_general_initial_graph.rs')
    tls=_runtime_source_text(sources,'ldso/src/x86_64_general_initial_tls_state.rs')
    attachment=_runtime_source_text(sources,'libc/src/c_abi/x86_64/owned_dynamic_attachment.rs')
    consumer=_runtime_source_text(sources,'libc/src/c_abi/x86_64/loader_tls_runtime_v1.rs')
    _runtime_order(builder,('LOADER_FEATURE = "x86_64-owned-dynamic-runtime"',
                            'str(ROOT / "libc/src/c_abi/x86_64/owned_dynamic_attachment.rs")',
                            'str(library / "crabc-dynamic-attach.o")',
                            '"--features",\n                      LOADER_FEATURE'), 'dynamic builder')
    attachment_compile=_runtime_region(
        builder,
        'run([rustup, "run", common.PINNED_TOOLCHAIN, "rustc", "--edition=2021",',
        '\n    (library / "crabc-dynamic-attach.o").chmod(0o644)',
        'selected attachment compile route',
    )
    _runtime_order(attachment_compile,(
        '"--crate-name", "crabc_dynamic_attachment"', '"--crate-type", "lib"',
        '"--emit=obj"', '"-C", "opt-level=2"',
        '"-C", "relocation-model=pic"',
        'str(ROOT / "libc/src/c_abi/x86_64/owned_dynamic_attachment.rs")',
        '"-o", str(library / "crabc-dynamic-attach.o")',
    ), 'selected attachment compile route')
    require(cargo.count('x86_64-owned-dynamic-runtime = ["x86_64-general-initial-lifecycle", "x86_64-general-initial-tls-runtime-v1-dynamic-main-thread-interpreter"]')==1,
            'dynamic loader feature route differs')
    dynamic_build=_runtime_region(
        build,
        'if std::env::var_os(\n        "CARGO_FEATURE_X86_64_GENERAL_INITIAL_TLS_RUNTIME_V1_DYNAMIC_MAIN_THREAD_INTERPRETER",',
        '\n    println!("cargo:rustc-cdylib-link-arg=-nostartfiles");',
        'dynamic loader build route',
    )
    _runtime_order(dynamic_build,('crabc_general_initial_graph','crabc_general_initial_tls_materialization_v1',
                                  'crabc_general_loader_libc_tls_runtime_v1','crabc_dynamic_main_thread_runtime_v1'),
                   'dynamic loader cfg route')
    _runtime_order(attachment,('#![no_std]','#[path = "loader_tls_runtime_v1.rs"]','mod loader_tls_runtime_v1;'),
                   'selected attachment root')
    require(attachment.count('mod loader_tls_runtime_v1;')==1,'selected attachment module roster differs')
    selected=_runtime_python_definition(crt_build,'def selected_objects(args: argparse.Namespace) -> tuple[ObjectSpec, ...]:','dynamic CRT selection')
    _runtime_order(selected,('owned = getattr(args, "owned_dynamic_sysroot", False)',
                             '"owned-dynamic-pie-entry"'), 'dynamic CRT selection')
    compile_loop=_runtime_python_definition(crt_build,'def build(args: argparse.Namespace) -> dict[str, object]:','dynamic CRT compile')
    _runtime_order(compile_loop,('["--cfg", "crabc_dynamic_main_thread_runtime_v1"]',
                                 'or (args.dynamic_main_thread_runtime_v1 and spec.name == "Scrt1.o")',
                                 'str(source)'), 'dynamic CRT compile')
    startup=_runtime_region(crt,'pub unsafe extern "C" fn __crabc_x86_64_dynamic_start(','\n\n#[no_mangle]\npub unsafe extern "C" fn __crabc_x86_64_dynamic_executable_init','dynamic CRT startup')
    _runtime_order(startup,('if unsafe { __crabc_x86_loader_tls_runtime_v1_attach() } != 0',
                            'startup_reject();','__libc_start_main('), 'dynamic CRT attachment')
    publisher=_runtime_region(tls,'unsafe fn publish_reserved_loader_tls_runtime_v1(installed: InstalledInitialTls) {','\n\nimpl GeneralInitialTlsState {','RuntimeV1 publisher')
    require(_runtime_source_code(publisher)==PUBLISHER_SOURCE_TEMPLATE,'RuntimeV1 publisher write/store template differs')
    implementation='impl GeneralInitialTlsState {\n'
    commit_signature='pub(crate) unsafe fn commit_runtime_v1(\n        mut self,'
    require(tls.count(implementation)==1,'RuntimeV1 commit implementation differs')
    implementation_start=tls.index(implementation)
    commit_start=tls.find(commit_signature,implementation_start+len(implementation))
    commit_end=tls.find('\n\n    /// Rolls back the map-owned portion',commit_start+len(commit_signature))
    require(commit_start>=0 and commit_end>=0,'RuntimeV1 commit boundary differs')
    commit=tls[commit_start:commit_end]
    _runtime_order(commit,('unsafe { publish_initial_tls_attachment(self.registry, installed) };','unsafe { self.loader.commit() };',
                           'unsafe { publish_reserved_loader_tls_runtime_v1(installed) };'),'RuntimeV1 commit')
    route=_runtime_region(graph,'fn run_with_initial_tls(','\n\n/// The complete prevalidated constructor call list','RuntimeV1 graph route')
    _runtime_order(route,('state.materialize_initial_tls()','let conventional_startup = unsafe { state.commit_runtime_v1(installed) };','runtime_registry.publish(ldso_base);'),
                   'RuntimeV1 graph route')
    validate=_runtime_region(consumer,"unsafe fn validate_loader_tls_runtime_v1() -> Option<&'static LoaderLibcTlsRuntimeV1> {",'\n\n/// Obtain the current x86-64 `%fs` base','RuntimeV1 consumer validation')
    _runtime_order(validate,('record.state.load(Ordering::Acquire)','record.thread_pointer.is_null()',
                             'record.dtv.is_null()','record.module_count.checked_add(1)?'), 'RuntimeV1 consumer validation')
    attach_body=_runtime_region(consumer,'pub unsafe extern "C" fn __crabc_x86_loader_tls_runtime_v1_attach() -> c_int {','\n}',
                                  'RuntimeV1 consumer attachment')
    _runtime_order(attach_body,('validate_loader_tls_runtime_v1()','observe_validated_loader_tls(record)'),
                   'RuntimeV1 consumer attachment')
    bodies=expected_contract()['descriptor_handoff']['runtime_admission']['consumer_bodies']
    for body in bodies:
        marker='#[inline(never)]\nunsafe fn '+body['source_function']+'('
        require(consumer.count(marker)==1,'RuntimeV1 selected consumer body differs: '+body['source_function'])
    return {'scope':'selected source release/acquire order and CRT attachment route; no compiler or concurrency proof',
            'builder':{'attachment':'direct PIC object','loader_feature':'x86_64-owned-dynamic-runtime'},
            'publisher':{'state_store':'Release READY last'},
            'consumer':{'state_load':'Acquire READY before TLS coordinate reads','bodies':bodies},
            'crt':{'attachment':'before __libc_start_main'}}


def expected_stdout(cell):
    mode=cell['mode']; owned=mode in MODES[:4]; empty=cell['variant']=='empty'
    prefix=('P' if owned and not empty else '')+'I'+('' if empty else 'C')
    wire='S' if 'static' in mode else 'O' if mode.startswith('owned') else 'V' if mode.startswith('conventional') else 'N' if mode=='default-pie' else 'R'
    return (prefix+wire+'MA'+('' if empty else 'F')+'L\n').encode()

def validate_streams(streams):
    expected={cell['label']:expected_stdout(cell) for cell in runtime_cells()}
    require(same(streams,expected),'startup runtime roster, wire owner or transcript differs')

RUNTIME_SOURCES=('crt/src/x86_64_startup.rs','crt/src/x86_64_dynamic_startup.rs','crt/src/x86_64_array_boundaries.rs',
    'crt/src/x86_64_crt1.rs','crt/src/x86_64_rcrt1.rs','crt/src/x86_64_Scrt1.rs','crt/build_x86_64.py',
    'scripts/build_x86_64_owned_dynamic_sysroot.py','ldso/Cargo.toml','ldso/build.rs',
    'libc/src/c_abi/x86_64/static_tls.rs','libc/src/c_abi/x86_64/static_startup.rs',
    'libc/src/c_abi/x86_64/conventional_startup_v1.rs','libc/src/c_abi/x86_64/dynamic_main_thread_runtime_v1_lifecycle.rs',
    'libc/src/c_abi/x86_64/owned_dynamic_attachment.rs','libc/src/c_abi/x86_64/loader_tls_runtime_v1.rs',
    'libc/src/c_abi/x86_64/allocator_mimalloc_lifecycle.rs',
    'ldso/src/x86_64_initial_graph.rs','ldso/src/x86_64_general_relocation.rs','ldso/src/x86_64_general_initial_graph.rs',
    'ldso/src/x86_64_general_initial_lifecycle.rs','ldso/src/x86_64_general_initial_tls_state.rs',
    'ldso/src/x86_64_dynamic_main_thread_runtime_v1_source_root.rs',
    'libc/src/c_abi/x86_64/dynamic_main_thread_runtime_v1_source_root.rs',
    'ldso/src/x86_64_conventional_startup_v1.rs','compat/x86_64/loader-libc-tls-runtime-v1.toml')
COLLECTOR_SOURCES=tuple(dict.fromkeys((*substrate.COLLECTOR_SOURCES,*RUNTIME_SOURCES,
    'compat/x86_64/installed_crt_startup_evidence.py','compat/x86_64/installed-crt-startup.toml',
    'compat/x86_64/installed_crt_startup_probe.c','compat/x86_64/installed_crt_startup_descriptor_dso.c',
    DESCRIPTOR_RUNTIME_PROBE,
    'compat/x86_64/owned_static_link_authority.py',
    'compat/x86_64/prepared_worker_tls_evidence.py')))
ORACLE_CRT=('crt1.o','Scrt1.o','rcrt1.o','crti.o','crtn.o')
EXTRA_TOOLS=substrate.EXTRA_TOOLS

def source_files(root,work,revision=None,capture=False):
    paths=RUNTIME_SOURCES if revision else COLLECTOR_SOURCES
    result={}; prefix='selected' if revision else 'collector'
    for name in paths:
        data=subprocess.check_output(['git','show',revision+':'+name],cwd=root) if revision else (root/name).read_bytes()
        require(data==(root/name).read_bytes(),'selected startup source differs: '+name)
        path=work/prefix/name
        if capture:path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        require(path.read_bytes()==data,'retained startup source differs: '+name)
        result[name]=ident(root,path)
    return result

def product_paths(root,inputs):
    static=root/inputs['static_preparation']['primary']['path'];dynamic=root/inputs['dynamic_product']['path']
    return {'candidate-static':static/'usr/lib/libc.a','candidate-shared':dynamic/'usr/lib/libc.so',
            'candidate-loader':dynamic/'lib/ld-crabc-x86_64.so.1',
            **{'static-'+n:static/'usr/lib'/n for n in ('crt1.o','Scrt1.o','rcrt1.o')},
            **{'dynamic-'+n:dynamic/'usr/lib'/n for n in ('crt1.o','Scrt1.o','crabc-dynamic-attach.o')}}


def descriptor_runtime_inputs(root,inputs):
    """Return the two selected physical inputs for the RuntimeV1 probe.

    The product reader already validates the whole source-owned mode policy.
    This narrower account records the two roles the standalone command uses,
    so a retained command cannot silently substitute a byte-identical file
    with a different installed permission.
    """
    paths=product_paths(root,inputs);policy=expected_contract()['descriptor_handoff']['runtime_admission']['probe']
    modes=products.link_input_mode_projection()
    selected={
        'attachment':(policy['attachment_artifact'],paths[policy['attachment_artifact']],
                      modes['dynamic']['usr/lib/crabc-dynamic-attach.o']),
        'static_libc':(policy['static_artifact'],paths[policy['static_artifact']],
                       modes['static']['usr/lib/libc.a']),
    }
    result={}
    for role,(artifact,path,expected_mode) in selected.items():
        require(path.is_file() and not path.is_symlink() and path.resolve()==path,
                'descriptor runtime selected input is not physical: '+role)
        identity=ident(root,path)
        require(same(identity,inputs['startup_artifacts'][artifact]),
                'descriptor runtime selected input identity differs: '+role)
        mode=stat.S_IMODE(path.stat().st_mode)
        require(mode==expected_mode,'descriptor runtime source-bound input mode differs: '+role)
        result[role]={'artifact':artifact,'identity':identity,'mode':mode}
    return result

def admit(root,preparation,static,dynamic,historical):
    value=substrate.admitted(root,preparation,static,dynamic,historical)
    history=read(historical)
    artifacts={}
    for key,path in product_paths(root,value).items():
        expected=history['artifacts'][key]['identity'];current=ident(root,path)
        require(type(expected['size']) is int and expected['size']==current['size'] and expected['sha256']==current['sha256'],
                'historical startup product identity differs: '+key)
        artifacts[key]=current
    return {**value,'startup_artifacts':artifacts}

def mode_owner(mode):
    return 'candidate' if mode in MODES[:6] else 'oracle'


def descriptor_runtime_plan(root,work,inputs,tools):
    """Build the closed selected-object probe command roster.

    The direct attachment object and selected static archive remain explicit
    argv entries.  This is deliberately an ordinary static link, not a
    product builder or a substitute dynamic-loader execution path.
    """
    m=lambda path:ordinary.mounted(root,path);p=lambda name:m(work/name)
    tool=lambda name:tools[name]['original']['path']
    policy=expected_contract()['descriptor_handoff']['runtime_admission']['probe']
    paths=product_paths(root,inputs);specs=[]
    for cell in descriptor_runtime_cells():
        specs.extend((
            {'label':cell['label']+'-source','argv':[
                tool('compiler'),'-std=c11','-O2','-ffreestanding','-fno-builtin',
                '-fno-stack-protector','-fno-pie',
                *([] if not cell['define'] else ['-D'+cell['define']]),
                '-c',p(Path(policy['source']).name),'-o',p(cell['label']+'.o'),
            ],'cwd':'/workspace','expected_stdout':b'','expected_stderr':b''},
            {'label':cell['label']+'-link','argv':[
                tool('linker'),'-static','--no-dynamic-linker','--no-undefined','--no-demangle','-e','_start',
                '-Map='+p(cell['label']+'.map'),p(cell['label']+'.o'),
                m(paths[policy['attachment_artifact']]),m(paths[policy['static_artifact']]),
                '-o',p(cell['label']),
            ],'cwd':'/workspace','expected_stdout':b'','expected_stderr':b''},
            {'label':cell['label'],'argv':[tool('env'),'-i',p(cell['label'])],
             'cwd':'/workspace','expected_status':cell['status'],
             'expected_stdout':cell['stdout'],'expected_stderr':cell['stderr']},
        ))
    return specs

def plan(root,work,inputs,tools):
    m=lambda path:ordinary.mounted(root,path);p=lambda name:m(work/name)
    tool=lambda name:tools[name]['original']['path']; specs=[]
    def add(label,argv,cwd='/workspace',**expected):
        specs.append({'label':label.replace('.','-').lower(),'argv':argv,'cwd':cwd,**expected})
    library=root/inputs['dynamic_product']['path']/'usr/lib';static=root/inputs['static_preparation']['primary']['path']/'usr/lib'
    for variant in ('normal','empty'):
        add(variant+'-compile',[tool('dynamic_driver'),'--dynamic-shared-object','-std=c11',
            *(['-DEMPTY_ARRAYS'] if variant=='empty' else []),'-c',p('installed_crt_startup_probe.c'),'-o',p(variant+'.o')])
    for case in cases():
        mode,variant,name=(case[k] for k in ('mode','variant','name'));obj=p(variant+'.o')
        if mode in ('static','static-pie'):
            add(name+'-link',[tool('static_driver'),'-'+mode,'--link-receipt',name+'.link.json',obj,'-o',p(name)],m(work))
        elif mode.startswith('owned-'):
            add(name+'-link',[tool('dynamic_driver'),'--dynamic-'+mode.removeprefix('owned-'),obj,'-o',p(name)])
        else:
            is_static='static' in mode;pie=mode.endswith('pie') and not mode.endswith('non-pie')
            entry='rcrt1.o' if mode=='oracle-static-pie' else 'Scrt1.o' if pie else 'crt1.o'
            crt=static/entry if mode=='default-pie' else work/'inputs/oracle-crt'/entry
            runtime=library/'libc.so' if mode.startswith('conventional') else work/'inputs/oracle-static/libc_a' if is_static else work/'qualification-oracle/runtime'
            # Explicit ordinary musl CRT input is essential: the owned driver
            # deliberately selects its own entry and cannot certify this mode.
            argv=[tool('linker'),*(['-static'] if is_static else []),*(['-pie'] if pie else []),
                  '--hash-style=sysv','-z','now','-z','relro','-z','noexecstack','--no-undefined',
                  *([] if is_static else ['--allow-shlib-undefined','--dynamic-linker',
                     '/lib/ld-crabc-x86_64.so.1' if mode.startswith('conventional') else '/lib/ld-musl-x86_64.so.1']),
                  m(crt),p('inputs/oracle-crt/crti.o'),obj,
                  *([m(runtime)] if is_static or mode.startswith('conventional') else ['-L',p('oracle-link'),'-l:libc.so']),p('inputs/oracle-crt/crtn.o'),'-Map='+p(name+'.map'),'-o',p(name)]
            add(name+'-link',argv)
    admission=expected_contract()['descriptor_handoff']['admission'];dso=admission['dso']
    add('descriptor-dso-compile',[tool('dynamic_driver'),'--dynamic-shared-object','-std=c11',
        '-c',p('installed_crt_startup_descriptor_dso.c'),'-o',p('descriptor-dso.o')])
    add('descriptor-dso-link',[tool('dynamic_driver'),'--dynamic-shared-object',p('descriptor-dso.o'),
        '-o',p(dso['shared_object'])])
    add('descriptor-endpoint-link',[tool('dynamic_driver'),'--dynamic-pie','--application-dso',
        p(dso['shared_object']),p('normal.o'),'-o',p(dso['endpoint'])])
    for spec in descriptor_runtime_plan(root,work,inputs,tools):
        add(spec['label'],spec['argv'],spec['cwd'],
            **{key:value for key,value in spec.items() if key not in ('label','argv','cwd')})
    paths={**product_paths(root,inputs),**{case['name']:work/case['name'] for case in cases()},
           **{variant+'-object':work/(variant+'.o') for variant in ('normal','empty')}}
    for key,path in paths.items():
        if key=='candidate-static':add(key+'-members',[tool('ar'),'t',m(path)])
        for flag,suffix in (('-hW','header'),('-SW','sections'),('-sW','symbols')):add(key+'-'+suffix,[tool('readelf'),flag,m(path)])
        if key!='candidate-static':add(key+'-relocations',[tool('readelf'),'-rW',m(path)])
    for cell in runtime_cells():
        mode=cell['mode'];argv=[tool('env'),'-i','CRABC_STARTUP=yes']
        if cell['entry']=='process':argv.append(p(cell['name']))
        else:
            owner=mode_owner(mode)
            argv.extend([ordinary.validate_chroot_invocation(tools['chroot']['invocation'],tools['chroot']['original']),p(owner+'-root')])
            if cell['entry']=='direct':argv.append('/lib/ld-crabc-x86_64.so.1' if owner=='candidate' else '/lib/ld-musl-x86_64.so.1')
            argv.append('/'+cell['name'])
        argv.append('static' if 'static' in mode else 'owned' if mode.startswith('owned') else 'conventional' if mode.startswith('conventional') else 'default' if mode=='default-pie' else 'oracle')
        add(cell['label'],argv)
    for cell in descriptor_admission_cells():
        argv=[tool('env'),'-i','CRABC_STARTUP=yes',
              ordinary.validate_chroot_invocation(tools['chroot']['invocation'],tools['chroot']['original']),p('candidate-root')]
        if cell['entry']=='direct':argv.append('/lib/ld-crabc-x86_64.so.1')
        argv.extend(['/{}'.format(cell['binary']),'owned'])
        add(cell['label'],argv,expected_status=admission['rejection']['status'],
            expected_stdout=admission['rejection']['stdout'].encode('ascii'),
            expected_stderr=admission['rejection']['stderr'].encode('ascii'))
    return specs

def validate_commands(root,work,inputs,tools,commands):
    expected=plan(root,work,inputs,tools)
    require(type(commands) is list and len(commands)==len(expected),'startup command roster differs')
    for row,spec in zip(commands,expected):
        require(set(row)=={'label','argv','cwd','outcome','command','stdout','stderr','status'}
                and same({k:row[k] for k in ('label','argv','cwd')},
                         {k:spec[k] for k in ('label','argv','cwd')})
                and row['outcome']=='ok','startup command differs')
        for field,suffix in (('command','command.json'),('stdout','stdout'),('stderr','stderr'),('status','status')):
            path=ordinary.resolve_work_identity(root,row[field],'startup '+field)
            require(path==ordinary.raw_path(work,spec['label'],suffix),'startup raw path differs')
        require(same(ordinary.read_json(ordinary.raw_path(work,spec['label'],'command.json'),'startup argv',list),spec['argv']), 'startup retained argv differs')
        require(ordinary.raw_path(work,spec['label'],'status').read_bytes()==str(spec.get('expected_status',0)).encode('ascii')+b'\n'
                and ordinary.raw_path(work,spec['label'],'stderr').read_bytes()==spec.get('expected_stderr',b''),
                'startup status or diagnostic differs')
        if 'expected_stdout' in spec:
            require(ordinary.raw_path(work,spec['label'],'stdout').read_bytes()==spec['expected_stdout'],
                    'startup command stdout differs')

def projection(root,work,inputs):
    paths={**product_paths(root,inputs),**{case['name']:work/case['name'] for case in cases()},
           **{variant+'-object':work/(variant+'.o') for variant in ('normal','empty')}}
    facts={}
    for key,path in paths.items():
        rows=[raw(work,key+'-'+part) for part in ('header','sections','symbols')]
        if key=='candidate-static':facts[key]=inventory.parse_archive_elf_facts(*rows,raw(work,key+'-members').splitlines(),expected_archive=ordinary.mounted(root,path))
        else:
            expected='REL' if key.endswith('.o') or key.endswith('-object') else 'DYN' if key in ('candidate-shared','candidate-loader') else 'PIE' if '-pie-' in key and '-non-pie-' not in key else 'EXEC'
            facts[key]=inventory.parse_elf_facts(*rows,expected_type=expected)
    return facts

def rows(facts,key,table='.symtab'):
    return substrate.occurrences({key:facts[key]},key,table)

def exact(facts,key,name,table='.symtab'):
    matches=[x for x in rows(facts,key,table) if x['row']['name']==name]
    require(len(matches)==1,'startup symbol missing/duplicate: '+key+'/'+table+'/'+name)
    return matches[0]

def account_products(facts):
    result={}
    for key in ('static-crt1.o','static-Scrt1.o','static-rcrt1.o','dynamic-crt1.o','dynamic-Scrt1.o'):
        result[key]={}
        for name in ARRAYS:
            item=exact(facts,key,name);require_import(item['row'],'NOTYPE','GLOBAL','DEFAULT');result[key][name]=item
    # Both products install the one conventional crt1.o. It carries failing
    # weak defaults for the static bootstrap and the RuntimeV1 attachment
    # that libc.a or crabc-dynamic-attach.o override, and never imports the
    # handoff; rcrt1.o and Scrt1.o keep their single mode's strong imports.
    for key in ('static-crt1.o','dynamic-crt1.o'):
        for name,visibility in ((BOOTSTRAP,'HIDDEN'),(ATTACH,'DEFAULT')):
            item=exact(facts,key,name);require_function(item['row'],item['section'],visibility,'WEAK');result[key][name]=item
    item=exact(facts,'static-rcrt1.o',BOOTSTRAP);require_import(item['row'],'NOTYPE','GLOBAL','HIDDEN');result['static-rcrt1.o'][BOOTSTRAP]=item
    bootstrap=exact(facts,'candidate-static',BOOTSTRAP);require_function(bootstrap['row'],bootstrap['section'],'HIDDEN')
    result['candidate-static']={BOOTSTRAP:bootstrap}
    got=exact(facts,'candidate-static','_GLOBAL_OFFSET_TABLE_');require_import(got['row'],'NOTYPE','GLOBAL','DEFAULT');result['candidate-static']['_GLOBAL_OFFSET_TABLE_']=got
    for key in ('static-Scrt1.o','dynamic-Scrt1.o','dynamic-crabc-dynamic-attach.o'):
        result.setdefault(key,{})
        item=exact(facts,key,HANDOFF);require_import(item['row'],'OBJECT','WEAK','DEFAULT');result[key][HANDOFF]=item
    for key in ('static-crt1.o','dynamic-crt1.o'):
        require(not any(x['row']['name']==HANDOFF for x in rows(facts,key)),'conventional crt1.o imports the loader handoff: '+key)
    item=exact(facts,'dynamic-Scrt1.o',ATTACH);require_import(item['row'],'NOTYPE','GLOBAL','DEFAULT');result['dynamic-Scrt1.o'][ATTACH]=item
    for name,visibility in ((ATTACH,'DEFAULT'),(RECORD,'HIDDEN')):
        item=exact(facts,'dynamic-crabc-dynamic-attach.o',name);require_function(item['row'],item['section'],visibility);result['dynamic-crabc-dynamic-attach.o'][name]=item
    result['candidate-shared']={}
    for table in ('.dynsym','.symtab'):
        item=exact(facts,'candidate-shared',CONVENTIONAL,table);require_import(item['row'],'OBJECT','WEAK','DEFAULT');result['candidate-shared'][table]=item
    # These records are supplied by source-selected startup resolution, not
    # exported loader functions. The one canonical libc import is checked
    # above; admitting another dynamic spelling would change this boundary.
    for key,allowed in (('candidate-shared',{CONVENTIONAL}),('candidate-loader',set())):
        require(all(x['row']['name'] not in NAMES or x['row']['name'] in allowed
                    for x in rows(facts,key,'.dynsym')),'unexpected public startup identity: '+key)
    # Retain local, weak and absent named providers without fabricating imports
    # for source-resolved private loader records or optimized attachments.
    result['all_named_rows']={key:[x for table in ('.symtab','.dynsym') for x in rows(facts,key,table) if x['row']['name'] in NAMES] for key in product_paths(ROOT,{'static_preparation':{'primary':{'path':'.work/s'}},'dynamic_product':{'path':'.work/d'}})}
    return result

def relocations(path):
    elf=Elf(path);result=[]
    for section_index,section in enumerate(elf.sections):
        if section[1]!=4:continue
        require(section[9]==24 and section[5]%24==0,'malformed retained RELA table')
        for index in range(section[5]//24):
            offset,info,addend=elf.unpack('<QQq',section[4]+index*24)
            symbol=elf.symbol_row(section[6],info>>32)
            result.append({'table_section_index':section_index,'row_index':index,'offset':offset,'kind':info&0xffffffff,
                           'addend':addend,'name':symbol['name'],'symbol_type':symbol['type'],'binding':symbol['binding'],
                           'visibility':symbol['visibility'],'symbol_section':symbol['section'],'symbol_value':symbol['value']})
    return result

# Pinned owned CRT callers use PLT32 (4) for direct non-PIC calls and
# GOTPCREL (9) for PIC calls/data references, each with the x86 PC bias -4.
# The conventional crt1.o calls its own weak defaults, which the matching
# link's strong definitions override, so those rows name defined symbols.
# The attach object's record callback is a defined hidden function; treating
# it as another undefined import would erase its actual ownership boundary.
# The attach object also carries the CRT's handoff slot reader.
CONVENTIONAL_CRT1_RELOCATIONS={
    BOOTSTRAP:(((4,-4),),'FUNC','WEAK','HIDDEN',True),
    ATTACH:(((4,-4),),'FUNC','WEAK','DEFAULT',True),
}
CRT_CALLER_RELOCATIONS={
    'static-crt1.o':CONVENTIONAL_CRT1_RELOCATIONS,
    'static-rcrt1.o':{BOOTSTRAP:(((9,-4),),'0','GLOBAL','HIDDEN',False)},
    'static-Scrt1.o':{HANDOFF:(((9,-4),),'OBJECT','WEAK','DEFAULT',False)},
    'dynamic-crt1.o':CONVENTIONAL_CRT1_RELOCATIONS,
    'dynamic-Scrt1.o':{HANDOFF:(((9,-4),),'OBJECT','WEAK','DEFAULT',False),ATTACH:(((9,-4),),'0','GLOBAL','DEFAULT',False)},
    'dynamic-crabc-dynamic-attach.o':{RECORD:(((9,-4),),'FUNC','GLOBAL','HIDDEN',True),
                                      HANDOFF:(((9,-4),),'OBJECT','WEAK','DEFAULT',False)},
}

def require_crt_caller_relocations(result):
    selected={BOOTSTRAP,HANDOFF,ATTACH,RECORD}
    for role,relations in CRT_CALLER_RELOCATIONS.items():
        rows=result.get(role)
        require(type(rows) is list,'CRT caller relocation object absent: '+role)
        observed=[row for row in rows if row['name'] in selected]
        require(len(observed)==sum(len(relation[0]) for relation in relations.values())
                and {row['name'] for row in observed}==set(relations),
                'CRT caller relocation roster differs: '+role)
        for name,(kinds,*_rest) in relations.items():
            require(sorted((row.get('kind'),row.get('addend')) for row in observed if row['name']==name)==sorted(kinds),
                    'CRT caller relocation kinds differ: '+role+'/'+name)
        for row in observed:
            _kinds,symbol_type,binding,visibility,defined=relations[row['name']]
            expected={'symbol_type':symbol_type,'binding':binding,'visibility':visibility,'symbol_value':0}
            require(same({key:row.get(key) for key in expected},expected),
                    'CRT caller relocation metadata differs: '+role+'/'+row['name'])
            section=row.get('symbol_section')
            require(type(section) is int and (0<section<0xff00 if defined else section==0),
                    'CRT caller relocation definition differs: '+role+'/'+row['name'])

def artifact_relocations(root,work,inputs):
    result={}
    paths=product_paths(root,inputs)
    for key,path in paths.items():
        if key=='candidate-static':continue
        result[key]=relocations(path)
    shared=[x for x in result['candidate-shared'] if x['name']==CONVENTIONAL]
    require(len(shared)==1,'canonical libc startup relocation count differs');require_handoff_relocation(shared[0],CONVENTIONAL)
    require_crt_caller_relocations(result)
    return result

def require_descriptor_relocation(row,expected,description):
    """Require one raw weak relocation without assigning a loader provider.

    The x86 object uses a GOTPCREL reference and the four final owned main
    images retain its resolved GLOB_DAT slot. The owner of the record is
    selected source, so neither spelling is an installed shared/loader
    definition claim.
    """
    require(same({key:row.get(key) for key in ('name',*expected)},
                 {'name':DESCRIPTOR,**expected}),description+' differs')

def descriptor_handoff(product_relocations,executables):
    """Account for the one private descriptor input and final main slots.

    This is a finite placement/control account, not a historical-product
    admission path. It accepts only the source object's one weak GOTPCREL
    record, exactly one weak GLOB_DAT slot in each owned final main image, and
    no descriptor relocation in every static, conventional, default, or
    oracle case.
    """
    policy=expected_contract()['descriptor_handoff']
    require(type(product_relocations) is dict
            and type(product_relocations.get(policy['source_artifact'])) is list,
            'descriptor source relocation artifact differs')
    source=[row for row in product_relocations[policy['source_artifact']]
            if row.get('name')==DESCRIPTOR]
    require(len(source)==1,'descriptor source relocation count differs')
    require_descriptor_relocation(source[0],policy['source_relocation'],'descriptor source relocation')
    expected_cases={case['name']:case for case in cases()}
    require(type(executables) is dict and set(executables)==set(expected_cases),
            'descriptor final executable roster differs')
    account={}
    for name,case in expected_cases.items():
        executable=executables[name]
        require(type(executable) is dict and type(executable.get('relocations')) is list,
                'descriptor final relocation account differs: '+name)
        slots=[row for row in executable['relocations'] if row.get('name')==DESCRIPTOR]
        owned=case['mode'] in policy['owned_modes']
        require(len(slots)==(1 if owned else 0),
                'descriptor main-image slot roster differs: '+name)
        if slots:
            require_descriptor_relocation(slots[0],policy['main_slot_relocation'],
                                          'descriptor main-image slot '+name)
        account[name]={'mode':case['mode'],'variant':case['variant'],'slot':copy.deepcopy(slots)}
    return {'source_artifact':policy['source_artifact'],'source_relocation':copy.deepcopy(source[0]),
            'executables':account,
            # Runtime process labels are separately sealed by `validate_streams`.
            # A successful owned probe has checked the record's 72/8 geometry,
            # magic/version/mode/owner, acquire READY and TP/DTV coordinates.
            'probe_owned_modes':list(policy['owned_modes']),
            'static_slot_absent':True}

def descriptor_loader_tables(data):
    """Bind descriptor section records to the loader-visible dynamic tables.

    Section headers make the retained byte offsets easy to audit, but an ELF
    loader follows ``PT_DYNAMIC.p_vaddr`` through one ``PT_LOAD`` mapping.
    This keeps a stale SHT_DYNAMIC/SHT_DYNSYM/SHT_RELA view from authenticating
    a changed loader-visible request.
    """
    require(type(data) in (bytes,bytearray) and len(data)>=64 and data[:7]==b'\x7fELF\x02\x01\x01',
            'descriptor admission input is not ELF64 little-endian')
    header=struct.unpack_from('<16sHHIQQQIHHHHHH',data,0)
    phoff,shoff,phentsize,phnum,shentsize,shnum=header[5],header[6],header[9],header[10],header[11],header[12]
    require(phentsize==56 and phnum<65536 and phoff+phentsize*phnum<=len(data),
            'descriptor admission program table differs')
    require(shentsize==64 and shoff+shentsize*shnum<=len(data),'descriptor admission section table differs')
    programs=[struct.unpack_from('<IIQQQQQQ',data,phoff+index*phentsize) for index in range(phnum)]
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+index*shentsize) for index in range(shnum)]

    def virtual_end(address,size,label):
        require(address+size<=1<<64,label+' leaves virtual address space')
        return address+size

    loads=[]
    for program in programs:
        if program[0]!=1:continue
        offset,address,size,memory_size=program[2],program[3],program[5],program[6]
        require(memory_size>=size and offset+size<=len(data),'descriptor admission PT_LOAD differs')
        virtual_end(address,size,'descriptor admission PT_LOAD')
        loads.append((offset,address,size))

    def mapped_offset(address,size,label):
        end=virtual_end(address,size,label);matches=[]
        for offset,load_address,load_size in loads:
            load_end=virtual_end(load_address,load_size,'descriptor admission PT_LOAD')
            if address<load_address or end>load_end:continue
            translated=offset+address-load_address
            require(translated+size<=len(data),'descriptor admission mapped table leaves file')
            matches.append(translated)
        require(len(matches)==1,label+' does not have one PT_LOAD mapping')
        return matches[0]

    dynamic=[program for program in programs if program[0]==2]
    require(len(dynamic)==1,'descriptor admission PT_DYNAMIC roster differs')
    _kind,_flags,dynamic_offset,dynamic_address,_paddr,dynamic_size,dynamic_memory,_align=dynamic[0]
    require(dynamic_memory>=dynamic_size and dynamic_size>0 and dynamic_size%16==0
            and dynamic_offset+dynamic_size<=len(data),'descriptor admission PT_DYNAMIC layout differs')
    require(mapped_offset(dynamic_address,dynamic_size,'descriptor admission PT_DYNAMIC')==dynamic_offset,
            'descriptor admission PT_DYNAMIC virtual mapping differs from its file offset')
    entries=[];terminated=False
    for offset in range(dynamic_offset,dynamic_offset+dynamic_size,16):
        tag,value=struct.unpack_from('<qQ',data,offset)
        if terminated:
            require(tag==0 and value==0,'descriptor admission dynamic table has entries after its terminator')
        elif tag==0:
            require(value==0,'descriptor admission dynamic table terminator differs')
            terminated=True
        else:entries.append((tag,value))
    require(terminated,'descriptor admission dynamic table has no terminator')

    def one(tag,label):
        values=[value for observed,value in entries if observed==tag]
        require(len(values)==1,label+' differs')
        return values[0]

    string_address,string_size=one(5,'descriptor admission DT_STRTAB'),one(10,'descriptor admission DT_STRSZ')
    require(string_size>0,'descriptor admission DT_STRSZ differs')
    string_offset=mapped_offset(string_address,string_size,'descriptor admission DT_STRTAB')
    dynamic_sections=[(index,section) for index,section in enumerate(sections) if section[1]==6]
    require(len(dynamic_sections)==1,'descriptor admission SHT_DYNAMIC roster differs')
    dynamic_section_index,dynamic_section=dynamic_sections[0]
    require(dynamic_section[3:6]==(dynamic_address,dynamic_offset,dynamic_size) and dynamic_section[9]==16,
            'descriptor admission SHT_DYNAMIC differs from PT_DYNAMIC')
    string_sections=[(index,section) for index,section in enumerate(sections)
                     if section[1]==3 and section[3:6]==(string_address,string_offset,string_size)]
    require(len(string_sections)==1,'descriptor admission dynstr section differs from DT_STRTAB')
    string_section_index,string_section=string_sections[0]
    require(dynamic_section[6]==string_section_index,'descriptor admission dynamic string link differs')

    symbol_address,symbol_entry=one(6,'descriptor admission DT_SYMTAB'),one(11,'descriptor admission DT_SYMENT')
    require(symbol_entry==24,'descriptor admission DT_SYMENT differs')
    symbol_sections=[(index,section) for index,section in enumerate(sections)
                     if section[1]==11 and section[3]==symbol_address]
    require(len(symbol_sections)==1,'descriptor admission dynsym section differs from DT_SYMTAB')
    symbol_section_index,symbol_section=symbol_sections[0]
    symbol_offset,symbol_size=symbol_section[4],symbol_section[5]
    require(symbol_section[9]==symbol_entry and symbol_size>0 and symbol_size%symbol_entry==0
            and symbol_section[6]==string_section_index
            and mapped_offset(symbol_address,symbol_size,'descriptor admission DT_SYMTAB')==symbol_offset,
            'descriptor admission dynsym layout differs')

    relocation_address,relocation_size,relocation_entry=(
        one(7,'descriptor admission DT_RELA'),one(8,'descriptor admission DT_RELASZ'),
        one(9,'descriptor admission DT_RELAENT'))
    require(relocation_entry==24 and relocation_size>0 and relocation_size%relocation_entry==0,
            'descriptor admission DT_RELA layout differs')
    relocation_sections=[(index,section) for index,section in enumerate(sections)
                         if section[1]==4 and section[3]==relocation_address]
    require(len(relocation_sections)==1,'descriptor admission RELA section differs from DT_RELA')
    relocation_section_index,relocation_section=relocation_sections[0]
    require(relocation_section[4:6]==(
                mapped_offset(relocation_address,relocation_size,'descriptor admission DT_RELA'),relocation_size)
            and relocation_section[9]==relocation_entry and relocation_section[6]==symbol_section_index,
            'descriptor admission RELA layout differs')
    return {'entries':entries,'sections':sections,'dynstr':(string_section_index,string_section),
            'dynsym':(symbol_section_index,symbol_section),'rela':(relocation_section_index,relocation_section)}

def descriptor_slot(data):
    """Locate the one canonical dynamic descriptor request in one ELF image.

    This parser exists only to derive finite byte mutations from the canonical
    linked main and to check the DSO fixture.  It does not select a provider
    and it cannot create an interpreter: `prepare_roots` executes every copy
    using the selected product loader already sealed by `admit` and `roots`.
    """
    tables=descriptor_loader_tables(data)
    section_index,section=tables['dynsym'];_string_index,string=tables['dynstr']
    offset,size,entry=section[4],section[5],section[9];names=[]
    for record in range(offset,offset+size,entry):
        name_offset=struct.unpack_from('<I',data,record)[0]
        require(name_offset<string[5],'descriptor admission name leaves dynstr')
        begin=string[4]+name_offset;end=data.find(b'\0',begin,string[4]+string[5])
        require(end>=0,'descriptor admission name is unterminated')
        if bytes(data[begin:end])==DESCRIPTOR.encode():
            names.append((record,(record-offset)//entry))
    require(len(names)==1,'descriptor admission dynsym roster differs')
    symbol,symbol_index=names[0];_rela_index,relocation_section=tables['rela'];relocations=[]
    offset,size,entry=relocation_section[4],relocation_section[5],relocation_section[9]
    for record in range(offset,offset+size,entry):
        info=struct.unpack_from('<Q',data,record+8)[0]
        if info>>32==symbol_index:relocations.append((record,info))
    require(len(relocations)==1,'descriptor admission relocation roster differs')
    relocation,info=relocations[0]
    require(data[symbol+4]==0x20 and data[symbol+5]&3==0
            and struct.unpack_from('<H',data,symbol+6)[0]==0
            and info&0xffffffff==6 and struct.unpack_from('<q',data,relocation+16)[0]==0,
            'descriptor admission positive wire differs')
    return symbol,relocation,info

def mutate_descriptor_main(source,destination,label):
    policy=expected_contract()['descriptor_handoff']['admission']
    mutations=policy['mutations']
    require(label in mutations and label in DESCRIPTOR_MUTATIONS,'descriptor admission mutation label differs')
    field,value=DESCRIPTOR_MUTATIONS[label]
    require(mutations[label]=={'field':field,'value':value},'descriptor admission mutation policy differs')
    before=source.read_bytes();data=bytearray(before);symbol,relocation,info=descriptor_slot(data)
    if field=='symbol-info':data[symbol+4]=value
    elif field=='relocation-kind':struct.pack_into('<Q',data,relocation+8,(info&~0xffffffff)|value)
    else:struct.pack_into('<q',data,relocation+16,value)
    require(not destination.exists() and not destination.is_symlink(),'descriptor admission mutation output exists')
    destination.write_bytes(data);destination.chmod(source.stat().st_mode&0o777)
    return {'symbol_file_offset':symbol,'rela_file_offset':relocation,'field':field,'value':value}

def descriptor_source_object(path):
    """Require the one PIC object compiled from the retained DSO source."""
    elf=Elf(path);require(elf.elf_type==1 and not elf.programs,'descriptor source object ELF type differs')
    symbols=[]
    for section_index,section in enumerate(elf.sections):
        if section[1]!=2:continue
        require(section[9]==24 and section[5]%24==0,'descriptor source object symtab differs')
        for index in range(section[5]//24):
            row=elf.symbol_row(section_index,index)
            if row['name']==DESCRIPTOR:symbols.append((section_index,index,row))
    require(len(symbols)==1,'descriptor source object symbol roster differs')
    section_index,index,row=symbols[0]
    require(same({key:row[key] for key in ('type','binding','visibility','section','value','size')},
                 {'type':'0','binding':'WEAK','visibility':'DEFAULT','section':0,'value':0,'size':0}),
            'descriptor source object symbol differs')
    relocations=[]
    for section in elf.sections:
        if section[1]!=4 or section[6]!=section_index:continue
        require(section[9]==24 and section[5]%24==0,'descriptor source object RELA differs')
        for offset in range(0,section[5],24):
            _,info,addend=elf.unpack('<QQq',section[4]+offset)
            if info>>32==index:relocations.append((section[4]+offset,info,addend))
    require(len(relocations)==1,'descriptor source object relocation roster differs')
    relocation,info,addend=relocations[0]
    policy=expected_contract()['descriptor_handoff']['admission']['source_object']['relocation']
    actual={'kind':info&0xffffffff,'addend':addend,'symbol_type':row['type'],'binding':row['binding'],
            'visibility':row['visibility'],'symbol_section':row['section'],'symbol_value':row['value']}
    require(actual==policy,'descriptor source object relocation differs')
    return {'symbol_file_offset':elf.sections[section_index][4]+index*24,'rela_file_offset':relocation,
            'relocation':actual}

def dynamic_names(path,require_table=False):
    """Return exact loader-visible DT_NEEDED and DT_SONAME records.

    `retained_elf_facts` already maps the one physical ``PT_DYNAMIC`` table
    through its containing ``PT_LOAD`` segment and resolves `DT_STRTAB` from
    that loader-visible table.  SHT_DYNAMIC is therefore never role authority.
    """
    elf=Elf(path)
    try:facts=products.retained_elf_facts(Path(path))
    except products.ProductEvidenceError as error:
        raise StartupEvidenceError('descriptor admission dynamic table differs: '+str(error)) from error
    require(facts['dynamic'] or not require_table,'descriptor admission PT_DYNAMIC roster differs')
    return elf,facts['needed'],facts['sonames']

def descriptor_admission_elf_roles(root,work):
    """Bind the DSO and direct endpoint to their distinct installed ELF roles."""
    policy=expected_contract()['descriptor_handoff']['admission'];dso_name=policy['dso']['shared_object']
    dso=work/dso_name;endpoint=work/policy['dso']['endpoint']
    require(all(path.is_file() and not path.is_symlink() for path in (dso,endpoint)),
            'descriptor admission DSO/endpoint is absent')
    dso_elf,dso_needed,dso_sonames=dynamic_names(dso,True)
    require(dso_elf.elf_type==3 and not [program for program in dso_elf.programs if program[0]==3]
            and dso_needed==['libc.so'] and dso_sonames==[dso_name],
            'descriptor admission DSO role differs')
    dso_symbol,dso_relocation,_=descriptor_slot(dso.read_bytes())
    endpoint_elf,endpoint_needed,endpoint_sonames=dynamic_names(endpoint,True)
    interpreters=[endpoint_elf.data[program[2]:program[2]+program[5]]
                  for program in endpoint_elf.programs if program[0]==3]
    require(endpoint_elf.elf_type==3 and interpreters==[b'/lib/ld-crabc-x86_64.so.1\0']
            and endpoint_needed==[dso_name,'libc.so'] and endpoint_sonames==[],
            'descriptor admission endpoint role differs')
    endpoint_symbol,endpoint_relocation,_=descriptor_slot(endpoint.read_bytes())
    return {'dso':{'identity':ident(root,dso),'symbol_file_offset':dso_symbol,
                   'rela_file_offset':dso_relocation,'needed':dso_needed,'soname':dso_sonames[0]},
            'endpoint':{'identity':ident(root,endpoint),'symbol_file_offset':endpoint_symbol,
                        'rela_file_offset':endpoint_relocation,'needed':endpoint_needed,
                        'interpreter':interpreters[0].decode('ascii').rstrip('\0')}}

def descriptor_admission_roles(root,work):
    """Bind the retained source object before its DSO and endpoint roles."""
    object_path=work/'descriptor-dso.o'
    require(object_path.is_file() and not object_path.is_symlink(),'descriptor admission source object is absent')
    return {'source_object':{'identity':ident(root,object_path),**descriptor_source_object(object_path)},
            **descriptor_admission_elf_roles(root,work)}

def descriptor_receipt(root,work,inputs,tools,label,mode,workload,output,application_dsos):
    """Validate the finite schema-2 receipt without widening ordinary link policy."""
    product=root/inputs['dynamic_product']['path'];library=product/'usr/lib';receipt=work/(output.name+'.crabc-link.json')
    record=ordinary.read_json(receipt,'descriptor '+label+' link receipt')
    search=dynamic_receipt.validate(record,format=products.DYNAMIC_PRODUCT_FORMAT,
                                    label='descriptor '+label+' link receipt',
                                    fail=lambda message:require(False,message))
    dynamic_receipt.require_runpath(search,'/usr/lib',label='descriptor '+label+' link receipt',
                                    fail=lambda message:require(False,message))
    require(search.schema==2 and record['mode']==mode and record['binding']=='now'
            and record['runtime_imports']==[] and record['application_dsos']=={
                path.name:ordinary.digest(path) for path in application_dsos}
            and record['campaign_complete'] is False,
            'descriptor '+label+' link receipt policy differs')
    runtime=['crti.o','libc.so','crtn.o']+([] if mode=='shared' else ['Scrt1.o','crabc-dynamic-attach.o'])
    archive=library/'libcrabc-builtins.a';runtime_paths=[library/name for name in runtime]
    require(record['owned_runtime_inputs']==sorted(path.relative_to(product).as_posix()
                                                    for path in [*runtime_paths,archive]),
            'descriptor '+label+' runtime input roster differs')
    expected_inputs=[*runtime_paths,workload,*application_dsos,archive]
    require(type(record['input_receipts']) is list and len(record['input_receipts'])==len(expected_inputs),
            'descriptor '+label+' input receipt roster differs')
    for received,path in zip(record['input_receipts'],expected_inputs):
        require(type(received) is dict and set(received)=={'path','sha256'}
                and received=={'path':ordinary.mounted(root,path),'sha256':ordinary.digest(path)},
                'descriptor '+label+' input receipt differs')
    linker=tools['linker']['original'];require(type(linker) is dict and set(('path','sha256'))<=set(linker),
                                                     'descriptor link tool identity differs')
    require(record['resolved_linker']=={key:linker[key] for key in ('path','sha256')},
            'descriptor '+label+' linker identity differs')
    mounted=lambda path:ordinary.mounted(root,path)
    common=[linker['path'],*(['-shared'] if mode=='shared' else ['-pie']),'--hash-style=sysv',
            '-z','relro','-z','now','-z','noexecstack','-z','text','--no-undefined',
            '--allow-shlib-undefined','--enable-new-dtags','-rpath','/usr/lib']
    if mode=='shared':common+=['-soname',output.name]
    else:common+=['--dynamic-linker','/lib/ld-crabc-x86_64.so.1',mounted(library/'Scrt1.o'),
                  mounted(library/'crabc-dynamic-attach.o')]
    command=[*common,mounted(library/'crti.o'),mounted(workload),*(mounted(path) for path in application_dsos),
             mounted(library/'libc.so'),mounted(archive),mounted(library/'crtn.o'),'-o',mounted(output)]
    require(record['link_command']==command,'descriptor '+label+' link command differs')
    direct=([mounted(library/'crti.o'),mounted(workload)] if mode=='shared' else
            [mounted(library/'Scrt1.o'),mounted(library/'crabc-dynamic-attach.o'),
             mounted(library/'crti.o'),mounted(workload)])
    direct += [*(mounted(path) for path in application_dsos),mounted(library/'libc.so'),mounted(library/'crtn.o')]
    trace=record['link_trace'];require(type(trace) is list and all(type(item) is str for item in trace),
                                        'descriptor '+label+' link trace differs')
    seen=[]
    for item in trace:
        if item in direct:seen.append(item)
        elif item==mounted(archive) or item.startswith(mounted(archive)+'(') and item.endswith(')'):continue
        else:require(False,'descriptor '+label+' link trace admits an unbound input')
    require(seen==direct,'descriptor '+label+' link trace differs')
    manifest=product/'share/crabc/manifest.json'
    require(record['output_path']==ordinary.mounted(root,output)
            and record['output_sha256']==ordinary.digest(output)
            and record['manifest_sha256']==ordinary.digest(manifest),
            'descriptor '+label+' link output differs')
    return {'receipt':ident(root,receipt),'workload':ident(root,workload),'output':ident(root,output),
            'manifest':ident(root,manifest),'application_dsos':{path.name:ident(root,path) for path in application_dsos}}

def descriptor_admission_links(root,work,inputs,tools):
    policy=expected_contract()['descriptor_handoff']['admission'];dso=work/policy['dso']['shared_object']
    return {'dso':descriptor_receipt(root,work,inputs,tools,'DSO','shared',work/'descriptor-dso.o',dso,()),
            'endpoint':descriptor_receipt(root,work,inputs,tools,'endpoint','pie',work/'normal.o',
                                           work/policy['dso']['endpoint'],(dso,))}

def prepare_descriptor_admission(work):
    policy=expected_contract()['descriptor_handoff']['admission'];source=work/policy['main_case']
    require(source.is_file() and not source.is_symlink(),'descriptor admission main is absent')
    descriptor_slot(source.read_bytes())
    for label in policy['mutations']:
        mutate_descriptor_main(source,work/('descriptor-'+label),label)
    dso=work/policy['dso']['shared_object'];endpoint=work/policy['dso']['endpoint']
    require(dso.is_file() and endpoint.is_file() and not dso.is_symlink() and not endpoint.is_symlink(),
            'descriptor admission DSO fixture is absent')
    descriptor_slot(dso.read_bytes());descriptor_slot(endpoint.read_bytes())

def descriptor_admission_observations(root,work,inputs,tools):
    policy=expected_contract()['descriptor_handoff']['admission'];source=work/policy['main_case']
    before=source.read_bytes();symbol,relocation,info=descriptor_slot(before);mutations={}
    for label,entry in policy['mutations'].items():
        path=work/('descriptor-'+label);actual=path.read_bytes();expected=bytearray(before)
        if entry['field']=='symbol-info':expected[symbol+4]=entry['value']
        elif entry['field']=='relocation-kind':struct.pack_into('<Q',expected,relocation+8,(info&~0xffffffff)|entry['value'])
        else:struct.pack_into('<q',expected,relocation+16,entry['value'])
        require(actual==expected,'descriptor admission mutation bytes differ: '+label)
        mutations[label]={'identity':ident(root,path),'field':entry['field'],'value':entry['value']}
    roles=descriptor_admission_roles(root,work)
    links=descriptor_admission_links(root,work,inputs,tools)
    return {'main':ident(root,source),'symbol_file_offset':symbol,'rela_file_offset':relocation,
            'mutations':mutations,**roles,'links':links,
            'entry_modes':list(policy['entry_modes']),'rejection':copy.deepcopy(policy['rejection'])}

def needed_libraries(path):
    return dynamic_names(path)[1]

def executable_observations(root,work,inputs,tools,facts):
    result={};linker={k:tools['linker']['original'][k] for k in ('path','sha256')}
    for case in cases():
        mode,name,variant=(case[k] for k in ('mode','name','variant'));path=work/name;elf=Elf(path)
        expected_type=3 if mode.endswith('pie') and not mode.endswith('non-pie') else 2
        require(elf.elf_type==expected_type,'startup final ELF mode differs')
        interp=[elf.data[p[2]:p[2]+p[5]] for p in elf.programs if p[0]==3]
        expected=[] if 'static' in mode else [(b'/lib/ld-crabc-x86_64.so.1\0' if mode_owner(mode)=='candidate' else b'/lib/ld-musl-x86_64.so.1\0')]
        require(interp==expected,'startup interpreter differs')
        needed=needed_libraries(path)
        require(needed==([] if 'static' in mode else ['libc.so']),'startup DT_NEEDED differs')
        account={'identity':ident(root,path),'needed':needed,'relocations':relocations(path),'arrays':{}}
        if mode in MODES[:4] or mode=='default-pie':
            for kind in ('preinit','init','fini'):
                start=int(exact(facts,name,'__'+kind+'_array_start')['row']['value'],16)
                end=int(exact(facts,name,'__'+kind+'_array_end')['row']['value'],16)
                sections=[s for s in facts[name]['sections'] if s['name']=='.'+kind+'_array']
                require(len(sections)<=1,'duplicate final array section')
                require_array_bounds(start,end,sections[0] if sections else None)
                entries={};contributions={}
                for slot in array_entry_names(mode,variant,kind):
                    final=exact(facts,name,slot)
                    source_key=variant+'-object' if slot in ('p','i','f') else 'candidate-static'
                    original=exact(facts,source_key,slot)
                    for item in (original,final):
                        required={'type':'OBJECT','binding':'LOCAL','visibility':'DEFAULT','size_bytes':8,
                                  'version':None,'version_default':False}
                        require(same({k:item['row'].get(k) for k in required},required)
                                and item['section'] is not None and item['section']['name']=='.'+kind+'_array',
                                'startup array slot definition differs')
                    entries[slot]=int(final['row']['value'],16)
                    contributions[slot]={'source_artifact':source_key,'source':original,'final':final}
                    if mode in ('static','static-pie'):
                        source_path=ordinary.mounted(root,work/(variant+'.o')) if source_key.endswith('-object') else \
                            ordinary.mounted(root,product_paths(root,inputs)['candidate-static'])+'('+original['member']+')'
                        expression=r'^\s*([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+(\d+)\s+'+re.escape(source_path+':(.'+kind+'_array)')+r'$'
                        matches=re.findall(expression,(work/(name+'.link.map')).read_text(),re.MULTILINE)
                        require(len(matches)==1 and int(matches[0][0],16)==entries[slot]
                                and int(matches[0][2],16)==8 and int(matches[0][3])==8,
                                'static startup array input contribution differs')
                        contributions[slot]['link_map_row']=list(matches[0])
                require_array_entries(mode,variant,kind,start,end,entries)
                account['arrays'][kind]={'start':start,'end':end,'section':sections[0] if sections else None,
                                        'contributions':contributions}
        handoffs=[x for x in account['relocations'] if x['name']==HANDOFF]
        require(len(handoffs)==(1 if mode.startswith('owned') or mode=='default-pie' else 0),'main handoff relocation differs')
        for row in handoffs:require_handoff_relocation(row,HANDOFF)
        if mode in MODES[:4]:
            static='static' in mode;product=root/(inputs['static_preparation']['primary']['path'] if static else inputs['dynamic_product']['path'])
            receipt=work/(name+('.link.json' if static else '.crabc-link.json'))
            linked=products.validate_retained_link(root,'/workspace',product,work/(variant+'.o'),path,receipt,
                                                  mode if static else mode.removeprefix('owned-'),linker,export_dynamic=False)
            account['link']={'receipt':ident(root,receipt),'validated':{k:v for k,v in linked.items() if k!='product'}}
            if static:
                trace=receipt.with_suffix('.trace').read_text();member=exact(facts,'candidate-static',BOOTSTRAP)['member']
                gotmember=exact(facts,'candidate-static','_GLOBAL_OFFSET_TABLE_')['member']
                require('libc.a('+member+')' in trace and 'libc.a('+gotmember+')' in trace,'ordinary archive extraction omits bootstrap/GOT member')
                final=exact(facts,name,BOOTSTRAP);require(final['row']['visibility']=='HIDDEN' and final['section'] is not None,'final bootstrap hidden definition differs')
                got=exact(facts,name,'_GLOBAL_OFFSET_TABLE_');require(got['row']['section_index'].isdigit() and got['section'] is not None,'final linker GOT definition absent')
                account['extraction']={'bootstrap':member,'got_member':gotmember,'trace':ident(root,receipt.with_suffix('.trace')),'map':ident(root,receipt.with_suffix('.map'))}
        result[name]=account
    return result

def prepare_roots(root,work,inputs):
    prepare_descriptor_admission(work)
    shutil.copytree(root/inputs['dynamic_product']['path'],work/'candidate-root',symlinks=True)
    (work/'oracle-root/lib').mkdir(parents=True);(work/'oracle-root/lib').chmod(0o755)
    shutil.copy2(work/'qualification-oracle/runtime',work/'oracle-root/lib/ld-musl-x86_64.so.1')
    (work/'oracle-root/lib/ld-musl-x86_64.so.1').chmod(0o755)
    (work/'oracle-root/lib/libc.so').symlink_to('ld-musl-x86_64.so.1')
    for case in cases():
        if 'static' not in case['mode']:shutil.copy2(work/case['name'],work/(mode_owner(case['mode'])+'-root')/case['name'])
    policy=expected_contract()['descriptor_handoff']['admission'];dso=policy['dso']
    for label in policy['mutations']:
        shutil.copy2(work/('descriptor-'+label),work/'candidate-root'/('descriptor-'+label))
    shutil.copy2(work/dso['endpoint'],work/'candidate-root'/dso['endpoint'])
    shutil.copy2(work/dso['shared_object'],work/'candidate-root'/'usr/lib'/dso['shared_object'])

def roots(root,work,inputs):
    result={}
    for owner in ('candidate','oracle'):
        expected=copy.deepcopy(inputs['dynamic_tree']) if owner=='candidate' else {
            'lib':{'kind':'directory','mode':0o755},'lib/libc.so':{'kind':'symlink','mode':0o777,'target':'ld-musl-x86_64.so.1'},
            'lib/ld-musl-x86_64.so.1':{'kind':'file','mode':0o755,'size':(work/'qualification-oracle/runtime').stat().st_size,'sha256':ordinary.digest(work/'qualification-oracle/runtime')}}
        for case in cases():
            if 'static' not in case['mode'] and mode_owner(case['mode'])==owner:
                path=work/case['name'];expected[case['name']]={'kind':'file','mode':0o755,'size':path.stat().st_size,'sha256':ordinary.digest(path)}
        if owner=='candidate':
            policy=expected_contract()['descriptor_handoff']['admission'];dso=policy['dso']
            for label in policy['mutations']:
                path=work/('descriptor-'+label)
                expected['descriptor-'+label]={'kind':'file','mode':0o755,'size':path.stat().st_size,'sha256':ordinary.digest(path)}
            endpoint=work/dso['endpoint'];shared=work/dso['shared_object']
            expected[dso['endpoint']]={'kind':'file','mode':0o755,'size':endpoint.stat().st_size,'sha256':ordinary.digest(endpoint)}
            expected['usr/lib/'+dso['shared_object']]={'kind':'file','mode':0o755,'size':shared.stat().st_size,'sha256':ordinary.digest(shared)}
        observed=ordinary.execution_tree(root,work/(owner+'-root'),'startup execution root')
        require(same(observed,expected),'startup execution root bytes/modes/roster differs')
        result[owner]=observed
    return result


def descriptor_runtime_map_relation(root,work,inputs,cell):
    """Bind selected attachment bodies through the sealed LLD map and final bytes."""
    inputs_account=descriptor_runtime_inputs(root,inputs)
    map_path=work/(cell['label']+'.map')
    require(map_path.is_file() and not map_path.is_symlink(),'descriptor runtime link map is absent: '+cell['label'])
    attachment=ordinary.mounted(root,product_paths(root,inputs)[inputs_account['attachment']['artifact']])
    archive=ordinary.mounted(root,product_paths(root,inputs)[inputs_account['static_libc']['artifact']])
    probe=ordinary.mounted(root,work/(cell['label']+'.o'))
    policy=expected_contract()['descriptor_handoff']['runtime_admission']
    contracts=(
        static_authority.StaticFunctionContract(ATTACH,attachment,'GLOBAL','DEFAULT','GLOBAL','DEFAULT'),
        static_authority.StaticFunctionContract(RECORD,attachment,'GLOBAL','HIDDEN','LOCAL','HIDDEN'),
        *(static_authority.StaticFunctionContract(
            body['symbol'],attachment,body['source_binding'],body['source_visibility'],
            body['final_binding'],body['final_visibility'],
        ) for body in policy['consumer_bodies']),
    )
    try:
        static_authority.require_static_functions(
            map_path,work/cell['label'],
            {probe:work/(cell['label']+'.o'),
             attachment:product_paths(root,inputs)[inputs_account['attachment']['artifact']]},
            contracts,
        )
    except static_authority.StaticLinkAuthorityError as error:
        raise StartupEvidenceError('descriptor runtime selected attachment authority differs: '+str(error)) from error
    source_functions={body['symbol']:body['source_function'] for body in policy['consumer_bodies']}
    return {'attachment':attachment,'static_libc':archive,'probe_object':probe,
            'functions':[
                {'name':row.name,'input_owner':row.input_owner,
                 'source_binding':row.source_binding,'source_visibility':row.source_visibility,
                 'final_binding':row.final_binding,'final_visibility':row.final_visibility,
                 **({'source_function':source_functions[row.name]} if row.name in source_functions else {})}
                for row in contracts
            ]}


def descriptor_runtime_probe_object(path,cell):
    """Require the exact descriptor definition intended by one source cell.

    This is a finite source-object check before the sealed direct link.  In
    particular, the unaligned alias must survive optimization as an actual
    defined address one byte after its backing storage; it cannot collapse to
    the deliberately absent weak-symbol endpoint.
    """
    path=Path(path)
    require(path.is_file() and not path.is_symlink(),'descriptor runtime probe object is absent: '+cell['label'])
    elf=Elf(path);descriptor=elf.symbol(DESCRIPTOR,dynamic=False,required=False)
    define=cell['define']
    if not define:
        require(descriptor is not None
                and {key:descriptor[key] for key in ('type','binding','visibility','size')}
                    =={'type':'OBJECT','binding':'GLOBAL','visibility':'DEFAULT','size':72},
                'descriptor runtime matrix object definition differs')
        return {'descriptor':descriptor}
    if define=='CRABC_RUNTIME_CASE_ABSENT':
        require(descriptor is None,'descriptor runtime absent object defines the descriptor')
        return {'descriptor':None}
    require(define=='CRABC_RUNTIME_CASE_UNALIGNED_RECORD','unknown descriptor runtime probe cell')
    backing=elf.symbol('runtime_unaligned_record',dynamic=False)
    require(descriptor is not None
            and {key:descriptor[key] for key in ('binding','visibility','section')}
                =={'binding':'GLOBAL','visibility':'DEFAULT','section':backing['section']}
            and descriptor['value']==backing['value']+1,
            'descriptor runtime unaligned object alias differs')
    require(backing['type']=='OBJECT' and backing['binding']=='LOCAL' and backing['size']==73,
            'descriptor runtime unaligned backing storage differs')
    return {'descriptor':descriptor,'backing':backing}


def descriptor_runtime_streams(work,cell):
    """Check retained raw endpoint streams and return their JSON-safe account."""
    streams={suffix:ordinary.raw_path(work,cell['label'],suffix).read_bytes()
             for suffix in ('stdout','stderr','status')}
    require(streams=={'stdout':cell['stdout'],'stderr':cell['stderr'],
                      'status':str(cell['status']).encode('ascii')+b'\n'},
            'descriptor runtime endpoint result differs: '+cell['label'])
    return {'stdout':'','stderr':'','status':cell['status']}


def descriptor_runtime_observations(root,work,inputs):
    """Reconstruct the selected-object RuntimeV1 admission exercise.

    Each process is static and terminates immediately after its raw FS-base
    setup.  The result therefore establishes the selected attachment's local
    admission behavior for this finite record roster; it is not an installed
    loader publication or a concurrent scheduling proof.
    """
    policy=expected_contract()['descriptor_handoff']['runtime_admission']
    cells=descriptor_runtime_cells();validate_descriptor_runtime_cells(cells)
    source=work/Path(policy['probe']['source']).name
    require(source.is_file() and not source.is_symlink() and source.read_bytes()==(root/DESCRIPTOR_RUNTIME_PROBE).read_bytes(),
            'descriptor runtime probe source differs')
    account=[]
    for cell in cells:
        binary=work/cell['label']
        require(binary.is_file() and not binary.is_symlink(),'descriptor runtime endpoint is absent: '+cell['label'])
        relation=descriptor_runtime_map_relation(root,work,inputs,cell)
        probe_object=work/(cell['label']+'.o')
        probe_account=descriptor_runtime_probe_object(probe_object,cell)
        account.append({'label':cell['label'],'define':cell['define'],'probe_object':ident(root,probe_object),
                        'probe_definition':probe_account,
                        'endpoint':ident(root,binary),
                        'map':ident(root,work/(cell['label']+'.map')),'relation':relation,
                        'streams':descriptor_runtime_streams(work,cell)})
    return {
        'scope':'selected attachment local admission only; source order is lexical and no concurrent publication claim is made',
        'source':ident(root,source),'inputs':descriptor_runtime_inputs(root,inputs),
        'source_order':descriptor_runtime_source_order(descriptor_runtime_source_bytes(root)),
        'value_cases':list(policy['value_cases']),'cells':account,
    }

def observations(root,work,inputs,tools):
    require((work/'oracle-link/libc.so').read_bytes()==(work/'qualification-oracle/runtime').read_bytes(),'oracle named link input differs')
    facts=projection(root,work,inputs);products_account=account_products(facts)
    for variant in ('normal','empty'):
        failure=exact(facts,variant+'-object','__stack_chk_guard')
        require_import(failure['row'],'NOTYPE','GLOBAL','DEFAULT')
    streams={cell['label']:ordinary.raw_path(work,cell['label'],'stdout').read_bytes() for cell in runtime_cells()}
    validate_streams(streams)
    relocations_account=artifact_relocations(root,work,inputs)
    executables_account=executable_observations(root,work,inputs,tools,facts)
    return {'complete_elf_facts':facts,'product_placements':products_account,'product_relocations':relocations_account,
            'executables':executables_account,
            'descriptor_handoff':descriptor_handoff(relocations_account,executables_account),'roots':roots(root,work,inputs),
            'descriptor_admission':descriptor_admission_observations(root,work,inputs,tools),
            'descriptor_runtime_admission':descriptor_runtime_observations(root,work,inputs),
            'runtime_labels':[cell['label'] for cell in runtime_cells()],
            'limits':{'descriptor_worker_lifecycle':'not requalified by startup receipt',
                      'failed_first_bootstrap':'source contract retained; dedicated runtime rejection receipt not supplied',
                      'descriptor_runtime_order':'source-level lexical account; arbitrary concurrent interleavings are not observed',
                      'family_semantics':'incomplete'}}

def retain_oracle_crt(work,source,name):
    relative='inputs/oracle-crt/'+name
    snapshot=inventory._snapshot_regular(work,source,relative,str(source))
    path=work/relative
    # Seal the eventual readable copy before recording its mode. Cleanup must
    # not invalidate the original/retained identity pair during public replay.
    path.chmod(path.stat().st_mode | 0o444)
    snapshot['retained']=inventory.file_record(path,logical_path=relative)
    return snapshot

def oracle_crt(work,record=None):
    if record is None:
        record={}
        for name in ORACLE_CRT:
            path=Path('/opt/musl-1.2.6/lib')/name
            record[name]=retain_oracle_crt(work,path,name)
    require(type(record) is dict and set(record)==set(ORACLE_CRT),'oracle CRT roster differs')
    for name in ORACLE_CRT:inventory._validate_snapshot(work,record[name],'oracle CRT '+name,
        expected_original_path='/opt/musl-1.2.6/lib/'+name,expected_retained_path='inputs/oracle-crt/'+name)
    return record

def tool_check(root,work,inputs,tools):
    require(type(tools) is dict and set(tools)==set(ordinary.TOOL_ROLES)|set(EXTRA_TOOLS),'startup tool roster differs')
    ordinary.validate_tool_roster(root,work,inputs,{k:v for k,v in tools.items() if k not in EXTRA_TOOLS})
    for role,path in EXTRA_TOOLS.items():inventory._validate_snapshot(work,tools[role],role,
        expected_original_path=path,expected_retained_path='inputs/tools/'+role)

def collect(root,output,preparation,static,dynamic,historical):
    output=substrate.fresh_output(root,output,[preparation,static,dynamic,historical])
    require(sys.platform=='linux' and os.uname().machine=='x86_64' and os.environ.get('LC_ALL')=='C','native pinned C-locale collection required')
    image=os.environ.get(ordinary.IMAGE_ENV,'');require(ordinary.IMAGE_PATTERN.fullmatch(image) is not None,'pinned image required')
    source=static_products.source_identity(root);policy=contract(root);before=admit(root,preparation,static,dynamic,historical)
    output.mkdir(parents=True)
    try:
        selected=source_files(root,output,before['selected_source']['revision'],True);collector=source_files(root,output,capture=True)
        oracle=qualification.capture_oracle(output);qualification.validate_oracle(output,oracle)
        static_oracle=ordinary.capture_oracle_static_inputs(output);crts=oracle_crt(output)
        tools=ordinary.capture_tool_roster(root,output,static,dynamic)
        for role,path in EXTRA_TOOLS.items():tools[role]=ordinary.retain_tool_snapshot(output,role,ordinary.fixed_image_tool_identity(Path(path),role))
        shutil.copy2(root/'compat/x86_64/installed_crt_startup_probe.c',output/'installed_crt_startup_probe.c')
        shutil.copy2(root/'compat/x86_64/installed_crt_startup_descriptor_dso.c',output/'installed_crt_startup_descriptor_dso.c')
        shutil.copy2(root/DESCRIPTOR_RUNTIME_PROBE,output/Path(DESCRIPTOR_RUNTIME_PROBE).name)
        (output/'oracle-link').mkdir();shutil.copyfile(output/'qualification-oracle/runtime',output/'oracle-link/libc.so')
        runner=ordinary.Collector(root,output,preparation,static,dynamic)
        for spec in plan(root,output,before,tools):
            if spec['label']==runtime_cells()[0]['label']:prepare_roots(root,output,before);roots(root,output,before)
            runner.run(spec['label'],spec['argv'],cwd=root if spec['cwd']=='/workspace' else output,timeout_seconds=45,
                       expected_status=spec.get('expected_status',0),stdout=spec.get('expected_stdout'),
                       stderr=spec.get('expected_stderr'))
        after=admit(root,preparation,static,dynamic,historical);require(same(before,after),'startup products changed during collection')
        require(same(source,static_products.source_identity(root)),'startup collector changed')
        ordinary.require_live_tool_roster({k:v for k,v in tools.items() if k not in EXTRA_TOOLS})
        ordinary.require_live_oracle_static_inputs(static_oracle)
        for name in ORACLE_CRT:require(ordinary.digest(Path('/opt/musl-1.2.6/lib')/name)==crts[name]['original']['sha256'],'oracle CRT changed')
        for role,path in EXTRA_TOOLS.items():require(same({k:tools[role]['original'][k] for k in ('path','sha256','mode')},ordinary.fixed_image_tool_identity(Path(path),role)),role+' changed')
        ordinary.write_new_json(output/'report.json',{'schema':SCHEMA,'status':STATUS,'image':image,'contract':policy,
            'collector_source':source,'collector_files':collector,'selected_files':selected,'inputs_before':before,'inputs_after':after,
            'oracle':oracle,'oracle_static':static_oracle,'oracle_crt':crts,'tools':tools,'commands':runner.commands,
            'observations':observations(root,output,before,tools),'files':substrate.retained_files(root,output)})
    finally:static_products.make_retained_evidence_readable(output)
    validate_report(root,output/'report.json');return output/'report.json'

def validate_report(root,report_path):
    report_path=ordinary.physical_work_path(root,report_path,'startup report');work=report_path.parent;report=read(report_path)
    require(set(report)=={'schema','status','image','contract','collector_source','collector_files','selected_files','inputs_before','inputs_after','oracle','oracle_static','oracle_crt','tools','commands','observations','files'},'startup report fields differ')
    require(report['schema']==SCHEMA and same(report['status'],STATUS) and same(report['contract'],contract(root)),'startup report contract or flags differ')
    require(type(report['image']) is str and ordinary.IMAGE_PATTERN.fullmatch(report['image']) is not None,'startup image identity differs')
    require(same(report['collector_source'],static_products.source_identity(root)),'startup collector source differs')
    supplied=report['inputs_before'];preparation=ordinary.resolve_work_identity(root,supplied['preparation'],'static preparation')
    historical=ordinary.resolve_work_identity(root,supplied['historical_facts'],'historical ELF facts')
    static=root/supplied['static_preparation']['primary']['path'];dynamic=root/supplied['dynamic_product']['path']
    actual=admit(root,preparation,static,dynamic,historical)
    require(same(supplied,actual) and same(report['inputs_after'],actual),'startup input seals differ')
    require(same(report['selected_files'],source_files(root,work,actual['selected_source']['revision'])),'selected startup source files differ')
    require(same(report['collector_files'],source_files(root,work)),'collector startup source files differ')
    qualification.validate_oracle(work,report['oracle']);ordinary.validate_oracle_static_inputs(work,report['oracle_static']);oracle_crt(work,report['oracle_crt'])
    tool_check(root,work,actual,report['tools']);validate_commands(root,work,actual,report['tools'],report['commands'])
    require(same(report['files'],substrate.retained_files(root,work)),'retained startup artifact roster differs')
    require(same(report['observations'],observations(root,work,actual,report['tools'])),'startup observations do not reconstruct')
    require(same(actual,admit(root,preparation,static,dynamic,historical)),'startup inputs changed during replay')
    return report

def main(argv=None):
    args=list(sys.argv[1:] if argv is None else argv)
    options=[arg.split('=',1)[0] for arg in args if arg.startswith('--')]
    require(len(options)==len(set(options)),'duplicate startup option')
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False);parser.add_argument('mode',choices=('collect','validate-report'))
    for name in ('output','report','static-preparation','static-product','dynamic-product','historical-facts'):parser.add_argument('--'+name,type=Path)
    ns=parser.parse_args(args);paths=[ns.static_preparation,ns.static_product,ns.dynamic_product,ns.historical_facts]
    if ns.mode=='collect':
        require(ns.output is not None and ns.report is None and all(x is not None for x in paths),'startup collection requires four supplied inputs and output')
        path=collect(ROOT,ns.output,*paths)
    else:
        require(ns.report is not None and ns.output is None and all(x is None for x in paths),'startup replay accepts only report')
        validate_report(ROOT,ns.report);path=ns.report
    print(json.dumps({'schema':SCHEMA,'report':str(path),'sha256':ordinary.digest(path),'status':STATUS},sort_keys=True));return 0
if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError,KeyError,static_products.PreparationError,products.ProductEvidenceError) as error:
        print('ERROR: installed CRT startup: '+str(error),file=sys.stderr);raise SystemExit(2)
