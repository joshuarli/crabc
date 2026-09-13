#!/usr/bin/env python3
"""Evidence for the installed pthread/loader prepared-worker TLS ownership.

The native owner uses an exact allocation token; frozen prepared-token names
are source-replacement obligations. Neither becomes a public export rule.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import re
import sys
import tomllib
from typing import Any, Mapping

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
import native_abi_inventory as inventory
import validate_loader_libc_tls_runtime_v1 as runtime_contract

ROOT = inventory.ROOT
CONTRACT = ROOT / 'compat/x86_64/prepared-worker-tls.toml'
TOKEN_FIELDS = ['mapping:*mut u8', 'mapping_size:usize', 'thread_pointer:*mut u8', 'allocation_id:usize']
WORKER_OWNER = 'ldso/src/x86_64_initial_worker_tls.rs'
ADAPTER = 'libc/src/c_abi/x86_64/dynamic_tls.rs'
PTHREAD = 'libc/src/c_abi/x86_64/pthread_create_join.rs'
OPERATIONS = {
    '__crabc_x86_64_initial_tls_allocate': {
        'producer': WORKER_OWNER+':allocate',
        'producer_signature': 'unsafe extern C fn(*mut WorkerTlsAllocation) -> i32',
        'consumer': ADAPTER+':allocate_thread',
        'consumer_signature': 'unsafe extern C fn(*mut StaticInitialTlsBlock) -> i32',
        'role': 'prepare-current-generation-before-clone_settls'},
    '__crabc_x86_64_initial_tls_release': {
        'producer': WORKER_OWNER+':release',
        'producer_signature': 'unsafe extern C fn(*const WorkerTlsAllocation) -> i64',
        'consumer': ADAPTER+':release_thread',
        'consumer_signature': 'unsafe extern C fn(*const StaticInitialTlsBlock) -> i64',
        'role': 'exact-token-release-after-worker-quiescence'},
    '__crabc_x86_64_resolve_initial_tls': {
        'producer': 'ldso/src/x86_64_initial_graph.rs:__tls_get_addr',
        'producer_signature': 'unsafe extern C fn(*const TlsIndex) -> *mut c_void',
        'consumer': ADAPTER+':__tls_get_addr',
        'consumer_signature': 'unsafe extern C fn(*const c_void) -> *mut c_void',
        'role': 'resolve-two-native-word-module-offset-on-owned-thread'},
}
LEGACY = {
    '__rc_clone': (PTHREAD+':__crabc_x86_pthread_clone', 'prepared-pthread-clone-stack-tid-and-tls-token'),
    '__rc_init_thread_tls': (PTHREAD+':create_selected_worker_with_attributes', 'consume-already-initialized-token-before-clone'),
    '__rc_tls_block_size': (PTHREAD+':create_selected_worker_with_attributes', 'consume-already-initialized-token-before-clone'),
    '__rc_tls_block_size_for': (PTHREAD+':reclaim_withdrawn_selected_worker', 'exact-token-release-not-arbitrary-fs-reconstruction'),
    '__rc_tls_base_offset_for': (PTHREAD+':reclaim_withdrawn_selected_worker', 'exact-token-release-not-arbitrary-fs-reconstruction'),
    '__rc_create_thread_tls': (ADAPTER+':allocate_thread', 'no-separate-native-caller-or-allocation-query-export'),
    '__rc_tls_base_offset': (ADAPTER+':allocate_thread', 'no-separate-native-caller-or-allocation-query-export'),
}
SOURCE_PATHS = (
    'compat/x86_64/prepared_worker_tls_evidence.py', 'compat/x86_64/prepared-worker-tls.toml',
    'compat/x86_64/loader_debug_abi_evidence.py',
    'compat/x86_64/prepared_worker_tls_probe.c', 'compat/x86_64/prepared_worker_tls_dependency.c',
    'compat/x86_64/loader-libc-tls-runtime-v1.toml', 'compat/x86_64/validate_loader_libc_tls_runtime_v1.py',
    WORKER_OWNER, ADAPTER, PTHREAD, 'libc/src/c_abi/x86_64/static_c_abi.rs',
    'libc/src/c_abi/x86_64/static_tls.rs', 'libc/src/c_abi/x86_64/loader_tls_runtime_v1.rs',
    'libc/src/c_abi/x86_64/owned_dynamic_attachment.rs',
    'ldso/src/x86_64_general_initial_tls_state.rs', 'ldso/src/x86_64_initial_graph.rs',
    'ldso/src/x86_64_runtime_tls_view.rs', 'ldso/src/x86_64_runtime_registry.rs',
    'ldso/src/x86_64_general_relocation.rs', 'ldso/src/x86_64_runtime_lock.rs',
    'ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs',
    'ldso/src/x86_64_general_initial_loader_state.rs', 'rust-toolchain.toml',
    'compat/x86_64/public_data_ordinary_link_evidence.py', 'compat/x86_64/owned_dynamic_fork_evidence.py',
    'compat/x86_64/owned_dynamic_receipt.py', 'compat/x86_64/native_abi_elf_facts.py',
    'compat/x86_64/native_abi_inventory.py', 'compat/x86_64/owned_dynamic_qualification.py',
    'compat/x86_64/owned_posix_static_products.py', 'compat/x86_64/owned_posix_product_evidence.py',
    'ldso/Cargo.toml', 'libc/Cargo.toml', 'crt/build_x86_64.py',
    'crt/src/x86_64_dynamic_startup.rs', 'scripts/build_x86_64_owned_dynamic_sysroot.py',
)


class PreparedWorkerTlsError(ValueError):
    """An installed token/lifecycle observation does not satisfy its owner."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreparedWorkerTlsError('prepared worker TLS: '+message)


def same(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys()==right.keys() and all(same(v,right[k]) for k,v in left.items())
    if isinstance(left, list):
        return len(left)==len(right) and all(same(a,b) for a,b in zip(left,right))
    return left==right


def expected_contract() -> dict[str, Any]:
    return {
        'schema':'crabc.x86_64-prepared-worker-tls-contract/v1', 'id':'x86-prepared-worker-tls',
        'status':'implemented-unqualified', 'target':'x86_64-unknown-linux-musl',
        'worker_token':{'owner':WORKER_OWNER+':WorkerTlsAllocation', 'consumer':ADAPTER+':StaticInitialTlsBlock',
            'size_bytes':32,'alignment_bytes':8,'fields':TOKEN_FIELDS,
            'identity':'exact-live-mapping-span-thread-pointer-nonzero-allocation-id',
            'release':'after-clear-child-tid-registry-withdrawal-and-reader-quiescence'},
        'descriptor':{'owner':'ldso/src/x86_64_general_initial_tls_state.rs:GeneralLoaderLibcTlsRuntimeV1',
            'size_bytes':72,'alignment_bytes':8,'initial_generation':1,
            'role':'private-process-lifetime-initial-tls-provenance',
            'current_view':'ldso/src/x86_64_runtime_tls_view.rs:RuntimeTlsView','current_view_tcb_offset':24,
            'require_installed_import':False},
        'operation':OPERATIONS,
        'legacy_replacement':[{'name':name,'owner':owner,'role':role} for name,(owner,role) in LEGACY.items()],
        'limits':{name:False for name in ('public_exports_added','public_facade_runtime_v1','static_main_tls_replaced',
                                        'general_pthread_qualification','family_completion','promotion_ready')},
    }


def validate_contract(contract: object) -> None:
    require(same(contract,expected_contract()), 'contract identity, exact owner roster, geometry or limits drifted')


def load_contract(root: Path = ROOT) -> dict[str, Any]:
    path=inventory.physical_regular(root/CONTRACT.relative_to(ROOT),'prepared worker contract')
    try:
        contract=tomllib.loads(path.read_text(encoding='utf-8'))
    except (UnicodeError,tomllib.TOMLDecodeError) as error:
        raise PreparedWorkerTlsError('prepared worker contract is unreadable') from error
    validate_contract(contract)
    return contract


def _tables(facts: Mapping[str, Any], artifact: str) -> dict[str, Any]:
    try:
        tables=facts['facts'][artifact]['symbol_tables']
    except (KeyError,TypeError) as error:
        raise PreparedWorkerTlsError('complete ELF facts omit '+artifact) from error
    require(type(tables) is list,artifact+' symbol tables are not a list')
    result={}
    for index,table in enumerate(tables):
        require(type(table) is dict and type(table.get('name')) is str and type(table.get('rows')) is list,
                artifact+' symbol table shape drifted')
        name=table['name']
        require(name not in result,artifact+' duplicate symbol table')
        result[name]={'table_index':index,'rows':table['rows']}
    return result


def account_elf(facts: Mapping[str, Any]) -> dict[str, Any]:
    """Project only after the owning complete-ELF reader authenticates facts.

    Keep every selected physical row and named table. Stripping private loader
    definitions or dropping an unused attachment does not manufacture a new
    descriptor import or an exported worker operation.
    """
    shared=_tables(facts,'candidate-shared')
    loader=_tables(facts,'candidate-loader')
    require(set(shared)=={'.dynsym','.symtab'},'shared libc needs both complete symbol tables')
    metadata={'type':'NOTYPE','binding':'GLOBAL','visibility':'DEFAULT','section_index':'UND',
              'size_bytes':0,'value':'0000000000000000','version':None,'version_default':False}
    observations={}
    for name in OPERATIONS:
        occurrences={}
        for table,record in shared.items():
            rows=[row for row in record['rows'] if row.get('name')==name]
            require(len(rows)==1,name+' must occur once in '+table)
            row=rows[0]
            require(same({key:row.get(key) for key in metadata},metadata),name+' import metadata drifted')
            require(type(row.get('row_index')) is int and row['row_index']>=0,name+' row identity drifted')
            occurrences[table]={'table_index':record['table_index'],'row_index':row['row_index'],'row':copy.deepcopy(row)}
        require(not any(row.get('name')==name for table in loader.values() for row in table['rows']),
                name+' unexpectedly has a loader ELF import/definition')
        observations[name]=occurrences
    legacy_rows=[{'artifact':artifact,'table':table,'row':copy.deepcopy(row)}
                 for artifact,tables in [('candidate-shared',shared),('candidate-loader',loader)]
                 for table,record in tables.items() for row in record['rows'] if row.get('name') in LEGACY]
    require(not legacy_rows,'legacy prepared-token exports are not selected native providers')
    descriptor=[]
    for artifact,tables in [('candidate-shared',shared),('candidate-loader',loader)]:
        for table,record in tables.items():
            for row in record['rows']:
                if row.get('name')=='__crabc_x86_64_loader_tls_runtime_v1':
                    descriptor.append({'artifact':artifact,'table':table,'row':copy.deepcopy(row)})
                    require(not(table=='.dynsym' and row.get('section_index')!='UND'),
                            'initial TLS descriptor is not a public dynamic provider')
    return {'operations':observations,'descriptor_named_elf_observations':descriptor,
            'descriptor_installed_import_required':False,'legacy_named_shared_loader_rows':legacy_rows}


def _body(source: str, name: str) -> str:
    match=re.search(r'\bfn\s+'+re.escape(name)+r'\s*\(',source)
    require(match is not None,'source function absent: '+name)
    start=source.index('{',match.end())
    depth=1
    cursor=start+1
    while depth and cursor<len(source):
        if source[cursor]=='{':depth+=1
        elif source[cursor]=='}':depth-=1
        cursor+=1
    require(depth==0,'source function is truncated: '+name)
    return source[start:cursor]


def _ordered(source: str, fragments: tuple[str,...], label: str) -> list[str]:
    cursor=0
    for fragment in fragments:
        where=source.find(fragment,cursor)
        require(where>=cursor,label+' source ordering drifted at '+fragment)
        cursor=where+len(fragment)
    return list(fragments)


def _fields(source: str, name: str) -> list[str]:
    match=re.search(r'#\[repr\(C\)\]\s*(?:#\[[^\]]+\]\s*)*(?:pub(?:\([^)]*\))?\s+)?struct\s+'+re.escape(name)+r'\s*\{([^}]+)\}',source)
    require(match is not None,'source token absent: '+name)
    return [re.sub(r'\s+',' ',field.strip()).replace(': ',':') for field in match.group(1).split(',') if field.strip()]


def check_operation_signatures(root: Path, consumer: str) -> dict[str, Any]:
    """Compare the named source declarations; opaque pointees stay distinct."""
    blocks=re.findall(r'unsafe\s+extern\s+"C"\s*\{([^}]+)\}',consumer)
    require(bool(blocks),'private consumer C declaration block drifted')
    observations={}
    for name,operation in OPERATIONS.items():
        path,function=operation['producer'].split(':')
        source=(root/path).read_text(encoding='utf-8')
        producer=re.findall(r'unsafe\s+extern\s+"C"\s+fn\s+'+function+r'\s*\(([^)]*)\)\s*->\s*([^\{]+)\{',source)
        caller=re.findall(r'\bfn\s+'+name+r'\s*\(([^)]*)\)\s*->\s*([^;]+);','\n'.join(blocks))
        require(len(producer)==len(caller)==1,name+' exact C declarations absent or duplicate')
        def signature(parts):
            arguments,returned=parts
            types=[argument.split(':',1)[1].strip() for argument in arguments.split(',') if argument.strip()]
            value='unsafe extern C fn('+', '.join(types)+') -> '+returned.strip()
            return re.sub(r'\s+',' ',value.replace('core::ffi::c_void','c_void'))
        observed={'producer_signature':signature(producer[0]),'consumer_signature':signature(caller[0])}
        require(same(observed,{key:operation[key] for key in observed}),name+' typed operation signature differs')
        observations[name]=observed
    graph=(root/'ldso/src/x86_64_initial_graph.rs').read_text()
    require(_fields(graph,'TlsIndex')==['ti_module:usize','ti_offset:usize'],'module/offset token fields drifted')
    view=(root/'ldso/src/x86_64_runtime_tls_view.rs').read_text()
    require(_fields(view,'RuntimeTlsView')==['mapping_bytes:usize','previous:*mut RuntimeTlsView',
            'module_count:usize','dtv:*mut usize','sizes:*mut usize'],'source-defined worker view fields drifted')
    return observations


def account_source(root: Path = ROOT) -> dict[str, Any]:
    """Bind source contracts without presenting lexical checks as machine proof."""
    load_contract(root)
    runtime_path=root/'compat/x86_64/loader-libc-tls-runtime-v1.toml'
    runtime=runtime_contract.load_toml(runtime_path)
    runtime_contract.validate_contract(runtime)
    sources={name:inventory.physical_regular(root/name,'prepared worker source '+name).read_text(encoding='utf-8') for name in SOURCE_PATHS}
    signatures=check_operation_signatures(root,sources[ADAPTER])
    descriptor_fields=_fields(sources['ldso/src/x86_64_general_initial_tls_state.rs'],'GeneralLoaderLibcTlsRuntimeV1')
    require(descriptor_fields==['magic:u64','version:u32','abi_size:u32','process_mode:u32','owner:u32',
            'state:AtomicU8','reserved:[u8; 7]','thread_pointer:*const u8','dtv:*const usize',
            'dtv_words:usize','module_count:usize','generation:u64'],'initial descriptor fields drifted')
    producer=_fields(sources[WORKER_OWNER],'WorkerTlsAllocation')
    consumer=_fields(sources[ADAPTER],'StaticInitialTlsBlock')
    require(producer==consumer==TOKEN_FIELDS,'producer/consumer token layout differs')
    for name,resolver in [('__crabc_x86_64_initial_tls_allocate','allocate'),
                          ('__crabc_x86_64_initial_tls_release','release'),
                          ('__crabc_x86_64_resolve_initial_tls','__tls_get_addr')]:
        require('b"'+name+'" => Some('+resolver+' as *const ()' in sources[WORKER_OWNER],name+' resolver entry drifted')
        require('fn '+name+'(' in sources[ADAPTER],name+' private consumer declaration absent')
    create=_body(sources[PTHREAD],'create_selected_worker_with_attributes')
    before=_ordered(create,('static_tls::allocate_thread()', 'ThreadControl {', 'publish_selected_worker(control)',
                            'start_ready.store(1, Ordering::Release)', '__crabc_x86_pthread_clone('),'prepared-before-clone')
    reclaim=_body(sources[PTHREAD],'reclaim_withdrawn_selected_worker')
    after=_ordered(reclaim,('wait_for_cancellation_wake_leases(control)', 'signal_target_leases.load(Ordering::Acquire)',
                           'static_tls::release_thread(tls_block)'), 'quiescent-release')
    detached=_body(sources[PTHREAD],'claim_finished_detached_selected_worker')
    _ordered(detached,('child_tid.load(Ordering::Acquire)', 'release_selected_worker_locked(control)',
                       'registry_retired.store(1, Ordering::Release)'), 'detached-withdrawal')
    release=_body(sources[WORKER_OWNER],'release')
    _ordered(release,('(*node).token } == token', 'x86_64_runtime_tls_view::release(token.thread_pointer)',
                      'SYS_MUNMAP', 'if result == 0'), 'loader-exact-token-release')
    graph=sources['libc/src/c_abi/x86_64/static_c_abi.rs']
    require('#[cfg_attr(not(feature = "x86-owned-dynamic-runtime"), path = "static_tls.rs")]' in graph
            and '#[cfg_attr(feature = "x86-owned-dynamic-runtime", path = "dynamic_tls.rs")]' in graph,
            'static/dynamic TLS owners lost their explicit feature split')
    return {'source_files':{name:inventory.file_record(root/name,logical_path=name) for name in SOURCE_PATHS},
            'operations':copy.deepcopy(OPERATIONS),'source_signatures':signatures,'legacy_replacement':copy.deepcopy(expected_contract()['legacy_replacement']),
            'worker_token':{'producer_fields':producer,'consumer_fields':consumer,'size_bytes':32,'alignment_bytes':8},
            'ordering':{'before-clone':before,'after-clear-child-tid-and-withdrawal':after},
            'descriptor':copy.deepcopy(runtime['owned_runtime']),'descriptor_source_fields':descriptor_fields,
            'scope':'Source selection and lexical ordering; native execution/compiled unit receipts remain separate.'}

# The supplied-product path owns no product builder. These are the existing
# ordinary-link capture/product APIs; pthread scenarios and private TLS views
# are specific to this component and are reconstructed below.
import argparse
import json
import os
import shutil
import stat
import subprocess
import native_abi_elf_facts as complete_elf
import public_data_ordinary_link_evidence as ordinary
import owned_dynamic_fork_evidence as dynamic_links
import owned_dynamic_receipt as dynamic_receipt
from loader_debug_abi_evidence import Elf

SCHEMA='crabc.x86_64-prepared-worker-tls-evidence/v1'
SCENARIOS=('normal','explicit','detached','cancelled','fork-worker')
PROBE='prepared_worker_tls_probe.c'
DEPENDENCY='prepared_worker_tls_dependency.c'
UNIT_ROOT='ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs'
UNIT_CFG=('feature="x86_64-owned-dynamic-runtime"','crabc_general_initial_graph',
          'crabc_general_initial_lifecycle','crabc_general_initial_tls_materialization_v1',
          'crabc_general_loader_libc_tls_runtime_v1','crabc_dynamic_main_thread_runtime_v1')
UNIT_TESTS=(
    'x86_64_initial_worker_tls::tests::worker_materialization_preserves_fs_and_copies_initial_images_not_live_tls',
    'x86_64_initial_worker_tls::tests::worker_tls_release_requires_exact_live_generation_and_mapping',
    'x86_64_runtime_tls_view::tests::abandoning_partial_all_thread_preparation_preserves_every_live_view',
    'x86_64_runtime_tls_view::tests::acquire_readers_keep_valid_old_generations_during_repeated_publication',
    'x86_64_runtime_tls_view::tests::malformed_new_population_fails_without_replacing_the_live_view',
    'x86_64_runtime_tls_view::tests::generations_preserve_live_addresses_and_publish_dtv_sizes_together',
    'x86_64_general_initial_tls_state::tests::pre_fs_publication_reservation_rolls_back_and_allows_retry',
)
UNIT_TESTS=tuple('x86_64_initial_graph::'+name for name in UNIT_TESTS)
STATUS={'component':'prepared-worker-lifecycle-observed','runtime_qualification':False,
        'family_completion':False,'promotion_ready':False,'public_support':False,
        'public_facade_runtime_v1':False,'legacy_exports_added':False}
REPORT_INPUTS=('base_inventory','elf_report','static_preparation','static_product','dynamic_product')
RUST_SELECTOR_INVOCATION=Path('/opt/cargo/bin/rustup')
RUST_SELECTOR_PHYSICAL=Path('/usr/bin/rustup-init')


def rust_selector_invocation() -> dict[str,str]:
    """Seal the pinned rustup applet spelling and its non-symlink executable.

    The image deliberately exposes the selector at `/opt/cargo/bin/rustup`,
    while its executable bytes live at `/usr/bin/rustup-init`. The generic
    fixed-image tool reader must continue to reject aliases; this one command
    needs its applet spelling for `rustup which rustc`, so retain the finite
    alias relation alongside a snapshot of the physical executable.
    """
    try:
        inventory.physical_directory(RUST_SELECTOR_INVOCATION.parent,
                                     'Rust selector invocation parent')
        inventory.physical_directory(RUST_SELECTOR_PHYSICAL.parent,
                                     'Rust selector physical parent')
        require(RUST_SELECTOR_INVOCATION.is_symlink(),
                'Rust selector invocation is not the pinned image alias')
        require(os.readlink(RUST_SELECTOR_INVOCATION)==str(RUST_SELECTOR_PHYSICAL),
                'Rust selector alias target differs')
        resolved=inventory.physical_executable(Path(os.path.realpath(RUST_SELECTOR_INVOCATION)),
                                                'Rust selector physical executable')
    except (inventory.InventoryError, OSError) as error:
        raise PreparedWorkerTlsError('cannot identify Rust selector invocation: '+str(error)) from error
    require(resolved==RUST_SELECTOR_PHYSICAL,
            'Rust selector invocation no longer resolves to the pinned physical executable')
    return {'path':str(RUST_SELECTOR_INVOCATION),'physical_path':str(resolved)}


def runtime_cells() -> list[dict[str,str]]:
    result=[]
    for mode in ('oracle-static','static','static-pie'):
        for scenario in SCENARIOS:
            result.append({'label':mode+'-'+scenario,'mode':mode,'entry':'kernel','scenario':scenario,
                           'owner':'oracle' if mode=='oracle-static' else 'candidate'})
    for owner in ('oracle','candidate'):
        for mode in ('pie','non-pie'):
            for entry in ('kernel','direct'):
                name=('oracle-dynamic-' if owner=='oracle' else 'dynamic-')+mode
                for scenario in SCENARIOS:
                    result.append({'label':name+'-'+entry+'-'+scenario,'mode':name,'entry':entry,
                                   'scenario':scenario,'owner':owner})
    return result


def runtime_stdout(cell: Mapping[str,str]) -> bytes:
    policy='owned' if cell['owner']=='candidate' else 'unspecified'
    return ('prepared-worker-tls case='+cell['scenario']+' initial=ready distinct=1 retained=1 cleanup=1 reclaimed='
            +policy+' fork='+str(int(cell['scenario']=='fork-worker'))+'\n').encode('ascii')


def command_plan(root: Path, work: Path, inputs: Mapping[str,Any], tools: Mapping[str,Any],
                 rust: Mapping[str,Any]) -> dict[str,dict[str,Any]]:
    # Reuse the exact seven executable link modes and ELF observation commands;
    # substitute only this component's source and execution roster.
    result=ordinary.expected_commands(root,work,inputs,tools)
    for label in ordinary.EXECUTION_LABELS:
        del result[label]
    result['compile']['argv']=[arg.replace('public_data_ordinary_link_probe.c',PROBE)
                               for arg in result['compile']['argv']]
    output=lambda name:ordinary.mounted(root,work/name)
    tool=lambda role:tools[role]['original']['path']
    def add(label,argv):
        require(label not in result,'duplicate command label '+label)
        result[label]={'cwd':'/workspace','argv':argv}
    for generation in (1,2):
        obj=f'dso-{generation}.o'
        add(f'dso-{generation}-compile',[tool('dynamic_driver'),'--dynamic-shared-object','-std=c11',
            '-DWORKER_TLS_GENERATION='+str(generation),'-c',output(DEPENDENCY),'-o',output(obj)])
        add(f'dso-{generation}-symbols',[tool('readelf'),'-sW',output(obj)])
        for owner in ('candidate','oracle'):
            name=f'{owner}-worker-{generation}.so'
            argv=([tool('dynamic_driver'),'--dynamic-shared-object'] if owner=='candidate'
                  else [tool('oracle_wrapper'),'-shared','-Wl,-soname,'+name])
            add(f'{owner}-worker-{generation}-link',argv+[output(obj),'-o',output(name)])
            for flag,suffix in (('-hW','header'),('-lW','program'),('-sW','symbols'),('-SW','sections'),('-dW','dynamic')):
                add(f'{owner}-worker-{generation}-'+suffix,[tool('readelf'),flag,output(name)])
    add('rustc-discover',[rust['selector_invocation']['path'],'which','rustc'])
    add('unit-build',[rust['compiler']['original']['path'],'--edition=2021','--test','--error-format=json',
        *[arg for cfg in UNIT_CFG for arg in ('--cfg',cfg)],'/workspace/'+UNIT_ROOT,'-o',output('loader-tests')])
    for index,name in enumerate(UNIT_TESTS):
        add(f'unit-{index}',[output('loader-tests'),name,'--exact','--test-threads=1'])
    for cell in runtime_cells():
        if cell['mode'] in ('oracle-static','static','static-pie'):
            argv=[tool('env'),'-i',output(cell['mode']),cell['scenario'],
                  'owned' if cell['owner']=='candidate' else 'portable','-','-']
        else:
            owner=cell['owner']; mode='non-pie' if cell['mode'].endswith('non-pie') else 'pie'
            argv=[tool('env'),'-i',ordinary.validate_chroot_invocation(tools['chroot']['invocation'],
                       tools['chroot']['original']),output(owner+'-root')]
            if cell['entry']=='direct':
                argv.append('/lib/ld-crabc-x86_64.so.1' if owner=='candidate' else '/lib/ld-musl-x86_64.so.1')
            argv+=['/consumer-'+mode,cell['scenario'],'owned' if owner=='candidate' else 'portable',
                   '/worker-1.so','/worker-2.so']
        add(cell['label'],argv)
    return {'rustc-discover':result.pop('rustc-discover'),**result}


def validate_commands(root: Path, work: Path, inputs: Mapping[str,Any], tools: Mapping[str,Any],
                      rust: Mapping[str,Any], commands: object) -> None:
    plan=command_plan(root,work,inputs,tools,rust)
    require(type(commands) is list and [row.get('label') if type(row) is dict else None for row in commands]
            ==list(plan),'finite command order or roster differs')
    for record in commands:
        require(set(record)=={'label','argv','cwd','outcome','command','stdout','stderr','status'},'command fields differ')
        label=record['label']
        require(same({key:record[key] for key in ('cwd','argv')},plan[label]),label+' command differs')
        paths={}
        for field,suffix in [('command','command.json'),('stdout','stdout'),('stderr','stderr'),('status','status')]:
            paths[field]=ordinary.resolve_work_identity(root,record[field],label+' '+field)
            require(paths[field]==ordinary.raw_path(work,label,suffix),label+' raw path differs')
        require(record['outcome']=='ok' and paths['status'].read_bytes()==b'0\n',label+' terminal status differs')
        require(same(ordinary.read_json(paths['command'],label+' argv',list),record['argv']),label+' raw argv differs')
        if label!='unit-build':
            require(paths['stderr'].read_bytes()==b'',label+' diagnostics are not empty')


def raw_stdout(work: Path, label: str) -> bytes:
    return ordinary.raw_path(work,label,'stdout').read_bytes()


def runtime_observations(work: Path) -> dict[str,Any]:
    observations={}
    for cell in runtime_cells():
        require(raw_stdout(work,cell['label'])==runtime_stdout(cell),cell['label']+' lifecycle observation differs')
        observations[cell['label']]=dict(cell)
    for index,name in enumerate(UNIT_TESTS):
        raw=raw_stdout(work,f'unit-{index}').decode('utf-8')
        pattern=(r'\nrunning 1 test\ntest '+re.escape(name)+r' \.\.\. ok\n\n'
                 r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s\n\n')
        require(re.fullmatch(pattern,raw) is not None,'exact source test result differs: '+name)
    return {'application_cells':observations,'source_tests':list(UNIT_TESTS),
            'source_test_executable':'loader-tests','source_root':UNIT_ROOT,
            'oracle_boundary':'Common installed C TLS/callback lifecycle only; no musl token/view/unmap-layout claim.',
            'owned_boundary':'Live TLS and retained views mapped until quiescence; joined/reaped TLS and views unmapped.'}


def admitted(root: Path, paths: Mapping[str,Path]) -> tuple[dict[str,Any],dict[str,Any]]:
    require(set(paths)==set(REPORT_INPUTS),'input path roster differs')
    paths={name:ordinary.physical_work_path(root,path,name) for name,path in paths.items()}
    current=ordinary.admit_inputs(root,paths['static_preparation'],paths['static_product'],paths['dynamic_product'])
    facts=complete_elf.validate_report(paths['elf_report'],base_inventory=paths['base_inventory'],
        static_product=paths['static_product'],dynamic_product=paths['dynamic_product'],
        static_preparation=paths['static_preparation'])
    binding={'products':current,'reports':{name:ordinary.work_file_identity(root,paths[name],name)
             for name in ('base_inventory','elf_report')},'elf':account_elf(facts)}
    return binding,paths


def rust_tools(work: Path, record: object) -> None:
    require(type(record) is dict and set(record)=={'selector_invocation','selector','compiler'},
            'Rust tool roster differs')
    invocation=record['selector_invocation']
    require(type(invocation) is dict and set(invocation)=={'path','physical_path'},
            'Rust selector invocation fields differ')
    require(invocation=={'path':str(RUST_SELECTOR_INVOCATION),'physical_path':str(RUST_SELECTOR_PHYSICAL)},
            'Rust selector invocation differs')
    for name,expected in [('selector',str(RUST_SELECTOR_PHYSICAL)),('compiler',None)]:
        inventory._validate_snapshot(work,record[name],'worker source-test '+name,
            expected_original_path=expected,expected_retained_path='inputs/tools/worker-'+name)
    require(record['selector']['original']['path']==invocation['physical_path'],
            'Rust selector invocation physical bytes differ')
    compiler=record['compiler']['original']['path']
    pinned=tomllib.loads((ROOT/'rust-toolchain.toml').read_text())['toolchain']['channel']
    require(re.fullmatch(r'/opt/rustup/toolchains/'+re.escape(pinned)+r'-x86_64-unknown-linux-(gnu|musl)/bin/rustc',compiler) is not None,
            'source-test compiler is not the pinned native toolchain')
    require(raw_stdout(work,'rustc-discover')==(compiler+'\n').encode(),'retained rustc discovery differs')


def execution_roots(root: Path, work: Path, dynamic_product: Path) -> dict[str,Any]:
    result={}
    for owner in ('candidate','oracle'):
        directory=work/(owner+'-root')
        tree=ordinary.execution_tree(root,directory,owner+' worker execution root')
        if owner=='candidate':
            expected=ordinary.readable_tree(ordinary.execution_tree(root,dynamic_product,'supplied dynamic product'))
        else:
            runtime=work/'qualification-oracle/runtime'
            expected={'lib':{'kind':'directory','mode':0o755},
                'lib/ld-musl-x86_64.so.1':{'kind':'file','mode':0o755,'size':runtime.stat().st_size,'sha256':ordinary.digest(runtime)},
                'lib/libc.so':{'kind':'symlink','mode':0o777,'target':'ld-musl-x86_64.so.1'}}
        copied={}
        for destination,source in [(f'consumer-{mode}',('dynamic-' if owner=='candidate' else 'oracle-dynamic-')+mode)
                                  for mode in ('pie','non-pie')]+[(f'worker-{generation}.so',f'{owner}-worker-{generation}.so') for generation in (1,2)]:
            require(destination not in expected,'execution fixture collides with product payload')
            copied[destination]=ordinary.execution_copy(root,work/source,directory/destination,owner+' '+destination)
            file=work/source
            expected[destination]={'kind':'file','mode':stat.S_IMODE(file.stat().st_mode)|0o444,
                                   'size':file.stat().st_size,'sha256':ordinary.digest(file)}
        require(same(ordinary.readable_tree(tree),expected),owner+' execution payload, permissions or roster differs')
        result[owner]={'tree':expected,'copies':copied}
    return result


def prepare_execution_roots(root: Path, work: Path) -> None:
    """Create the private oracle root with its recorded directory mode.

    A setgid output parent propagates that bit to a newly created `lib/`
    directory. The root is a disposable fixture, so clear inheritance before
    sealing its exact 0755 payload rather than weakening the root-mode check.
    """
    oracle_root=work/'oracle-root'
    ordinary.prepare_oracle_execution_root(root,work,oracle_root)
    library=inventory.physical_directory(oracle_root/'lib','oracle execution library directory')
    library.chmod(0o755)
    require(stat.S_IMODE(library.stat().st_mode)==0o755,
            'oracle execution library directory mode differs')


def dso_observations(root: Path, work: Path, inputs: Mapping[str,Any], tools: Mapping[str,Any]) -> dict[str,Any]:
    result={}; product=root/inputs['dynamic_product']['path']
    linker={key:tools['linker']['original'][key] for key in ('path','sha256')}
    for owner in ('candidate','oracle'):
        for generation in (1,2):
            label=f'{owner}-worker-{generation}';binary=work/(label+'.so');obj=work/f'dso-{generation}.o'
            text=lambda suffix:raw_stdout(work,label+'-'+suffix).decode('utf-8')
            facts=inventory.parse_elf_facts(text('header'),text('sections'),text('symbols'),expected_type='DYN')
            programs=text('program');dynamic=text('dynamic')
            require(not re.search(r'^\s*INTERP\b',programs,re.M),'worker DSO unexpectedly has interpreter')
            require(len(re.findall(r'^\s*TLS\b',programs,re.M))==1,'worker DSO TLS segment absent/duplicate')
            require('TEXTREL' not in dynamic,'worker DSO has text relocations')
            require(re.findall(r'\(NEEDED\).*?\[([^\]]+)\]',dynamic)==['libc.so'],'worker DSO foreign dependency')
            require(re.findall(r'\(SONAME\).*?\[([^\]]+)\]',dynamic)==[binary.name],'worker DSO SONAME differs')
            tables={table['name']:table['rows'] for table in facts['symbol_tables']}
            require(set(tables)=={'.dynsym','.symtab'},'worker DSO table roster differs')
            for name in ('prepared_worker_initialized','prepared_worker_zero'):
                rows=[row for row in tables['.dynsym'] if row['name']==name]
                require(len(rows)==1 and rows[0]['type']=='FUNC' and rows[0]['binding']=='GLOBAL'
                        and rows[0]['section_index'].isdigit() and int(rows[0]['section_index'])>0,
                        'typed worker DSO callback missing')
            record={'elf':facts,'binary':ordinary.work_file_identity(root,binary,label),'object':ordinary.work_file_identity(root,obj,label+' object')}
            if owner=='candidate':
                receipt_path=Path(str(binary)+'.crabc-link.json')
                receipt=ordinary.read_json(receipt_path,label+' producer receipt')
                dynamic_receipt.validate(receipt,format=dynamic_links.PRODUCT_FORMAT,label=label,fail=lambda message:require(False,message))
                owned,argv=dynamic_links.expected_base(Path(ordinary.mounted(root,product)),Path(ordinary.mounted(root,binary)),
                    'shared',Path(ordinary.mounted(root,obj)),[],linker['path'])
                expected_inputs=[{'path':str(path),'sha256':ordinary.digest(root/path.relative_to('/workspace'))} for path in owned]
                checks={'mode':'shared','binding':'now','runtime_imports':[],'campaign_complete':False,
                        'output_path':ordinary.mounted(root,binary),'output_sha256':ordinary.digest(binary),
                        'manifest_sha256':inputs['dynamic_product']['manifest_sha256'],'application_dsos':{},
                        'resolved_linker':linker,'input_receipts':expected_inputs,'link_command':argv,
                        'owned_runtime_inputs':sorted(['usr/lib/crti.o','usr/lib/crtn.o','usr/lib/libc.so','usr/lib/libcrabc-builtins.a'])}
                require(same({key:receipt.get(key) for key in checks},checks),label+' installed driver binding differs')
                trace=receipt['link_trace'];archive=ordinary.mounted(root,product/'usr/lib/libcrabc-builtins.a')
                direct={str(path) for path in owned if str(path)!=archive}
                require(type(trace) is list and all(type(line) is str and (line in direct or line==archive
                        or (line.startswith(archive+'(') and line.endswith(')'))) for line in trace)
                        and direct.issubset(set(trace)),label+' link trace differs')
                record['receipt']=ordinary.work_file_identity(root,receipt_path,label+' driver receipt')
            result[label]=record
    return result


def worker_relocations(elf: Elf) -> dict[str, Any]:
    """Reopen the exact installed libc word relocations, not a copied summary.

    This producer currently emits one GLOB_DAT with a zero addend for each
    operation. The loader's source word-kind gate and finite registry remain
    the provider; these imports do not require provider dynsym aliases.
    """
    result={}
    for index,section in enumerate(elf.sections):
        if section[1]!=4:continue
        require(section[9]==24 and section[5]%24==0,'malformed worker RELA table')
        for offset in range(0,section[5],24):
            destination,info,addend=elf.unpack('<QQq',section[4]+offset)
            symbol=elf.symbol_row(section[6],info>>32)
            name=symbol['name']
            if name not in OPERATIONS:continue
            expected={'name':name,'type':'0','binding':'GLOBAL','visibility':'DEFAULT','section':0,
                      'value':0,'size':0,'version_index':1}
            require(name not in result and same(symbol,expected),'worker relocation symbol or uniqueness differs')
            require((info & 0xffffffff)==6 and same(addend,0) and destination%8==0,'worker GLOB_DAT shape differs')
            result[name]={'relocation_section':index,'relocation_row':offset//24,'destination':destination,
                          'symbol_table_section':section[6],'symbol_row':info>>32,'type':6,'addend':addend,'symbol':symbol}
    require(set(result)==set(OPERATIONS),'worker relocation roster differs')
    return result


def retained_artifacts(root: Path, work: Path) -> dict[str,Any]:
    names=(PROBE,DEPENDENCY,'probe.o','dso-1.o','dso-2.o','loader-tests')
    result={name:ordinary.work_file_identity(root,work/name,name) for name in names}
    for name in (PROBE,DEPENDENCY):
        require((work/name).read_bytes()==(root/'compat/x86_64'/name).read_bytes(),name+' source substitution')
    for label in ('object-symbols','dso-1-symbols','dso-2-symbols'):
        result[label]=inventory.parse_elf_symbol_tables(raw_stdout(work,label).decode('utf-8'))
    return result


def unit_diagnostics(work: Path) -> list[dict[str,Any]]:
    result=[]
    raw=ordinary.raw_path(work,'unit-build','stderr').read_text(encoding='utf-8')
    for line in raw.splitlines():
        def pairs(items):
            result={}
            for key,value in items:
                require(key not in result,'duplicate source compiler diagnostic field')
                result[key]=value
            return result
        def invalid_number(value):
            raise PreparedWorkerTlsError('non-JSON source compiler diagnostic number')
        item=json.loads(line,object_pairs_hook=pairs,parse_constant=invalid_number)
        require(type(item) is dict and item.get('$message_type')=='diagnostic' and item.get('level')=='warning',
                'source-test compiler emitted non-warning diagnostics')
        result.append(item)
    return result


def source_copies(root: Path, work: Path, *, capture: bool = False) -> dict[str,Any]:
    result={}
    for relative in SOURCE_PATHS:
        source=root/relative; target=work/'inputs/source'/relative
        if capture:
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source,target)
        require(target.read_bytes()==source.read_bytes(),'retained source drifted: '+relative)
        result[relative]=ordinary.work_file_identity(root,target,'retained '+relative)
    return result


def report_observations(root: Path, work: Path, inputs: Mapping[str,Any], tools: Mapping[str,Any]) -> dict[str,Any]:
    return {'artifacts':retained_artifacts(root,work),
            'worker_relocations':worker_relocations(Elf(root/inputs['dynamic_product']['path']/'usr/lib/libc.so')),
            'executables':ordinary.executable_observations(root,work),
            'dsos':dso_observations(root,work,inputs,tools),
            'runtime':runtime_observations(work),'unit_diagnostics':unit_diagnostics(work),
            'execution_roots':execution_roots(root,work,root/inputs['dynamic_product']['path'])}


def validate_report(root: Path, report_path: Path, *, base_inventory: Path, elf_report: Path,
                    static_preparation: Path, static_product: Path, dynamic_product: Path) -> dict[str,Any]:
    root=Path(root).absolute()
    require(root==ROOT,'public replay root differs from current collector checkout')
    report_path=ordinary.physical_work_path(root,report_path,'prepared worker report')
    require(report_path.name=='report.json','prepared worker report filename differs')
    work=report_path.parent
    before=ordinary.work_file_identity(root,report_path,'worker report')
    record=ordinary.read_json(report_path,'prepared worker report')
    require(type(record) is dict and set(record)=={'schema','target','image','status','source_before','source_after',
            'source_account','source_copies','inputs_before','inputs_after','tools','rust_tools','oracle','oracle_static_inputs',
            'commands','links','observations'},'prepared worker report fields differ')
    require(record['schema']==SCHEMA and record['target']==inventory.TARGET and same(record['status'],STATUS),
            'prepared worker report contract or status differs')
    require(type(record['image']) is str and ordinary.IMAGE_PATTERN.fullmatch(record['image']) is not None,'image identity differs')
    source=inventory.collector_source_seal()
    require(same(record['source_before'],source) and same(record['source_after'],source),'collector source changed')
    binding,paths=admitted(root,dict(base_inventory=base_inventory,elf_report=elf_report,static_preparation=static_preparation,
                                  static_product=static_product,dynamic_product=dynamic_product))
    require(same(record['inputs_before'],binding) and same(record['inputs_after'],binding),'source/product/fact binding changed')
    require(same(record['source_account'],account_source(root)),'source account differs')
    require(same(record['source_copies'],source_copies(root,work)),'retained source roster differs')
    inputs=binding['products']
    tools=ordinary.validate_tool_roster(root,work,inputs,record['tools'])
    rust_tools(work,record['rust_tools'])
    ordinary.validate_oracle_identity(work,record['oracle'])
    ordinary.validate_oracle_static_inputs(work,record['oracle_static_inputs'])
    validate_commands(root,work,inputs,tools,record['rust_tools'],record['commands'])
    ordinary.validate_links(root,work,inputs,tools,record['links'])
    require(same(record['links'],ordinary.candidate_links(root,work,inputs,tools)),'executable links do not reconstruct')
    require(same(record['observations'],report_observations(root,work,inputs,tools)),'worker observations do not reconstruct')
    require(same(before,ordinary.work_file_identity(root,report_path,'worker report')),'report changed during replay')
    require(same(source,inventory.collector_source_seal()),'source changed during replay')
    return record


def fresh_output(root: Path, output: Path, paths: Mapping[str,Path]) -> Path:
    output=ordinary.fresh_output(root,output)
    ordinary.admit_output_disjoint(root,output,paths['static_preparation'],paths['static_product'],paths['dynamic_product'])
    for name in ('base_inventory','elf_report'):
        protected=ordinary.physical_work_path(root,paths[name],name).parent
        require(not output.is_relative_to(protected),'output enters supplied '+name+' receipt')
    return output


def collect(root: Path, output: Path, **paths: Path) -> Path:
    root=Path(root).absolute()
    require(root==ROOT==Path('/workspace'),'native collection requires the current canonical /workspace mount')
    output=fresh_output(root,output,paths)
    require(os.environ.get('LC_ALL')=='C','native capture requires explicit LC_ALL=C')
    require(os.environ.get('RUSTUP_HOME')=='/opt/rustup','native source tests require pinned RUSTUP_HOME')
    image=os.environ.get(ordinary.IMAGE_ENV,'')
    require(ordinary.IMAGE_PATTERN.fullmatch(image) is not None,'native collection requires resolved image identity')
    source=inventory.collector_source_seal()
    before,paths=admitted(root,paths)
    account=account_source(root)
    output.mkdir()
    copies=source_copies(root,output,capture=True)
    for name in (PROBE,DEPENDENCY):shutil.copyfile(root/'compat/x86_64'/name,output/name)
    oracle=ordinary.qualification.capture_oracle(output)
    ordinary.validate_oracle_identity(output,oracle)
    oracle_static=ordinary.capture_oracle_static_inputs(output)
    tools=ordinary.capture_tool_roster(root,output,paths['static_product'],paths['dynamic_product'])
    collector=ordinary.Collector(root,output,paths['static_preparation'],paths['static_product'],paths['dynamic_product'])
    selector_invocation=rust_selector_invocation()
    selector=ordinary.retain_tool_snapshot(output,'worker-selector',ordinary.fixed_image_tool_identity(
        Path(selector_invocation['physical_path']),'Rust selector physical executable'))
    collector.run('rustc-discover',[selector_invocation['path'],'which','rustc'])
    compiler_path=Path(raw_stdout(output,'rustc-discover').decode('utf-8').strip())
    compiler=ordinary.retain_tool_snapshot(output,'worker-compiler',ordinary.fixed_image_tool_identity(compiler_path,'Rust compiler'))
    rust={'selector_invocation':selector_invocation,'selector':selector,'compiler':compiler}
    rust_tools(output,rust)
    plan=command_plan(root,output,before['products'],tools,rust)
    runtime_labels={cell['label'] for cell in runtime_cells()}
    for label,spec in plan.items():
        if label=='rustc-discover' or label in runtime_labels:continue
        collector.run(label,spec['argv'],cwd=root if spec['cwd']=='/workspace' else output)
    # Separate private roots; the supplied, sealed product is never a fixture
    # destination. Its full payload, each DSO and each executable are rejoined.
    prepare_execution_roots(root,output)
    shutil.copytree(paths['dynamic_product'],output/'candidate-root',symlinks=True)
    for owner in ('candidate','oracle'):
        execution=output/(owner+'-root')
        for mode in ('pie','non-pie'):
            prefix='dynamic-' if owner=='candidate' else 'oracle-dynamic-'
            shutil.copy2(output/(prefix+mode),execution/('consumer-'+mode))
        for generation in (1,2):
            shutil.copy2(output/f'{owner}-worker-{generation}.so',execution/f'worker-{generation}.so')
    for cell in runtime_cells():
        collector.run(cell['label'],plan[cell['label']]['argv'],stdout=runtime_stdout(cell))
    after,_=admitted(root,paths)
    require(same(before,after),'supplied source/products changed during collection')
    ordinary.require_live_tool_roster(tools)
    ordinary.require_live_oracle_static_inputs(oracle_static)
    ordinary.qualification.require_live_oracle(output,oracle)
    require(same(rust['selector_invocation'],rust_selector_invocation()),
            'Rust selector invocation changed during collection')
    for role in ('selector','compiler'):
        original=rust[role]['original']
        require(same(original,inventory.file_record(Path(original['path']),logical_path=original['path'])),'Rust tool changed')
    require(same(source,inventory.collector_source_seal()),'collector source changed')
    require(same(copies,source_copies(root,output)),'source copy changed')
    # Retention changes only readability; execution modes were already exact.
    ordinary.static_products.make_retained_evidence_readable(output)
    record={'schema':SCHEMA,'target':inventory.TARGET,'image':image,'status':STATUS,
        'source_before':source,'source_after':inventory.collector_source_seal(),'source_account':account,
        'source_copies':copies,'inputs_before':before,'inputs_after':after,'tools':tools,'rust_tools':rust,
        'oracle':oracle,'oracle_static_inputs':oracle_static,'commands':collector.commands,
        'links':ordinary.candidate_links(root,output,before['products'],tools),
        'observations':report_observations(root,output,before['products'],tools)}
    ordinary.write_new_json(output/'report.json',record)
    validate_report(root,output/'report.json',**paths)
    return output/'report.json'


def parse_cli(argv: list[str] | None = None) -> argparse.Namespace:
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    parser.add_argument('mode',choices=('collect','validate-report'))
    for name in REPORT_INPUTS:
        parser.add_argument('--'+name.replace('_','-'),type=Path,action='append',required=True)
    parser.add_argument('--output',type=Path,action='append')
    parser.add_argument('--report',type=Path,action='append')
    args=parser.parse_args(argv)
    for name in (*REPORT_INPUTS,'output','report'):
        values=getattr(args,name)
        if values is not None and len(values)!=1:parser.error(name+' must occur exactly once')
        setattr(args,name,values[0] if values else None)
    if (args.mode=='collect')!=(args.output is not None) or (args.mode=='validate-report')!=(args.report is not None):
        parser.error('collect requires only --output; validate-report requires only --report')
    return args


def main(argv: list[str] | None = None) -> int:
    args=parse_cli(argv)
    try:
        inputs={name:getattr(args,name) for name in REPORT_INPUTS}
        if args.mode=='collect':collect(ROOT,args.output,**inputs)
        else:validate_report(ROOT,args.report,**inputs)
        print('prepared worker TLS validated: 3 private operations, 55 lifecycle cells, 7 source tests; unqualified')
        return 0
    except (ValueError,OSError,RuntimeError,subprocess.SubprocessError) as error:
        print('ERROR: prepared worker TLS: '+str(error),file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())
