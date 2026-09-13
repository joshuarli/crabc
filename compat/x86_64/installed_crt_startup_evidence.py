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
import struct
import subprocess
import sys
import tomllib
sys.path.insert(0,str(Path(__file__).resolve().parent))
import owned_stdio_alias_contract_reader as substrate
import public_data_ordinary_link_evidence as ordinary
import native_abi_inventory as inventory
import owned_posix_product_evidence as products
import owned_posix_static_products as static_products
import owned_dynamic_qualification as qualification
from loader_debug_abi_evidence import Elf
ROOT=Path(__file__).resolve().parents[2]
SCHEMA='crabc.x86_64-installed-crt-startup/v3'
CONVENTIONAL='__crabc_x86_64_loader_conventional_startup_v1'
HANDOFF='__crabc_x86_64_owned_crt_handoff'
ATTACH='__crabc_x86_loader_tls_runtime_v1_attach'
RECORD='__crabc_x86_loader_tls_runtime_v1_record'
BOOTSTRAP='__crabc_x86_static_tls_bootstrap'
DESCRIPTOR='__crabc_x86_64_loader_tls_runtime_v1'
DESCRIPTOR_DSO='descriptor-rogue-dso.so'
DESCRIPTOR_ENDPOINT='descriptor-dso-endpoint'
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
                    'entry_modes':['kernel','direct'],
                    'rejection':{'status':127,'stdout':'','stderr':'reloc\n'},
                },
            },
            'descriptor_import_required':False,'family_completion':False,'public_support':False}

def validate_contract(value):require(same(value,expected_contract()),'startup contract differs')
def contract(root):
    value=tomllib.loads((root/'compat/x86_64/installed-crt-startup.toml').read_text());validate_contract(value);return value

def require_import(row,kind,binding,visibility):
    expected={'type':kind,'binding':binding,'visibility':visibility,'section_index':'UND','version':None,'version_default':False,'size_bytes':0}
    require(same({k:row.get(k) for k in expected},expected),'startup import metadata differs')

def require_function(row,section,visibility):
    expected={'type':'FUNC','binding':'GLOBAL','visibility':visibility,'version':None,'version_default':False}
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
        p('installed_crt_startup_descriptor_dso.c'),'-o',p(dso['shared_object'])])
    add('descriptor-dso-link',[tool('dynamic_driver'),'--dynamic-pie','--application-dso',
        p(dso['shared_object']),p('normal.o'),'-o',p(dso['endpoint'])])
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
                    'startup descriptor admission stdout differs')

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
    for key in ('static-crt1.o','static-rcrt1.o'):
        item=exact(facts,key,BOOTSTRAP);require_import(item['row'],'NOTYPE','GLOBAL','HIDDEN');result[key][BOOTSTRAP]=item
    bootstrap=exact(facts,'candidate-static',BOOTSTRAP);require_function(bootstrap['row'],bootstrap['section'],'HIDDEN')
    result['candidate-static']={BOOTSTRAP:bootstrap}
    got=exact(facts,'candidate-static','_GLOBAL_OFFSET_TABLE_');require_import(got['row'],'NOTYPE','GLOBAL','DEFAULT');result['candidate-static']['_GLOBAL_OFFSET_TABLE_']=got
    for key in ('static-Scrt1.o','dynamic-crt1.o','dynamic-Scrt1.o'):
        item=exact(facts,key,HANDOFF);require_import(item['row'],'OBJECT','WEAK','DEFAULT');result[key][HANDOFF]=item
    for key in ('dynamic-crt1.o','dynamic-Scrt1.o'):
        item=exact(facts,key,ATTACH);require_import(item['row'],'NOTYPE','GLOBAL','DEFAULT');result[key][ATTACH]=item
    result['dynamic-crabc-dynamic-attach.o']={}
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
# The attach object's record callback is a defined hidden function; treating
# it as another undefined import would erase its actual ownership boundary.
CRT_CALLER_RELOCATIONS={
    'static-crt1.o':{BOOTSTRAP:(4,'0','GLOBAL','HIDDEN',False)},
    'static-rcrt1.o':{BOOTSTRAP:(9,'0','GLOBAL','HIDDEN',False)},
    'static-Scrt1.o':{HANDOFF:(9,'OBJECT','WEAK','DEFAULT',False)},
    'dynamic-crt1.o':{HANDOFF:(9,'OBJECT','WEAK','DEFAULT',False),ATTACH:(4,'0','GLOBAL','DEFAULT',False)},
    'dynamic-Scrt1.o':{HANDOFF:(9,'OBJECT','WEAK','DEFAULT',False),ATTACH:(9,'0','GLOBAL','DEFAULT',False)},
    'dynamic-crabc-dynamic-attach.o':{RECORD:(9,'FUNC','GLOBAL','HIDDEN',True)},
}

def require_crt_caller_relocations(result):
    selected={BOOTSTRAP,HANDOFF,ATTACH,RECORD}
    for role,relations in CRT_CALLER_RELOCATIONS.items():
        rows=result.get(role)
        require(type(rows) is list,'CRT caller relocation object absent: '+role)
        observed=[row for row in rows if row['name'] in selected]
        require(len(observed)==len(relations) and {row['name'] for row in observed}==set(relations),
                'CRT caller relocation roster differs: '+role)
        for row in observed:
            kind,symbol_type,binding,visibility,defined=relations[row['name']]
            expected={'kind':kind,'addend':-4,'symbol_type':symbol_type,'binding':binding,
                      'visibility':visibility,'symbol_value':0}
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

def descriptor_slot(data):
    """Locate the one canonical dynamic descriptor request in one ELF image.

    This parser exists only to derive finite byte mutations from the canonical
    linked main and to check the DSO fixture.  It does not select a provider
    and it cannot create an interpreter: `prepare_roots` executes every copy
    using the selected product loader already sealed by `admit` and `roots`.
    """
    require(type(data) in (bytes,bytearray) and len(data)>=64 and data[:7]==b'\x7fELF\x02\x01\x01',
            'descriptor admission input is not ELF64 little-endian')
    header=struct.unpack_from('<16sHHIQQQIHHHHHH',data,0)
    shoff,shentsize,shnum=header[6],header[11],header[12]
    require(shentsize==64 and shoff+shentsize*shnum<=len(data),'descriptor admission section table differs')
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+index*shentsize) for index in range(shnum)]
    names=[]
    for section_index,section in enumerate(sections):
        if section[1]!=11:continue
        offset,size,entry,strings=section[4],section[5],section[9],section[6]
        require(entry==24 and size%entry==0 and offset+size<=len(data) and strings<len(sections),
                'descriptor admission dynsym layout differs')
        string=sections[strings]
        require(string[4]+string[5]<=len(data),'descriptor admission dynstr layout differs')
        for record in range(offset,offset+size,entry):
            name_offset=struct.unpack_from('<I',data,record)[0]
            require(name_offset<string[5],'descriptor admission name leaves dynstr')
            begin=string[4]+name_offset;end=data.find(b'\0',begin,string[4]+string[5])
            require(end>=0,'descriptor admission name is unterminated')
            if bytes(data[begin:end])==DESCRIPTOR.encode():
                names.append((section_index,record,(record-offset)//entry))
    require(len(names)==1,'descriptor admission dynsym roster differs')
    section_index,symbol,symbol_index=names[0];relocations=[]
    for section in sections:
        if section[1]!=4 or section[6]!=section_index:continue
        offset,size,entry=section[4],section[5],section[9]
        require(entry==24 and size%entry==0 and offset+size<=len(data),'descriptor admission RELA layout differs')
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

def descriptor_admission_observations(root,work):
    policy=expected_contract()['descriptor_handoff']['admission'];source=work/policy['main_case']
    before=source.read_bytes();symbol,relocation,info=descriptor_slot(before);mutations={}
    for label,entry in policy['mutations'].items():
        path=work/('descriptor-'+label);actual=path.read_bytes();expected=bytearray(before)
        if entry['field']=='symbol-info':expected[symbol+4]=entry['value']
        elif entry['field']=='relocation-kind':struct.pack_into('<Q',expected,relocation+8,(info&~0xffffffff)|entry['value'])
        else:struct.pack_into('<q',expected,relocation+16,entry['value'])
        require(actual==expected,'descriptor admission mutation bytes differ: '+label)
        mutations[label]={'identity':ident(root,path),'field':entry['field'],'value':entry['value']}
    dso=work/policy['dso']['shared_object'];endpoint=work/policy['dso']['endpoint']
    dso_symbol,dso_relocation,_=descriptor_slot(dso.read_bytes())
    endpoint_symbol,endpoint_relocation,_=descriptor_slot(endpoint.read_bytes())
    return {'main':ident(root,source),'symbol_file_offset':symbol,'rela_file_offset':relocation,
            'mutations':mutations,
            'dso':{'identity':ident(root,dso),'symbol_file_offset':dso_symbol,'rela_file_offset':dso_relocation},
            'endpoint':{'identity':ident(root,endpoint),'symbol_file_offset':endpoint_symbol,'rela_file_offset':endpoint_relocation},
            'entry_modes':list(policy['entry_modes']),'rejection':copy.deepcopy(policy['rejection'])}

def needed_libraries(path):
    elf=Elf(path);result=[]
    for section in elf.sections:
        if section[1]!=6:continue
        require(section[9]==16 and section[5]%16==0,'malformed dynamic section')
        strings=elf.sections[section[6]]
        require(strings[1]==3 and strings[4]+strings[5]<=len(elf.data),'invalid dynamic string table')
        for index in range(section[5]//16):
            tag,value=elf.unpack('<qQ',section[4]+index*16)
            if tag==0:break
            if tag!=1:continue
            require(value<strings[5],'invalid NEEDED string offset')
            begin=strings[4]+value;end=elf.data.find(b'\0',begin,strings[4]+strings[5])
            require(end>=begin,'unterminated NEEDED string')
            result.append(elf.data[begin:end].decode('ascii'))
    return result

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
            'descriptor_admission':descriptor_admission_observations(root,work),
            'runtime_labels':[cell['label'] for cell in runtime_cells()],
            'limits':{'descriptor_worker_lifecycle':'not requalified by startup receipt',
                      'failed_first_bootstrap':'source contract retained; dedicated runtime rejection receipt not supplied',
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
