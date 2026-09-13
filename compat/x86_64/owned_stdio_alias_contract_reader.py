"""Small readelf-record predicates for the stdio alias contract runner.

ELF relocatable object symbols in different function sections commonly both
have ``st_value == 0``.  An alias assertion must therefore retain the defining
section as well as the address when it distinguishes a real ``.set`` alias
from a forwarding function.
"""

from __future__ import annotations

from typing import NamedTuple


class SymbolRow(NamedTuple):
    member: str
    value: str
    symbol_type: str
    binding: str
    visibility: str
    section: str
    name: str


def same_definition(left: SymbolRow, right: SymbolRow) -> bool:
    """Return whether two symbols designate the same ELF function definition."""

    return (
        left.member == right.member
        and left.value == right.value
        and left.symbol_type == right.symbol_type
        and left.section == right.section
    )

# The sealed supplied-product mode is separate from the historical shell-only
# predicate above. It observes this FILE owner; it never qualifies a family.
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
import native_abi_inventory as inventory
import owned_posix_product_evidence as products
import owned_posix_static_products as static_products
import owned_dynamic_qualification as qualification
import public_data_ordinary_link_evidence as ordinary
import owned_pthread_alias_contract_reader as pthread_reader
from loader_debug_abi_evidence import Elf

SCHEMA = 'crabc.x86_64-owned-stdio-alias-receipt/v1'
STATUS = {'component': 'verified', 'family_completion': False, 'runtime_qualification': False,
          'selection_closure': False, 'public_support': False}
ALIASES = {'fdopen':'__fdopen', 'fgetc_unlocked':'getc_unlocked', 'fputc_unlocked':'putc_unlocked',
           'fread_unlocked':'fread', 'fwrite_unlocked':'fwrite', 'fseeko':'__fseeko', 'ftello':'__ftello',
           'fgetwc_unlocked':'__fgetwc_unlocked', 'getwc_unlocked':'__fgetwc_unlocked',
           'fputwc_unlocked':'__fputwc_unlocked', 'putwc_unlocked':'__fputwc_unlocked',
           'fgetws_unlocked':'fgetws', 'fputws_unlocked':'fputws',
           'getwchar_unlocked':'getwchar', 'putwchar_unlocked':'putwchar'}
HIDDEN = ('__fdopen','__fseeko','__ftello')
PROTECTED = ('__uflow','__overflow')
EXTRA_TOOLS = {'ar':'/usr/bin/ar','oracle_cc':'/usr/bin/gcc','oracle_as':'/usr/bin/as','oracle_ld':'/usr/bin/ld'}
PROBES = {'contract':'owned_stdio_alias_contract_probe.c', 'override':'owned_stdio_alias_override_probe.c',
          'protected':'owned_stdio_protected_runtime_probe.c'}
RUNTIME_SOURCES = ('libc/src/c_abi/x86_64/owned_static_stdio.rs',
                   'libc/src/c_abi/x86_64/owned_wide_stdio.rs',
                   'libc/src/c_abi/x86_64/owned_stdio_extensions.rs',
                   'libc/src/c_abi/x86_64/owned_stdio_backends.rs',
                   'libc/src/c_abi/x86_64/static_c_abi.rs', 'libc/Cargo.toml',
                   'include/stdio.h','include/wchar.h')
COLLECTOR_SOURCES = ('compat/x86_64/owned_stdio_alias_contract_reader.py',
                     'compat/x86_64/run_owned_stdio_alias_contract.sh',
                     'compat/x86_64/owned-stdio-alias-receipt.toml',
                     *(f'compat/x86_64/{x}' for x in PROBES.values()),
                     'compat/x86_64/public_data_ordinary_link_evidence.py',
                     'compat/x86_64/native_abi_inventory.py',
                     'compat/x86_64/owned_posix_product_evidence.py',
                     'compat/x86_64/owned_posix_static_products.py',
                     'compat/x86_64/owned_dynamic_qualification.py',
                     'compat/x86_64/owned_pthread_alias_contract_reader.py',
                     'compat/x86_64/loader_debug_abi_evidence.py')

class StdioAliasEvidenceError(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise StdioAliasEvidenceError(message)

def same(left, right):
    return ordinary.same_json(left, right)

def read(path):
    return ordinary.read_json(path, 'stdio alias receipt')

def ident(root, path):
    return ordinary.work_file_identity(root, path, 'stdio alias artifact')

def require_function_shape(row, binding, visibility):
    require(same({k:row.get(k) for k in ('type','binding','visibility','version','version_default')},
                 {'type':'FUNC','binding':binding,'visibility':visibility,'version':None,'version_default':False}),
            'selected FILE function metadata differs')

def same_physical_definition(left, right):
    for item in (left,right):
        row,section=item['row'],item['section']
        if not (type(row['section_index']) is str and row['section_index'].isdigit()
                and int(row['section_index']) > 0 and section is not None
                and type(section['index']) is int and section['index']==int(row['section_index'])
                and section['type']=='PROGBITS' and 'X' in section['flags']):
            return False
    return (left['member_index']==right['member_index']
            and left['table_section_index']==right['table_section_index']
            and all(left['row'][k]==right['row'][k] for k in ('section_index','value','type')))

def runtime_cells():
    cells=[]
    for owner,modes in (('oracle',('static','dynamic-pie')),('candidate',('static','static-pie','dynamic-pie','dynamic-non-pie'))):
        for mode in modes:
            probes=('protected',) if owner=='oracle' and mode=='dynamic-pie' else ('contract','override','protected') if mode.startswith('dynamic') else ('contract','override')
            for probe in probes:
                for entry in (('kernel','direct') if mode.startswith('dynamic') else ('process',)):
                    cells.append({'owner':owner,'mode':mode,'probe':probe,'entry':entry,
                                  'label':f'{owner}-{mode}-{probe}-{entry}'})
    return cells

def transcript(probe):
    return {'contract':b'owned-stdio-alias-contract-ok\n','override':b'owned-stdio-alias-override-ok\n',
            'protected':b'owned-stdio-protected-runtime-ok\n'}[probe]

def validate_runtime_streams(streams):
    cells=runtime_cells()
    require(set(streams)=={x['label'] for x in cells},'runtime stream roster differs')
    for cell in cells:
        require(streams[cell['label']]=={'stdout':transcript(cell['probe']),'stderr':b'','status':b'0\n'},
                'runtime/oracle transcript differs: '+cell['label'])

def fresh_output(root, output, inputs):
    try:
        output=ordinary.fresh_output(root,output)
        for path in inputs:
            path=ordinary.physical_work_path(root,path,'supplied input')
            base=path if path.is_dir() else path.parent
            require(not output.is_relative_to(base) and not base.is_relative_to(output),'output overlaps supplied input')
        return output
    except ordinary.PublicDataEvidenceError as error:
        raise StdioAliasEvidenceError(str(error)) from error

def contract(root):
    value=tomllib.loads((root/'compat/x86_64/owned-stdio-alias-receipt.toml').read_text())
    require(same(value,{'schema':SCHEMA,'aliases':ALIASES,'hidden':list(HIDDEN),'protected':list(PROTECTED),
                        'family_completion':False,'public_support':False}),'stdio alias source contract differs')
    return value

def source_account(root, revision, work, capture=False):
    require(type(revision) is str and re.fullmatch('[0-9a-f]{40}',revision),'invalid selected revision')
    records={}
    joined='\n'.join((root/p).read_text() for p in RUNTIME_SOURCES)
    for alias,target in ALIASES.items():
        require(f'.set {alias}, {target}' in joined,'named source alias differs: '+alias)
    for name in HIDDEN:require('.hidden '+name in joined,'source hidden boundary differs')
    for name in PROTECTED:require('.protected '+name in joined,'source protected boundary differs')
    for path in RUNTIME_SOURCES:
        selected=subprocess.check_output(['git','show',f'{revision}:{path}'],cwd=root)
        # Runtime and header source may be historical. This component requires
        # its named FILE owner to be byte-identical to that selected producer.
        require((root/path).read_bytes()==selected,'selected FILE source changed: '+path)
        dest=work/'source-selected'/path
        if capture:
            dest.parent.mkdir(parents=True,exist_ok=True); dest.write_bytes(selected)
        require(dest.read_bytes()==selected,'retained selected source changed: '+path)
        records[path]=ident(root,dest)
    return records

def collector_source(root,work,capture=False):
    records={}
    for path in COLLECTOR_SOURCES:
        dest=work/'source-collector'/path
        if capture:
            dest.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(root/path,dest)
        require(dest.read_bytes()==(root/path).read_bytes(),'collector source changed: '+path)
        records[path]=ident(root,dest)
    return records

def admitted(root, preparation, static, dynamic, historical):
    paths=[ordinary.physical_work_path(root,p,'supplied FILE input') for p in (preparation,static,dynamic,historical)]
    preparation,static,dynamic,historical=paths
    require(preparation.name=='preparation.json' and static==preparation.parent/'products/primary',
            'static product is not the supplied preparation primary')
    prep=read(preparation); history=read(historical)
    require(set(prep)=={'archives','pins','products','schema','source','source_seals','status','steps','work'}
            and prep['schema']==static_products.SCHEMA and prep['status']=='prepared-unqualified',
            'historical static preparation shape differs')
    source=prep['source']
    require(set(source)=={'revision','content_sha256'} and type(source['content_sha256']) is str
            and re.fullmatch('[0-9a-f]{64}',source['content_sha256']), 'selected source fields differ')
    for label in ('source-before.json','source-after.json'):
        require(same(read(preparation.parent/label),source),'historical preparation source seal differs')
    static_manifest,_=products._validate_static_product(static)
    dynamic_manifest,dynamic_files=products._validate_dynamic_product(dynamic)
    state=read(dynamic/'share/crabc/dynamic-product-state.json')
    pthread_reader._validate_dynamic_materialization_state(state,source['content_sha256'],dynamic_files,'selected FILE dynamic state')
    require(same(static_products.tree_identity(static),prep['products']['primary']['tree']),
            'selected static payload differs from historical preparation')
    require(ordinary.digest(static_manifest)==prep['products']['primary']['manifest']['sha256'],
            'historical static manifest differs')
    require(history.get('schema')=='crabc.x86_64-native-abi-elf-facts/v1'
            and same(history.get('status'),{'classification':'measurement-only-no-abi-selection-or-promotion',
                     'family_completion':False,'promotion_ready':False,'public_support':False}),
            'historical complete facts status differs')
    # This is a provenance cross-check, not a current-collector replay of the
    # historical inventory. Fresh raw rows below independently observe these bytes.
    build=history['base_inventory']['candidate_build']
    require(build['revision']==source['revision'] and build['source_content_sha256']==source['content_sha256'],
            'historical facts product source differs')
    for key,path in (('candidate-static',static/'usr/lib/libc.a'),('candidate-shared',dynamic/'usr/lib/libc.so')):
        expected=history['artifacts'][key]['identity']
        require(type(expected.get('size')) is int and expected['sha256']==ordinary.digest(path)
                and expected['size']==path.stat().st_size,'historical ELF artifact bytes differ: '+key)
    commands=read(static/'share/crabc/build.commands.json')['commands']['libc']
    shared=read(dynamic/'share/crabc/libc-shared.provenance.json')['libc_command']
    for argv,feature in ((commands,'x86-owned-static-runtime'),(shared,'x86-owned-dynamic-runtime')):
        require(type(argv) is list and argv.count('--features')==1
                and argv[argv.index('--features')+1]==feature, 'installed FILE feature selection differs')
    return {'selected_source':source,'producer_commands':{'static':commands,'shared':shared},'preparation':ident(root,preparation),'historical_facts':ident(root,historical),
            'static_preparation':{'primary':{'path':static.relative_to(root).as_posix(),'manifest':ident(root,static_manifest)}},
            'dynamic_product':{'path':dynamic.relative_to(root).as_posix(),'manifest':ident(root,dynamic_manifest)},
            'static_tree':ordinary.execution_tree(root,static,'static payload'),
            'dynamic_tree':ordinary.execution_tree(root,dynamic,'dynamic payload'),
            'state':ident(root,dynamic/'share/crabc/dynamic-product-state.json')}

def elf_paths(root,work,inputs):
    return {'candidate-static':root/inputs['static_preparation']['primary']['path']/'usr/lib/libc.a',
            'candidate-shared':root/inputs['dynamic_product']['path']/'usr/lib/libc.so',
            'reference-static':work/'inputs/oracle-static/libc_a',
            'reference-shared':work/'qualification-oracle/runtime'}

def binaries():
    return sorted({f"{x['owner']}-{x['mode']}-{x['probe']}" for x in runtime_cells()})

def plan(root,work,inputs,tools):
    mount=lambda p:ordinary.mounted(root,p)
    path=lambda n:mount(work/n)
    tool=lambda n:tools[n]['original']['path']
    specs=[]
    def add(label,argv,cwd='/workspace'):specs.append({'label':label,'argv':argv,'cwd':cwd})
    for probe in PROBES:
        add(probe+'-compile',[tool('dynamic_driver'),'--dynamic-pie','-std=c11','-fno-builtin','-fno-stack-protector','-pthread','-c',path(PROBES[probe]),'-o',path(probe+'.o')])
        for flag,suffix in (('-hW','header'),('-SW','sections'),('-sW','symbols')):
            add(probe+'-object-'+suffix,[tool('readelf'),flag,path(probe+'.o')])
    for name in binaries():
        owner,mode,probe=name.split('-',1)[0],name.rsplit('-',1)[0].split('-',1)[1],name.rsplit('-',1)[1]
        obj=path(probe+'.o')
        if owner=='oracle':
            flags=['-static','-fno-pie','-no-pie'] if mode=='static' else ['-Wl,--export-dynamic','-Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1']
            add(name+'-link',[tool('oracle_wrapper'),*flags,obj,'-Wl,-Map,'+path(name+'.map'),'-ldl','-pthread','-o',path(name)])
        elif mode in ('static','static-pie'):
            add(name+'-link',[tool('static_driver'),'-'+mode,'--link-receipt',name+'.link.json',obj,'-o',path(name)],mount(work))
        else:
            add(name+'-link',[tool('dynamic_driver'),'--'+mode,*(['-pthread'] if probe=='contract' else ['-rdynamic']),obj,'-o',path(name)])
        for flag,suffix in (('-hW','header'),('-lW','program'),('-sW','symbols')):
            add(name+'-'+suffix,[tool('readelf'),flag,path(name)])
    for key,p in elf_paths(root,work,inputs).items():
        if key.endswith('static'):add(key+'-members',[tool('ar'),'t',mount(p)])
        for flag,suffix in (('-hW','header'),('-SW','sections'),('-sW','symbols')):
            add(key+'-'+suffix,[tool('readelf'),flag,mount(p)])
    for cell in runtime_cells():
        name=f"{cell['owner']}-{cell['mode']}-{cell['probe']}"
        argv=[tool('env'),'-i']
        if cell['entry']=='process':
            argv.append(path(name))
            if cell['probe']=='override':argv.append(path('scratch-'+name))
        else:
            argv += [ordinary.validate_chroot_invocation(tools['chroot']['invocation'],tools['chroot']['original']),path(cell['owner']+'-root')]
            if cell['entry']=='direct':argv.append('/lib/ld-musl-x86_64.so.1' if cell['owner']=='oracle' else '/lib/ld-crabc-x86_64.so.1')
            argv.append('/'+name)
            if cell['probe']=='override':argv.append('/scratch-'+name)
        add(cell['label'],argv)
    return specs

def validate_commands(root,work,inputs,tools,commands):
    expected=plan(root,work,inputs,tools)
    require(type(commands) is list and len(commands)==len(expected),'command roster differs')
    for command,spec in zip(commands,expected):
        require(set(command)=={'label','argv','cwd','outcome','command','stdout','stderr','status'},'command fields differ')
        require(same({k:command[k] for k in spec},spec) and command['outcome']=='ok','command plan differs')
        for field,suffix in (('command','command.json'),('stdout','stdout'),('stderr','stderr'),('status','status')):
            p=ordinary.resolve_work_identity(root,command[field],'stdio raw '+field)
            require(p==ordinary.raw_path(work,spec['label'],suffix),'raw command path differs')
        require(same(ordinary.read_json(ordinary.raw_path(work,spec['label'],'command.json'),'command',list),spec['argv']), 'retained argv differs')
        require(ordinary.raw_path(work,spec['label'],'status').read_bytes()==b'0\n','command status differs')
        require(ordinary.raw_path(work,spec['label'],'stderr').read_bytes()==b'','command diagnostic is not accounted')

def raw(work,label):return ordinary.raw_path(work,label,'stdout').read_text()

def project_facts(root,work,inputs):
    result={}
    for key,path in elf_paths(root,work,inputs).items():
        args=[raw(work,key+'-'+part) for part in ('header','sections','symbols')]
        if key.endswith('static'):
            result[key]=inventory.parse_archive_elf_facts(*args,raw(work,key+'-members').splitlines(),expected_archive=ordinary.mounted(root,path))
        else:result[key]=inventory.parse_elf_facts(*args,expected_type='DYN')
    return result

def occurrences(facts,key,table_name):
    members=facts[key] if key.endswith('static') else [facts[key]]
    rows=[]
    for member in members:
        sections=member['sections']
        for table in member['symbol_tables']:
            if table['name']!=table_name:continue
            for row in table['rows']:
                ndx=row['section_index']; section=sections[int(ndx)] if ndx.isdigit() and 0<int(ndx)<len(sections) else None
                rows.append({'member_index':member.get('member_index'),'member':member.get('member'),
                             'member_occurrence':member.get('member_occurrence'),
                             'table_section_index':table['section_index'],'row':row,'section':section})
    return rows

def account_aliases(facts):
    results={}
    for key in ('candidate-static','reference-static','candidate-shared','reference-shared'):
        rows=occurrences(facts,key,'.symtab')
        def one(name):
            selected=[x for x in rows if x['row']['name']==name and x['row']['section_index']!='UND']
            require(len(selected)==1,'missing/ambiguous FILE definition: '+key+'/'+name)
            require(same_physical_definition(selected[0],selected[0]),'FILE definition is not in a real executable section')
            return selected[0]
        pairs={}
        for alias,target in ALIASES.items():
            left,right=one(alias),one(target)
            require_function_shape(left['row'],'WEAK','DEFAULT')
            if target in HIDDEN:
                require_function_shape(right['row'],'GLOBAL' if key.endswith('static') else 'LOCAL',
                                       'HIDDEN' if key.endswith('static') or key=='candidate-shared' else 'DEFAULT')
            else:require_function_shape(right['row'],'GLOBAL','DEFAULT')
            require(same_physical_definition(left,right),'named FILE alias crosses definition domain: '+alias)
            pairs[alias]={'target':target,'alias_occurrence':left,'target_occurrence':right}
        protected={name:one(name) for name in PROTECTED}
        for value in protected.values():require_function_shape(value['row'],'GLOBAL','PROTECTED')
        if key.endswith('shared'):
            dyn=occurrences(facts,key,'.dynsym')
            require(not any(x['row']['name'] in HIDDEN for x in dyn),'hidden FILE body leaked to dynsym')
            for name in set(ALIASES)|set(ALIASES.values())|set(PROTECTED)-set(HIDDEN):
                if name in HIDDEN:continue
                matches=[x for x in dyn if x['row']['name']==name]
                require(len(matches)==1,'public FILE dynsym roster differs: '+name)
                dynamic_definition=matches[0]
                require_function_shape(dynamic_definition['row'],'WEAK' if name in ALIASES else 'GLOBAL',
                                       'PROTECTED' if name in PROTECTED else 'DEFAULT')
                require(same_physical_definition(dynamic_definition,dynamic_definition),
                        'public FILE dynsym is not a defined executable function: '+name)
                # .dynsym and .symtab are separate tables in this one DSO.
                # Their public definition must identify the same actual body;
                # matching names/binding alone admits UND or another address.
                definition=one(name)
                placement=('section_index','value','type','size_bytes')
                require(type(dynamic_definition['row'].get('size_bytes')) is int
                        and same({field:dynamic_definition['row'].get(field) for field in placement},
                                 {field:definition['row'].get(field) for field in placement}),
                        'public FILE dynsym differs from its symtab definition: '+name)
        results[key]={'aliases':pairs,'protected':protected}
    return results

def product_links(root,work,inputs,tools):
    result={}
    linker={k:tools['linker']['original'][k] for k in ('path','sha256')}
    for name in binaries():
        if not name.startswith('candidate-'):continue
        mode=name[len('candidate-'):].rsplit('-',1)[0]; probe=name.rsplit('-',1)[1]
        static=mode in ('static','static-pie')
        product=root/(inputs['static_preparation']['primary']['path'] if static else inputs['dynamic_product']['path'])
        receipt=work/(name+('.link.json' if static else '.crabc-link.json'))
        value=products.validate_retained_link(root,'/workspace',product,work/(probe+'.o'),work/name,receipt,
                                             mode if static else mode.removeprefix('dynamic-'),linker,
                                             export_dynamic=not static and probe in ('override','protected'))
        result[name]={'receipt':ident(root,receipt),'workload':ident(root,work/(probe+'.o')),
                      'executable':ident(root,work/name),'validated':{k:v for k,v in value.items() if k!='product'}}
    return result

def prepare_execution_roots(work,dynamic):
    shutil.copytree(dynamic,work/'candidate-root',symlinks=True)
    (work/'oracle-root/lib').mkdir(parents=True)
    # The raw-input retention helper may select a restrictive umask. Execution
    # directory access is an explicit root layout contract, not ambient state.
    (work/'oracle-root/lib').chmod(0o755)
    shutil.copy2(work/'qualification-oracle/runtime',work/'oracle-root/lib/ld-musl-x86_64.so.1')
    (work/'oracle-root/lib/ld-musl-x86_64.so.1').chmod(0o755)
    (work/'oracle-root/lib/libc.so').symlink_to('ld-musl-x86_64.so.1')
    for name in binaries():
        if '-dynamic-' in name:shutil.copy2(work/name,work/(name.split('-',1)[0]+'-root')/name)

def execution_roots(root,work,inputs):
    result={}
    for owner in ('candidate','oracle'):
        directory=work/(owner+'-root'); tree=ordinary.execution_tree(root,directory,'FILE execution root')
        expected=dict(inputs['dynamic_tree']) if owner=='candidate' else {
            'lib':{'kind':'directory','mode':0o755},
            'lib/ld-musl-x86_64.so.1':{'kind':'file','mode':0o755,'size':(work/'qualification-oracle/runtime').stat().st_size,'sha256':ordinary.digest(work/'qualification-oracle/runtime')},
            'lib/libc.so':{'kind':'symlink','mode':0o777,'target':'ld-musl-x86_64.so.1'}}
        for name in binaries():
            if name.startswith(owner+'-dynamic'):
                p=work/name; expected[name]={'kind':'file','mode':p.stat().st_mode&0o777,'size':p.stat().st_size,'sha256':ordinary.digest(p)}
        require(same(tree,expected),'execution root bytes/modes/roster differ: '+owner)
        result[owner]=tree
    return result

def observations(root,work,inputs,tools):
    facts=project_facts(root,work,inputs)
    aliases=account_aliases(facts)
    streams={x['label']:{k:ordinary.raw_path(work,x['label'],k).read_bytes() for k in ('stdout','stderr','status')} for x in runtime_cells()}
    validate_runtime_streams(streams)
    objects={}
    for probe in PROBES:
        obj=inventory.parse_elf_facts(*(raw(work,probe+'-object-'+suffix) for suffix in ('header','sections','symbols')),expected_type='REL')
        objects[probe]={'identity':ident(root,work/(probe+'.o')),'facts':obj}
    elfs={}
    for name in binaries():
        # The owning installed linker reader independently checks candidate
        # ET_EXEC/PIE/interpreter/needed rules from the actual bytes.
        mode=name.split('-',1)[1].rsplit('-',1)[0]
        products._audit_elf(work/name,mode if mode in ('static','static-pie') else mode.removeprefix('dynamic-')) if name.startswith('candidate-') else None
        elf=Elf(work/name)
        require(elf.elf_type==(3 if mode in ('static-pie','dynamic-pie') else 2),'actual ELF type differs: '+name)
        interps=[elf.data[p[2]:p[2]+p[5]] for p in elf.programs if p[0]==3]
        expected_interp=[] if mode in ('static','static-pie') else [(b'/lib/ld-crabc-x86_64.so.1\0' if name.startswith('candidate-') else b'/lib/ld-musl-x86_64.so.1\0')]
        require(interps==expected_interp,'actual ELF interpreter differs: '+name)
        if name.startswith('candidate-dynamic-') and name.endswith(('-override','-protected')):
            for collision in (('fdopen','fseeko','ftello') if name.endswith('-override') else PROTECTED):
                value=elf.symbol(collision)
                require(value['type']=='FUNC' and value['binding']=='GLOBAL' and value['visibility']=='DEFAULT',
                        'application strong override metadata differs: '+collision)
        header=raw(work,name+'-header')
        expected='DYN' if mode in ('static-pie','dynamic-pie') else 'EXEC'
        require(re.search(r'Type:\s+'+expected+r'\b',header) is not None,'linked ELF mode differs: '+name)
        tables=inventory.parse_elf_symbol_tables(raw(work,name+'-symbols'))
        elfs[name]={'identity':ident(root,work/name),'tables':tables,'header':header,'program':raw(work,name+'-program')}
    return {'complete_elf_facts':facts,'aliases':aliases,'objects':objects,'executables':elfs,
            'candidate_links':product_links(root,work,inputs,tools),'execution_roots':execution_roots(root,work,inputs),
            'runtime_labels':[x['label'] for x in runtime_cells()]}

def retained_files(root,work):
    return {p.relative_to(work).as_posix():ident(root,p) for p in sorted(work.rglob('*'))
            if p.is_file() and not p.is_symlink() and p!=work/'report.json'
            and not p.relative_to(work).parts[0].endswith('-root')}

def collect(root,output,preparation,static,dynamic,historical):
    output=fresh_output(root,output,[preparation,static,dynamic,historical])
    require(sys.platform=='linux' and os.uname().machine=='x86_64','native x86-64 collection required')
    require(os.environ.get('LC_ALL')=='C','C locale collection required')
    image=os.environ.get(ordinary.IMAGE_ENV,'')
    require(ordinary.IMAGE_PATTERN.fullmatch(image) is not None,'pinned image identity is required')
    source=static_products.source_identity(root); policy=contract(root)
    before=admitted(root,preparation,static,dynamic,historical)
    output.mkdir(parents=True)
    try:
        selected=source_account(root,before['selected_source']['revision'],output,True)
        collecting=collector_source(root,output,True)
        oracle=qualification.capture_oracle(output); qualification.validate_oracle(output,oracle)
        oracle_static=ordinary.capture_oracle_static_inputs(output)
        tools=ordinary.capture_tool_roster(root,output,static,dynamic)
        for role,path in EXTRA_TOOLS.items():
            tools[role]=ordinary.retain_tool_snapshot(output,role,ordinary.fixed_image_tool_identity(Path(path),role))
        for probe,path in PROBES.items():shutil.copy2(root/'compat/x86_64'/path,output/path)
        runner=ordinary.Collector(root,output,preparation,static,dynamic)
        specs=plan(root,output,before,tools)
        for spec in specs:
            if spec['label']==runtime_cells()[0]['label']:
                prepare_execution_roots(output,dynamic)
                execution_roots(root,output,before)
            runner.run(spec['label'],spec['argv'],cwd=root if spec['cwd']=='/workspace' else output,timeout_seconds=45)
        after=admitted(root,preparation,static,dynamic,historical)
        require(same(before,after),'supplied FILE inputs changed during collection')
        require(same(source,static_products.source_identity(root)),'collector source changed during collection')
        ordinary.require_live_tool_roster({k:v for k,v in tools.items() if k not in EXTRA_TOOLS})
        ordinary.require_live_oracle_static_inputs(oracle_static)
        for role,path in EXTRA_TOOLS.items():
            require(same({k:tools[role]['original'][k] for k in ('path','sha256','mode')},ordinary.fixed_image_tool_identity(Path(path),role)),role+' changed')
        ordinary.write_new_json(output/'report.json',{'schema':SCHEMA,'status':STATUS,'image':image,'contract':policy,
            'collector_source':source,'collector_files':collecting,'selected_files':selected,'inputs_before':before,'inputs_after':after,
            'oracle':oracle,'oracle_static':oracle_static,'tools':tools,'commands':runner.commands,
            'observations':observations(root,output,before,tools),'files':retained_files(root,output)})
    finally:
        static_products.make_retained_evidence_readable(output)
    validate_report(root,output/'report.json')
    return output/'report.json'

def validate_report(root,report_path):
    report_path=ordinary.physical_work_path(root,report_path,'FILE receipt'); work=report_path.parent
    report=read(report_path)
    require(set(report)=={'schema','status','image','contract','collector_source','collector_files','selected_files','inputs_before','inputs_after','oracle','oracle_static','tools','commands','observations','files'},'FILE receipt fields differ')
    require(report['schema']==SCHEMA and same(report['status'],STATUS),'FILE receipt status differs')
    require(same(report['contract'],contract(root)),'FILE receipt contract differs')
    require(ordinary.IMAGE_PATTERN.fullmatch(report['image']) is not None,'pinned image differs')
    require(same(report['collector_source'],static_products.source_identity(root)),'current collector source differs')
    inputs=report['inputs_before']
    preparation=ordinary.resolve_work_identity(root,inputs['preparation'],'preparation')
    historical=ordinary.resolve_work_identity(root,inputs['historical_facts'],'historical facts')
    static=root/inputs['static_preparation']['primary']['path']; dynamic=root/inputs['dynamic_product']['path']
    observed=admitted(root,preparation,static,dynamic,historical)
    require(same(inputs,observed) and same(report['inputs_after'],observed),'supplied FILE inputs differ')
    require(same(report['selected_files'],source_account(root,inputs['selected_source']['revision'],work)),'selected source copies differ')
    require(same(report['collector_files'],collector_source(root,work)),'collector copies differ')
    qualification.validate_oracle(work,report['oracle']); ordinary.validate_oracle_static_inputs(work,report['oracle_static'])
    tools=report['tools']; require(type(tools) is dict and set(tools)==set(ordinary.TOOL_ROLES)|set(EXTRA_TOOLS),'tool roster differs')
    ordinary.validate_tool_roster(root,work,inputs,{k:v for k,v in tools.items() if k not in EXTRA_TOOLS})
    for role,path in EXTRA_TOOLS.items():
        inventory._validate_snapshot(work,tools[role],role,expected_original_path=path,expected_retained_path='inputs/tools/'+role)
    validate_commands(root,work,inputs,tools,report['commands'])
    require(same(report['files'],retained_files(root,work)),'retained FILE artifact roster or bytes differ')
    require(same(report['observations'],observations(root,work,inputs,tools)),'FILE observations do not reconstruct')
    require(same(inputs,admitted(root,preparation,static,dynamic,historical)),'FILE inputs changed during replay')
    return report

def main(argv=None):
    args=list(sys.argv[1:] if argv is None else argv)
    options=[arg.split('=',1)[0] for arg in args if arg.startswith('--')]
    require(len(options)==len(set(options)),'duplicate FILE option')
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    parser.add_argument('mode',choices=('collect','validate-report'))
    for name in ('output','report','static-preparation','static-product','dynamic-product','historical-facts'):
        parser.add_argument('--'+name,type=Path)
    ns=parser.parse_args(args)
    paths=[ns.static_preparation,ns.static_product,ns.dynamic_product,ns.historical_facts]
    if ns.mode=='collect':
        require(ns.output is not None and ns.report is None and all(p is not None for p in paths),'collect needs four supplied inputs and fresh output')
        path=collect(ROOT,ns.output,*paths)
    else:
        require(ns.report is not None and ns.output is None and all(p is None for p in paths),'replay accepts only report')
        validate_report(ROOT,ns.report); path=ns.report
    print(json.dumps({'schema':SCHEMA,'report':str(path),'sha256':ordinary.digest(path),'status':STATUS},sort_keys=True))
    return 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except (StdioAliasEvidenceError,ordinary.PublicDataEvidenceError,inventory.InventoryError,
            products.ProductEvidenceError,static_products.PreparationError,pthread_reader.ReceiptError,
            OSError,ValueError,KeyError) as error:
        print('ERROR: stdio alias receipt: '+str(error),file=sys.stderr); raise SystemExit(2)
