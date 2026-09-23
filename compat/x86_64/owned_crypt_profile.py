#!/usr/bin/env python3
"""Retain and reconstruct the installed crypt ABI and finite vector companion.

The original libc-test unit remains unchanged. This additional observer proves
actual nonnull output for every pinned vector and is never an upstream pass.
"""
from __future__ import annotations

import argparse
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

import owned_posix_family_execution as family
import owned_posix_native_observations as native
import owned_posix_native_dispositions as dispositions
import owned_crypt_runtime_evidence as copies
import owned_dynamic_receipt as receipt_contract
import owned_posix_product_evidence as products

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 'crabc.x86_64-owned-crypt-profile/v1'
ABI_SOURCE = 'compat/x86_64/libc_crypt_probe.c'
SOURCES = (*dispositions.PROFILE_SOURCES, ABI_SOURCE,
    'compat/x86_64/run_owned_crypt_runtime.sh', 'compat/x86_64/owned_crypt_profile.py',
    'compat/x86_64/owned_crypt_runtime_evidence.py', 'compat/x86_64/owned_dynamic_receipt.py',
    'compat/x86_64/owned_posix_product_evidence.py',
    'compat/x86_64/owned_posix_native_observations.py', 'compat/x86_64/owned_posix_family_execution.py',
    'compat/x86_64/owned_posix_static_products.py', 'compat/x86_64/owned_libc_test.py',
    'compat/x86_64/run_qualification_manifest.py', 'compat/x86_64/owned_dynamic_qualification.py',
    'compat/x86_64/crabc_cc_static.py', 'compat/x86_64/crabc_cc_owned_dynamic.py',
    'compat/upstreams.toml', 'docker/x86_64-musl-oracle-gcc')
ENVIRONMENT = {'LC_ALL': 'C', 'PATH': '/usr/bin:/bin', 'SOURCE_DATE_EPOCH': '1', 'TZ': 'UTC'}
RUNTIME_ENVIRONMENT = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'}
MODES = dispositions.DYNAMIC_MODES
ORACLE_CC = '/usr/local/bin/crabc-x86_64-musl-gcc'
INTERPRETER = '/lib/ld-crabc-x86_64.so.1'
ABI_FLAGS = ['-std=c11', '-D_GNU_SOURCE', '-DCRABC_X86_CRYPT_CANDIDATE', '-fno-builtin', '-fno-stack-protector']
VECTOR_FLAGS = ['-std=c11', '-D_GNU_SOURCE', '-fno-builtin', '-fno-stack-protector']


class CryptProfileError(RuntimeError):
    """The complete installed crypt companion is absent or changed."""


same, require, keys = native.same, native.require, native.keys


def generated_observer(root):
    rows = dispositions.crypt_vectors(root)
    table = ''.join(f'    /* upstream vector {r["ordinal"]:02d}, source line {r["line"]} */\n'
                    f'    {{ {r["ordinal"]}, {r["line"]}, {r["key_literal"]}, "{r["setting"]}", '
                    f'"{r["candidate"]}", "{r["oracle"]}" }},\n' for r in rows)
    return ('''/* Generated observation fixture; original crypt.c is reference data.
 * Vector literals are from the adjacent MIT-licensed pinned libc-test source.
 * This program reports actual results and does not implement cryptography. */
#include <crypt.h>
#include <stdio.h>
#include <string.h>
struct vector { unsigned ordinal, line; const char *key, *setting, *candidate, *oracle; };
static const struct vector vectors[] = {
''' + table + '''};
int main(int argc, char **argv)
{
    int oracle, failed = 0;
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "oracle")) oracle = 1;
    else if (!strcmp(argv[1], "candidate")) oracle = 0;
    else return 2;
    for (unsigned i = 0; i < sizeof vectors / sizeof vectors[0]; i++) {
        const char *result = crypt(vectors[i].key, vectors[i].setting);
        const char *expected = oracle ? vectors[i].oracle : vectors[i].candidate;
        printf("vector %02u line=%u nonnull=%d output=", vectors[i].ordinal, vectors[i].line, result != NULL);
        if (result == NULL) failed = 1;
        else {
            unsigned n = 0;
            while (n < 256 && result[n]) {
                printf("%02x", (unsigned char)result[n]);
                n++;
            }
            if (n == 256 || strcmp(result, expected)) failed = 1;
        }
        putchar('\\n');
    }
    return failed;
}
''').encode()


def elf_facts(path):
    """Read only x86-64 little-endian ELF facts needed by this companion.

    Section/program bounds are checked before reading. No host readelf process,
    architecture substitution or target execution participates in validation.
    """
    data = native.read_bytes(path)
    def part(offset, size):
        require(type(offset) is int and type(size) is int and 0 <= offset <= len(data)
                and 0 <= size <= len(data) - offset, 'crypt ELF table escapes physical bytes')
        return data[offset:offset+size]
    def unpack(fmt, offset):
        return struct.unpack(fmt, part(offset, struct.calcsize(fmt)))
    require(part(0, 7) == b'\x7fELF\x02\x01\x01', 'crypt artifact is not ELF64 little-endian')
    header = unpack('<HHIQQQIHHHHHH', 16)
    kind, machine, version, _, phoff, shoff, _, ehsize, phsize, phnum, shsize, shnum, _ = header
    require(machine == 62 and version == 1 and ehsize == 64 and (phnum == 0 or phsize == 56)
            and (shnum == 0 or shsize == 64), 'crypt ELF architecture or header contract differs')
    require(phnum < 65536 and shnum < 65536, 'crypt ELF table count differs')
    def cstring(blob, offset):
        require(0 <= offset < len(blob) and b'\0' in blob[offset:], 'crypt ELF string lacks terminator')
        return blob[offset:blob.index(b'\0', offset)].decode('ascii')
    interpreters = []
    for index in range(phnum):
        ptype, _, offset, _, _, size, _, _ = unpack('<IIQQQQQQ', phoff + index*phsize)
        if ptype == 3:
            blob = part(offset, size)
            require(blob.endswith(b'\0') and blob.count(b'\0') == 1, 'crypt ELF interpreter is malformed')
            interpreters.append(blob[:-1].decode('ascii'))
    sections = [unpack('<IIQQQQIIQQ', shoff + index*shsize) for index in range(shnum)]
    needed, runpaths, rpaths, tags, symbols, relocations = [], [], [], [], [], []
    for section in sections:
        _, stype, _, _, offset, size, link, _, _, entry = section
        if stype in (6, 11):
            require(link < len(sections), 'crypt ELF linked string table is missing')
            strings = part(sections[link][4], sections[link][5])
            expected_size = 16 if stype == 6 else 24
            require(entry == expected_size and size % entry == 0, 'crypt ELF entry size differs')
            for pos in range(offset, offset+size, entry):
                if stype == 6:
                    tag, value = unpack('<qQ', pos)
                    tags.append(tag)
                    if tag in (1, 15, 29):
                        {1: needed, 15: rpaths, 29: runpaths}[tag].append(cstring(strings, value))
                else:
                    name, info, other, index, value, length = unpack('<IBBHQQ', pos)
                    if name:
                        symbols.append({'name': cstring(strings, name), 'binding': info >> 4,
                                        'type': info & 15, 'visibility': other & 3, 'defined': index != 0})
        elif stype in (4, 9):
            require(entry == (24 if stype == 4 else 16) and size % entry == 0, 'crypt ELF relocation size differs')
            for pos in range(offset, offset+size, entry):
                relocations.append(unpack('<QQ', pos)[1] & 0xffffffff)
    return {'type': kind, 'machine': machine, 'interpreters': interpreters,
            'needed': needed, 'runpaths': runpaths, 'rpaths': rpaths, 'textrel': 22 in tags,
            'symbols': symbols, 'relocations': relocations}


def require_elf(path, linkage):
    facts = elf_facts(path)
    require(not facts['textrel'], 'crypt ELF has text relocations')
    if linkage == 'object':
        same(facts['type'], 1, 'crypt installed source object type')
        require(not any(kind in (10, 11) for kind in facts['relocations']), 'crypt object has absolute 32-bit relocations')
    elif linkage == 'oracle':
        same([facts['type'], facts['interpreters'], facts['needed']], [2, [], []], 'crypt pinned static oracle ELF')
    else:
        require(linkage in ('pie', 'non-pie'), 'crypt dynamic linkage differs')
        same([facts['type'], facts['interpreters'], facts['needed'], facts['runpaths'], facts['rpaths']],
             [3 if linkage == 'pie' else 2, [INTERPRETER], ['libc.so'], ['/usr/lib'], []], 'crypt installed dynamic ELF')
    return facts


def link_command(reader, obj, binary, mode, linker):
    library = reader.product / 'usr/lib'
    paths = [library / ('Scrt1.o' if mode == 'pie' else 'crt1.o'), library / 'crabc-dynamic-attach.o',
             library / 'crti.o', obj, library / 'libc.so', library / 'libcrabc-builtins.a', library / 'crtn.o']
    return [linker, *(['-pie'] if mode == 'pie' else []), '--hash-style=sysv', '-z', 'relro', '-z', 'now',
            '-z', 'noexecstack', '-z', 'text', '--no-undefined', '--allow-shlib-undefined', '--enable-new-dtags',
            '-rpath', '/usr/lib', '--dynamic-linker', INTERPRETER, *map(reader.recorded, paths), '-o', reader.recorded(binary)]


def collect_link(reader, obj, binary, receipt_path, mode):
    receipt = native.read_json(receipt_path)
    search = receipt_contract.validate(
        receipt, format=native.PRODUCT_FORMAT, label='crypt sealed link receipt', fail=lambda message: require(False, message)
    )
    library = reader.product / 'usr/lib'
    runtime = [library / name for name in ('crti.o', 'libc.so', 'crtn.o',
               'Scrt1.o' if mode == 'pie' else 'crt1.o', 'crabc-dynamic-attach.o')]
    builtins = library / 'libcrabc-builtins.a'
    same({key: receipt[key] for key in ('format','mode','binding','runtime_imports','application_runpath',
         'application_dsos','campaign_complete','output_path','output_sha256','manifest_sha256','owned_runtime_inputs','input_receipts')},
         {'format': native.PRODUCT_FORMAT, 'mode': 'pie' if mode == 'pie' else 'exec', 'binding': 'now',
          'runtime_imports': [], 'application_runpath': '/usr/lib', 'application_dsos': {}, 'campaign_complete': False,
          'output_path': reader.recorded(binary), 'output_sha256': native.digest(binary), 'manifest_sha256': native.digest(reader.manifest),
          'owned_runtime_inputs': sorted(path.relative_to(reader.product).as_posix() for path in [*runtime,builtins]),
          'input_receipts': [reader.binding(path) for path in [*runtime,obj,builtins]]}, 'crypt canonical source/product link inputs')
    receipt_contract.require_runpath(search, '/usr/lib', label='crypt sealed link receipt', fail=lambda message: require(False, message))
    linker = keys(receipt['resolved_linker'], ('path', 'sha256'), 'crypt recorded linker')
    require(isinstance(linker['path'], str) and Path(linker['path']).name == 'ld.lld'
            and isinstance(linker['sha256'], str) and re.fullmatch('[0-9a-f]{64}', linker['sha256']) is not None, 'crypt linker identity differs')
    same(receipt['link_command'], link_command(reader, obj, binary, mode, linker['path']), 'crypt sealed linker invocation')
    direct = {reader.recorded(path) for path in [*runtime,obj]}
    archive = reader.recorded(builtins)
    trace = receipt['link_trace']
    require(isinstance(trace, list) and all(isinstance(item, str) and (item in direct or item == archive or
            (item.startswith(archive+'(') and item.endswith(')'))) for item in trace)
            and direct <= set(trace), 'crypt sealed trace admits foreign or missing inputs')
    return {'receipt': reader.identity(receipt_path), 'object': reader.identity(obj),
            'executable': reader.identity(binary), 'elf': require_elf(binary, mode), 'linker': linker}


def run_command(root, work, label, command, environment):
    """Keep exact raw command evidence even when an invoked build or test fails."""
    prefix = work / label
    prefix.parent.mkdir(parents=True, exist_ok=True)
    require(all(not Path(str(prefix)+suffix).exists() and not Path(str(prefix)+suffix).is_symlink()
                for suffix in ('.stdout', '.stderr', '.command.json', '.status')),
            'crypt command requires fresh evidence files')
    status = 127
    try:
        with Path(str(prefix)+'.stdout').open('xb') as out, Path(str(prefix)+'.stderr').open('xb') as err:
            try:
                result = subprocess.run(command, cwd=root, env=environment, stdin=subprocess.DEVNULL, stdout=out, stderr=err, check=False)
                status = result.returncode
            except OSError as error:
                err.write((str(error)+'\n').encode())
    finally:
        family.static_products.write_new(Path(str(prefix)+'.command.json'),
            {'command': command, 'cwd': str(root), 'environment': environment, 'status': status})
        with Path(str(prefix)+'.status').open('x') as stream:
            stream.write(str(status)+'\n')
    if status != 0:
        raise CryptProfileError(f'crypt {label} exited with {status}')


def runtime_command(work, label):
    if label == 'oracle':
        argv = [str(work / 'oracle')]
    elif label in ('static', 'static-pie'):
        argv = [str(work / (label+'-consumer'))]
    elif label in ('vector-oracle',):
        argv = [str(work / 'vectors/oracle'), 'oracle']
    else:
        vector = label.startswith('vector-')
        suffix = label[len('vector-'):] if vector else label[len('dynamic-'):]
        require(suffix in MODES, 'crypt runtime label differs')
        mode, entry = suffix.rsplit('-',1)
        directory = work / ('vectors' if vector else '') / ('dynamic-'+mode+'-root')
        argv = ['/usr/sbin/chroot', str(directory), *([INTERPRETER] if entry == 'direct' else []), '/consumer']
        if vector:
            argv.append('candidate')
    return ['/usr/bin/timeout','30','/usr/bin/env','-i',
            *(key+'='+value for key,value in RUNTIME_ENVIRONMENT.items()), *argv]


def source_records(root):
    return {path: {'path': path, 'sha256': native.digest(root / path),
                   'mode': (root / path).stat().st_mode} for path in SOURCES}


def product_record(root, product):
    manifest, _ = products._validate_dynamic_product(product)
    return {'manifest': family.file_identity(root, manifest), 'tree': family.snapshot(product)}


def live_tools(product):
    import crabc_cc_static as compiler
    return {role: {'path': str(path), 'sha256': native.digest(path)} for role, path in
            (('compiler', Path(compiler.compiler()).resolve(strict=True)),
             ('linker', Path(compiler.linker(product)).resolve(strict=True)))}


def live_oracle():
    import owned_libc_test
    return owned_libc_test.pinned_musl_identity()


def prepare(root, work, product):
    work, product = family.physical(root, work), family.physical(root, product)
    require(work.is_dir() and not work.is_relative_to(product), 'crypt evidence cannot be inside its product')
    request = {'schema': SCHEMA, 'source_mount': str(root), 'product': product.relative_to(root).as_posix()}
    family.static_products.write_new(work / 'profile-request.json', request)
    for name, value in (('source-before', source_records(root)), ('product-before', product_record(root, product)),
                        ('tools-before', live_tools(product)), ('oracle-before', live_oracle())):
        family.static_products.write_new(work / ('profile-'+name+'.json'), value)
    oracle = native.read_json(work / 'profile-oracle-before.json')
    retained = work / 'profile-oracle'
    retained.mkdir()
    for name, value in oracle['files'].items():
        path = Path(value.get('resolved_path', value['path']))
        if name == 'headers':
            shutil.copytree(path, retained / name, symlinks=True)
        else:
            shutil.copyfile(path, retained / name)


def guard(root, work, product):
    same(source_records(root), native.read_json(work / 'profile-source-before.json'), 'crypt source changed during execution')
    same(product_record(root, product), native.read_json(work / 'profile-product-before.json'), 'crypt supplied product changed during execution')
    same(live_tools(product), native.read_json(work / 'profile-tools-before.json'), 'crypt compiler/linker changed during execution')
    same(live_oracle(), native.read_json(work / 'profile-oracle-before.json'), 'crypt pinned oracle changed during execution')


def abi_oracle_command(root, work):
    return [ORACLE_CC, '-static', '-fno-pie', '-no-pie', '-std=c11', '-D_GNU_SOURCE',
            '-fno-builtin', '-fno-stack-protector', str(root / ABI_SOURCE), '-o', str(work / 'oracle')]


def vector_commands(reader, compiler):
    source, obj = reader.leaf / 'vectors/observer.c', reader.leaf / 'vectors/workload.o'
    prefix = ['-nostdinc','-isystem',reader.recorded(reader.product/'usr/include'),'-ffreestanding',
              '-fno-builtin','-fstack-protector-strong']
    return {'compile': [reader.recorded(reader.product/'bin/crabc-cc-dynamic'),'--dynamic-pie',*VECTOR_FLAGS,
                        '-c',reader.recorded(source),'-o',reader.recorded(obj)],
            'dependencies': [compiler,*prefix,*VECTOR_FLAGS,'-fPIE','-M',reader.recorded(source)],
            'oracle-link': [ORACLE_CC,'-static','-fno-pie','-no-pie',reader.recorded(obj),'-o',reader.recorded(reader.leaf/'vectors/oracle')]}


def extend(root, work, product):
    """Run the separately generated observer after the existing ABI fixture."""
    work, product = family.physical(root, work), family.physical(root, product)
    guard(root, work, product)
    vectors = work / 'vectors'
    vectors.mkdir()
    (vectors / 'observer.c').write_bytes(generated_observer(root))
    reader = native.Reader(work, str(root), product, root)
    commands = vector_commands(reader, live_tools(product)['compiler']['path'])
    try:
        for label in ('dependencies', 'compile', 'oracle-link'):
            guard(root, work, product)
            run_command(root, work, 'vector-'+label, commands[label], ENVIRONMENT)
        require_elf(vectors/'workload.o', 'object')
        require_elf(vectors/'oracle', 'oracle')
        run_command(root, work, 'vector-oracle', runtime_command(work, 'vector-oracle'), ENVIRONMENT)
        for mode in ('pie','non-pie'):
            guard(root, work, product)
            binary = vectors / ('dynamic-'+mode+'-consumer')
            command = [str(product/'bin/crabc-cc-dynamic'),'--dynamic-'+mode,str(vectors/'workload.o'),'-o',str(binary)]
            run_command(root, work, 'vector-link-'+mode, command, ENVIRONMENT)
            products.validate_link(product, vectors/'workload.o', binary, Path(str(binary)+'.crabc-link.json'), mode)
            execution = vectors / ('dynamic-'+mode+'-root')
            shutil.copytree(product, execution, symlinks=True)
            shutil.copyfile(binary, execution/'consumer')
            (execution/'consumer').chmod(binary.stat().st_mode & 0o7777)
            record = vectors / ('dynamic-'+mode+'-execution-payload.json')
            copies.record_execution_payload(product, execution, binary, execution/'consumer', record)
            for phase in ('pre','post','final'):
                if phase == 'post':
                    for entry in ('kernel','direct'):
                        label = 'vector-'+mode+'-'+entry
                        run_command(root, work, label, runtime_command(work, label), ENVIRONMENT)
                value = copies.audit_execution_payload(product, execution, binary, execution/'consumer', record)
                family.static_products.write_new(vectors / ('dynamic-'+mode+'-execution-'+phase+'.json'), value)
    finally:
        for name, capture in (('source-after', lambda: source_records(root)), ('product-after', lambda: product_record(root, product)),
                              ('tools-after', live_tools), ('oracle-after', live_oracle)):
            try:
                family.static_products.write_new(work / ('profile-'+name+'.json'), capture())
            except Exception as error:
                family.static_products.write_new(work / ('profile-'+name+'-error.json'), {'error': str(error)})
    result = collect(root, work)
    path = work/'crypt-profile.json'
    family.static_products.write_new(path, result)
    return path


def _reader(root, work, product=None):
    work = family.physical(root, work)
    request = native.read_json(work/'profile-request.json')
    keys(request, ('schema','source_mount','product'), 'crypt profile request')
    same(request['schema'], SCHEMA, 'crypt profile request schema')
    require(isinstance(request['product'], str) and not Path(request['product']).is_absolute(), 'crypt product path must be checkout-relative')
    selected = family.physical(root, root/request['product'])
    if product is not None:
        same(str(selected), str(family.physical(root, product)), 'crypt companion selected product')
    products._validate_dynamic_product(selected)
    return native.Reader(work, request['source_mount'], selected, root)


def collect_command(reader, label, command, *, raw_stdout=None, environment=ENVIRONMENT):
    path = reader.leaf / (label+'.command.json')
    value = native.read_json(path)
    same(value, {'command': command, 'cwd': str(reader.mount), 'environment': environment, 'status': 0},
         'crypt exact retained command '+label)
    values, identity = reader.raw(label)
    if raw_stdout is not None:
        require(values['stdout'] == raw_stdout, 'crypt raw stdout differs: '+label)
    require(values['stderr'] == b'', 'crypt command has unexpected stderr: '+label)
    return {'invocation': reader.identity(path), **identity}


def dependency_inputs(reader, path, source, required_headers):
    text = native.read_bytes(path).decode().replace('\\\n',' ')
    require(':' in text, 'crypt installed dependency list missing')
    names = text.split(':',1)[1].split()
    require(names and len(names) == len(set(names)), 'crypt installed dependency roster is empty or duplicated')
    headers = reader.product/'usr/include'
    bindings = {}
    for name in names:
        local = reader.local(name, within=reader.root)
        require(local == source or local.is_relative_to(headers), 'crypt dependency escapes installed source/headers')
        bindings[name] = native.digest(local)
    require(reader.recorded(source) in bindings and all(reader.recorded(headers/name) in bindings for name in required_headers),
            'crypt required installed source/header missing')
    return bindings


def collect_abi_compile(reader, tools):
    work, product, root = reader.leaf, reader.product, reader.root
    receipt = native.read_json(work/'compile.json')
    keys(receipt, ('schema','preparation','object'), 'crypt ABI compile receipt')
    same(receipt['schema'], 'crabc.x86_64-owned-crypt-runtime-compile/v1', 'crypt ABI compile schema')
    prep = receipt['preparation']
    same(prep, native.read_json(work/'compile-preparation.json'), 'crypt ABI compile preparation sidecar')
    keys(prep, ('schema','installed_dynamic','translation','source','dependencies','dependency_audit'), 'crypt ABI compile preparation')
    same(prep['schema'], 'crabc.x86_64-owned-crypt-runtime-compile-preparation/v1', 'crypt ABI preparation schema')
    same(prep['installed_dynamic'], {'root': reader.recorded(product), 'manifest': reader.binding(reader.manifest),
        'driver': reader.binding(product/'bin/crabc-cc-dynamic'), 'installed_helper': reader.binding(product/'share/crabc/crabc_cc_static.py'),
        'compiler': tools['compiler'], 'clean_environment': ENVIRONMENT}, 'crypt installed compiler inputs')
    source = root/ABI_SOURCE
    prefix = ['-nostdinc','-isystem',reader.recorded(product/'usr/include'),'-ffreestanding','-fno-builtin','-fstack-protector-strong']
    same(prep['translation'], {'driver_mode':'--dynamic-pie','effective_codegen_flag':'-fPIE','caller_flags':ABI_FLAGS,
        'driver_compile_prefix':prefix, 'actual_compile_command':[reader.recorded(product/'bin/crabc-cc-dynamic'),'--dynamic-pie',
            *ABI_FLAGS,'-c',reader.recorded(source),'-o',reader.recorded(work/'workload.o')],
        'dependency_audit_command':[tools['compiler']['path'],*prefix,*ABI_FLAGS,'-fPIE','-M',reader.recorded(source)]},
         'crypt ABI exact installed translation')
    reader.bind(prep['source'], source, 'crypt ABI source')
    reader.bind(prep['dependency_audit'], work/'installed-header-dependencies.d', 'crypt ABI dependency transcript')
    same(prep['dependencies'], dependency_inputs(reader, work/'installed-header-dependencies.d', source,
        ('crypt.h','string.h','unistd.h','features.h','bits/alltypes.h')), 'crypt ABI dependency identities')
    reader.bind(receipt['object'], work/'workload.o', 'crypt ABI canonical object')
    return {'receipt': reader.identity(work/'compile.json'), 'source': reader.identity(source, source=True),
            'object': reader.identity(work/'workload.o'), 'elf': require_elf(work/'workload.o','object'),
            'dependencies': prep['dependencies']}


def collect_copy(reader, directory, mode, binary):
    product = reader.product
    manifest = native.read_json(reader.manifest)
    files, aliases = manifest['files'], manifest['symlinks']
    execution = directory/('dynamic-'+mode+'-root')
    def file_pair(source, copied):
        same(native.digest(source), native.digest(copied), 'crypt execution copy bytes')
        return {'source': reader.binding(source), 'execution': reader.binding(copied)}
    def alias_pair(name, target):
        source, copied = product/name, execution/name
        require(source.is_symlink() and copied.is_symlink() and os.readlink(source) == target and os.readlink(copied) == target,
                'crypt execution loader alias differs')
        return {'source': {'path':reader.recorded(source),'target':target},
                'execution': {'path':reader.recorded(copied),'target':target}}
    expected = {'schema': copies.EXECUTION_PAYLOAD_SCHEMA,
        'product': {'root':reader.recorded(product),'manifest':file_pair(reader.manifest,execution/'share/crabc/manifest.json')},
        'execution_root':reader.recorded(execution),
        'payload':{name:file_pair(product/name,execution/name) for name in files},
        'aliases':{name:alias_pair(name,target) for name,target in aliases.items()},
        'consumer':file_pair(binary,execution/'consumer')}
    copies.assert_execution_tree(execution, files, aliases, execution/'consumer')
    identities = {}
    for suffix in ('payload','pre','post','final'):
        path = directory/('dynamic-'+mode+'-execution-'+suffix+'.json')
        same(native.read_json(path), expected, 'crypt before/after execution payload')
        identities[suffix] = reader.identity(path)
    return identities


def collect(root, work, *, product=None):
    reader = _reader(root, work, product)
    work, product = reader.leaf, reader.product
    source = source_records(root)
    payload = product_record(root, product)
    tools = native.read_json(work/'profile-tools-before.json')
    keys(tools, ('compiler','linker'), 'crypt compiler/linker roster')
    for role, item in tools.items():
        keys(item, ('path','sha256'), 'crypt recorded tool identity')
        require(isinstance(item['path'], str) and Path(item['path']).is_absolute() and '..' not in Path(item['path']).parts
                and isinstance(item['sha256'], str) and re.fullmatch('[0-9a-f]{64}', item['sha256']) is not None, 'crypt malformed tool identity')
    for phase in ('before','after'):
        same(native.read_json(work/('profile-source-'+phase+'.json')), source, 'crypt source before/after seal')
        same(native.read_json(work/('profile-product-'+phase+'.json')), payload, 'crypt product before/after seal')
        same(native.read_json(work/('profile-tools-'+phase+'.json')), tools, 'crypt tools before/after seal')
    oracle = native._libc_oracle(reader, {'oracle': {phase:native.read_json(work/('profile-oracle-'+phase+'.json'))
                                                   for phase in ('before','after')}})
    import run_qualification_manifest as qualification
    for name, item in oracle['files'].items():
        path = work/'profile-oracle'/name
        observed = (qualification.directory_tree_sha256(path, 'crypt retained musl headers') if name == 'headers'
                    else native.digest(path))
        same(observed, item['sha256'], 'crypt physically retained pinned oracle '+name)
    abi = collect_abi_compile(reader, tools)
    abi['oracle_link'] = collect_command(reader, 'abi-oracle-link', abi_oracle_command(reader.mount, Path(reader.recorded(work))), raw_stdout=b'')
    abi['oracle_elf'] = require_elf(work/'oracle','oracle')
    abi['oracle'] = collect_command(reader, 'oracle', runtime_command(Path(reader.recorded(work)),'oracle'), raw_stdout=b'crypt ok\n')
    source = work/'vectors/observer.c'
    require(native.read_bytes(source) == generated_observer(root), 'crypt generated observer source differs')
    commands = vector_commands(reader, tools['compiler']['path'])
    vector_build = {label:collect_command(reader,'vector-'+label,command,
                     raw_stdout=None if label == 'dependencies' else b'') for label,command in commands.items()}
    vector_build['headers'] = dependency_inputs(reader, work/'vector-dependencies.stdout', source,
        ('crypt.h','stdio.h','string.h','features.h','bits/alltypes.h'))
    vector_build['object'] = reader.identity(work/'vectors/workload.o')
    vector_build['elf'] = require_elf(work/'vectors/workload.o','object')
    vector_build['oracle_elf'] = require_elf(work/'vectors/oracle','oracle')
    vector_raw = {'oracle':collect_command(reader,'vector-oracle',runtime_command(Path(reader.recorded(work)),'vector-oracle'))}
    vector_observations = {'oracle':dispositions.crypt_vector_observations(root,native.read_bytes(work/'vector-oracle.stdout'),'oracle')}
    abi['entries'], vector_entries = {}, {}
    for mode in ('pie','non-pie'):
        for role, directory, obj, entries in (('abi',work,work/'workload.o',abi['entries']),
                                            ('vector',work/'vectors',work/'vectors/workload.o',vector_entries)):
            binary = directory/('dynamic-'+mode+'-consumer')
            linked = collect_link(reader,obj,binary,Path(str(binary)+'.crabc-link.json'),mode)
            same(linked['linker'], tools['linker'], 'crypt unchanged pinned linker')
            if role == 'abi':
                expected_identity = {'linkage':mode,'product':reader.recorded(product),'product_format':native.PRODUCT_FORMAT,
                    'product_manifest_sha256':native.digest(reader.manifest),'workload_sha256':native.digest(obj),
                    'executable_sha256':native.digest(binary),'receipt_sha256':native.digest(Path(str(binary)+'.crabc-link.json'))}
                same(native.read_json(work/('dynamic-'+mode+'-link-evidence.json')),expected_identity,'crypt independently recorded product link')
            else:
                linked['command'] = collect_command(reader,'vector-link-'+mode,
                    [reader.recorded(product/'bin/crabc-cc-dynamic'),'--dynamic-'+mode,reader.recorded(obj),'-o',reader.recorded(binary)],raw_stdout=b'')
            copied = collect_copy(reader,directory,mode,binary)
            for entry in ('kernel','direct'):
                cell = mode+'-'+entry
                label = ('dynamic-' if role == 'abi' else 'vector-')+cell
                observed = collect_command(reader,label,runtime_command(Path(reader.recorded(work)),label),
                    raw_stdout=b'crypt ok\n' if role == 'abi' else None)
                entries[cell] = {'link':linked,'copies':copied,'raw':observed}
                if role == 'vector':
                    vector_observations[cell] = dispositions.crypt_vector_observations(root,native.read_bytes(work/(label+'.stdout')),'candidate')
    require(set(abi['entries']) == set(MODES) and set(vector_entries) == set(MODES), 'crypt required dynamic mode roster differs')
    providers = elf_facts(product/'usr/lib/libc.so')['symbols']
    for name, binding in {'crypt':1,'crypt_r':2,'__crypt_r':1,'__crypt_sha256':1,'__crypt_sha512':1,'__crypt_md5':1,'__crypt_blowfish':1}.items():
        same([item for item in providers if item['name'] == name],
             [{'name':name,'binding':binding,'type':2,'visibility':0,'defined':True}], 'crypt installed provider '+name)
    require(not any(item['name'].startswith('__crabc_x86_crypt') for item in providers), 'crypt test-only export leaked')
    snapshot = family.snapshot(work)
    snapshot.pop('crypt-profile.json',None)
    return {'schema':SCHEMA,'status':'profile-companion-verified','source_mount':str(reader.mount),
            'product':payload,'sources':source_records(root),'oracle':oracle,'tools':tools,
            'abi':abi,'vector_build':vector_build,'vector_oracle':vector_raw['oracle'],'vector_entries':vector_entries,
            'vectors':dispositions.crypt_vectors(root),'vector_observations':vector_observations,'artifacts':snapshot,
            'native_aggregate_complete':False,'family_completion':False,'campaign_complete':False,'public_support':False}


def validate_receipt(root, path, *, product=None):
    path = family.physical(root,path)
    require(path.name == 'crypt-profile.json','expected crypt-profile.json companion receipt')
    observed = collect(root,path.parent,product=product)
    same(native.read_json(path),observed,'crypt whole-run profile receipt')
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action',required=True)
    for action in ('prepare','extend'):
        item=commands.add_parser(action)
        item.add_argument('--work',type=Path,required=True)
        item.add_argument('--product',type=Path,required=True)
    item=commands.add_parser('abi-oracle')
    item.add_argument('--work',type=Path,required=True)
    item=commands.add_parser('runtime')
    item.add_argument('--work',type=Path,required=True)
    item.add_argument('--label',required=True)
    item=commands.add_parser('validate')
    item.add_argument('receipt',type=Path)
    args=parser.parse_args()
    try:
        if args.action == 'prepare': prepare(ROOT,args.work,args.product)
        elif args.action == 'extend': print(extend(ROOT,args.work,args.product))
        elif args.action == 'abi-oracle': run_command(ROOT,args.work,'abi-oracle-link',abi_oracle_command(ROOT,args.work),ENVIRONMENT)
        elif args.action == 'runtime': run_command(ROOT,args.work,args.label,runtime_command(args.work,args.label),ENVIRONMENT)
        else:
            validate_receipt(ROOT,args.receipt)
            print('crypt profile companion: PASS')
    except (RuntimeError,ValueError,OSError,KeyError,TypeError,IndexError) as error:
        print('crypt profile: '+str(error),file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
