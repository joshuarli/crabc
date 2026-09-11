#!/usr/bin/env python3
"""Complete pinned fmaf/fmal/powf/nextafterl test units against an owned static sysroot.

This is a focused numerical test, not the full libc-test dynamic aggregate.
Shared application objects use installed headers; candidate links go through
its sealed driver and pinned musl links stay separate. No upstream test edits.
"""
import argparse
import concurrent.futures
import json
import os
import resource
from pathlib import Path
import subprocess

import owned_libc_test as source_contract


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sysroot', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args()
    if os.uname().sysname != 'Linux' or os.uname().machine != 'x86_64':
        raise SystemExit('requires native Linux/x86-64')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    evidence = args.evidence.resolve()
    product = args.sysroot.resolve()
    boundary = source_contract.ROOT / '.work'
    if not evidence.is_relative_to(boundary) or not product.is_relative_to(boundary):
        raise SystemExit('sysroot and evidence must remain inside checkout .work')
    evidence.mkdir(parents=True)
    compiler = product / 'bin/crabc-cc'
    source, upstream = source_contract.ensure_source()
    prepared = evidence / 'source-prepared'
    source_hashes = source_contract.copy_pinned_source(source, prepared)
    report = dict(upstream=upstream, source_hashes=source_hashes, units=[])
    options = evidence / 'generated'
    source_contract.generate_options_header(compiler=source_contract.ORACLE_CC,
        environment=dict(os.environ), include=product / 'usr/include',
        source=prepared / 'src/common/options.h.in', output=options / 'options.h',
        trace=options / 'options.headers.stderr')
    common = []
    def command(argv, prefix):
        result = subprocess.run([str(x) for x in argv], capture_output=True, cwd=prefix.parent)
        Path(str(prefix)+'.stdout').write_bytes(result.stdout)
        Path(str(prefix)+'.stderr').write_bytes(result.stderr)
        Path(str(prefix)+'.command.json').write_text(json.dumps([str(x) for x in argv],indent=2)+'\n')
        return result.returncode
    flags = ['-nostdinc', '-isystem', str(product/'usr/include'), *source_contract.BASE_TRANSLATION_FLAGS, '-frounding-math', '-I'+str(prepared/'src/common'), '-I'+str(options)]
    for name in source_contract.COMMON_MEMBERS:
        output = evidence / (name.replace('/','-')+'.o')
        status = command([source_contract.ORACLE_CC,*flags,'-c',prepared/('src/'+name+'.c'),'-o',output],output.with_suffix('.compile'))
        if status: raise SystemExit(f'common source failed: {name}')
        common.append(output)
    def unit(name):
        work = evidence / name
        work.mkdir()
        obj = work/'test.o'
        is_local = name == 'errno-regression'
        source_file = source_contract.ROOT / 'compat/x86_64/math_scalar_corrections_probe.c' if is_local else prepared/('src/math/'+name+'.c')
        definitions = ['-DCRABC_MATH_CORRECTIONS_INSTALLED'] if is_local else []
        status = command([source_contract.ORACLE_CC,*flags,*definitions,'-c',source_file,'-o',obj],work/'compile')
        if status: return dict(name=name,compile_status=status)
        result = dict(name=name, compile_status=0)
        for arm in ('oracle','candidate'):
            output=work/arm
            if arm=='candidate':
                link=[compiler,'-static','--link-receipt','link.receipt.json',obj,*common,'-o',output.name]
            else:
                link=[source_contract.ORACLE_CC,'-static','-no-pie',obj,*common,'-o',output]
            status=command(link,work/(arm+'.link'))
            result[arm]=dict(link_status=status)
            if not status:
                status=command([output],work/(arm+'.run'))
                result[arm]['run_status']=status
        return result
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        report['units']=list(executor.map(unit,('fmaf','fmal','powf','nextafterl')))
    report['errno_regression'] = unit('errno-regression')
    (evidence/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(units=report['units'],errno_regression=report['errno_regression']),indent=2))
    return int(any(row.get('candidate',{}).get('run_status')!=0 for row in [*report['units'],report['errno_regression']]))


if __name__=='__main__':
    raise SystemExit(main())
