#!/usr/bin/env python3
"""Read current qualification and owned products before public policy changes.

A completed ledger does not establish execution. This boundary rereads the
selected ordered receipt, reviewed full product receipts, native dependency
provenance and actual allocator symbol ownership. Public policy may still be
false during readiness; changing it requires fresh source-bound evidence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile

import aarch64_parity_inventory as inventory
import generate_qualification_manifest as manifest
import owned_dynamic_qualification as dynamic
import owned_static_sysroot_package as package
import run_qualification_manifest as qualification
import static_product_contract as static
import validate_parity_ledger as ledger

ROOT = Path(__file__).resolve().parents[2]


class PromotionClosureError(RuntimeError):
    """Actual current-source execution or native ownership remains unqualified."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PromotionClosureError(message)


def validate_promotion_closure(receipt_path: Path | None) -> dict:
    """Compose existing owning readers without creating another receipt or seal."""
    require(receipt_path is not None, "promotion requires an explicit complete qualification receipt")
    qualification.require_pinned_native_execution()
    before = qualification.source_identity()
    chain = qualification.validate_chain_receipt(receipt_path)
    contract = manifest.load_contract()
    profile = contract['qualification_profile']
    active = list(manifest.active_chain(profile))
    require(chain.get('qualification_profile') == profile
            and chain.get('active_gate_ids') == active
            and chain.get('deferred_gate_ids') == list(manifest.deferred_gate_ids(profile))
            and chain.get('complete_profile') is True and chain.get('outcome') == 'passed'
            and chain.get('qualified_gates') == active and chain.get('through') == active[-1],
            "promotion requires the complete selected profile, not a prefix or historical full shape")
    require(chain.get('source_before') == before and chain.get('source_after') == before,
            "qualification source differs from promotion source")
    data = ledger.load_toml(ledger.LEDGER_PATH)
    ledger.validate_ledger(data)
    required = ledger.completion_family_ids(data)
    require(data.get('completion', {}).get('qualification_profile', 'full') == profile,
            "ledger and qualification profiles differ")
    families = {row['id']: row for row in data['family']}
    require(all(families[name]['status'] == 'foundation-verified' for name in required),
            "functional prerequisite families remain incomplete")
    capabilities = inventory.validate_inventory()
    require(all(row['contract_state'] == 'implemented-foundation'
                for row in capabilities['capabilities']), "capability implementation remains incomplete")

    # Import the physical builder API so opt-in native products cannot masquerade
    # as a native default. The builders capture their default in callable arguments.
    sys.path.insert(0, str(ROOT))
    from scripts import build_x86_64_owned_sysroot as static_builder
    from scripts import build_x86_64_owned_dynamic_sysroot as dynamic_builder
    require(static_builder.DEFAULT_ALLOCATOR_BACKEND == 'native'
            and static_builder.build.__kwdefaults__['allocator_backend'] == 'native'
            and dynamic_builder.build.__kwdefaults__['allocator_backend'] == 'native',
            "source still selects the C or shadow allocator default")
    static_receipt = static.load_publication()
    dynamic_receipt = dynamic.load_publication()
    require(static_receipt is not None and dynamic_receipt is not None,
            "reviewed current-source static and dynamic qualification publications are required")
    source = static.source_digest()
    require(source == dynamic.source_digest()
            and static_receipt['source_sha256'] == source
            and dynamic_receipt['source_sha256'] == source,
            "reviewed product source differs from promotion source")
    nm = qualification.tool_identity('nm')['path']
    scratch = static.evidence_directory(ROOT / '.work/x86_64/tmp')
    scratch.mkdir(parents=True, exist_ok=True)
    report = static.evidence_directory(ROOT / static_receipt['report'])
    with tempfile.TemporaryDirectory(prefix='.promotion-static.', dir=scratch) as temporary:
        tree = package.extract_archive(report / 'archives/primary.tar.xz', Path(temporary) / 'tree')
        product_manifest = static.read_json(tree / 'share/crabc/manifest.json')
        provenance = static.read_json(tree / 'share/crabc/libc-static.provenance.json')
        require(product_manifest['allocator_backend'] == 'native'
                and provenance.get('allocator_lifecycle_test_audit') is False,
                "static product does not select the production native allocator")
        graph = provenance['dependency_graph']
        require(graph.get('c_allocator_selected') is False and graph.get('native_allocator_selected') is True
                and graph.get('edges') == ['normal', 'build']
                and any(name.startswith('crabc-mimalloc ') for name in graph['packages'])
                and not any(name.startswith('libmimalloc-sys ') for name in graph['packages']),
                "static product native dependency ownership differs")
        require(provenance['allocator_backend']['upstream_sha256'] == static.digest(ROOT / 'crabc-mimalloc/UPSTREAM.md'),
                "static native allocator source differs")
        archive = tree / 'usr/lib/libc.a'
        definitions = static_builder.archive_defined_symbols(nm, archive)
        # Dormant members can import a foreign allocator without being extracted
        # by a workload, so native ownership covers unresolved symbols too.
        output = static_builder.run([nm, '--undefined-only', '--extern-only', str(archive)])
        imports = {line.split()[-1] for line in output.decode('utf-8', errors='replace').splitlines()
                   if len(line.split()) >= 2 and not line.endswith(':')}
        require(not any(name.startswith(('mi_', '_mi_')) for name in definitions | imports)
                and {'malloc', 'free'} <= definitions, "static allocator symbol ownership differs")
    work = dynamic.evidence_path(ROOT / dynamic_receipt['work'])
    for product in ('installed', 'second', 'extracted'):
        tree = dynamic.evidence_path(work / product)
        state = dynamic.read(tree / 'share/crabc/dynamic-product-state.json')
        provenance = dynamic.read(tree / 'share/crabc/libc-shared.provenance.json')
        require(state['allocator_backend'] == provenance['allocator_backend'] == 'native'
                and state['allocator_lifecycle_test_audit'] is False
                and provenance['allocator_lifecycle_test_audit'] is False,
                "dynamic product does not select the production native allocator")
        graph = provenance['dependency_graph']
        require(graph.get('c_allocator_selected') is False and graph.get('native_allocator_selected') is True
                and graph.get('edges') == ['normal', 'build']
                and any(name.startswith('crabc-mimalloc ') for name in graph['packages'])
                and not any(name.startswith('libmimalloc-sys ') for name in graph['packages']),
                "dynamic product native dependency ownership differs")
        native = provenance['native_allocator']
        require(native['path'] == 'crabc-mimalloc/UPSTREAM.md'
                and native['sha256'] == static.digest(ROOT / native['path']), "dynamic native allocator source differs")
        libc = tree / 'usr/lib/libc.so'
        loader = tree / 'lib/ld-crabc-x86_64.so.1'
        definitions = dynamic_builder.elf_symbols(nm, libc, '--defined-only')
        imports = dynamic_builder.elf_symbols(nm, libc, '--undefined-only')
        loader_symbols = (dynamic_builder.elf_symbols(nm, loader, '--defined-only')
                          | dynamic_builder.elf_symbols(nm, loader, '--undefined-only'))
        dynamic_builder.validate_native_allocator_symbols(definitions, imports, loader_symbols)
        require({'malloc', 'free', '__crabc_x86_native_mimalloc_process_finalizer'} <= definitions,
                "dynamic native allocator public ownership or finalizer is absent")
    require(static.load_publication() == static_receipt and dynamic.load_publication() == dynamic_receipt
            and qualification.validate_chain_receipt(receipt_path) == chain,
            'qualification or reviewed products changed during promotion validation')
    require(qualification.source_identity() == before
            and qualification.execution_inputs() == chain['inputs_after'],
            "source or execution inputs changed during promotion validation")
    return {'qualification_profile': profile, 'source': before,
            'qualification_receipt': str(receipt_path), 'functional_readiness': True,
            'public_support': data['policy']['public_support']}


def main(arguments=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification-receipt', required=True, type=Path)
    args = parser.parse_args(arguments)
    try:
        result = validate_promotion_closure(args.qualification_receipt)
    except (RuntimeError, OSError, KeyError, ValueError, TypeError) as error:
        print(f'x86 campaign promotion closure: UNMET ({error})', file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    print('x86 campaign promotion closure: PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
