#!/usr/bin/env python3
"""Invocation regressions for the focused installed scalar math tests."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_math_scalar_corrections_libc_test as helper


class ReachedCompilation(Exception):
    pass


class ScalarCorrectionsLibcTestTests(unittest.TestCase):
    def test_options_preprocessor_uses_the_supplied_products_translation(self):
        scratch = helper.source_contract.ROOT / '.work/x86_64/tmp'
        scratch.mkdir(parents=True, exist_ok=True)
        for flags in ((), ('-fstack-protector-strong', '-D_PRODUCT_OPTIONS=1')):
            with self.subTest(flags=flags), tempfile.TemporaryDirectory(dir=scratch) as temporary:
                root = Path(temporary)
                product = root / '.work/product'
                include = product / 'usr/include'
                include.mkdir(parents=True)
                installed_helper = product / 'share/crabc/crabc_cc_static.py'
                installed_helper.parent.mkdir(parents=True)
                installed_helper.write_text(f'HOSTED_TRANSLATION_FLAGS = {flags!r}\n')
                evidence = root / '.work/evidence'
                invocations = []

                def copy_source(source, prepared):
                    template = prepared / 'src/common/options.h.in'
                    template.parent.mkdir(parents=True)
                    template.write_text('options template\n')
                    return {}

                def preprocess(command, **arguments):
                    invocations.append(command)
                    arguments['stdout'].write_text('optiongroups_unistd_end\nPRODUCT_OPTIONS 1\n')
                    arguments['stderr'].write_bytes(b'')
                    return {'exit_status': 0}

                arguments = ['focused-math', '--sysroot', str(product), '--evidence', str(evidence)]
                with patch.object(helper.source_contract, 'ROOT', root), \
                     patch.object(helper.source_contract, 'ensure_source', return_value=(root, {})), \
                     patch.object(helper.source_contract, 'copy_pinned_source', side_effect=copy_source), \
                     patch.object(helper.source_contract, 'run_capture', side_effect=preprocess), \
                     patch.object(helper.resource, 'setrlimit'), \
                     patch.object(helper.subprocess, 'run', side_effect=ReachedCompilation), \
                     patch('sys.argv', arguments):
                    with self.assertRaises(ReachedCompilation):
                        helper.main()

                self.assertEqual(invocations, [[str(helper.source_contract.ORACLE_CC),
                    '-nostdinc', '-isystem', str(include), *flags, '-std=c99',
                    '-D_POSIX_C_SOURCE=200809L', '-D_FILE_OFFSET_BITS=64', '-E', '-H', '-']])
                self.assertEqual((evidence / 'generated/options.h').read_text(),
                                 '#define PRODUCT_OPTIONS 1\n')


if __name__ == '__main__':
    unittest.main()
