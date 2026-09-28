"""The guarded EH fixture reports the exact child result for each case."""
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location('unwinder_eh_frame_bounds', ROOT / 'eh_frame_bounds.py')
eh_frame_bounds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(eh_frame_bounds)


class InstalledGuardedMetadataContract(unittest.TestCase):
    def test_each_case_requires_its_child_result_and_clean_wait(self):
        for label, result in eh_frame_bounds.CASES.items():
            expected = f'{label} unwind={result}\n{label} wait=0\n'
            eh_frame_bounds.assert_case_result(label, 0, expected, '')
            with self.assertRaisesRegex(RuntimeError, label):
                eh_frame_bounds.assert_case_result(label, -11, expected, '')
            with self.assertRaisesRegex(RuntimeError, label):
                eh_frame_bounds.assert_case_result(label, 0, expected.replace('wait=0', 'wait=139'), '')
            with self.assertRaisesRegex(RuntimeError, label):
                eh_frame_bounds.assert_case_result(label, 0, expected, 'unexpected diagnostic')
