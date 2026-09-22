import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
spec = importlib.util.spec_from_file_location("heap_destroy", ROOT / "compat/allocator/heap_destroy.py")
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


class HeapDestroyTraceTests(unittest.TestCase):
    def test_real_libtest_prefix_preserves_the_first_observation(self):
        fields = "\n".join(f"m2.heap.destroy.{index}={value}" for index, value in enumerate([4, 3, 3, 1, 3, 4, 5]))
        output = f"test {producer.TEST} ... {fields}\nok\n"
        self.assertEqual(producer.trace(output), [4, 3, 3, 1, 3, 4, 5])

    def test_duplicate_or_missing_observation_is_rejected(self):
        for indexes in ([0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5, 6, 6]):
            with self.subTest(indexes=indexes):
                fields = "\n".join(f"m2.heap.destroy.{index}=1" for index in indexes)
                with self.assertRaises(producer.harness.HarnessError):
                    producer.trace(fields)


if __name__ == "__main__":
    unittest.main()
