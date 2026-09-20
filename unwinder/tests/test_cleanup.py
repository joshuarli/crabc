"""The cleanup fixture's observable contract is fixed before target execution."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'unwinder_cleanup', Path(__file__).parents[1] / 'cleanup.py'
)
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)


class CleanupExecutionContract(unittest.TestCase):
    def test_cleanup_fixture_requires_the_full_main_and_worker_observation(self):
        cleanup.assert_execution(0, 'unwind: backtrace cleanup payload main thread\n')
        with self.assertRaisesRegex(RuntimeError, 'unexpected cleanup fixture output'):
            cleanup.assert_execution(0, 'unwind: cleanup only\n')
        with self.assertRaisesRegex(RuntimeError, 'status'):
            cleanup.assert_execution(101, 'unwind: backtrace cleanup payload main thread\n')

    def test_binary_requires_executed_provider_abi_and_rejects_foreign_abi(self):
        provider = set(cleanup.EXECUTED_UNWIND_ABI) | {'_Unwind_DeleteException'}
        cleanup.assert_binary_unwind_symbols(set(cleanup.EXECUTED_UNWIND_ABI), provider)
        with self.assertRaisesRegex(RuntimeError, 'unselected'):
            cleanup.assert_binary_unwind_symbols(
                set(cleanup.EXECUTED_UNWIND_ABI) | {'_Unwind_Foreign'}, provider,
            )
        with self.assertRaisesRegex(RuntimeError, 'lacks'):
            cleanup.assert_binary_unwind_symbols({'_Unwind_Backtrace'}, provider)


if __name__ == '__main__':
    unittest.main()
