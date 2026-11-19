import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import validate_owned_math_fenv_all_entry_aarch64 as stream


def rounding_rows():
    for mode, rounding in enumerate((0, 0x800000, 0x400000, 0xc00000)):
        for seed, flags in enumerate((0, 0x10, 2, 0x12)):
            for operation in range(2):
                for index in range(12):
                    exceptions = flags | (0x10 if not operation and index not in (0, 1, 8, 9) else 0)
                    for precision in range(3):
                        yield stream.ROUNDING.pack(precision, operation, mode, seed, index, 0,
                                                   rounding, exceptions, rounding, exceptions, bytes(16))


def valid_stream():
    result = bytearray()
    for stage, size in stream.STAGES:
        result += stream.FRAME.pack(0x4d464131, stage, 1, 0, 0x400000, 0x12)
        result += b''.join(rounding_rows()) if stage == 2 else bytes(size)
        result += stream.FRAME.pack(0x4d464131, stage, 2, 0, 0x400000, 0x12)
    return result


class NativeMathStreamTests(unittest.TestCase):
    def test_requires_complete_ordered_frames(self):
        data = valid_stream()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stream'
            path.write_bytes(data)
            self.assertEqual(len(stream.read(path)[2]), 4 * 4 * 2 * 12 * 3 * stream.ROUNDING.size)
            data[-stream.FRAME.size] ^= 1
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'invalid stage 10 frame'):
                stream.read(path)

    def test_rejects_rounding_register_and_flag_disagreement(self):
        data = valid_stream()
        offset = 3 * stream.FRAME.size
        data[offset + 12] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stream'
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'invalid rounding record'):
                stream.read(path)

    def test_domain_exception_account_requires_the_actual_domain_and_flags(self):
        operand = (0x3ffe << 112).to_bytes(16, 'little')
        oracle = (1, 1, 0, 0, 17, 0, 3, 0, 0, 0, 0, bytes(32), operand)
        candidate = (*oracle[:4], 1, *oracle[5:])
        self.assertTrue(stream.domain_flag_correction(oracle, oracle, candidate))
        outside = (*oracle[:-1], (0x4000 << 112).to_bytes(16, 'little'))
        outside_candidate = (*outside[:4], 1, *outside[5:])
        self.assertFalse(stream.domain_flag_correction(outside, outside, outside_candidate))
        self.assertFalse(stream.domain_flag_correction(oracle, oracle, (*candidate[:4], 0, *candidate[5:])))

    def test_corrected_sqrt_must_match_musl_even_if_helper_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stream'
            path.write_bytes(valid_stream())
            oracle = stream.read(path)
        reference = dict(oracle)
        candidate = dict(oracle)
        record = stream.RECORDS[7].pack(32, 0, 0, 0, 1, bytes(32))
        changed = stream.RECORDS[7].pack(32, 0, 0, 16, 1, bytes(32))
        oracle[7] = record + oracle[7][len(record):]
        reference[7] = changed + reference[7][len(record):]
        candidate[7] = reference[7]
        with patch.object(stream.completion, 'compare_aarch64'):
            with self.assertRaisesRegex(ValueError, 'stage 7 record 0'):
                stream.compare(oracle, reference, candidate)


if __name__ == '__main__':
    unittest.main()
