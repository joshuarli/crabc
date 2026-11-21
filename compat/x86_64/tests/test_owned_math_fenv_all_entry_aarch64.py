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


MINUS_LDBL_MAX = 0xfffe << 112 | (1 << 112) - 1
MINUS_32_INEXACT = 0xc004 << 112 | 1
BINARY64_MAX = 0x43fe << 112 | ((1 << 52) - 1) << 60


def quad(bits):
    return bits.to_bytes(16, 'little')


def elementary(case, flags):
    return (1, case, 0, flags, 1, quad(0x7fff8 << 108) + bytes(16))


def boundary(function, kind, flags, value, case=0x8000, operand=bytes(16)):
    return (function, case, 0x400000, 0, flags, 0, kind, 0x400000, 0x3c3c, 0, 0x5a5a5a5a, value, operand)


def acoshl_boundary(operand, flags):
    return boundary(1, 3, flags, quad(0x7fff8 << 108) + bytes(16), operand=quad(operand))


def cpowl(case, real, imaginary):
    return boundary(185, 9, 1, quad(real) + quad(imaginary), case=case)


def with_field(record, index, value):
    return (*record[:index], value, *record[index + 1:])


def compare_one(stage, musl, reference, candidate):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'stream'
        path.write_bytes(valid_stream())
        base = stream.read(path)
    bodies = []
    for record in (musl, reference, candidate):
        packed = stream.RECORDS[stage].pack(*record)
        bodies.append({**base, stage: packed + base[stage][len(packed):]})
    with patch.object(stream.completion, 'compare_aarch64'):
        return stream.compare(*bodies)


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

    def test_reference_agreement_never_accepts_an_uncontracted_difference(self):
        special = boundary(100, 3, 0, quad(0x3fff << 112) + bytes(16))
        changed = (*special[:11], quad(0x3fff << 112 | 1) + bytes(16), special[12])
        acoshl = elementary(1, 21)
        corrected = elementary(1, 1)
        complex_record = (0, 0, 0, 0, 0, bytes(48))
        complex_changed = (*complex_record[:5], b'\x01' + bytes(47))
        for stage, musl, candidate in ((10, special, changed), (7, acoshl, corrected),
                                       (9, complex_record, complex_changed)):
            with self.subTest(stage=stage, function=musl[0]):
                with self.assertRaisesRegex(ValueError, 'outside every difference contract'):
                    compare_one(stage, musl, candidate, candidate)

    def test_acoshl_contract_accepts_only_narrowing_flags_on_domain_errors(self):
        for stage, musl, candidate in (
                (7, elementary(1, 21), elementary(1, 1)),
                (7, elementary(10, 25), elementary(10, 1)),
                (10, acoshl_boundary(MINUS_32_INEXACT, 17), acoshl_boundary(MINUS_32_INEXACT, 1)),
                (10, acoshl_boundary(MINUS_LDBL_MAX, 21), acoshl_boundary(MINUS_LDBL_MAX, 1))):
            with self.subTest(stage=stage, accepted=musl):
                self.assertEqual(compare_one(stage, musl, musl, candidate)['acoshl-domain-flags'], 1)
        nan = quad(0x7fff8 << 108) + bytes(16)
        x = MINUS_32_INEXACT
        outside = (
            ('x = 1', 7, elementary(14, 21), elementary(14, 1), None),
            ('x > 1', 10, acoshl_boundary(0x4005 << 112 | 1, 17), acoshl_boundary(0x4005 << 112 | 1, 1), None),
            ('NaN x', 10, acoshl_boundary(0x7fff4 << 108, 17), acoshl_boundary(0x7fff4 << 108, 1), None),
            ('exact x with overflow', 7, elementary(2, 5), elementary(2, 1), None),
            ('exact x with inexact', 7, elementary(6, 17), elementary(6, 1), None),
            ('divide-by-zero', 10, acoshl_boundary(x, 19), acoshl_boundary(x, 1), None),
            ('no invalid', 10, acoshl_boundary(x, 16), acoshl_boundary(x, 1), None),
            ('extra candidate flag', 10, acoshl_boundary(x, 17), acoshl_boundary(x, 17 | 8), None),
            ('candidate omits invalid', 7, elementary(1, 21), elementary(1, 0), None),
            ('other function', 7, (2, 1, 0, 21, 1, nan), (2, 1, 0, 1, 1, nan), None),
            ('result differs', 7, elementary(1, 21), (1, 1, 0, 1, 1, quad(0x7fffc << 108) + bytes(16)), None),
            ('non-NaN result', 7, (1, 1, 0, 21, 1, bytes(32)), (1, 1, 0, 1, 1, bytes(32)), None),
            ('errno differs', 10, acoshl_boundary(x, 17), with_field(acoshl_boundary(x, 1), 8, 33), None),
            ('reference carries the correction', 7, elementary(1, 21), elementary(1, 1), elementary(1, 1)),
        )
        for name, stage, musl, candidate, reference in outside:
            with self.subTest(name):
                with self.assertRaisesRegex(ValueError, 'outside every difference contract'):
                    compare_one(stage, musl, reference or musl, candidate)

    def test_narrowing_exceptions_follow_binary64_representability(self):
        for bits, expected in ((MINUS_LDBL_MAX, 20), (1, 24), (1 << 112, 24), (0xc002 << 112, 0),
                               (BINARY64_MAX, 0), (BINARY64_MAX + (1 << 59), 20),
                               ((0x3fff - 1074) << 112, 0), ((0x3fff - 1075) << 112, 24),
                               (0x3fff << 112 | 1 << 60, 0), (0x3fff << 112 | 1 << 59, 16),
                               (0x7fff << 112, 0), (1 << 127, 0)):
            with self.subTest(bits=hex(bits)):
                self.assertEqual(stream.narrowing_exceptions(bits), expected)

    def test_cpowl_contract_accepts_only_quiet_nan_sign_and_payload(self):
        positive, negative = 0x7fffc << 108, 0xffffc << 108
        default = 0x7fff8 << 108
        accepted = ((0x001, positive, negative), (0x104, positive, default), (0x105, default, negative))
        for case, expected, actual in accepted:
            with self.subTest(case=hex(case)):
                candidate = cpowl(case, actual, actual)
                self.assertEqual(compare_one(10, cpowl(case, expected, expected), candidate,
                                             candidate)['cpowl-nan-propagation'], 1)
        outside = (
            ('dense case', cpowl(0x8001, positive, positive), cpowl(0x8001, negative, negative), None),
            ('single NaN factor', cpowl(0x100, positive, positive), cpowl(0x100, negative, negative), None),
            ('other function', with_field(cpowl(0x001, positive, positive), 0, 184),
             with_field(cpowl(0x001, negative, negative), 0, 184), None),
            ('finite component', cpowl(0x001, positive, 0x3fff << 112),
             cpowl(0x001, negative, 0x3fff << 112 | 1), None),
            ('NaN against number', cpowl(0x001, positive, positive), cpowl(0x001, positive, 0), None),
            ('signaling result', cpowl(0x001, positive, positive),
             cpowl(0x001, 0x7fff4 << 108 | 1, positive), None),
            ('flags differ', cpowl(0x001, positive, positive),
             with_field(cpowl(0x001, negative, negative), 4, 17), None),
            ('helper composition differs', cpowl(0x001, positive, positive),
             cpowl(0x001, negative, negative), cpowl(0x001, positive, positive)),
        )
        for name, musl, candidate, reference in outside:
            with self.subTest(name):
                with self.assertRaisesRegex(ValueError, 'outside every difference contract'):
                    compare_one(10, musl, reference or candidate, candidate)
        musl = cpowl(0x100, positive, positive)
        reference_only = compare_one(10, musl, cpowl(0x100, negative, negative), musl)
        self.assertEqual((reference_only['acoshl-domain-flags'], reference_only['cpowl-nan-propagation']), (0, 0))

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
