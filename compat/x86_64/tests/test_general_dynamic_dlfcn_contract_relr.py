import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
PACKER = ROOT / "compat/x86_64/general_dynamic_dlfcn_contract_relr.py"
sys.path.insert(0, str(ROOT / "scripts"))
import native_build_tools

SPEC = importlib.util.spec_from_file_location("general_dynamic_relr_packer", PACKER)
PACKER_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKER_MODULE)

DT_NULL, DT_RELA, DT_RELASZ = 0, 7, 8
DT_RUNPATH, DT_SONAME = 29, 14
DT_RELRSZ, DT_RELR, DT_RELRENT, DT_RELACOUNT = 35, 36, 37, 0x6FFFFFF9
PT_LOAD, PT_DYNAMIC, R_X86_64_RELATIVE = 1, 2, 8


def load_headers(image):
    phoff = struct.unpack_from("<Q", image, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", image, 54)
    return [
        struct.unpack_from("<IIQQQQQQ", image, phoff + index * phentsize)
        for index in range(phnum)
    ]


def file_offset(image, address):
    for kind, _, offset, vaddr, _, filesz, _, _ in load_headers(image):
        if kind == PT_LOAD and vaddr <= address < vaddr + filesz:
            return offset + address - vaddr
    raise AssertionError(f"address {address:#x} is not file-backed")


def dynamic_rows(image):
    dynamic, = [header for header in load_headers(image) if header[0] == PT_DYNAMIC]
    rows = []
    for at in range(dynamic[2], dynamic[2] + dynamic[5], 16):
        tag, value = struct.unpack_from("<qQ", image, at)
        rows.append((at, tag, value))
    return dynamic, rows


def relr_offsets(image, address, size):
    table = file_offset(image, address)
    words = [struct.unpack_from("<Q", image, table + offset)[0] for offset in range(0, size, 8)]
    offsets = []
    cursor = None
    for word in words:
        if word & 1 == 0:
            offsets.append(word)
            cursor = word + 8
            continue
        if cursor is None:
            raise AssertionError("RELR bitmap precedes its base")
        for bit in range(63):
            if word >> (bit + 1) & 1:
                offsets.append(cursor + bit * 8)
        cursor += 63 * 8
    return offsets


@unittest.skipUnless(Path("/opt/cargo/bin/rustup").is_file() and native_build_tools.MOLD.is_file(),
                     "requires the pinned native mold image")
class GeneralDynamicRelrPackerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(dir=ROOT / ".work")
        cls.work = Path(cls.temporary.name)
        source = cls.work / "relr-fixture.c"
        source.write_text(
            "static int local_value;\n"
            "static int *relative_pointer = &local_value;\n"
            "extern int external_value;\n"
            "int *external_pointer = &external_value;\n"
            "int fixture(void) { return *relative_pointer + *external_pointer; }\n"
        )
        cls.object = cls.work / "relr-fixture.o"
        cls.dso = cls.work / "librelr-fixture.so"
        commands = (
            ["/usr/bin/gcc", "-fPIC", "-c", str(source), "-o", str(cls.object)],
            [str(native_build_tools.MOLD), "--shared", "--soname=librelr-fixture.so",
             "--rpath=/unused", "-o", str(cls.dso), str(cls.object)],
        )
        for command in commands:
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if completed.returncode:
                raise AssertionError(completed.stderr.decode(errors="replace"))
        cls.source_image = bytearray(cls.dso.read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_mold_relative_relocations_pack_without_relacount(self):
        original = self.source_image
        dynamic, rows = dynamic_rows(original)
        entries = {tag: value for _, tag, value in rows if tag != DT_NULL}
        self.assertNotIn(DT_RELACOUNT, entries)
        self.assertTrue({DT_RELA, DT_RELASZ, DT_RUNPATH, DT_SONAME} <= entries.keys())
        rela = entries[DT_RELA]
        rela_size = entries[DT_RELASZ]
        self.assertEqual(rela_size % 24, 0)
        table = file_offset(original, rela)
        relocations = [
            struct.unpack_from("<QQq", original, table + offset)
            for offset in range(0, rela_size, 24)
        ]
        leading_count = next(
            (index for index, (_, info, _) in enumerate(relocations)
             if info != R_X86_64_RELATIVE), len(relocations)
        )
        self.assertGreater(leading_count, 0)
        self.assertLess(leading_count, len(relocations))
        relative_offsets = sorted(row[0] for row in relocations[:leading_count])
        remaining_rela = bytes(original[table + leading_count * 24:table + rela_size])

        packed = bytearray(original)
        self.assertEqual(PACKER_MODULE.pack(packed), leading_count)

        _, packed_rows = dynamic_rows(packed)
        packed_tags = {tag: value for _, tag, value in packed_rows if tag != DT_NULL}
        self.assertEqual(packed_tags[DT_RELA], rela + leading_count * 24)
        self.assertEqual(packed_tags[DT_RELASZ], rela_size - leading_count * 24)
        self.assertEqual(packed_tags[DT_RELRENT], 8)
        self.assertEqual(packed_tags[DT_RELRSZ] % 8, 0)
        self.assertEqual(relr_offsets(packed, packed_tags[DT_RELR], packed_tags[DT_RELRSZ]), relative_offsets)
        self.assertEqual(
            bytes(packed[table + leading_count * 24:table + rela_size]), remaining_rela
        )
        for offset, _, addend in relocations[:leading_count]:
            self.assertEqual(struct.unpack_from("<q", packed, file_offset(packed, offset))[0], addend)
        null_rows = [row for row in packed_rows if row[1] == DT_NULL]
        self.assertGreaterEqual(len(null_rows), 1)
        terminator_index = next(index for index, row in enumerate(packed_rows) if row[1] == DT_NULL)
        self.assertTrue(all(tag == DT_NULL and value == 0 for _, tag, value in packed_rows[terminator_index:]))

    def test_rejects_relacount_that_disagrees_with_the_leading_block(self):
        malformed = bytearray(self.source_image)
        _, rows = dynamic_rows(malformed)
        entries = {tag: value for _, tag, value in rows if tag != DT_NULL}
        table = file_offset(malformed, entries[DT_RELA])
        count = 0
        while count * 24 < entries[DT_RELASZ]:
            _, info, _ = struct.unpack_from("<QQq", malformed, table + count * 24)
            if info != R_X86_64_RELATIVE:
                break
            count += 1
        first_null = next(at for at, tag, _ in rows if tag == DT_NULL)
        struct.pack_into("<qQ", malformed, first_null, DT_RELACOUNT, count + 1)
        with self.assertRaisesRegex(SystemExit, "DT_RELACOUNT disagrees"):
            PACKER_MODULE.pack(malformed)

    def test_reuses_a_relacount_that_matches_the_leading_block(self):
        image = bytearray(self.source_image)
        _, rows = dynamic_rows(image)
        entries = {tag: value for _, tag, value in rows if tag != DT_NULL}
        table = file_offset(image, entries[DT_RELA])
        count = 0
        while count * 24 < entries[DT_RELASZ]:
            _, info, _ = struct.unpack_from("<QQq", image, table + count * 24)
            if info != R_X86_64_RELATIVE:
                break
            count += 1
        first_null = next(at for at, tag, _ in rows if tag == DT_NULL)
        struct.pack_into("<qQ", image, first_null, DT_RELACOUNT, count)

        self.assertEqual(PACKER_MODULE.pack(image), count)

        _, packed_rows = dynamic_rows(image)
        packed_tags = {tag: value for _, tag, value in packed_rows if tag != DT_NULL}
        self.assertNotIn(DT_RELACOUNT, packed_tags)
        self.assertEqual(packed_tags[DT_RELR], entries[DT_RELA])
        self.assertEqual(next(tag for at, tag, _ in packed_rows if at == first_null), DT_RELR)

    def test_rejects_missing_padding_slot(self):
        malformed = bytearray(self.source_image)
        dynamic, rows = dynamic_rows(malformed)
        terminator = next(index for index, row in enumerate(rows) if row[1] == DT_NULL)
        phoff = struct.unpack_from("<Q", malformed, 32)[0]
        phentsize, phnum = struct.unpack_from("<HH", malformed, 54)
        dynamic_header = next(
            index for index in range(phnum)
            if struct.unpack_from("<I", malformed, phoff + index * phentsize)[0] == PT_DYNAMIC
        )
        header_at = phoff + dynamic_header * phentsize
        size = (terminator + 1) * 16
        struct.pack_into("<QQ", malformed, header_at + 32, size, size)
        with self.assertRaisesRegex(SystemExit, "no dynamic-table slot remains"):
            PACKER_MODULE.pack(malformed)

    def test_rejects_rela_table_without_a_leading_relative_block(self):
        malformed = bytearray(self.source_image)
        _, rows = dynamic_rows(malformed)
        entries = {tag: value for _, tag, value in rows if tag != DT_NULL}
        struct.pack_into("<Q", malformed, file_offset(malformed, entries[DT_RELA]) + 8, 1)
        with self.assertRaisesRegex(SystemExit, "no leading RELATIVE block"):
            PACKER_MODULE.pack(malformed)


if __name__ == "__main__":
    unittest.main()
