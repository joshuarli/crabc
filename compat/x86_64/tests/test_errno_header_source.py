#!/usr/bin/env python3
"""Source-form contract for the x86 pinned-musl errno headers."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]


class ErrnoHeaderSourceTests(unittest.TestCase):
    def test_x86_errno_header_uses_musl_feature_and_bits_boundaries(self) -> None:
        header = (ROOT / "include/errno.h").read_text(encoding="utf-8")
        x86 = header.split("#else\n", 1)[0]
        self.assertIn("#ifndef\t_ERRNO_H\n", x86)
        self.assertIn("#include <features.h>\n", x86)
        self.assertIn("#include <bits/errno.h>\n", x86)
        self.assertIn("__attribute__((const))", x86)
        self.assertIn("program_invocation_short_name, *program_invocation_name", x86)
        self.assertNotIn("#define EPERM", x86)

    def test_x86_bits_errno_retains_pinned_linux_values_and_aliases(self) -> None:
        bits = (ROOT / "include/bits/errno.h").read_text(encoding="utf-8")
        for definition in (
            "#define EPERM            1",
            "#define EWOULDBLOCK      EAGAIN",
            "#define EDEADLOCK        EDEADLK",
            "#define ENOTSUP          EOPNOTSUPP",
            "#define EHWPOISON        133",
        ):
            self.assertIn(definition, bits)

    def test_aarch64_errno_body_remains_the_legacy_fallback(self) -> None:
        fallback = (ROOT / "include/errno.h").read_text(encoding="utf-8").split(
            "#else\n", 1
        )[1]
        self.assertIn("#define EWOULDBLOCK EAGAIN", fallback)
        self.assertIn("#define EHWPOISON 133", fallback)
        self.assertNotIn("program_invocation_short_name", fallback)


if __name__ == "__main__":
    unittest.main()
