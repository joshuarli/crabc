# LLVM/Clang integration (future)

Once `plan.md` is complete, crabc is meant to become the C runtime substrate
of an LLVM/Clang toolchain. crabc would supply the public C/POSIX headers,
libc, dynamic loader, startup objects, and a sealed sysroot, and LLVM would
supply Clang, LLVM, lld, compiler-rt, libunwind, libc++abi, and libc++.

That integration is out of scope until then. No current work, gate, or
requirement depends on it.
