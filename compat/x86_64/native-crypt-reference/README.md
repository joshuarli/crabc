# Fixed libc-test crypt source reference

`crypt.c` is an unchanged copy of `src/functional/crypt.c` from
`https://github.com/laputa-systems/libc-test.git`, revision
`68edb8bd73dab8147ee54c8bec638f4d2b3cff37`, Git tree
`4f7a5373652c6534b0fbafb58fe3fed1489f3b3b`.
Its SHA-256 is `d25b9d533b304f9bbae0c8eae8212196e431fdbeb18e805aebf667741235aafe`.
The adjacent `COPYRIGHT` is the upstream license notice.

This is reference data for the finite native profile disposition, never a
replacement aggregate test. The companion extracts all 32 active `T` calls,
retains their original source-line identity, and generates a separate observer
that reports actual nonnull/output observations. Native qualification requires
its full prepared original source to equal this reference byte-for-byte.
Commented-out calls remain inactive; no source or upstream comparator is edited.
