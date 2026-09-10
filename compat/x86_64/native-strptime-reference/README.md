# Fixed libc-test strptime source reference

`strptime.c` is an unchanged copy of `src/functional/strptime.c` from
`https://github.com/laputa-systems/libc-test.git`, revision
`68edb8bd73dab8147ee54c8bec638f4d2b3cff37`, Git tree
`4f7a5373652c6534b0fbafb58fe3fed1489f3b3b`.
Its SHA-256 is
`af24cbeb224b18937c7396ce38710df72f7e35ba896dc5603de2119d16cffe8c`.
The adjacent `COPYRIGHT` is the upstream MIT license notice.

This is source reference data for one finite native profile disposition. It
does not replace the upstream unit or change its raw result. Qualification
requires the prepared source to equal these bytes and both candidate and
pinned-musl runs to retain exactly the two original diagnostics and exit 1.
The diagnostic calls are in the upstream file's `/* Glibc */` block; ordinary
`strptime` behavior remains covered by the untouched upstream unit and the
installed numeric/calendar component.
