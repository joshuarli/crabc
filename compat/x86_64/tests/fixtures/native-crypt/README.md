# Original native libc-test crypt diagnostics

`candidate.stdout` is the unmodified raw stream from
`.work/x86_64/tmp/owned-libc-test.GETcCg/execution/functional/crypt/candidate.stdout`.
Its SHA-256 is `95d5eda0a0ba43a027e6ad4bafcf64b0eccfcaaa896d227cf77f91d3fc1a52f9`.
That original unit exited 1 with empty stderr; pinned musl exited 0 with both
streams empty. The prepared source is the exact reference documented in
`compat/x86_64/native-crypt-reference/README.md`; source-derived diagnostic
strings retain that reference's MIT license and copyright notice.

This fixture independently fixes the real diagnostic spelling, including the
first invocation line of multiline `T` calls. Tests replace only the recorded
absolute source path with their private fixture path. They do not generate
these expected diagnostics from the disposition parser. This single retained
unit is not qualification of the historical incomplete GETcCg campaign.
