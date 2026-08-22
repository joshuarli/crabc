# M12 stock-`std` fixture

This is the isolated stock-Rust-`std` companion to the no-std native fixture.
It depends only on the direct `crabc-rs` facade, performs a deterministic
direct write, and emits `m12-stock-std:ok`.
There are no C `extern` declarations in the fixture; the normal `std` runtime
is intentionally part of this lane's LTO/dynamic-linking boundary.

The Docker harness should build it as an AArch64 musl binary with its selected
fat-LTO flags, then stage the matching musl interpreter and `libc.so` beside
the executable before running it. The direct facade witness is exported as
`crabc_rs_m12_getpid_witness` and consumed by `m12_std_direct_route`; the main
function's `std` output remains the runtime assertion for the stock-`std` lane.
