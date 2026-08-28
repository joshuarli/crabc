# Upstream provenance

## Gregorian UTC conversion

`crabc-rs/src/civil_time.rs` contains a semantic Rust translation of the
Gregorian UTC kernels in the pinned musl **1.2.6** release. The authoritative
source is the SHA-256-verified
[`musl-1.2.6.tar.gz`](https://musl.libc.org/releases/musl-1.2.6.tar.gz)
archive (`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`),
with the matching upstream release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`. Both pins are recorded in
`compat/upstreams.toml`.

| Pinned musl source | Function | Rust target | Intentional Rust-native difference |
| --- | --- | --- | --- |
| `src/time/__secs_to_tm.c` | `__secs_to_tm` | `civil_time::calendar_from_unix_seconds` | Uses `i128` with Euclidean division/remainder rather than C quotient/remainder repair; returns `Errno::RANGE` and an owned `CalendarTime`, never a mutable `struct tm *`, `-1`, or TLS `errno`. |
| `src/time/__year_to_secs.c` | `__year_to_secs` | `civil_time::year_to_seconds` | Preserves the material `year-2ULL <= 136` fast path and the 400-year negative-year correction while using `i128` and a mandatory Rust `&mut bool`, with no C signed-overflow or nullable-output-pointer behavior. |
| `src/time/__month_to_secs.c` | `__month_to_secs` | `civil_time::MONTH_DAYS_BEFORE` and the month term in `civil_time::calendar_seconds` | Stores the fixed month offsets as a typed table; no C `struct tm` field normalization is accepted at the public boundary. |
| `src/time/__tm_to_secs.c` | `__tm_to_secs` | `civil_time::calendar_seconds` | Accepts only a normalized `CalendarTime`; unlike musl's mutable `struct tm` path, invalid fields are rejected and no input is rewritten. |
| `src/time/gmtime_r.c` | `gmtime_r` | `time::gmtime` / `CalendarTime::from_unix_seconds` | Omits C output storage, `tm_isdst`, `tm_gmtoff`, `tm_zone`, and TLS-`errno` protocol. |
| `src/time/timegm.c` | `timegm` | `time::timegm` / `CalendarTime::unix_seconds` | Is strict and non-mutating rather than normalizing or rewriting a C `struct tm`. |
| `src/time/difftime.c` | `difftime` | `time::difftime` | Casts both signed operands independently before subtraction so no signed integer intermediate can overflow. |

The implementation preserves musl's March-2000 epoch, 400/100/4-year cycle
decomposition, weekday/year-day calculation, `tm_year`-fits-`int` bound, and
the material fast-path and negative-year behavior named above. It deliberately
does not port C time APIs, C record layouts, global `TZ` state, zoneinfo I/O,
or `mktime`-style ambiguous local-time conversion.

### License provenance

These musl `src/time/*.c` files carry no individual copyright notice. The
pinned release's root `COPYRIGHT` states that musl as a whole is standard MIT
licensed and identifies ordinary source files as musl-original work by Rich
Felker and/or contributors recorded in the git history. These files are not
among that file's listed third-party exceptions. The retained notice is:

> Copyright © 2005-2020 Rich Felker, et al.
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in
> all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
> THE SOFTWARE.
