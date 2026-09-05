# Owned legacy time and clock adjustment

The installed native x86-64 products provide `times`, `getitimer`,
`setitimer`, `ualarm`, `adjtime`, `adjtimex`, `settimeofday`, and `stime`.
The owned runtime profile composes the already-verified
`x86-interval-timers` and `x86-ualarm` leaves for the three interval-timer
spellings. It directly owns the remaining `times` and clock-adjustment source
slice in
`libc/src/c_abi/x86_64/owned_legacy_time.rs`. `clock_adjtime` remains its
separate syscall owner; `getrusage`, `clock`, and `nanosleep` retain their
existing owners.

The translation follows pinned musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license in
`COPYRIGHT`. The source map is `src/time/times.c::times`,
`src/signal/getitimer.c::getitimer`, `src/signal/setitimer.c::setitimer`,
`src/unistd/ualarm.c::ualarm`, `src/linux/adjtime.c::adjtime`,
`src/linux/adjtimex.c::adjtimex`, `src/linux/settimeofday.c::settimeofday`,
and `src/linux/stime.c::stime`. `times` intentionally preserves Linux's raw
signed result: a negative `clock_t` can be elapsed-tick wrap rather than an
errno value. `adjtime` preserves musl's narrow source bounds, LP64 wrapping
microsecond conversion, zero-mode query, and canonical negative remainder
normalization. `adjtimex` uses the existing `clock_adjtime(CLOCK_REALTIME, …)`
C boundary, including normal `-1` and initial-TLS `errno` publication.
`settimeofday` preserves musl's null success, unsigned microsecond rejection,
and realtime `clock_settime` conversion; `stime` preserves its direct LP64
`time_t` dereference and zero-microsecond `settimeofday` adapter.

Run `./scripts/dev-x86_64.sh owned-legacy-time`. The runner compiles one
installed-header C object and runs it with pinned musl, installed static and
static-PIE products, and dynamic PIE/non-PIE applications through both kernel
and direct-interpreter entry. It checks strong static and global-default shared
providers; accounting ticks without negative-result misclassification;
process timer query, disarm, SIGALRM delivery, cancellation, and invalid-input
state preservation; and local `timeval` validation. Clock adjustment is never
successfully requested: query modes use a null adjustment or zero `timex`
modes, and every
non-null `adjtime`, `settimeofday`, or `stime` error path runs only after a
disposable child installs a seccomp `EPERM` filter for both adjustment and both
clock-setting syscalls. `settimeofday(NULL, …)` is also checked as musl's
non-mutating success path.

This component slice does not select host clock mutation, timer policy outside
the process fixture, general time/calendar behavior, runtime-family completion,
or public native-x86 support. It is a required dynamic product qualification
case.
