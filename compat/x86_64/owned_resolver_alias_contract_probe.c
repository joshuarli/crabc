/*
 * The receipt intentionally executes the established public resolver fixture
 * from one source-compiled translation unit. That fixture carries the private
 * chroot and loopback DNS setup; this wrapper must not invent resolver policy.
 */
#include "libc_resolver_runtime_probe.c"
