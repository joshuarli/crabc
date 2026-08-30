/* Linux/x86-64 <sys/uio.h> C ABI profile probe.
 *
 * Pinned musl 1.2.6 owns this selected declaration, feature-visibility, LP64
 * layout, and large-file spelling contract. This probe intentionally proves
 * no runtime vector-I/O behavior or crabc-libc implementation.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if (defined(CRABC_VECTOR_IO_BASE) + defined(CRABC_VECTOR_IO_POSITIONED) + \
     defined(CRABC_VECTOR_IO_POSITIONED_LARGEFILE64)) != 1
#error "select exactly one vector-I/O header profile class"
#endif

#include <stddef.h>
#include <sys/uio.h>

_Static_assert(sizeof(struct iovec) == 16 && _Alignof(struct iovec) == 8,
    "x86 struct iovec ABI");
_Static_assert(offsetof(struct iovec, iov_base) == 0 &&
    offsetof(struct iovec, iov_len) == 8, "x86 struct iovec field offsets");
_Static_assert(UIO_MAXIOV == 1024, "x86 UIO_MAXIOV value");

typedef ssize_t (*readv_signature)(int, const struct iovec *, int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&readv),
    readv_signature), "readv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&writev),
    readv_signature), "writev declaration");

#if defined(CRABC_VECTOR_IO_POSITIONED) || \
    defined(CRABC_VECTOR_IO_POSITIONED_LARGEFILE64)
typedef ssize_t (*positioned_signature)(int, const struct iovec *, int, off_t);

_Static_assert(__builtin_types_compatible_p(__typeof__(&preadv),
    positioned_signature), "preadv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pwritev),
    positioned_signature), "pwritev declaration");
#endif

#ifdef _GNU_SOURCE
typedef ssize_t (*positioned_v2_signature)(int, const struct iovec *, int,
    off_t, int);
typedef ssize_t (*process_vm_signature)(pid_t, const struct iovec *,
    unsigned long, const struct iovec *, unsigned long, unsigned long);

_Static_assert(__builtin_types_compatible_p(__typeof__(&preadv2),
    positioned_v2_signature), "preadv2 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pwritev2),
    positioned_v2_signature), "pwritev2 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&process_vm_readv),
    process_vm_signature), "process_vm_readv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&process_vm_writev),
    process_vm_signature), "process_vm_writev declaration");
_Static_assert(RWF_HIPRI == 0x00000001 && RWF_DSYNC == 0x00000002 &&
    RWF_SYNC == 0x00000004 && RWF_NOWAIT == 0x00000008 &&
    RWF_APPEND == 0x00000010 && RWF_NOAPPEND == 0x00000020,
    "GNU RWF values");
#endif

#if defined(CRABC_VECTOR_IO_BASE)
#ifdef preadv64
#error "preadv64 must stay hidden without the selected large-file extension"
#endif
#ifdef pwritev64
#error "pwritev64 must stay hidden without the selected large-file extension"
#endif
#ifdef off64_t
#error "off64_t must stay hidden without the selected large-file extension"
#endif
#endif

#if defined(CRABC_VECTOR_IO_POSITIONED_LARGEFILE64)
#ifndef _LARGEFILE64_SOURCE
#error "large-file vector-I/O profile requires _LARGEFILE64_SOURCE"
#endif
#ifndef preadv64
#error "selected large-file extension must expose preadv64"
#endif
#ifndef pwritev64
#error "selected large-file extension must expose pwritev64"
#endif
#ifndef off64_t
#error "selected large-file extension must expose off64_t"
#endif

typedef off64_t vector_io_off64_alias;
_Static_assert(__builtin_types_compatible_p(vector_io_off64_alias, off_t),
    "off64_t macro alias");
_Static_assert(__builtin_types_compatible_p(__typeof__(&preadv64),
    positioned_signature), "preadv64 macro alias declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pwritev64),
    positioned_signature), "pwritev64 macro alias declaration");
#endif

#ifdef CRABC_VECTOR_IO_REQUIRE_POSITIONED_HIDDEN
static ssize_t (*vector_io_positioned_must_be_hidden)(int,
    const struct iovec *, int, long) = preadv;
#endif

#ifdef CRABC_VECTOR_IO_REQUIRE_GNU_V2_HIDDEN
static int vector_io_gnu_v2_must_be_hidden = sizeof(&preadv2);
#endif

#ifdef CRABC_VECTOR_IO_REQUIRE_GNU_PROCESS_VM_HIDDEN
static int vector_io_gnu_process_vm_must_be_hidden = sizeof(&process_vm_readv);
#endif

#ifdef CRABC_VECTOR_IO_REQUIRE_GNU_RWF_HIDDEN
#if defined(RWF_HIPRI) || defined(RWF_DSYNC) || defined(RWF_SYNC) || \
    defined(RWF_NOWAIT) || defined(RWF_APPEND) || defined(RWF_NOAPPEND)
#error "GNU RWF constants must stay hidden outside _GNU_SOURCE"
#endif
#endif

int crabc_x86_64_vector_io_header_abi_probe(void)
{
    return UIO_MAXIOV;
}
