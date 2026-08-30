/* Linux/x86-64 <sys/uio.h> C++17 ABI profile probe. */

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

static_assert(sizeof(struct iovec) == 16 && alignof(struct iovec) == 8,
    "x86 struct iovec ABI");
static_assert(__builtin_offsetof(struct iovec, iov_base) == 0 &&
    __builtin_offsetof(struct iovec, iov_len) == 8,
    "x86 struct iovec field offsets");
static_assert(UIO_MAXIOV == 1024, "x86 UIO_MAXIOV value");

using readv_signature = ssize_t (*)(int, const struct iovec *, int);

static_assert(__is_same(decltype(&readv), readv_signature),
    "readv C++ declaration");
static_assert(__is_same(decltype(&writev), readv_signature),
    "writev C++ declaration");

__attribute__((used)) static readv_signature vector_io_cxx_readv = readv;
__attribute__((used)) static readv_signature vector_io_cxx_writev = writev;

#if defined(CRABC_VECTOR_IO_POSITIONED) || \
    defined(CRABC_VECTOR_IO_POSITIONED_LARGEFILE64)
using positioned_signature = ssize_t (*)(int, const struct iovec *, int, off_t);

static_assert(__is_same(decltype(&preadv), positioned_signature),
    "preadv C++ declaration");
static_assert(__is_same(decltype(&pwritev), positioned_signature),
    "pwritev C++ declaration");

__attribute__((used)) static positioned_signature vector_io_cxx_preadv = preadv;
__attribute__((used)) static positioned_signature vector_io_cxx_pwritev = pwritev;
#endif

#ifdef _GNU_SOURCE
using positioned_v2_signature = ssize_t (*)(int, const struct iovec *, int,
    off_t, int);
using process_vm_signature = ssize_t (*)(pid_t, const struct iovec *,
    unsigned long, const struct iovec *, unsigned long, unsigned long);

static_assert(__is_same(decltype(&preadv2), positioned_v2_signature),
    "preadv2 C++ declaration");
static_assert(__is_same(decltype(&pwritev2), positioned_v2_signature),
    "pwritev2 C++ declaration");
static_assert(__is_same(decltype(&process_vm_readv), process_vm_signature),
    "process_vm_readv C++ declaration");
static_assert(__is_same(decltype(&process_vm_writev), process_vm_signature),
    "process_vm_writev C++ declaration");
static_assert(RWF_HIPRI == 0x00000001 && RWF_DSYNC == 0x00000002 &&
    RWF_SYNC == 0x00000004 && RWF_NOWAIT == 0x00000008 &&
    RWF_APPEND == 0x00000010 && RWF_NOAPPEND == 0x00000020,
    "GNU RWF values");

__attribute__((used)) static positioned_v2_signature vector_io_cxx_preadv2 = preadv2;
__attribute__((used)) static positioned_v2_signature vector_io_cxx_pwritev2 = pwritev2;
__attribute__((used)) static process_vm_signature vector_io_cxx_process_vm_readv = process_vm_readv;
__attribute__((used)) static process_vm_signature vector_io_cxx_process_vm_writev = process_vm_writev;
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

using vector_io_off64_alias = off64_t;
static_assert(__is_same(vector_io_off64_alias, off_t), "off64_t macro alias");
static_assert(__is_same(decltype(&preadv64), positioned_signature),
    "preadv64 macro alias declaration");
static_assert(__is_same(decltype(&pwritev64), positioned_signature),
    "pwritev64 macro alias declaration");

__attribute__((used)) static positioned_signature vector_io_cxx_preadv64 = preadv64;
__attribute__((used)) static positioned_signature vector_io_cxx_pwritev64 = pwritev64;
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

int crabc_x86_64_vector_io_header_abi_probe_cpp()
{
    return UIO_MAXIOV;
}
