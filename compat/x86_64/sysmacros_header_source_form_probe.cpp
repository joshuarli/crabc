/* Direct Linux/x86-64 C++17 sys/sysmacros.h source-form probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <sys/sysmacros.h>

static_assert(major(makedev(0x12345U, 0x6789abU)) == 0x12345U,
    "C++ x86 major/makedev round trip");
static_assert(minor(makedev(0x12345U, 0x6789abU)) == 0x6789abU,
    "C++ x86 minor/makedev round trip");

extern "C" int crabc_x86_sysmacros_header_source_form_probe_cpp()
{
    return static_cast<int>(minor(makedev(0x12345U, 0x6789abU)));
}
