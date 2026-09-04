// Direct pinned-musl x86 <sys/klog.h> source-form and C-linkage witness.

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/klog.h>

#ifndef _SYS_KLOG_H
#error "<sys/klog.h> must retain musl's public guard"
#endif

#if defined(KLOG_CLOSE) || defined(KLOG_OPEN) || defined(KLOG_READ) || \
    defined(KLOG_READ_ALL) || defined(KLOG_READ_CLEAR) || \
    defined(KLOG_CLEAR) || defined(KLOG_CONSOLE_OFF) || \
    defined(KLOG_CONSOLE_ON) || defined(KLOG_CONSOLE_LEVEL) || \
    defined(KLOG_SIZE_UNREAD) || defined(KLOG_SIZE_BUFFER)
#error "<sys/klog.h> must not leak non-musl KLOG command macros"
#endif

using klogctl_signature = int (*)(int, char *, int);
static_assert(__is_same(decltype(&klogctl), klogctl_signature));

__attribute__((used)) static klogctl_signature klogctl_reference = klogctl;

extern "C" int crabc_x86_klog_header_source_form_probe_cpp()
{
    return klogctl(-1, nullptr, 0);
}
