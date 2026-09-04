/* Native Linux/x86-64 C++17 <sys/fanotify.h> event-traversal macro probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/fanotify.h>

#ifndef FAN_EVENT_METADATA_LEN
#error "musl fanotify metadata length macro is missing"
#endif
#ifndef FAN_EVENT_NEXT
#error "musl fanotify traversal macro is missing"
#endif
#ifndef FAN_EVENT_OK
#error "musl fanotify record-validity macro is missing"
#endif

static fanotify_event_metadata first{};
static unsigned long remaining{};

static_assert(sizeof(struct fanotify_event_metadata) == 24,
    "musl x86 fanotify metadata record size");
static_assert(alignof(struct fanotify_event_metadata) == 8,
    "musl x86 fanotify metadata record alignment");
static_assert(__builtin_offsetof(struct fanotify_event_metadata, event_len) == 0 &&
    __builtin_offsetof(struct fanotify_event_metadata, vers) == 4 &&
    __builtin_offsetof(struct fanotify_event_metadata, reserved) == 5 &&
    __builtin_offsetof(struct fanotify_event_metadata, metadata_len) == 6 &&
    __builtin_offsetof(struct fanotify_event_metadata, mask) == 8 &&
    __builtin_offsetof(struct fanotify_event_metadata, fd) == 16 &&
    __builtin_offsetof(struct fanotify_event_metadata, pid) == 20,
    "musl x86 fanotify metadata record offsets");
static_assert(FAN_EVENT_METADATA_LEN == sizeof(struct fanotify_event_metadata),
    "fanotify metadata length macro");
static_assert(__is_same(decltype(FAN_EVENT_METADATA_LEN), unsigned long),
    "fanotify metadata length type");
static_assert(__is_same(decltype(FAN_EVENT_NEXT(&first, remaining)),
    struct fanotify_event_metadata *), "fanotify next-record type");
static_assert(__is_same(decltype(FAN_EVENT_OK(&first, remaining)), bool),
    "fanotify record-validity type");
static_assert(sizeof(struct fanotify_event_info_header) == 4 &&
    alignof(struct fanotify_event_info_header) == 2,
    "fanotify info header layout");
static_assert(sizeof(struct fanotify_response) == 8 &&
    alignof(struct fanotify_response) == 4 &&
    __builtin_offsetof(struct fanotify_response, response) == 4,
    "fanotify response layout");
static_assert(FANOTIFY_METADATA_VERSION == 3 && FAN_EVENT_INFO_TYPE_FID == 1 &&
    FAN_EVENT_INFO_TYPE_DFID_NAME == 2 && FAN_EVENT_INFO_TYPE_DFID == 3 &&
    FAN_NOFD == -1, "fanotify protocol constants");
static_assert(FAN_MARK_FILESYSTEM == 0x100 &&
    FAN_ALL_CLASS_BITS == 0x0c && FAN_ALL_EVENTS == 0x3b,
    "fanotify aggregate constants");

/* Form both macros through a properly aligned caller-owned record array. */
static void fanotify_macro_expression_formation()
{
    struct fanotify_event_metadata records[2]{};
    unsigned long bytes = sizeof(records);
    struct fanotify_event_metadata *next;

    records[0].event_len = FAN_EVENT_METADATA_LEN;
    next = FAN_EVENT_NEXT(&records[0], bytes);
    (void)FAN_EVENT_OK(&records[0], bytes);
    (void)FAN_EVENT_OK(next, bytes);
}

int crabc_x86_64_fanotify_header_abi_probe_cpp()
{
    (void)fanotify_macro_expression_formation;
    return 0;
}
