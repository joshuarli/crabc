/* Static x86-64 insque/remque C ABI and pinned-musl behavioral fixture.
 *
 * One fixture executes unchanged through pinned musl and the selected true
 * static archive. It proves the exact caller-owned two-link node prefix:
 * null-predecessor reset, insertion before an existing successor, and
 * neighbor repair with remque retaining a removed node's own links.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <search.h>

typedef void (*insque_signature)(void *, void *);
typedef void (*remque_signature)(void *);

_Static_assert(sizeof(void *) == 8, "x86 LP64 pointer width");
_Static_assert(__builtin_types_compatible_p(__typeof__(&insque),
    insque_signature), "insque declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&remque),
    remque_signature), "remque declaration");

struct node {
    struct node *next;
    struct node *prev;
    unsigned char payload[11];
};

_Static_assert(offsetof(struct node, next) == 0, "next begins the node");
_Static_assert(offsetof(struct node, prev) == sizeof(void *),
    "prev follows next");
_Static_assert(_Alignof(struct node) >= _Alignof(void *),
    "node preserves pointer alignment");

static void fill_payload(struct node *node, unsigned char seed)
{
    size_t index;

    for (index = 0; index < sizeof(node->payload); ++index)
        node->payload[index] = (unsigned char)(seed + index);
}

static int has_payload(const struct node *node, unsigned char seed)
{
    size_t index;

    for (index = 0; index < sizeof(node->payload); ++index) {
        if (node->payload[index] != (unsigned char)(seed + index))
            return 0;
    }
    return 1;
}

static int check_null_predecessor_reset(void)
{
    struct node stale_next = { 0 };
    struct node stale_prev = { 0 };
    struct node element = { 0 };
    const insque_signature insert = insque;

    stale_next.prev = &stale_prev;
    stale_prev.next = &stale_next;
    element.next = &stale_next;
    element.prev = &stale_prev;
    fill_payload(&element, 0x30);

    insert(&element, NULL);
    if (element.next != NULL || element.prev != NULL ||
        stale_next.prev != &stale_prev || stale_prev.next != &stale_next)
        return 1;
    return has_payload(&element, 0x30) ? 0 : 2;
}

static int check_splice_and_unlink(void)
{
    struct node first = { 0 };
    struct node successor = { 0 };
    struct node element = { 0 };
    const insque_signature insert = insque;
    const remque_signature remove = remque;

    first.next = &successor;
    successor.prev = &first;
    fill_payload(&first, 0x10);
    fill_payload(&successor, 0x50);
    fill_payload(&element, 0x90);

    insert(&element, &first);
    if (first.next != &element || first.prev != NULL ||
        element.next != &successor || element.prev != &first ||
        successor.prev != &element || successor.next != NULL)
        return 1;
    if (!has_payload(&first, 0x10) || !has_payload(&successor, 0x50) ||
        !has_payload(&element, 0x90))
        return 2;

    remove(&element);
    if (first.next != &successor || successor.prev != &first ||
        element.next != &successor || element.prev != &first)
        return 3;
    if (!has_payload(&first, 0x10) || !has_payload(&successor, 0x50) ||
        !has_payload(&element, 0x90))
        return 4;

    remove(&first);
    if (successor.prev != NULL || first.next != &successor ||
        first.prev != NULL)
        return 5;
    remove(&successor);
    return successor.next == NULL && successor.prev == NULL ? 0 : 6;
}

int crabc_x86_64_intrusive_queue_probe(void)
{
    int result = check_null_predecessor_reset();

    if (result != 0)
        return result;
    result = check_splice_and_unlink();
    return result == 0 ? 0 : 10 + result;
}

#ifndef CRABC_INTRUSIVE_QUEUE_FREESTANDING
int main(void)
{
    return crabc_x86_64_intrusive_queue_probe();
}
#endif
