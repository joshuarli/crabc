/* Static x86-64 insque/remque C ABI and pinned-musl behavioral fixture.
 *
 * One caller-owned node layout executes unchanged through pinned musl 1.2.6
 * and the selected true-static archive. It proves only musl's first-two-word
 * intrusive link rewiring: null-predecessor initialization, middle/tail
 * insertion, neighbor reconnection, and a removed node's intentionally stale
 * links. It does not allocate, search, retain a queue, synchronize, or touch
 * a process/filesystem/runtime boundary.
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

_Static_assert(sizeof(void *) == 8 && _Alignof(void *) == 8,
    "x86 LP64 pointer ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&insque),
    insque_signature), "insque declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&remque),
    remque_signature), "remque declaration");

struct intrusive_node {
    struct intrusive_node *next;
    struct intrusive_node *previous;
    unsigned long tag;
};

_Static_assert(offsetof(struct intrusive_node, next) == 0,
    "first intrusive link word");
_Static_assert(offsetof(struct intrusive_node, previous) == sizeof(void *),
    "second intrusive link word");

static int check_null_predecessor(void)
{
    struct intrusive_node node = { (void *)1, (void *)2, 11 };
    const insque_signature insertion = insque;

    insertion(&node, NULL);
    return node.next == NULL && node.previous == NULL && node.tag == 11 ? 0 : 1;
}

static int check_middle_splice_and_remove(void)
{
    struct intrusive_node left = { NULL, NULL, 21 };
    struct intrusive_node right = { NULL, &left, 22 };
    struct intrusive_node middle = { (void *)3, (void *)4, 23 };
    const insque_signature insertion = insque;
    const remque_signature removal = remque;

    left.next = &right;
    insertion(&middle, &left);
    if (left.next != &middle || middle.previous != &left ||
        middle.next != &right || right.previous != &middle ||
        left.tag != 21 || right.tag != 22 || middle.tag != 23)
        return 1;

    removal(&middle);
    if (left.next != &right || right.previous != &left)
        return 2;
    /* musl reconnects neighbors but deliberately retains these stale links. */
    if (middle.previous != &left || middle.next != &right || middle.tag != 23)
        return 3;
    return 0;
}

static int check_tail_and_head_edges(void)
{
    struct intrusive_node head = { NULL, NULL, 31 };
    struct intrusive_node tail = { NULL, &head, 32 };
    struct intrusive_node inserted = { NULL, NULL, 33 };

    head.next = &tail;
    insque(&inserted, &tail);
    if (head.next != &tail || tail.next != &inserted ||
        inserted.previous != &tail || inserted.next != NULL)
        return 1;

    remque(&inserted);
    if (tail.next != NULL || inserted.previous != &tail || inserted.next != NULL)
        return 2;

    remque(&head);
    if (tail.previous != NULL || head.next != &tail || head.previous != NULL ||
        head.tag != 31 || tail.tag != 32)
        return 3;
    return 0;
}

int crabc_x86_64_intrusive_queue_probe(void)
{
    int result = check_null_predecessor();

    if (result != 0)
        return result;
    result = check_middle_splice_and_remove();
    if (result != 0)
        return 10 + result;
    result = check_tail_and_head_edges();
    return result == 0 ? 0 : 20 + result;
}

#ifndef CRABC_INTRUSIVE_QUEUE_FREESTANDING
int main(void)
{
    return crabc_x86_64_intrusive_queue_probe();
}
#endif
