/* Native Linux/x86-64 GNU <sched.h> CPU-set construction macro probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sched.h>

#if defined(CRABC_REQUIRE_CPU_MACROS_HIDDEN)
#if defined(CPU_ALLOC) || defined(CPU_ALLOC_SIZE) || defined(CPU_AND) || \
    defined(CPU_AND_S) || defined(CPU_CLR) || defined(CPU_CLR_S) || \
    defined(CPU_EQUAL) || defined(CPU_EQUAL_S) || defined(CPU_FREE) || \
    defined(CPU_ISSET) || defined(CPU_ISSET_S) || defined(CPU_OR) || \
    defined(CPU_OR_S) || defined(CPU_SET) || defined(CPU_SET_S) || \
    defined(CPU_SETSIZE) || defined(CPU_XOR) || defined(CPU_XOR_S) || \
    defined(CPU_ZERO) || defined(CPU_ZERO_S) || defined(__CPU_op_S) || \
    defined(__CPU_op_func_S)
#error "CPU-set construction macros must remain GNU-only"
#endif
#endif

#if defined(CRABC_EXPECT_CPU_MACROS)
#ifndef CPU_ALLOC
#error "GNU <sched.h> must expose CPU_ALLOC"
#endif
#ifndef CPU_ALLOC_SIZE
#error "GNU <sched.h> must expose CPU_ALLOC_SIZE"
#endif
#ifndef CPU_AND
#error "GNU <sched.h> must expose CPU_AND"
#endif
#ifndef CPU_AND_S
#error "GNU <sched.h> must expose CPU_AND_S"
#endif
#ifndef CPU_CLR
#error "GNU <sched.h> must expose CPU_CLR"
#endif
#ifndef CPU_CLR_S
#error "GNU <sched.h> must expose CPU_CLR_S"
#endif
#ifndef CPU_EQUAL
#error "GNU <sched.h> must expose CPU_EQUAL"
#endif
#ifndef CPU_EQUAL_S
#error "GNU <sched.h> must expose CPU_EQUAL_S"
#endif
#ifndef CPU_FREE
#error "GNU <sched.h> must expose CPU_FREE"
#endif
#ifndef CPU_ISSET
#error "GNU <sched.h> must expose CPU_ISSET"
#endif
#ifndef CPU_ISSET_S
#error "GNU <sched.h> must expose CPU_ISSET_S"
#endif
#ifndef CPU_OR
#error "GNU <sched.h> must expose CPU_OR"
#endif
#ifndef CPU_OR_S
#error "GNU <sched.h> must expose CPU_OR_S"
#endif
#ifndef CPU_SET
#error "GNU <sched.h> must expose CPU_SET"
#endif
#ifndef CPU_SET_S
#error "GNU <sched.h> must expose CPU_SET_S"
#endif
#ifndef CPU_SETSIZE
#error "GNU <sched.h> must expose CPU_SETSIZE"
#endif
#ifndef CPU_XOR
#error "GNU <sched.h> must expose CPU_XOR"
#endif
#ifndef CPU_XOR_S
#error "GNU <sched.h> must expose CPU_XOR_S"
#endif
#ifndef CPU_ZERO
#error "GNU <sched.h> must expose CPU_ZERO"
#endif
#ifndef CPU_ZERO_S
#error "GNU <sched.h> must expose CPU_ZERO_S"
#endif
#ifndef __CPU_op_S
#error "GNU <sched.h> must expose __CPU_op_S"
#endif
#ifndef __CPU_op_func_S
#error "GNU <sched.h> must expose __CPU_op_func_S"
#endif

#define CRABC_TYPE_IS(expression, type) \
    __builtin_types_compatible_p(__typeof__(expression), type)

typedef int (*memcmp_signature)(const void *, const void *, size_t);
typedef void *(*memset_signature)(void *, int, size_t);
typedef void *(*calloc_signature)(size_t, size_t);
typedef void (*free_signature)(void *);
typedef void (*cpu_binary_signature)(
    size_t, cpu_set_t *, const cpu_set_t *, const cpu_set_t *);

static cpu_set_t macro_set;

__CPU_op_func_S(PROBE, ^)

_Static_assert(sizeof(cpu_set_t) == 128, "musl cpu_set_t width");
_Static_assert(_Alignof(cpu_set_t) == _Alignof(unsigned long),
    "musl cpu_set_t alignment");
_Static_assert(CPU_SETSIZE == 1024, "musl CPU_SETSIZE");
_Static_assert(CPU_ALLOC_SIZE(0) == 0, "zero-bit allocation size");
_Static_assert(CPU_ALLOC_SIZE(1) == 8, "one-bit allocation size");
_Static_assert(CPU_ALLOC_SIZE(64) == 8, "one-word allocation size");
_Static_assert(CPU_ALLOC_SIZE(65) == 16, "next-word allocation size");
_Static_assert(CPU_ALLOC_SIZE(1024) == 128, "full cpu_set allocation size");
_Static_assert(CRABC_TYPE_IS(&memcmp, memcmp_signature),
    "parenthesized memcmp declaration");
_Static_assert(CRABC_TYPE_IS(&memset, memset_signature),
    "parenthesized memset declaration");
_Static_assert(CRABC_TYPE_IS(&calloc, calloc_signature),
    "parenthesized calloc declaration");
_Static_assert(CRABC_TYPE_IS(&free, free_signature),
    "parenthesized free declaration");
_Static_assert(CRABC_TYPE_IS(CPU_SETSIZE, int), "CPU_SETSIZE type");
_Static_assert(CRABC_TYPE_IS(CPU_ALLOC_SIZE(1), unsigned long),
    "CPU_ALLOC_SIZE type");
_Static_assert(CRABC_TYPE_IS(CPU_ALLOC(1), cpu_set_t *), "CPU_ALLOC type");
_Static_assert(CRABC_TYPE_IS(CPU_FREE((cpu_set_t *)0), void), "CPU_FREE type");
_Static_assert(CRABC_TYPE_IS(CPU_SET_S(0, sizeof(macro_set), &macro_set),
    unsigned long), "CPU_SET_S type");
_Static_assert(CRABC_TYPE_IS(CPU_CLR_S(0, sizeof(macro_set), &macro_set),
    unsigned long), "CPU_CLR_S type");
_Static_assert(CRABC_TYPE_IS(CPU_ISSET_S(0, sizeof(macro_set), &macro_set),
    unsigned long), "CPU_ISSET_S type");
_Static_assert(CRABC_TYPE_IS(__CPU_op_S(0, sizeof(macro_set), &macro_set, |=),
    unsigned long), "__CPU_op_S type");
_Static_assert(CRABC_TYPE_IS(CPU_ZERO_S(sizeof(macro_set), &macro_set), void *),
    "CPU_ZERO_S type");
_Static_assert(CRABC_TYPE_IS(CPU_EQUAL_S(sizeof(macro_set), &macro_set,
    &macro_set), int), "CPU_EQUAL_S type");
_Static_assert(CRABC_TYPE_IS(CPU_AND_S(sizeof(macro_set), &macro_set,
    &macro_set, &macro_set), void), "CPU_AND_S type");
_Static_assert(CRABC_TYPE_IS(CPU_OR_S(sizeof(macro_set), &macro_set,
    &macro_set, &macro_set), void), "CPU_OR_S type");
_Static_assert(CRABC_TYPE_IS(CPU_XOR_S(sizeof(macro_set), &macro_set,
    &macro_set, &macro_set), void), "CPU_XOR_S type");
_Static_assert(CRABC_TYPE_IS(CPU_SET(0, &macro_set), unsigned long),
    "CPU_SET type");
_Static_assert(CRABC_TYPE_IS(CPU_CLR(0, &macro_set), unsigned long),
    "CPU_CLR type");
_Static_assert(CRABC_TYPE_IS(CPU_ISSET(0, &macro_set), unsigned long),
    "CPU_ISSET type");
_Static_assert(CRABC_TYPE_IS(CPU_ZERO(&macro_set), void *), "CPU_ZERO type");
_Static_assert(CRABC_TYPE_IS(CPU_EQUAL(&macro_set, &macro_set), int),
    "CPU_EQUAL type");
_Static_assert(CRABC_TYPE_IS(CPU_AND(&macro_set, &macro_set, &macro_set), void),
    "CPU_AND type");
_Static_assert(CRABC_TYPE_IS(CPU_OR(&macro_set, &macro_set, &macro_set), void),
    "CPU_OR type");
_Static_assert(CRABC_TYPE_IS(CPU_XOR(&macro_set, &macro_set, &macro_set), void),
    "CPU_XOR type");
_Static_assert(CRABC_TYPE_IS(&__CPU_AND_S, cpu_binary_signature),
    "generated __CPU_AND_S declaration");
_Static_assert(CRABC_TYPE_IS(&__CPU_OR_S, cpu_binary_signature),
    "generated __CPU_OR_S declaration");
_Static_assert(CRABC_TYPE_IS(&__CPU_XOR_S, cpu_binary_signature),
    "generated __CPU_XOR_S declaration");
_Static_assert(CRABC_TYPE_IS(&__CPU_PROBE_S, cpu_binary_signature),
    "__CPU_op_func_S expansion");

/* Compile every expansion without linking or executing allocator/memory calls. */
static void cpu_macro_expression_formation(void)
{
    cpu_set_t destination = {0};
    cpu_set_t source1 = {0};
    cpu_set_t source2 = {0};
    cpu_set_t *allocated = CPU_ALLOC(65);

    CPU_SET_S(0, sizeof(destination), &destination);
    CPU_CLR_S(0, sizeof(destination), &destination);
    (void)CPU_ISSET_S(0, sizeof(destination), &destination);
    CPU_AND_S(sizeof(destination), &destination, &source1, &source2);
    CPU_OR_S(sizeof(destination), &destination, &source1, &source2);
    CPU_XOR_S(sizeof(destination), &destination, &source1, &source2);
    (void)CPU_ZERO_S(sizeof(destination), &destination);
    (void)CPU_EQUAL_S(sizeof(destination), &source1, &source2);
    CPU_SET(0, &destination);
    CPU_CLR(0, &destination);
    (void)CPU_ISSET(0, &destination);
    CPU_AND(&destination, &source1, &source2);
    CPU_OR(&destination, &source1, &source2);
    CPU_XOR(&destination, &source1, &source2);
    (void)CPU_ZERO(&destination);
    (void)CPU_EQUAL(&source1, &source2);
    __CPU_PROBE_S(sizeof(destination), &destination, &source1, &source2);
    CPU_FREE(allocated);
}
#endif

int crabc_x86_64_sched_cpu_macros_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_CPU_MACROS)
    (void)cpu_macro_expression_formation;
#endif
    return 0;
}
