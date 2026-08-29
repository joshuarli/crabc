#ifndef _STDATOMIC_H
#define _STDATOMIC_H

#ifdef __cplusplus

/* C++17 has no C `<stdatomic.h>` interface, and musl 1.2.6 does not supply
 * this project-only header.  Do not expose C11 `_Atomic` syntax to C++
 * consumers; they use the C++ standard atomic interface instead. */

#else

/* Keep the C11 atomic vocabulary self-contained.  Pulling in the compiler's
 * fallback stdatomic.h also imports its private stdint/stddef namespace,
 * which is not part of this header's public contract. */
#include <features.h>

#define __NEED_size_t
#define __NEED_ptrdiff_t
#define __NEED_uintptr_t
#define __NEED_intptr_t
#define __NEED_intmax_t
#define __NEED_uintmax_t
#define __NEED_wchar_t
#include <bits/alltypes.h>

typedef _Atomic(_Bool) atomic_bool;
typedef _Atomic(char) atomic_char;
typedef _Atomic(signed char) atomic_schar;
typedef _Atomic(unsigned char) atomic_uchar;
typedef _Atomic(short) atomic_short;
typedef _Atomic(unsigned short) atomic_ushort;
typedef _Atomic(int) atomic_int;
typedef _Atomic(unsigned int) atomic_uint;
typedef _Atomic(long) atomic_long;
typedef _Atomic(unsigned long) atomic_ulong;
typedef _Atomic(long long) atomic_llong;
typedef _Atomic(unsigned long long) atomic_ullong;
typedef _Atomic(unsigned short) atomic_char16_t;
typedef _Atomic(unsigned int) atomic_char32_t;
typedef _Atomic(wchar_t) atomic_wchar_t;
typedef _Atomic(signed char) atomic_int_least8_t;
typedef _Atomic(unsigned char) atomic_uint_least8_t;
typedef _Atomic(short) atomic_int_least16_t;
typedef _Atomic(unsigned short) atomic_uint_least16_t;
typedef _Atomic(int) atomic_int_least32_t;
typedef _Atomic(unsigned int) atomic_uint_least32_t;
typedef _Atomic(long) atomic_int_least64_t;
typedef _Atomic(unsigned long) atomic_uint_least64_t;
typedef _Atomic(signed char) atomic_int_fast8_t;
typedef _Atomic(unsigned char) atomic_uint_fast8_t;
typedef _Atomic(long) atomic_int_fast16_t;
typedef _Atomic(unsigned long) atomic_uint_fast16_t;
typedef _Atomic(long) atomic_int_fast32_t;
typedef _Atomic(unsigned long) atomic_uint_fast32_t;
typedef _Atomic(long) atomic_int_fast64_t;
typedef _Atomic(unsigned long) atomic_uint_fast64_t;
typedef _Atomic(uintptr_t) atomic_uintptr_t;
typedef _Atomic(intptr_t) atomic_intptr_t;
typedef _Atomic(size_t) atomic_size_t;
typedef _Atomic(ptrdiff_t) atomic_ptrdiff_t;
typedef _Atomic(intmax_t) atomic_intmax_t;
typedef _Atomic(uintmax_t) atomic_uintmax_t;

typedef struct { _Bool __val; } atomic_flag;

typedef enum memory_order {
    memory_order_relaxed,
    memory_order_consume,
    memory_order_acquire,
    memory_order_release,
    memory_order_acq_rel,
    memory_order_seq_cst
} memory_order;

#if defined(__clang__)
#define ATOMIC_BOOL_LOCK_FREE __CLANG_ATOMIC_BOOL_LOCK_FREE
#define ATOMIC_CHAR_LOCK_FREE __CLANG_ATOMIC_CHAR_LOCK_FREE
#define ATOMIC_CHAR16_T_LOCK_FREE __CLANG_ATOMIC_CHAR16_T_LOCK_FREE
#define ATOMIC_CHAR32_T_LOCK_FREE __CLANG_ATOMIC_CHAR32_T_LOCK_FREE
#define ATOMIC_WCHAR_T_LOCK_FREE __CLANG_ATOMIC_WCHAR_T_LOCK_FREE
#define ATOMIC_SHORT_LOCK_FREE __CLANG_ATOMIC_SHORT_LOCK_FREE
#define ATOMIC_INT_LOCK_FREE __CLANG_ATOMIC_INT_LOCK_FREE
#define ATOMIC_LONG_LOCK_FREE __CLANG_ATOMIC_LONG_LOCK_FREE
#define ATOMIC_LLONG_LOCK_FREE __CLANG_ATOMIC_LLONG_LOCK_FREE
#define ATOMIC_POINTER_LOCK_FREE __CLANG_ATOMIC_POINTER_LOCK_FREE
#else
#define ATOMIC_BOOL_LOCK_FREE __GCC_ATOMIC_BOOL_LOCK_FREE
#define ATOMIC_CHAR_LOCK_FREE __GCC_ATOMIC_CHAR_LOCK_FREE
#define ATOMIC_CHAR16_T_LOCK_FREE __GCC_ATOMIC_CHAR16_T_LOCK_FREE
#define ATOMIC_CHAR32_T_LOCK_FREE __GCC_ATOMIC_CHAR32_T_LOCK_FREE
#define ATOMIC_WCHAR_T_LOCK_FREE __GCC_ATOMIC_WCHAR_T_LOCK_FREE
#define ATOMIC_SHORT_LOCK_FREE __GCC_ATOMIC_SHORT_LOCK_FREE
#define ATOMIC_INT_LOCK_FREE __GCC_ATOMIC_INT_LOCK_FREE
#define ATOMIC_LONG_LOCK_FREE __GCC_ATOMIC_LONG_LOCK_FREE
#define ATOMIC_LLONG_LOCK_FREE __GCC_ATOMIC_LLONG_LOCK_FREE
#define ATOMIC_POINTER_LOCK_FREE __GCC_ATOMIC_POINTER_LOCK_FREE
#endif
#define ATOMIC_FLAG_INIT { 0 }

#define kill_dependency(value) (value)

#define __CRABC_ATOMIC_VALUE_TYPE(object) __typeof__(*(object) + 0)
#define __CRABC_ATOMIC_VALUE_PTR(object) \
    (__CRABC_ATOMIC_VALUE_TYPE(object) *)(object)

#define atomic_init(object, value) \
    __atomic_store_n(__CRABC_ATOMIC_VALUE_PTR(object), (value), __ATOMIC_RELAXED)
#define atomic_is_lock_free(object) \
    __atomic_is_lock_free(sizeof(*(object)), 0)
#define atomic_store(object, value) \
    __atomic_store_n(__CRABC_ATOMIC_VALUE_PTR(object), (value), __ATOMIC_SEQ_CST)
#define atomic_store_explicit(object, value, order) \
    __atomic_store_n(__CRABC_ATOMIC_VALUE_PTR(object), (value), (order))
#define atomic_load(object) \
    __atomic_load_n(__CRABC_ATOMIC_VALUE_PTR(object), __ATOMIC_SEQ_CST)
#define atomic_load_explicit(object, order) \
    __atomic_load_n(__CRABC_ATOMIC_VALUE_PTR(object), (order))
#define atomic_exchange(object, value) \
    __atomic_exchange_n(__CRABC_ATOMIC_VALUE_PTR(object), (value), __ATOMIC_SEQ_CST)
#define atomic_exchange_explicit(object, value, order) \
    __atomic_exchange_n(__CRABC_ATOMIC_VALUE_PTR(object), (value), (order))
#define atomic_compare_exchange_strong(object, expected, desired) \
    __atomic_compare_exchange_n(__CRABC_ATOMIC_VALUE_PTR(object), (expected), (desired), \
        0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define atomic_compare_exchange_strong_explicit(object, expected, desired, success, failure) \
    __atomic_compare_exchange_n(__CRABC_ATOMIC_VALUE_PTR(object), (expected), (desired), \
        0, (success), (failure))
#define atomic_compare_exchange_weak(object, expected, desired) \
    __atomic_compare_exchange_n(__CRABC_ATOMIC_VALUE_PTR(object), (expected), (desired), \
        1, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define atomic_compare_exchange_weak_explicit(object, expected, desired, success, failure) \
    __atomic_compare_exchange_n(__CRABC_ATOMIC_VALUE_PTR(object), (expected), (desired), \
        1, (success), (failure))
#define atomic_fetch_add(object, value) \
    __atomic_fetch_add(__CRABC_ATOMIC_VALUE_PTR(object), (value), __ATOMIC_SEQ_CST)
#define atomic_fetch_add_explicit(object, value, order) \
    __atomic_fetch_add(__CRABC_ATOMIC_VALUE_PTR(object), (value), (order))
#define atomic_fetch_sub(object, value) \
    __atomic_fetch_sub(__CRABC_ATOMIC_VALUE_PTR(object), (value), __ATOMIC_SEQ_CST)
#define atomic_fetch_sub_explicit(object, value, order) \
    __atomic_fetch_sub(__CRABC_ATOMIC_VALUE_PTR(object), (value), (order))
#define atomic_fetch_or(object, value) \
    __atomic_fetch_or(__CRABC_ATOMIC_VALUE_PTR(object), (value), __ATOMIC_SEQ_CST)
#define atomic_fetch_or_explicit(object, value, order) \
    __atomic_fetch_or(__CRABC_ATOMIC_VALUE_PTR(object), (value), (order))
#define atomic_fetch_xor(object, value) \
    __atomic_fetch_xor(__CRABC_ATOMIC_VALUE_PTR(object), (value), __ATOMIC_SEQ_CST)
#define atomic_fetch_xor_explicit(object, value, order) \
    __atomic_fetch_xor(__CRABC_ATOMIC_VALUE_PTR(object), (value), (order))
#define atomic_fetch_and(object, value) \
    __atomic_fetch_and(__CRABC_ATOMIC_VALUE_PTR(object), (value), __ATOMIC_SEQ_CST)
#define atomic_fetch_and_explicit(object, value, order) \
    __atomic_fetch_and(__CRABC_ATOMIC_VALUE_PTR(object), (value), (order))

/* These entry points remain libc-provided, as in the compiler's musl
 * stdatomic interface.  The macros below are used for normal calls, while
 * taking their address after an explicit #undef keeps the external symbol
 * contract visible to consumers. */
void atomic_flag_clear(volatile atomic_flag *);
void atomic_flag_clear_explicit(volatile atomic_flag *, memory_order);
_Bool atomic_flag_test_and_set(volatile atomic_flag *);
_Bool atomic_flag_test_and_set_explicit(volatile atomic_flag *, memory_order);
void atomic_signal_fence(memory_order);
void atomic_thread_fence(memory_order);

#define atomic_flag_clear(object) \
    __atomic_store_n(&(object)->__val, 0, __ATOMIC_SEQ_CST)
#define atomic_flag_clear_explicit(object, order) \
    __atomic_store_n(&(object)->__val, 0, (order))
#define atomic_flag_test_and_set(object) \
    __atomic_exchange_n(&(object)->__val, 1, __ATOMIC_SEQ_CST)
#define atomic_flag_test_and_set_explicit(object, order) \
    __atomic_exchange_n(&(object)->__val, 1, (order))
#define atomic_signal_fence(order) __atomic_signal_fence(order)
#define atomic_thread_fence(order) __atomic_thread_fence(order)

#endif

#endif
