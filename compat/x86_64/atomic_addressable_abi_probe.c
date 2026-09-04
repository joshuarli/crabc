#include <stdatomic.h>

#undef atomic_flag_clear
#undef atomic_flag_clear_explicit
#undef atomic_flag_test_and_set
#undef atomic_flag_test_and_set_explicit
#undef atomic_signal_fence
#undef atomic_thread_fence

extern int crabc_x86_64_atomic_addressable_cxx_probe(void);

int crabc_x86_64_atomic_addressable_probe(void) {
    atomic_flag flag = ATOMIC_FLAG_INIT;
    _Static_assert(sizeof(atomic_flag) == 1, "atomic_flag must be one byte");
    _Static_assert(_Alignof(atomic_flag) == 1, "atomic_flag must be byte aligned");
    void (*clear)(volatile atomic_flag *) = atomic_flag_clear;
    void (*clear_explicit)(volatile atomic_flag *, memory_order) = atomic_flag_clear_explicit;
    _Bool (*test)(volatile atomic_flag *) = atomic_flag_test_and_set;
    _Bool (*test_explicit)(volatile atomic_flag *, memory_order) = atomic_flag_test_and_set_explicit;
    void (*signal_fence)(memory_order) = atomic_signal_fence;
    void (*thread_fence)(memory_order) = atomic_thread_fence;
    if (test(&flag) != 0 || test_explicit(&flag, memory_order_acquire) != 1)
        return 1;
    clear_explicit(&flag, memory_order_release);
    if (test(&flag) != 0)
        return 2;
    clear_explicit(&flag, memory_order_relaxed);
    if (test_explicit(&flag, memory_order_consume) != 0)
        return 3;
    clear_explicit(&flag, memory_order_seq_cst);
    if (test_explicit(&flag, memory_order_release) != 0)
        return 4;
    clear_explicit(&flag, memory_order_seq_cst);
    if (test_explicit(&flag, memory_order_acq_rel) != 0)
        return 5;
    clear(&flag);
    signal_fence(memory_order_relaxed);
    signal_fence(memory_order_consume);
    signal_fence(memory_order_acquire);
    signal_fence(memory_order_release);
    signal_fence(memory_order_acq_rel);
    signal_fence(memory_order_seq_cst);
    thread_fence(memory_order_relaxed);
    thread_fence(memory_order_consume);
    thread_fence(memory_order_acquire);
    thread_fence(memory_order_release);
    thread_fence(memory_order_acq_rel);
    thread_fence(memory_order_seq_cst);
    return crabc_x86_64_atomic_addressable_cxx_probe();
}
