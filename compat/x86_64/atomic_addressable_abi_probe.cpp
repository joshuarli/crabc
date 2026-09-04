struct atomic_flag { bool value; };
static_assert(sizeof(atomic_flag) == 1, "C atomic_flag ABI is one byte");
static_assert(alignof(atomic_flag) == 1, "C atomic_flag ABI is byte aligned");

extern "C" {
void atomic_flag_clear(volatile atomic_flag *);
void atomic_flag_clear_explicit(volatile atomic_flag *, int);
bool atomic_flag_test_and_set(volatile atomic_flag *);
bool atomic_flag_test_and_set_explicit(volatile atomic_flag *, int);
void atomic_signal_fence(int);
void atomic_thread_fence(int);
}

extern "C" int crabc_x86_64_atomic_addressable_cxx_probe() {
    atomic_flag flag{false};
    void (*clear)(volatile atomic_flag *) = atomic_flag_clear;
    void (*clear_explicit)(volatile atomic_flag *, int) = atomic_flag_clear_explicit;
    bool (*test)(volatile atomic_flag *) = atomic_flag_test_and_set;
    bool (*test_explicit)(volatile atomic_flag *, int) = atomic_flag_test_and_set_explicit;
    void (*signal_fence)(int) = atomic_signal_fence;
    void (*thread_fence)(int) = atomic_thread_fence;

    if (test(&flag) || !test_explicit(&flag, 2))
        return 3;
    clear_explicit(&flag, 3);
    if (test(&flag))
        return 4;
    clear(&flag);
    signal_fence(5);
    thread_fence(5);
    return 0;
}
