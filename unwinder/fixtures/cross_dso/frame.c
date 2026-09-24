/* One C frame that Rust panics must unwind through.
 *
 * The consumer gate builds this file twice with the installed dynamic
 * driver: once as the executable's DT_NEEDED dependency and once as a
 * dlopen'd runtime DSO. GCC's default x86-64 asynchronous unwind tables give
 * the frame CFI; the provider must discover it through dl_iterate_phdr. The
 * volatile slot keeps the call from becoming a tail call, so the frame is
 * live while the callback panics.
 */
typedef int (*crabc_unwind_callback)(void *);

int crabc_unwind_call_through(crabc_unwind_callback callback, void *argument) {
    volatile int depth = 1;
    int result = callback(argument);
    return result + depth;
}
