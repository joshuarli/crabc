/* One C frame that Rust panics must unwind through.
 *
 * The same frame can reside in a linked static image or in an initial/runtime
 * DSO. Its unwind tables describe the saved context in either location. The
 * volatile slot keeps the call from becoming a tail call, so the frame is
 * live while the callback panics.
 */
typedef int (*crabc_unwind_callback)(void *);

int crabc_unwind_call_through(crabc_unwind_callback callback, void *argument) {
    volatile int depth = 1;
    int result = callback(argument);
    return result + depth;
}
