/* Private static Linux/x86-64 stack-check failure archive evidence.
 *
 * This invokes exactly one musl compiler-support terminal spelling per
 * executable. The runner observes the native process result independently:
 * pinned musl and each freestanding candidate must terminate with SIGSEGV
 * after x86 `hlt`. The companion hidden weak local spelling remains an ELF
 * archive-object contract rather than an externally callable API.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

extern void __stack_chk_fail(void);

#if defined(CRABC_STACK_CHK_FAIL_LOCAL_CALL)
extern void __stack_chk_fail_local(void);
#endif

static int stack_check_failure_case(void)
{
#if defined(CRABC_STACK_CHK_FAIL_LOCAL_CALL)
    __stack_chk_fail_local();
#else
    __stack_chk_fail();
#endif
    return 125;
}

#if defined(CRABC_STACK_CHK_FAIL_FREESTANDING)
int crabc_x86_64_stack_chk_fail_probe(void)
{
    return stack_check_failure_case();
}
#else
int main(void)
{
    return stack_check_failure_case();
}
#endif
