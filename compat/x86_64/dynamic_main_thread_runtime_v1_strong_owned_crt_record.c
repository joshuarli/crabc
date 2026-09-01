/* Force one strong undefined main-image data import of Scrt1's optional
 * owned-CRT handoff record.  The dynamic-main-thread bridge admits only the
 * exact weak undefined Scrt1 relocation and must reject this before it can
 * install the initial FS base. */

extern const unsigned char __crabc_x86_64_owned_crt_handoff;

__attribute__((used)) void *dynamic_main_thread_strong_owned_crt_record(void)
{
	return (void *)&__crabc_x86_64_owned_crt_handoff;
}
