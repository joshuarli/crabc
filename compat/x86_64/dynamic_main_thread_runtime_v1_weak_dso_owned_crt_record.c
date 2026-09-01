/* Force one weak undefined DSO data import of Scrt1's optional owned-CRT
 * handoff record.  Weak binding is not enough: this exception belongs only
 * to the unmapped real-Scrt1 main image and must reject before ARCH_SET_FS. */

extern const unsigned char __crabc_x86_64_owned_crt_handoff
	__attribute__((weak));

__attribute__((used)) void *dynamic_main_thread_weak_dso_owned_crt_record(void)
{
	return (void *)&__crabc_x86_64_owned_crt_handoff;
}
