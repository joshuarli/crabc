/*
 * Runtime-loaded TLS provider for the native `dl` facade differential. Its
 * one general-dynamic TLS object gives the copied loaded-image snapshot a
 * nonzero module ID and a calling-thread block address to compare.
 */
__thread int runtime_facade_tls_value = 41;

int *runtime_facade_tls_address(void)
{
	return &runtime_facade_tls_value;
}
