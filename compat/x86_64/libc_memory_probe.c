/*
 * Source-only Linux/x86-64 C bulk-memory fixture.
 *
 * The runner executes this against pinned musl 1.2.6 and then against the
 * isolated crabc x86 object with project headers first. It covers only
 * memcpy/memmove/memset behavior and ABI invariants, not a crabc-libc artifact.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#if !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

enum { BUFFER_BYTES = 320, PAGE_BYTES = 4096 };

static void fill(unsigned char *bytes, size_t length, unsigned seed)
{
	for (size_t index = 0; index < length; index++)
		bytes[index] = (unsigned char)(seed + index * 37U);
}

static int equal(const unsigned char *left, const unsigned char *right, size_t length)
{
	for (size_t index = 0; index < length; index++)
		if (left[index] != right[index])
			return 0;
	return 1;
}

static void reference_copy(unsigned char *destination, const unsigned char *source,
	size_t length)
{
	for (size_t index = 0; index < length; index++)
		destination[index] = source[index];
}

static void reference_move(unsigned char *destination, const unsigned char *source,
	size_t length)
{
	if (destination < source) {
		for (size_t index = 0; index < length; index++)
			destination[index] = source[index];
	} else {
		for (size_t index = length; index != 0; index--)
			destination[index - 1] = source[index - 1];
	}
}

static int direction_flag_is_clear(void)
{
	unsigned long flags;

	__asm__ volatile("pushfq; popq %0" : "=r"(flags));
	return (flags & (1UL << 10)) == 0;
}

static int test_memcpy_matrix(void)
{
	unsigned char source[BUFFER_BYTES + 16];
	unsigned char actual[BUFFER_BYTES + 16];
	unsigned char expected[BUFFER_BYTES + 16];

	for (size_t length = 0; length <= 256; length++) {
		for (size_t source_offset = 0; source_offset < 16; source_offset++) {
			for (size_t destination_offset = 0; destination_offset < 16;
				destination_offset++) {
				fill(source, sizeof source, 17U);
				fill(actual, sizeof actual, 91U);
				reference_copy(expected, actual, sizeof actual);
				reference_copy(expected + destination_offset,
					source + source_offset, length);
				if (memcpy(actual + destination_offset, source + source_offset,
					length) != actual + destination_offset)
					return 10;
				if (!equal(actual, expected, sizeof actual))
					return 11;
			}
		}
	}
	return 0;
}

static int test_memset_matrix(void)
{
	static const int values[] = { 0, 1, 0x5a, 0xff, 0x1ab };
	unsigned char actual[BUFFER_BYTES + 16];
	unsigned char expected[BUFFER_BYTES + 16];

	for (size_t length = 0; length <= 256; length++) {
		for (size_t offset = 0; offset < 16; offset++) {
			for (size_t value_index = 0;
				value_index < sizeof values / sizeof values[0]; value_index++) {
				fill(actual, sizeof actual, 43U);
				reference_copy(expected, actual, sizeof actual);
				for (size_t index = 0; index < length; index++)
					expected[offset + index] = (unsigned char)values[value_index];
				if (memset(actual + offset, values[value_index], length) != actual + offset)
					return 20;
				if (!equal(actual, expected, sizeof actual))
					return 21;
			}
		}
	}
	return 0;
}

static int test_memmove_matrix(void)
{
	unsigned char actual[BUFFER_BYTES];
	unsigned char expected[BUFFER_BYTES];

	for (size_t length = 0; length <= 192; length++) {
		for (int displacement = -48; displacement <= 48; displacement++) {
			unsigned char *actual_source = actual + 64;
			unsigned char *expected_source = expected + 64;
			unsigned char *actual_destination = actual_source + displacement;
			unsigned char *expected_destination = expected_source + displacement;

			fill(actual, sizeof actual, 29U);
			reference_copy(expected, actual, sizeof actual);
			reference_move(expected_destination, expected_source, length);
			if (memmove(actual_destination, actual_source, length) != actual_destination)
				return 30;
			if (!equal(actual, expected, sizeof actual))
				return 31;
			if (!direction_flag_is_clear())
				return 32;
		}
	}
	return 0;
}

static int test_guard_pages(void)
{
	unsigned char *source_mapping;
	unsigned char *destination_mapping;

	source_mapping = mmap(0, PAGE_BYTES * 2, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	destination_mapping = mmap(0, PAGE_BYTES * 2, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (source_mapping == MAP_FAILED || destination_mapping == MAP_FAILED)
		return 40;
	if (mprotect(source_mapping + PAGE_BYTES, PAGE_BYTES, PROT_NONE) != 0 ||
		mprotect(destination_mapping + PAGE_BYTES, PAGE_BYTES, PROT_NONE) != 0)
		return 41;

	for (size_t length = 0; length <= 64; length++) {
		unsigned char *source = source_mapping + PAGE_BYTES - length;
		unsigned char *destination = destination_mapping + PAGE_BYTES - length;

		fill(source, length, 11U);
		if (memcpy(destination, source, length) != destination ||
			!equal(destination, source, length))
			return 42;
		if (memset(destination, 0xa5, length) != destination)
			return 43;
		for (size_t index = 0; index < length; index++)
			if (destination[index] != 0xa5)
				return 44;
	}
	if (munmap(source_mapping, PAGE_BYTES * 2) != 0 ||
		munmap(destination_mapping, PAGE_BYTES * 2) != 0)
		return 45;
	return 0;
}

int main(void)
{
	int result;

	if ((result = test_memcpy_matrix()) != 0)
		return result;
	if ((result = test_memset_matrix()) != 0)
		return result;
	if ((result = test_memmove_matrix()) != 0)
		return result;
	return test_guard_pages();
}
