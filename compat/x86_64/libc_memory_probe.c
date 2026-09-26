/*
 * Source-only Linux/x86-64 C bulk-memory fixture.
 *
 * The runner executes this against pinned musl 1.2.6 and then against the
 * isolated crabc x86 object with project headers first. It covers only
 * memcpy/memmove/memset/memcmp/bcmp behavior and ABI invariants, not a
 * crabc-libc artifact. Every size class (register, overlapping-block and
 * bulk paths), source/destination alignment, disjoint memmove and overlap in
 * both directions, and memcmp difference position runs between PROT_NONE guard
 * pages on both sides, so an access outside the requested range faults.
 */

#define _DEFAULT_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
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

/* Sizes that reach every kernel path boundary, up to 256 KiB. */
static const size_t large_lengths[] = {
	65, 79, 80, 95, 96, 127, 128, 129, 255, 257, 511, 512, 513, 1000, 1023,
	4095, 4096, 4097, 16383, 16384, 16385, 65543, 262144,
};
static const size_t large_offsets[] = { 0, 1, 3, 7, 8, 13, 15, 16, 31, 63 };

enum { GUARDED_SPAN = 262144 + 2 * 4096 };

/* One read/write span with PROT_NONE pages directly before and after it. */
struct guarded {
	unsigned char *mapping;
	unsigned char *start;
	unsigned char *end;
};

static int guarded_map(struct guarded *region)
{
	size_t total = GUARDED_SPAN + 2 * PAGE_BYTES;

	region->mapping = mmap(0, total, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region->mapping == MAP_FAILED)
		return 1;
	if (mprotect(region->mapping, PAGE_BYTES, PROT_NONE) != 0 ||
		mprotect(region->mapping + PAGE_BYTES + GUARDED_SPAN, PAGE_BYTES, PROT_NONE) != 0)
		return 1;
	region->start = region->mapping + PAGE_BYTES;
	region->end = region->start + GUARDED_SPAN;
	return 0;
}

static int guarded_unmap(struct guarded *region)
{
	return munmap(region->mapping, GUARDED_SPAN + 2 * PAGE_BYTES) != 0;
}

/* Place `length` bytes flush against the leading guard (after `offset`
   bytes) or flush against the trailing guard. */
static unsigned char *placed(const struct guarded *region, size_t length, size_t offset,
	int at_end)
{
	return at_end ? region->end - length : region->start + offset;
}

static int test_guarded_copy_and_set(void)
{
	struct guarded source_region, destination_region;
	static unsigned char expected[GUARDED_SPAN];

	if (guarded_map(&source_region) != 0 || guarded_map(&destination_region) != 0)
		return 50;
	for (size_t size_index = 0; size_index < sizeof large_lengths / sizeof large_lengths[0];
		size_index++) {
		for (size_t offset_index = 0;
			offset_index < sizeof large_offsets / sizeof large_offsets[0]; offset_index++) {
			for (int placement = 0; placement < 4; placement++) {
				size_t length = large_lengths[size_index];
				size_t offset = large_offsets[offset_index];
				unsigned char *source = placed(&source_region, length, offset, placement & 1);
				unsigned char *destination = placed(&destination_region, length,
					(offset * 5U) & 63U, placement >> 1);

				fill(source, length, (unsigned)(length + offset));
				if (memcpy(destination, source, length) != destination ||
					!equal(destination, source, length))
					return 51;
				fill(destination, length, (unsigned)(length ^ offset ^ 0x5aU));
				if (memmove(destination, source, length) != destination ||
					!equal(destination, source, length) || !direction_flag_is_clear())
					return 57;
				for (size_t index = 0; index < length; index++)
					expected[index] = (unsigned char)(length + offset);
				if (memset(destination, (int)(length + offset), length) != destination ||
					!equal(destination, expected, length))
					return 52;
			}
		}
	}
	for (size_t length = 0; length <= 256; length++) {
		for (size_t offset = 0; offset < 16; offset++) {
			for (int placement = 0; placement < 4; placement++) {
				unsigned char *source = placed(&source_region, length, offset, placement & 1);
				unsigned char *destination = placed(&destination_region, length,
					15 - offset, placement >> 1);

				fill(source, length, (unsigned)length);
				if (memcpy(destination, source, length) != destination ||
					!equal(destination, source, length))
					return 53;
				if (memset(destination, 0x3c, length) != destination)
					return 54;
				for (size_t index = 0; index < length; index++)
					if (destination[index] != 0x3c)
						return 55;
			}
		}
	}
	if (guarded_unmap(&source_region) != 0 || guarded_unmap(&destination_region) != 0)
		return 56;
	return 0;
}

/* Overlapping moves in both directions, each flush against a guard. */
static int test_guarded_memmove(void)
{
	static const long displacements[] = {
		0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 4095, 4096, 4097,
	};
	static unsigned char expected[GUARDED_SPAN];
	struct guarded region;

	if (guarded_map(&region) != 0)
		return 60;
	for (size_t size_index = 0; size_index < sizeof large_lengths / sizeof large_lengths[0];
		size_index++) {
		size_t length = large_lengths[size_index];
		for (size_t displacement_index = 0;
			displacement_index < sizeof displacements / sizeof displacements[0];
			displacement_index++) {
			size_t displacement = (size_t)displacements[displacement_index];
			if (length + displacement > GUARDED_SPAN)
				continue;
			for (int direction = 0; direction < 2; direction++) {
				for (int at_end = 0; at_end < 2; at_end++) {
					/* The window [low, low + length + displacement) touches
					   the leading guard or the trailing one. */
					unsigned char *low = at_end
						? region.end - length - displacement : region.start;
					unsigned char *source = direction ? low : low + displacement;
					unsigned char *destination = direction ? low + displacement : low;

					fill(low, length + displacement, (unsigned)(length ^ displacement));
					reference_copy(expected, low, length + displacement);
					reference_move(expected + (destination - low), expected + (source - low),
						length);
					if (memmove(destination, source, length) != destination)
						return 61;
					if (!equal(low, expected, length + displacement))
						return 62;
					if (!direction_flag_is_clear())
						return 63;
				}
			}
		}
	}
	return guarded_unmap(&region) != 0 ? 64 : 0;
}

static int sign(int value)
{
	return (value > 0) - (value < 0);
}

static int reference_compare(const unsigned char *left, const unsigned char *right,
	size_t length)
{
	for (size_t index = 0; index < length; index++)
		if (left[index] != right[index])
			return left[index] - right[index];
	return 0;
}

/* memcmp and bcmp over every difference position of short inputs and
   selected positions of long ones, with both inputs flush against guards. */
static int test_guarded_compare(void)
{
	static const unsigned char pairs[][2] = { { 0x01, 0xff }, { 0xff, 0x01 }, { 0x7f, 0x80 },
		{ 0x00, 0x01 } };
	struct guarded left_region, right_region;

	if (guarded_map(&left_region) != 0 || guarded_map(&right_region) != 0)
		return 70;
	for (size_t length = 0; length <= 300; length++) {
		for (size_t offset = 0; offset < 16; offset += 5) {
			for (int placement = 0; placement < 4; placement++) {
				unsigned char *left = placed(&left_region, length, offset, placement & 1);
				unsigned char *right = placed(&right_region, length, 15 - offset,
					placement >> 1);

				fill(left, length, 7U);
				reference_copy(right, left, length);
				if (memcmp(left, right, length) != 0 || bcmp(left, right, length) != 0)
					return 71;
				for (size_t position = 0; position < length; position++) {
					const unsigned char *pair = pairs[position % 4];
					unsigned char saved_left = left[position], saved_right = right[position];
					int expected;

					left[position] = pair[0];
					right[position] = pair[1];
					/* A later difference must not change the result. */
					if (position + 1 < length)
						right[length - 1] ^= 0x55;
					expected = reference_compare(left, right, length);
					if (memcmp(left, right, length) != expected ||
						sign(bcmp(left, right, length)) != sign(expected))
						return 72;
					if (position + 1 < length)
						right[length - 1] ^= 0x55;
					left[position] = saved_left;
					right[position] = saved_right;
				}
			}
		}
	}
	for (size_t size_index = 0; size_index < sizeof large_lengths / sizeof large_lengths[0];
		size_index++) {
		size_t length = large_lengths[size_index];
		size_t positions[] = { 0, 1, 15, 16, 17, length / 2, length - 17, length - 16,
			length - 2, length - 1 };
		for (int placement = 0; placement < 4; placement++) {
			unsigned char *left = placed(&left_region, length, 3, placement & 1);
			unsigned char *right = placed(&right_region, length, 11, placement >> 1);

			fill(left, length, 9U);
			reference_copy(right, left, length);
			if (memcmp(left, right, length) != 0)
				return 73;
			for (size_t index = 0; index < sizeof positions / sizeof positions[0]; index++) {
				size_t position = positions[index];
				unsigned char saved = right[position];
				right[position] = (unsigned char)(saved + 1U);
				if (memcmp(left, right, length) != reference_compare(left, right, length) ||
					memcmp(right, left, length) != reference_compare(right, left, length))
					return 74;
				right[position] = saved;
			}
		}
	}
	if (guarded_unmap(&left_region) != 0 || guarded_unmap(&right_region) != 0)
		return 75;
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
	if ((result = test_guard_pages()) != 0)
		return result;
	if ((result = test_guarded_copy_and_set()) != 0)
		return result;
	if ((result = test_guarded_memmove()) != 0)
		return result;
	return test_guarded_compare();
}
