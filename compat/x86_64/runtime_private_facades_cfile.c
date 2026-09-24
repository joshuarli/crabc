/*
 * Installed-product differential for crabc-rs's native x86-64 `cfile` facade.
 *
 * Each scenario runs once through the product's public fmemopen stream and
 * once through the Rust interpreter, which reaches only the private RuntimeV1
 * table, over identical buffers. Traces record every count, position,
 * indicator, read byte, and failure; failures are the positive errno, or EIO
 * when the stream fails without one, as the private table documents. The
 * facade call must also leave the caller's errno unchanged.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>

enum facade_op_kind { OP_WRITE, OP_READ, OP_FLUSH, OP_SEEK, OP_TELL, OP_EOF, OP_ERROR, OP_RESET, OP_CLOSE };

struct facade_op {
	int kind;
	int whence;
	long long value;
	const char *data;
};

struct facade_scenario {
	int mode;
	size_t size;
	const char *initial;
	size_t initial_len;
	const struct facade_op *ops;
	size_t op_count;
};

int crabc_rs_x86_64_cfile_facade_run(const struct facade_scenario *, unsigned char *, long long *, size_t, size_t *);
int crabc_rs_x86_64_cfile_facade_directions(unsigned char *, size_t);

enum { TRACE = 256, BUFFER = 64 };

static const char *const modes[] = { "r", "w", "a", "r+", "w+", "a+" };

#define W(text) { OP_WRITE, 0, sizeof text - 1, text }
#define R(count) { OP_READ, 0, count, 0 }
#define SEEK(whence, offset) { OP_SEEK, whence, offset, 0 }
#define OP(kind) { kind, 0, 0, 0 }

static const struct facade_op read_ops[] = {
	R(5), OP(OP_TELL), SEEK(SEEK_SET, 6), R(10), OP(OP_EOF), OP(OP_RESET), OP(OP_EOF),
	SEEK(SEEK_END, -5), SEEK(SEEK_SET, 12), SEEK(SEEK_CUR, -100), OP(OP_TELL), OP(OP_ERROR), OP(OP_CLOSE),
};
static const struct facade_op write_ops[] = {
	W("abc"), OP(OP_FLUSH), OP(OP_TELL), W("de"), SEEK(SEEK_SET, 1), W("Z"), OP(OP_FLUSH), OP(OP_TELL), OP(OP_CLOSE),
};
static const struct facade_op append_ops[] = {
	OP(OP_TELL), W("cd"), OP(OP_FLUSH), OP(OP_TELL), SEEK(SEEK_SET, 0), W("e"), OP(OP_FLUSH), OP(OP_TELL), OP(OP_CLOSE),
};
static const struct facade_op read_update_ops[] = {
	W("ab"), SEEK(SEEK_SET, 0), R(6), OP(OP_EOF), R(1), OP(OP_EOF), OP(OP_ERROR), OP(OP_CLOSE),
};
static const struct facade_op write_update_ops[] = {
	W("hello"), SEEK(SEEK_SET, 0), R(16), OP(OP_EOF), OP(OP_RESET), R(2), SEEK(SEEK_END, 0), W("!"), OP(OP_FLUSH),
	SEEK(SEEK_SET, 0), R(16), OP(OP_CLOSE),
};
static const struct facade_op append_update_ops[] = {
	R(4), OP(OP_EOF), SEEK(SEEK_SET, 0), R(4), W("z"), OP(OP_FLUSH), OP(OP_TELL), OP(OP_CLOSE),
};
static const struct facade_op overflow_ops[] = {
	W("abcdef"), OP(OP_FLUSH), OP(OP_ERROR), OP(OP_TELL), OP(OP_CLOSE),
};
static const struct facade_op overflow_close_ops[] = {
	W("abcdef"), OP(OP_CLOSE),
};
static const struct facade_op empty_ops[] = {
	R(1), OP(OP_EOF), OP(OP_CLOSE),
};

#define SCENARIO(mode, size, initial, ops) { mode, size, initial, sizeof initial - 1, ops, sizeof ops / sizeof ops[0] }

static const struct facade_scenario scenarios[] = {
	SCENARIO(0, 11, "hello world", read_ops),
	SCENARIO(1, 8, "XXXXXXXX", write_ops),
	SCENARIO(2, 10, "ab", append_ops),
	SCENARIO(3, 6, "123456", read_update_ops),
	SCENARIO(4, 16, "garbage garbage!", write_update_ops),
	SCENARIO(5, 8, "xy", append_update_ops),
	SCENARIO(1, 4, "", overflow_ops),
	SCENARIO(4, 4, "", overflow_close_ops),
	SCENARIO(0, 0, "", empty_ops),
};

static long long failure(void)
{
	return -(long long)(errno > 0 && errno <= 4095 ? errno : EIO);
}

static int push(long long *trace, size_t *count, long long value)
{
	if (*count == TRACE) return 0;
	trace[(*count)++] = value;
	return 1;
}

static int run_c(const struct facade_scenario *scenario, unsigned char *buffer, long long *trace, size_t *count)
{
	FILE *stream;
	*count = 0;
	errno = 0;
	if (!(stream = fmemopen(buffer, scenario->size, modes[scenario->mode])))
		return !push(trace, count, failure());
	for (size_t index = 0; index < scenario->op_count; index++) {
		const struct facade_op *op = &scenario->ops[index];
		long long value = 0;
		unsigned char bytes[64];
		size_t done;
		errno = 0;
		switch (op->kind) {
		case OP_WRITE:
			done = fwrite(op->data, 1, (size_t)op->value, stream);
			value = done < (size_t)op->value && ferror(stream) ? failure() : (long long)done;
			break;
		case OP_READ:
			done = fread(bytes, 1, (size_t)op->value, stream);
			if (done < (size_t)op->value && ferror(stream)) { value = failure(); break; }
			if (!push(trace, count, (long long)done)) return 1;
			for (size_t byte = 0; byte < done; byte++)
				if (!push(trace, count, bytes[byte])) return 1;
			continue;
		case OP_FLUSH:
			value = fflush(stream) ? failure() : 0;
			break;
		case OP_SEEK:
			if (fseeko(stream, op->value, op->whence)) { value = failure(); break; }
			/* fall through: the facade reports the resulting position. */
		case OP_TELL: {
			off_t position = ftello(stream);
			value = position < 0 ? failure() : position;
			break;
		}
		case OP_EOF:
			value = feof(stream) != 0;
			break;
		case OP_ERROR:
			value = ferror(stream) != 0;
			break;
		case OP_RESET:
			if (fseeko(stream, 0, SEEK_SET)) { value = failure(); break; }
			clearerr(stream);
			value = 0;
			break;
		case OP_CLOSE:
			value = fclose(stream) ? failure() : 0;
			break;
		default:
			return 1;
		}
		if (!push(trace, count, value)) return 1;
	}
	return 0;
}

static int fail(int code)
{
	printf("x86 runtime private cfile facade FAIL %d\n", code);
	return 1;
}

int main(void)
{
	static long long c_trace[TRACE], facade_trace[TRACE];
	unsigned char c_buffer[BUFFER], facade_buffer[BUFFER];
	size_t c_count, facade_count;

	for (size_t index = 0; index < sizeof scenarios / sizeof scenarios[0]; index++) {
		const struct facade_scenario *scenario = &scenarios[index];
		int code = 10 * (int)index;
		memset(c_buffer, 0x5a, sizeof c_buffer);
		memcpy(c_buffer, scenario->initial, scenario->initial_len);
		if (scenario->initial_len < scenario->size) c_buffer[scenario->initial_len] = 0;
		memcpy(facade_buffer, c_buffer, sizeof c_buffer);
		if (run_c(scenario, c_buffer, c_trace, &c_count)) return fail(code + 1);
		errno = 55;
		if (crabc_rs_x86_64_cfile_facade_run(scenario, facade_buffer, facade_trace, TRACE, &facade_count))
			return fail(code + 2);
		if (errno != 55) return fail(code + 3);
		if (c_count != facade_count || memcmp(c_trace, facade_trace, c_count * sizeof c_trace[0]))
			return fail(code + 4);
		if (memcmp(c_buffer, facade_buffer, sizeof c_buffer)) return fail(code + 5);
	}
	memset(facade_buffer, 0, sizeof facade_buffer);
	int result = crabc_rs_x86_64_cfile_facade_directions(facade_buffer, 8);
	if (result) return fail(200 + result);
	puts("x86 runtime private cfile facade ok");
	return 0;
}
