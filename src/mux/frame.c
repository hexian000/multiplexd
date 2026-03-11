/* multiplexd (c) 2022-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file frame.c
 * @brief Mux frame serialization and parsing helpers.
 */

#include "mux/frame.h"

#include "utils/serialize.h"

#include <stddef.h>
#include <stdint.h>

struct mux_frame *
mux_frame_get(const struct mux_frame_allocator *restrict allocator)
{
	struct mux_frame *frame = allocator->alloc(allocator->data);
	if (frame != NULL) {
		frame->pos = 0;
		frame->len = 0;
		frame->next = NULL;
	}
	return frame;
}

void mux_frame_put(
	const struct mux_frame_allocator *restrict allocator,
	struct mux_frame *frame)
{
	allocator->free(allocator->data, frame);
}

void mux_write_header(
	unsigned char *restrict buf, const struct mux_header *restrict header)
{
	write_uint8(buf + 0, header->version);
	write_uint8(buf + 1, header->flags);
	write_uint16(buf + 2, header->length);
	write_uint16(buf + 4, header->stream_id);
	write_uint16(buf + 6, (uint16_t)header->extra);
}

void mux_read_header(
	const unsigned char *restrict buf, struct mux_header *restrict header)
{
	header->version = read_uint8(buf + 0);
	header->flags = read_uint8(buf + 1);
	header->length = read_uint16(buf + 2);
	header->stream_id = read_uint16(buf + 4);
	header->extra = read_uint16(buf + 6);
}
