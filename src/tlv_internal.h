/* libtlv internal definitions. Not part of the public API. */
#ifndef TLV_INTERNAL_H
#define TLV_INTERNAL_H

#include "tlv.h"

#include <stdint.h>
#include <string.h>

/* ---- arena ---- */

#define TLV_ARENA_FIRST_BLOCK 128u

typedef struct tlv_arena_block {
    struct tlv_arena_block *next;
    size_t used;
    size_t cap;
    tlv_node nodes[]; /* flexible array member */
} tlv_arena_block;

typedef struct tlv_arena {
    tlv_arena_block *head;
    size_t count;
    size_t limit;
} tlv_arena;

void tlv_arena_init(tlv_arena *a, size_t limit);
tlv_node *tlv_arena_alloc(tlv_arena *a); /* NULL if exhausted or OOM */
void tlv_arena_free(tlv_arena *a);

/* ---- decoders ---- */

/* Unsigned LEB128 from a bounded stream. Advances *pos only on success.
 * A sequence that does not terminate within max_bytes -> TLV_ERR_VARINT.
 * Running into `limit` -> TLV_ERR_TRUNCATED.
 * canonical (1 or 2 bytes) reports whether the encoding is the shortest form. */
tlv_error tlv_uleb_read(const uint8_t *buf, size_t limit, size_t *pos,
                        unsigned max_bytes, uint64_t *out, int *canonical);

/* Slice decoders: the field length is authoritative, so the encoding must
 * consume exactly n bytes (1 <= n <= 8). */
tlv_error tlv_uleb_decode(const uint8_t *p, size_t n, uint64_t *out,
                          int *canonical);
tlv_error tlv_sleb_decode(const uint8_t *p, size_t n, int64_t *out,
                          int *canonical);

/* RFC 3629 strict validation. TLV_OK or TLV_ERR_UTF8. */
tlv_error tlv_utf8_check(const uint8_t *p, size_t n);

/* ---- document ---- */

struct tlv_document {
    tlv_options opt;
    tlv_arena arena;
    tlv_node *root;
};

/* ---- options ---- */

void tlv_options_normalize(const tlv_options *in, tlv_options *out);

#endif /* TLV_INTERNAL_H */
