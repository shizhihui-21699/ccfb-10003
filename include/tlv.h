/* libtlv — defensive TLVX parser.
 *
 * Wire format: docs/PROTOCOL.md (normative).
 * SPDX-License-Identifier: MIT
 */
#ifndef TLV_H
#define TLV_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TLV_MAGIC0 0x54 /* 'T' */
#define TLV_MAGIC1 0x4C /* 'L' */
#define TLV_MAGIC2 0x56 /* 'V' */
#define TLV_MAGIC3 0x58 /* 'X' */

#define TLV_HEADER_SIZE 11
#define TLV_VERSION 0x01

#define TLV_FLAG_STRICT 0x0001

#define TLV_MAX_DEPTH_HARD 64
#define TLV_MAX_FIELDS_PER_SCOPE_HARD 65536u
#define TLV_MAX_TOTAL_FIELDS_HARD 262144u
#define TLV_MAX_MESSAGE_BYTES_HARD (64u * 1024u * 1024u)

typedef enum tlv_error {
    TLV_OK = 0,
    TLV_ERR_ARG,              /* NULL/invalid caller argument */
    TLV_ERR_TRUNCATED,        /* input ended inside a header/field/value */
    TLV_ERR_BAD_MAGIC,
    TLV_ERR_BAD_VERSION,
    TLV_ERR_BAD_FLAGS,
    TLV_ERR_LENGTH_MISMATCH,  /* declared length disagrees with actual bytes */
    TLV_ERR_BAD_TAG,          /* tag 0 or tag > 2^32-1 */
    TLV_ERR_TAG_ORDER,        /* tags not strictly increasing in a scope */
    TLV_ERR_BAD_TYPE,         /* type byte violates C-bit/kind/slot rules */
    TLV_ERR_RESERVED_KIND,    /* kind 7 */
    TLV_ERR_BAD_LENGTH_ENCODING,
    TLV_ERR_VARINT,           /* malformed or non-canonical LEB128 */
    TLV_ERR_BAD_OPTIONAL,     /* optional slot misuse */
    TLV_ERR_OPTIONAL_UNUSED,  /* presence bit set but no field claimed it */
    TLV_ERR_VALUE,            /* value violates the kind's constraints (e.g. BOOL) */
    TLV_ERR_UTF8,
    TLV_ERR_DEPTH,
    TLV_ERR_FIELDS,
    TLV_ERR_LIMIT,
    TLV_ERR_NOMEM
} tlv_error;

typedef enum tlv_kind {
    TLV_KIND_INT = 0,
    TLV_KIND_UINT = 1,
    TLV_KIND_BYTES = 2,
    TLV_KIND_STRING = 3,
    TLV_KIND_BOOL = 4,
    TLV_KIND_CONTAINER = 5,
    TLV_KIND_SKIP = 6
} tlv_kind;

typedef struct tlv_options {
    unsigned strict;            /* plus the per-message STRICT flag; 1 = strict */
    unsigned max_depth;         /* 0 => default 16; clamped to hard max 64 */
    uint32_t max_fields;        /* 0 => default 65536, per scope */
    uint32_t max_total_fields;  /* 0 => default 262144, whole message */
    uint32_t max_message_bytes; /* 0 => default 16 MiB */
} tlv_options;

void tlv_options_init(tlv_options *opt);

typedef struct tlv_node {
    uint32_t tag;
    uint8_t kind;      /* tlv_kind */
    uint8_t is_optional;
    uint8_t slot;      /* meaningful when is_optional */
    uint8_t flags;     /* bit0: value validated as canonical */
    uint16_t depth;    /* 0 = root pseudo node */
    uint32_t value_len;
    size_t offset;               /* offset of the tag byte in the input */
    const uint8_t *value;        /* leaf: raw value bytes; container: bitmap byte */
    struct tlv_node *first_child;
    struct tlv_node *next_sibling;
    struct tlv_node *parent;
} tlv_node;

typedef struct tlv_document tlv_document;

/* Parse `buf[0..len)`. On success *out_doc receives an owned document that
 * must be released with tlv_document_free(). On failure *out_doc is NULL and
 * nothing is leaked. `buf` must outlive the document. */
tlv_error tlv_parse(const uint8_t *buf, size_t len, const tlv_options *opt,
                    tlv_document **out_doc);
tlv_error tlv_parse_strict(const uint8_t *buf, size_t len, tlv_document **out_doc);

void tlv_document_free(tlv_document *doc);
const tlv_node *tlv_document_root(const tlv_document *doc);
const tlv_node *tlv_document_find(const tlv_document *doc, uint32_t tag);

/* Number of nodes in the document (excluding the root pseudo node). */
size_t tlv_document_node_count(const tlv_document *doc);

/* Tree navigation. All are NULL-safe. */
const tlv_node *tlv_node_child(const tlv_node *n, uint32_t tag);
const tlv_node *tlv_node_nth_child(const tlv_node *n, size_t index);
size_t tlv_node_child_count(const tlv_node *n);

/* Scalar extraction. Return TLV_OK and write the value, or an error. */
tlv_error tlv_node_get_int(const tlv_node *n, int64_t *out);
tlv_error tlv_node_get_uint(const tlv_node *n, uint64_t *out);
tlv_error tlv_node_get_bool(const tlv_node *n, int *out);
tlv_error tlv_node_get_bytes(const tlv_node *n, const uint8_t **out, size_t *out_len);
tlv_error tlv_node_get_string(const tlv_node *n, const char **out, size_t *out_len);

const char *tlv_strerror(tlv_error err);
const char *tlv_kind_name(uint8_t kind);

/* ---- Builder / encoder (used by tests, tools and corpus seeding) ---- */

typedef struct tlv_writer tlv_writer;

/* Creates an empty root scope. header_flags supplies the message flags word. */
tlv_writer *tlv_writer_new(uint16_t header_flags, const tlv_options *opt);
void tlv_writer_free(tlv_writer *w);

/* Field emission. Every call appends to the innermost open scope; tags must be
 * added in strictly increasing order within that scope. */
tlv_error tlv_writer_u64(tlv_writer *w, uint32_t tag, uint64_t v);
tlv_error tlv_writer_i64(tlv_writer *w, uint32_t tag, int64_t v);
tlv_error tlv_writer_bytes(tlv_writer *w, uint32_t tag, const void *p, size_t n);
/* NUL-terminated convenience form (the NUL is not part of the value). */
tlv_error tlv_writer_string(tlv_writer *w, uint32_t tag, const char *s);
/* Explicit-length form: the only safe way to write a value slice that is not
 * NUL-terminated (for example a pointer into a parsed buffer). */
tlv_error tlv_writer_string_n(tlv_writer *w, uint32_t tag, const char *s,
                              size_t n);
tlv_error tlv_writer_bool(tlv_writer *w, uint32_t tag, int v);
tlv_error tlv_writer_skip(tlv_writer *w, uint32_t tag, const void *p, size_t n);
/* Optional fields: presence bit `slot` (0..7) is set in the current scope. */
tlv_error tlv_writer_u64_opt(tlv_writer *w, uint32_t tag, uint8_t slot, uint64_t v);
tlv_error tlv_writer_i64_opt(tlv_writer *w, uint32_t tag, uint8_t slot, int64_t v);
tlv_error tlv_writer_bool_opt(tlv_writer *w, uint32_t tag, uint8_t slot, int v);
tlv_error tlv_writer_string_opt(tlv_writer *w, uint32_t tag, uint8_t slot,
                                const char *s, size_t n);
tlv_error tlv_writer_bytes_opt(tlv_writer *w, uint32_t tag, uint8_t slot,
                               const void *p, size_t n);
tlv_error tlv_writer_skip_opt(tlv_writer *w, uint32_t tag, uint8_t slot,
                              const void *p, size_t n);

tlv_error tlv_writer_container_begin(tlv_writer *w, uint32_t tag);
tlv_error tlv_writer_container_begin_opt(tlv_writer *w, uint32_t tag, uint8_t slot);
tlv_error tlv_writer_container_end(tlv_writer *w);

/* Serialize. *out is malloc'd and owned by the caller. */
tlv_error tlv_writer_finish(tlv_writer *w, uint8_t **out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* TLV_H */
