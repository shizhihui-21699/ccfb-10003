/* Iterative TLVX parser.
 *
 * The parser never recurses: scopes live on an explicit, depth-bounded stack,
 * so a hostile message with thousands of nested containers costs bounded
 * heap/stack and yields TLV_ERR_DEPTH long before anything overflows.
 */
#include "tlv_internal.h"

#include <stdlib.h>

/* Explicit scope stack frame. `last_child` avoids walking the sibling list on
 * every append (which would make wide scopes quadratic). */
typedef struct scope_frame {
    tlv_node *container;  /* node owning this scope; NULL for the root */
    tlv_node *last_child;
    size_t end;           /* absolute end offset of the field region */
    uint8_t bitmap;       /* presence bitmap of this scope */
    uint8_t used_mask;    /* optional slots actually claimed */
    uint32_t last_tag;
    uint32_t field_count;
} scope_frame;


void tlv_options_init(tlv_options *opt)
{
    if (opt == NULL)
        return;
    opt->strict = 1;
    opt->max_depth = 0;
    opt->max_fields = 0;
    opt->max_total_fields = 0;
    opt->max_message_bytes = 0;
}

void tlv_options_normalize(const tlv_options *in, tlv_options *out)
{
    if (out == NULL)
        return;
    if (in == NULL) {
        tlv_options_init(out);
    } else {
        out->strict = in->strict ? 1u : 0u;
        out->max_depth = in->max_depth;
        out->max_fields = in->max_fields;
        out->max_total_fields = in->max_total_fields;
        out->max_message_bytes = in->max_message_bytes;
    }

    if (out->max_depth == 0)
        out->max_depth = 16;
    if (out->max_depth > TLV_MAX_DEPTH_HARD)
        out->max_depth = TLV_MAX_DEPTH_HARD;
    if (out->max_fields == 0)
        out->max_fields = TLV_MAX_FIELDS_PER_SCOPE_HARD;
    if (out->max_fields > TLV_MAX_FIELDS_PER_SCOPE_HARD)
        out->max_fields = TLV_MAX_FIELDS_PER_SCOPE_HARD;
    if (out->max_total_fields == 0)
        out->max_total_fields = TLV_MAX_TOTAL_FIELDS_HARD;
    if (out->max_total_fields > TLV_MAX_TOTAL_FIELDS_HARD)
        out->max_total_fields = TLV_MAX_TOTAL_FIELDS_HARD;
    if (out->max_message_bytes == 0)
        out->max_message_bytes = 16u * 1024u * 1024u;
    if (out->max_message_bytes > TLV_MAX_MESSAGE_BYTES_HARD)
        out->max_message_bytes = TLV_MAX_MESSAGE_BYTES_HARD;
}

/* Decode the length field at *pos, bounded by `end`. Advances *pos past it. */
static tlv_error read_length(const uint8_t *buf, size_t end, size_t *pos,
                             uint32_t *out_len, int strict)
{
    size_t p = *pos;
    uint8_t b0;
    uint64_t len;

    if (p >= end)
        return TLV_ERR_TRUNCATED;
    b0 = buf[p++];

    if ((b0 & 0x80u) == 0) {
        len = b0;
    } else if ((b0 & 0xE0u) == 0x80u) {
        if (p >= end)
            return TLV_ERR_TRUNCATED;
        len = ((uint64_t)(b0 & 0x1Fu) << 8) | buf[p++];
    } else if ((b0 & 0xF0u) == 0xC0u) {
        if (end - p < 2)
            return TLV_ERR_TRUNCATED;
        len = ((uint64_t)(b0 & 0x0Fu) << 16) | ((uint64_t)buf[p] << 8) |
              buf[p + 1];
        p += 2;
    } else if (b0 == 0xE0u) {
        uint64_t v;
        int canon = 1;
        tlv_error e = tlv_uleb_read(buf, end, &p, 5, &v, &canon);
        if (e != TLV_OK)
            return e == TLV_ERR_VARINT ? TLV_ERR_BAD_LENGTH_ENCODING : e;
        if (strict && !canon)
            return TLV_ERR_BAD_LENGTH_ENCODING;
        if (v > 0xFFFFFFFFu)
            return TLV_ERR_BAD_LENGTH_ENCODING;
        len = v;
    } else {
        /* 0xD0..0xDF and 0xF0..0xFF are reserved. */
        return TLV_ERR_BAD_LENGTH_ENCODING;
    }

    *pos = p;
    *out_len = (uint32_t)len;
    return TLV_OK;
}

/* Validate a leaf value slice. Returns TLV_OK for readability/conformance. */
static tlv_error validate_value(uint8_t kind, const uint8_t *v, uint32_t len,
                                int strict, uint8_t *out_flags)
{
    int canon = 1;

    switch (kind) {
    case TLV_KIND_INT: {
        int64_t x;
        tlv_error e = tlv_sleb_decode(v, len, &x, &canon);
        if (e != TLV_OK)
            return e;
        if (strict && !canon)
            return TLV_ERR_VARINT;
        break;
    }
    case TLV_KIND_UINT: {
        uint64_t x;
        tlv_error e = tlv_uleb_decode(v, len, &x, &canon);
        if (e != TLV_OK)
            return e;
        if (strict && !canon)
            return TLV_ERR_VARINT;
        break;
    }
    case TLV_KIND_BOOL:
        if (len != 1)
            return TLV_ERR_VALUE;
        if (v[0] > 1u)
            return TLV_ERR_VALUE;
        break;
    case TLV_KIND_STRING:
        if (tlv_utf8_check(v, len) != TLV_OK)
            return TLV_ERR_UTF8;
        break;
    default:
        break; /* BYTES / SKIP / CONTAINER */
    }

    if (out_flags != NULL && canon)
        *out_flags |= 0x01u;
    return TLV_OK;
}

static tlv_node *append_child(scope_frame *fr, tlv_node *n)
{
    if (fr->last_child != NULL)
        fr->last_child->next_sibling = n;
    else
        fr->container->first_child = n;
    fr->last_child = n;
    return n;
}

static tlv_error parse_internal(const uint8_t *buf, size_t len,
                                const tlv_options *opt_in,
                                tlv_document **out_doc)
{
    tlv_options opt;
    tlv_document *doc;
    scope_frame *stack;
    size_t depth;     /* index of the current top frame */
    size_t pos;
    size_t root_end;
    uint32_t total_fields = 0;
    int strict;
    tlv_error err = TLV_OK;

    tlv_options_normalize(opt_in, &opt);
    strict = opt.strict != 0;

    if (len < TLV_HEADER_SIZE)
        return TLV_ERR_TRUNCATED;
    if (len > opt.max_message_bytes)
        return TLV_ERR_LIMIT;

    if (buf[0] != TLV_MAGIC0 || buf[1] != TLV_MAGIC1 ||
        buf[2] != TLV_MAGIC2 || buf[3] != TLV_MAGIC3)
        return TLV_ERR_BAD_MAGIC;
    if (buf[4] != TLV_VERSION)
        return TLV_ERR_BAD_VERSION;

    {
        uint16_t flags = (uint16_t)((uint16_t)buf[5] << 8 | buf[6]);
        if (flags & (uint16_t)~TLV_FLAG_STRICT)
            return TLV_ERR_BAD_FLAGS;
        if (flags & TLV_FLAG_STRICT)
            strict = 1;
    }

    {
        uint32_t frl = ((uint32_t)buf[7] << 24) | ((uint32_t)buf[8] << 16) |
                       ((uint32_t)buf[9] << 8) | (uint32_t)buf[10];
        if (frl < 1)
            return TLV_ERR_TRUNCATED; /* needs at least the presence bitmap */
        if ((uint64_t)frl > (uint64_t)(len - TLV_HEADER_SIZE))
            return TLV_ERR_TRUNCATED;
        if (strict && (uint64_t)frl != (uint64_t)(len - TLV_HEADER_SIZE))
            return TLV_ERR_LENGTH_MISMATCH;
        root_end = TLV_HEADER_SIZE + (size_t)frl;
    }

    doc = calloc(1, sizeof(*doc));
    if (doc == NULL)
        return TLV_ERR_NOMEM;
    doc->opt = opt;

    /* Worst case node count is bounded; size the arena to the configured
     * total-field ceiling plus the root, so exhaustion is deterministic. */
    {
        size_t node_limit = (size_t)opt.max_total_fields + 1u;
        tlv_arena_init(&doc->arena, node_limit);
    }

    doc->root = tlv_arena_alloc(&doc->arena);
    if (doc->root == NULL) {
        err = TLV_ERR_NOMEM;
        goto fail;
    }
    doc->root->kind = TLV_KIND_CONTAINER;
    doc->root->depth = 0;
    doc->root->value_len = (uint32_t)(root_end - TLV_HEADER_SIZE);
    doc->root->offset = 0;

    /* max_depth+1 nested scopes are reachable (depths 0..max_depth). */
    stack = calloc((size_t)opt.max_depth + 2u, sizeof(*stack));
    if (stack == NULL) {
        err = TLV_ERR_NOMEM;
        goto fail;
    }

    /* Frame 0: root scope. Its region starts with the bitmap byte. */
    depth = 0;
    pos = TLV_HEADER_SIZE;
    stack[0].container = doc->root;
    stack[0].last_child = NULL;
    stack[0].end = root_end;
    if (pos >= root_end) {
        err = TLV_ERR_TRUNCATED;
        goto fail_free_stack;
    }
    stack[0].bitmap = buf[pos++];
    stack[0].used_mask = 0;
    stack[0].last_tag = 0;
    stack[0].field_count = 0;
    doc->root->value = buf + TLV_HEADER_SIZE;

    for (;;) {
        scope_frame *fr = &stack[depth];
        size_t field_start;
        uint32_t tag;
        uint8_t type;
        uint8_t kind;
        uint32_t vlen;
        const uint8_t *value;
        tlv_node *node;

        if (pos >= fr->end) {
            /* Scope complete. */
            if (strict && (fr->bitmap & (uint8_t)~fr->used_mask) != 0) {
                err = TLV_ERR_OPTIONAL_UNUSED;
                goto fail_free_stack;
            }
            if (depth == 0)
                break;
            depth--;
            continue;
        }

        field_start = pos;

        /* --- tag --- */
        {
            int canon = 1;
            uint64_t t;
            err = tlv_uleb_read(buf, fr->end, &pos, 5, &t, &canon);
            if (err != TLV_OK) {
                if (err == TLV_ERR_VARINT)
                    err = TLV_ERR_BAD_TAG;
                goto fail_free_stack;
            }
            if (strict && !canon) {
                err = TLV_ERR_VARINT;
                goto fail_free_stack;
            }
            if (t == 0 || t > 0xFFFFFFFFu) {
                err = TLV_ERR_BAD_TAG;
                goto fail_free_stack;
            }
            tag = (uint32_t)t;
        }

        if (tag <= fr->last_tag) {
            err = TLV_ERR_TAG_ORDER;
            goto fail_free_stack;
        }
        fr->last_tag = tag;

        if (fr->field_count >= opt.max_fields) {
            err = TLV_ERR_FIELDS;
            goto fail_free_stack;
        }
        if (total_fields >= opt.max_total_fields) {
            err = TLV_ERR_FIELDS;
            goto fail_free_stack;
        }

        /* --- type byte --- */
        if (pos >= fr->end) {
            err = TLV_ERR_TRUNCATED;
            goto fail_free_stack;
        }
        type = buf[pos++];

        kind = (uint8_t)((type >> 4) & 0x07u);
        if (kind == 7u) {
            err = TLV_ERR_RESERVED_KIND;
            goto fail_free_stack;
        }

        {
            int constructed = (type & 0x80u) != 0;
            int optbit = (type & 0x08u) != 0;
            uint8_t slot = (uint8_t)(type & 0x07u);

            if (constructed != (kind == TLV_KIND_CONTAINER)) {
                err = TLV_ERR_BAD_TYPE;
                goto fail_free_stack;
            }
            if (!optbit && slot != 0) {
                err = TLV_ERR_BAD_TYPE;
                goto fail_free_stack;
            }
            if (optbit) {
                uint8_t bit = (uint8_t)(1u << slot);
                if ((fr->bitmap & bit) == 0) {
                    /* Declared optional but the bitmap says it is absent. */
                    err = TLV_ERR_BAD_OPTIONAL;
                    goto fail_free_stack;
                }
                if (fr->used_mask & bit) {
                    err = TLV_ERR_BAD_OPTIONAL; /* slot claimed twice */
                    goto fail_free_stack;
                }
                fr->used_mask |= bit;
            }

            /* --- length --- */
            err = read_length(buf, fr->end, &pos, &vlen, strict);
            if (err != TLV_OK)
                goto fail_free_stack;

            if ((uint64_t)vlen > (uint64_t)(fr->end - pos)) {
                err = TLV_ERR_TRUNCATED;
                goto fail_free_stack;
            }

            value = buf + pos;

            if (kind == TLV_KIND_CONTAINER) {
                if (vlen < 1) {
                    err = TLV_ERR_TRUNCATED; /* needs its own bitmap */
                    goto fail_free_stack;
                }
                if (depth + 1 > (size_t)opt.max_depth) {
                    err = TLV_ERR_DEPTH;
                    goto fail_free_stack;
                }
                node = tlv_arena_alloc(&doc->arena);
                if (node == NULL) {
                    err = TLV_ERR_NOMEM;
                    goto fail_free_stack;
                }
                node->tag = tag;
                node->kind = kind;
                node->is_optional = (uint8_t)(optbit ? 1 : 0);
                node->slot = optbit ? slot : 0;
                node->depth = (uint16_t)(depth + 1);
                node->offset = field_start;
                node->value = value;
                node->value_len = vlen;
                node->parent = fr->container;
                append_child(fr, node);

                fr->field_count++;
                total_fields++;

                /* Descend. The container's own region is [pos, pos+vlen). */
                depth++;
                stack[depth].container = node;
                stack[depth].last_child = NULL;
                stack[depth].end = pos + vlen;
                stack[depth].bitmap = *value;
                stack[depth].used_mask = 0;
                stack[depth].last_tag = 0;
                stack[depth].field_count = 0;
                pos++; /* skip the child bitmap byte */
                continue;
            }

            node = tlv_arena_alloc(&doc->arena);
            if (node == NULL) {
                err = TLV_ERR_NOMEM;
                goto fail_free_stack;
            }
            node->tag = tag;
            node->kind = kind;
            node->is_optional = (uint8_t)(optbit ? 1 : 0);
            node->slot = optbit ? slot : 0;
            node->depth = (uint16_t)(depth + 1);
            node->offset = field_start;
            node->value = value;
            node->value_len = vlen;
            node->parent = fr->container;

            err = validate_value(kind, value, vlen, strict, &node->flags);
            if (err != TLV_OK)
                goto fail_free_stack;

            append_child(fr, node);
            fr->field_count++;
            total_fields++;
            pos += vlen;
        }
    }

    free(stack);
    *out_doc = doc;
    return TLV_OK;

fail_free_stack:
    free(stack);
fail:
    tlv_arena_free(&doc->arena);
    free(doc);
    return err;
}

tlv_error tlv_parse(const uint8_t *buf, size_t len, const tlv_options *opt,
                    tlv_document **out_doc)
{
    if (out_doc == NULL)
        return TLV_ERR_ARG;
    *out_doc = NULL;
    if (buf == NULL && len != 0)
        return TLV_ERR_ARG;
    if (buf == NULL)
        return TLV_ERR_TRUNCATED;
    return parse_internal(buf, len, opt, out_doc);
}

tlv_error tlv_parse_strict(const uint8_t *buf, size_t len, tlv_document **out_doc)
{
    tlv_options opt;
    tlv_options_init(&opt);
    opt.strict = 1;
    return tlv_parse(buf, len, &opt, out_doc);
}

void tlv_document_free(tlv_document *doc)
{
    if (doc == NULL)
        return;
    tlv_arena_free(&doc->arena);
    free(doc);
}

const tlv_node *tlv_document_root(const tlv_document *doc)
{
    return doc ? doc->root : NULL;
}

size_t tlv_document_node_count(const tlv_document *doc)
{
    return doc ? doc->arena.count - 1u : 0u;
}
