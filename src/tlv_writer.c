/* Encoder. Used by tests, corpus seeding and the CLI tool; it is deliberately
 * independent of the parser so that the two can be cross-checked
 * (encode -> parse -> re-encode must be byte-identical). */
#include "tlv_internal.h"

#include <stdlib.h>

typedef struct wbuf {
    uint8_t *p;
    size_t len;
    size_t cap;
} wbuf;

typedef struct wscope {
    wbuf body;        /* field bytes, excluding the presence bitmap */
    uint8_t bitmap;
    uint32_t last_tag;
    uint32_t tag;      /* tag of the owning container (unused for root) */
    uint8_t optbit;
    uint8_t slot;
    uint32_t field_count;
} wscope;

struct tlv_writer {
    wscope stack[TLV_MAX_DEPTH_HARD + 2];
    size_t depth;      /* index of the innermost open scope */
    uint16_t header_flags;
    tlv_options opt;
    tlv_error err;     /* sticky first error */
    int finished;
};

static tlv_error wbuf_reserve(wbuf *b, size_t extra)
{
    size_t need;
    uint8_t *np;

    if (extra > SIZE_MAX - b->len)
        return TLV_ERR_NOMEM;
    need = b->len + extra;
    if (need <= b->cap)
        return TLV_OK;

    size_t cap = b->cap ? b->cap : 64u;
    while (cap < need) {
        if (cap > SIZE_MAX / 2u) {
            cap = need;
            break;
        }
        cap *= 2u;
    }
    np = realloc(b->p, cap);
    if (np == NULL)
        return TLV_ERR_NOMEM;
    b->p = np;
    b->cap = cap;
    return TLV_OK;
}

static tlv_error wbuf_append(wbuf *b, const void *src, size_t n)
{
    tlv_error e;

    if (n == 0)
        return TLV_OK;
    e = wbuf_reserve(b, n);
    if (e != TLV_OK)
        return e;
    memcpy(b->p + b->len, src, n);
    b->len += n;
    return TLV_OK;
}

static tlv_error wbuf_byte(wbuf *b, uint8_t v)
{
    return wbuf_append(b, &v, 1);
}

/* Canonical unsigned LEB128 (no size cap; caller bounds by value type). */
static tlv_error put_uleb(wbuf *b, uint64_t v)
{
    do {
        uint8_t byte = (uint8_t)(v & 0x7Fu);
        v >>= 7;
        if (v != 0)
            byte |= 0x80u;
        tlv_error e = wbuf_byte(b, byte);
        if (e != TLV_OK)
            return e;
    } while (v != 0);
    return TLV_OK;
}

/* Canonical signed LEB128. Caller must have checked the value fits 8 bytes. */
static tlv_error put_sleb(wbuf *b, int64_t v)
{
    int more = 1;

    while (more) {
        uint8_t byte = (uint8_t)((uint64_t)v & 0x7Fu);
        int64_t rest = v >> 7; /* arithmetic shift */
        int sign = (byte & 0x40u) != 0;

        if ((rest == 0 && !sign) || (rest == -1 && sign))
            more = 0;
        else
            byte |= 0x80u;

        tlv_error e = wbuf_byte(b, byte);
        if (e != TLV_OK)
            return e;
        v = rest;
    }
    return TLV_OK;
}

static tlv_error put_length(wbuf *b, uint32_t len)
{
    if (len <= 0x7Fu) {
        return wbuf_byte(b, (uint8_t)len);
    } else if (len <= 0x1FFFu) {
        uint8_t b0 = (uint8_t)(0x80u | (len >> 8));
        uint8_t b1 = (uint8_t)(len & 0xFFu);
        tlv_error e = wbuf_byte(b, b0);
        return e != TLV_OK ? e : wbuf_byte(b, b1);
    } else if (len <= 0xFFFFFu) {
        uint8_t b0 = (uint8_t)(0xC0u | (len >> 16));
        uint8_t b1 = (uint8_t)((len >> 8) & 0xFFu);
        uint8_t b2 = (uint8_t)(len & 0xFFu);
        tlv_error e = wbuf_byte(b, b0);
        if (e != TLV_OK)
            return e;
        e = wbuf_byte(b, b1);
        return e != TLV_OK ? e : wbuf_byte(b, b2);
    } else {
        tlv_error e = wbuf_byte(b, 0xE0u);
        return e != TLV_OK ? e : put_uleb(b, len);
    }
}

static tlv_error fail(tlv_writer *w, tlv_error e)
{
    if (w->err == TLV_OK)
        w->err = e;
    return w->err;
}

static tlv_error emit(wbuf *dst, uint32_t tag, uint8_t kind, int optbit,
                      uint8_t slot, const uint8_t *value, uint32_t vlen)
{
    tlv_error e;

    if (tag == 0)
        return TLV_ERR_BAD_TAG;
    if (vlen > 0xFFFFFFFFu)
        return TLV_ERR_LIMIT;
    if (optbit && slot > 7)
        return TLV_ERR_BAD_OPTIONAL;
    if (!optbit && slot != 0)
        return TLV_ERR_BAD_OPTIONAL;

    e = put_uleb(dst, tag);
    if (e != TLV_OK)
        return e;

    uint8_t type = (uint8_t)((uint8_t)((kind & 0x07u) << 4) |
                             ((kind == TLV_KIND_CONTAINER) ? 0x80u : 0u) |
                             (optbit ? 0x08u : 0u) | (optbit ? slot : 0u));
    e = wbuf_byte(dst, type);
    if (e != TLV_OK)
        return e;
    e = put_length(dst, vlen);
    if (e != TLV_OK)
        return e;
    return wbuf_append(dst, value, vlen);
}

static tlv_error append_to_current(tlv_writer *w, uint32_t tag, const uint8_t *body,
                                   size_t body_len, uint8_t kind, int optbit,
                                   uint8_t slot)
{
    wscope *sc = &w->stack[w->depth];
    wbuf tmp = {0};
    tlv_error e;

    if (sc->last_tag != 0 && tag <= sc->last_tag)
        return fail(w, TLV_ERR_TAG_ORDER);
    if (sc->field_count >= w->opt.max_fields)
        return fail(w, TLV_ERR_FIELDS);

    if (optbit) {
        uint8_t bit = (uint8_t)(1u << slot);
        if (sc->bitmap & bit)
            return fail(w, TLV_ERR_BAD_OPTIONAL);
        sc->bitmap |= bit;
    }

    /* Assemble into a scratch buffer so a failure leaves no partial field. */
    e = emit(&tmp, tag, kind, optbit, slot, body, (uint32_t)body_len);
    if (e == TLV_OK)
        e = wbuf_append(&sc->body, tmp.p, tmp.len);
    free(tmp.p);
    if (e != TLV_OK)
        return fail(w, e);

    sc->last_tag = tag;
    sc->field_count++;
    return TLV_OK;
}

tlv_writer *tlv_writer_new(uint16_t header_flags, const tlv_options *opt)
{
    tlv_writer *w;

    if ((header_flags & (uint16_t)~TLV_FLAG_STRICT) != 0)
        return NULL;

    w = calloc(1, sizeof(*w));
    if (w == NULL)
        return NULL;
    w->header_flags = header_flags;
    tlv_options_normalize(opt, &w->opt);
    w->depth = 0;
    w->stack[0].bitmap = 0;
    w->stack[0].last_tag = 0;
    w->stack[0].field_count = 0;
    return w;
}

void tlv_writer_free(tlv_writer *w)
{
    if (w == NULL)
        return;
    for (size_t i = 0; i <= w->depth && i < TLV_MAX_DEPTH_HARD + 2u; i++)
        free(w->stack[i].body.p);
    free(w);
}

tlv_error tlv_writer_u64(tlv_writer *w, uint32_t tag, uint64_t v)
{
    wbuf tmp = {0};
    tlv_error e;

    if (w == NULL)
        return TLV_ERR_ARG;
    if (v > (1ULL << 56) - 1)
        return fail(w, TLV_ERR_VALUE);
    if ((e = put_uleb(&tmp, v)) == TLV_OK)
        e = append_to_current(w, tag, tmp.p, tmp.len, TLV_KIND_UINT, 0, 0);
    free(tmp.p);
    return e;
}

tlv_error tlv_writer_i64(tlv_writer *w, uint32_t tag, int64_t v)
{
    wbuf tmp = {0};
    tlv_error e;

    if (w == NULL)
        return TLV_ERR_ARG;
    if (v < -(INT64_C(1) << 55) || v > (INT64_C(1) << 55) - 1)
        return fail(w, TLV_ERR_VALUE);
    if ((e = put_sleb(&tmp, v)) == TLV_OK)
        e = append_to_current(w, tag, tmp.p, tmp.len, TLV_KIND_INT, 0, 0);
    free(tmp.p);
    return e;
}

tlv_error tlv_writer_bytes(tlv_writer *w, uint32_t tag, const void *p, size_t n)
{
    if (w == NULL)
        return TLV_ERR_ARG;
    if (p == NULL && n != 0)
        return fail(w, TLV_ERR_ARG);
    return append_to_current(w, tag, (const uint8_t *)p, n, TLV_KIND_BYTES, 0, 0);
}

tlv_error tlv_writer_string_n(tlv_writer *w, uint32_t tag, const char *s,
                              size_t n)
{
    if (w == NULL || (s == NULL && n != 0))
        return TLV_ERR_ARG;
    if (n > 0xFFFFFFFFu)
        return fail(w, TLV_ERR_LIMIT);
    if (tlv_utf8_check((const uint8_t *)s, n) != TLV_OK)
        return fail(w, TLV_ERR_UTF8);
    return append_to_current(w, tag, (const uint8_t *)s, n, TLV_KIND_STRING, 0, 0);
}

tlv_error tlv_writer_string(tlv_writer *w, uint32_t tag, const char *s)
{
    if (w == NULL || s == NULL)
        return TLV_ERR_ARG;
    return tlv_writer_string_n(w, tag, s, strlen(s));
}

tlv_error tlv_writer_bool(tlv_writer *w, uint32_t tag, int v)
{
    uint8_t b = v ? 1u : 0u;

    if (w == NULL)
        return TLV_ERR_ARG;
    return append_to_current(w, tag, &b, 1, TLV_KIND_BOOL, 0, 0);
}

tlv_error tlv_writer_skip(tlv_writer *w, uint32_t tag, const void *p, size_t n)
{
    if (w == NULL)
        return TLV_ERR_ARG;
    if (p == NULL && n != 0)
        return fail(w, TLV_ERR_ARG);
    return append_to_current(w, tag, (const uint8_t *)p, n, TLV_KIND_SKIP, 0, 0);
}

tlv_error tlv_writer_u64_opt(tlv_writer *w, uint32_t tag, uint8_t slot, uint64_t v)
{
    wbuf tmp = {0};
    tlv_error e;

    if (w == NULL)
        return TLV_ERR_ARG;
    if (slot > 7 || v > (1ULL << 56) - 1)
        return fail(w, TLV_ERR_VALUE);
    if ((e = put_uleb(&tmp, v)) == TLV_OK)
        e = append_to_current(w, tag, tmp.p, tmp.len, TLV_KIND_UINT, 1, slot);
    free(tmp.p);
    return e;
}

tlv_error tlv_writer_bytes_opt(tlv_writer *w, uint32_t tag, uint8_t slot,
                               const void *p, size_t n)
{
    if (w == NULL)
        return TLV_ERR_ARG;
    if (slot > 7)
        return fail(w, TLV_ERR_BAD_OPTIONAL);
    if (p == NULL && n != 0)
        return fail(w, TLV_ERR_ARG);
    return append_to_current(w, tag, (const uint8_t *)p, n, TLV_KIND_BYTES, 1, slot);
}

tlv_error tlv_writer_i64_opt(tlv_writer *w, uint32_t tag, uint8_t slot, int64_t v)
{
    wbuf tmp = {0};
    tlv_error e;

    if (w == NULL)
        return TLV_ERR_ARG;
    if (slot > 7 || v < -(INT64_C(1) << 55) || v > (INT64_C(1) << 55) - 1)
        return fail(w, slot > 7 ? TLV_ERR_BAD_OPTIONAL : TLV_ERR_VALUE);
    if ((e = put_sleb(&tmp, v)) == TLV_OK)
        e = append_to_current(w, tag, tmp.p, tmp.len, TLV_KIND_INT, 1, slot);
    free(tmp.p);
    return e;
}

tlv_error tlv_writer_bool_opt(tlv_writer *w, uint32_t tag, uint8_t slot, int v)
{
    uint8_t b = v ? 1u : 0u;

    if (w == NULL)
        return TLV_ERR_ARG;
    if (slot > 7)
        return fail(w, TLV_ERR_BAD_OPTIONAL);
    return append_to_current(w, tag, &b, 1, TLV_KIND_BOOL, 1, slot);
}

tlv_error tlv_writer_string_opt(tlv_writer *w, uint32_t tag, uint8_t slot,
                                const char *s, size_t n)
{
    if (w == NULL)
        return TLV_ERR_ARG;
    if (slot > 7)
        return fail(w, TLV_ERR_BAD_OPTIONAL);
    if (s == NULL && n != 0)
        return fail(w, TLV_ERR_ARG);
    if (n > 0xFFFFFFFFu)
        return fail(w, TLV_ERR_LIMIT);
    if (tlv_utf8_check((const uint8_t *)s, n) != TLV_OK)
        return fail(w, TLV_ERR_UTF8);
    return append_to_current(w, tag, (const uint8_t *)s, n, TLV_KIND_STRING, 1, slot);
}

tlv_error tlv_writer_skip_opt(tlv_writer *w, uint32_t tag, uint8_t slot,
                              const void *p, size_t n)
{
    if (w == NULL)
        return TLV_ERR_ARG;
    if (slot > 7)
        return fail(w, TLV_ERR_BAD_OPTIONAL);
    if (p == NULL && n != 0)
        return fail(w, TLV_ERR_ARG);
    return append_to_current(w, tag, (const uint8_t *)p, n, TLV_KIND_SKIP, 1, slot);
}

static tlv_error container_begin_common(tlv_writer *w, uint32_t tag, int optbit,
                                        uint8_t slot)
{
    wscope *sc;

    if (w == NULL)
        return TLV_ERR_ARG;
    if (w->depth + 1 > (size_t)w->opt.max_depth)
        return fail(w, TLV_ERR_DEPTH);
    if (w->depth + 1 >= TLV_MAX_DEPTH_HARD + 2u)
        return fail(w, TLV_ERR_DEPTH);

    sc = &w->stack[w->depth];
    if (sc->last_tag != 0 && tag <= sc->last_tag)
        return fail(w, TLV_ERR_TAG_ORDER);
    if (sc->field_count >= w->opt.max_fields)
        return fail(w, TLV_ERR_FIELDS);
    if (optbit) {
        uint8_t bit = (uint8_t)(1u << slot);
        if (sc->bitmap & bit)
            return fail(w, TLV_ERR_BAD_OPTIONAL);
    }
    /* The child scope commits its tag/slot into the parent on end. */
    w->depth++;
    memset(&w->stack[w->depth], 0, sizeof(wscope));
    w->stack[w->depth].tag = tag;
    w->stack[w->depth].optbit = (uint8_t)(optbit ? 1 : 0);
    w->stack[w->depth].slot = optbit ? slot : 0;
    return TLV_OK;
}

tlv_error tlv_writer_container_begin(tlv_writer *w, uint32_t tag)
{
    return container_begin_common(w, tag, 0, 0);
}

tlv_error tlv_writer_container_begin_opt(tlv_writer *w, uint32_t tag, uint8_t slot)
{
    if (slot > 7)
        return w ? fail(w, TLV_ERR_BAD_OPTIONAL) : TLV_ERR_ARG;
    return container_begin_common(w, tag, 1, slot);
}

tlv_error tlv_writer_container_end(tlv_writer *w)
{
    wscope *child;
    wbuf tmp = {0};
    tlv_error e;

    if (w == NULL)
        return TLV_ERR_ARG;
    if (w->depth == 0)
        return fail(w, TLV_ERR_ARG);

    child = &w->stack[w->depth];
    if (child->body.len + 1u > 0xFFFFFFFFu)
        return fail(w, TLV_ERR_LIMIT);

    /* Value = bitmap byte followed by the child's field bytes. */
    e = wbuf_byte(&tmp, child->bitmap);
    if (e == TLV_OK)
        e = wbuf_append(&tmp, child->body.p, child->body.len);
    if (e != TLV_OK) {
        free(tmp.p);
        return fail(w, e);
    }

    w->depth--;
    {
        wscope *parent = &w->stack[w->depth];
        if (parent->last_tag != 0 && child->tag <= parent->last_tag)
            e = TLV_ERR_TAG_ORDER;
        else if (parent->field_count >= w->opt.max_fields)
            e = TLV_ERR_FIELDS;
        else if (child->optbit) {
            uint8_t bit = (uint8_t)(1u << child->slot);
            if (parent->bitmap & bit)
                e = TLV_ERR_BAD_OPTIONAL;
            else
                parent->bitmap |= bit;
        }
        if (e == TLV_OK)
            e = emit(&parent->body, child->tag, TLV_KIND_CONTAINER,
                     child->optbit, child->slot, tmp.p, (uint32_t)tmp.len);
        if (e == TLV_OK) {
            parent->last_tag = child->tag;
            parent->field_count++;
        }
    }

    free(tmp.p);
    free(child->body.p);
    child->body.p = NULL;
    child->body.len = child->body.cap = 0;

    return e == TLV_OK ? TLV_OK : fail(w, e);
}

tlv_error tlv_writer_finish(tlv_writer *w, uint8_t **out, size_t *out_len)
{
    wbuf msg = {0};
    tlv_error e = TLV_OK;
    uint32_t region_len;

    if (w == NULL || out == NULL || out_len == NULL)
        return TLV_ERR_ARG;
    *out = NULL;
    *out_len = 0;
    if (w->err != TLV_OK)
        return w->err;
    if (w->depth != 0)
        return TLV_ERR_ARG; /* unclosed container */
    if (w->finished)
        return TLV_ERR_ARG;

    /* Field region = bitmap + body, and the declared length includes it. */
    if (w->stack[0].body.len + 1u > 0xFFFFFFFFu)
        return TLV_ERR_LIMIT;
    region_len = (uint32_t)(w->stack[0].body.len + 1u);

    uint8_t header[TLV_HEADER_SIZE] = {
        TLV_MAGIC0, TLV_MAGIC1, TLV_MAGIC2, TLV_MAGIC3, TLV_VERSION,
        (uint8_t)(w->header_flags >> 8), (uint8_t)(w->header_flags & 0xFFu),
        (uint8_t)(region_len >> 24), (uint8_t)(region_len >> 16),
        (uint8_t)(region_len >> 8), (uint8_t)(region_len & 0xFFu)
    };

    e = wbuf_append(&msg, header, sizeof(header));
    if (e == TLV_OK)
        e = wbuf_byte(&msg, w->stack[0].bitmap);
    if (e == TLV_OK)
        e = wbuf_append(&msg, w->stack[0].body.p, w->stack[0].body.len);
    if (e != TLV_OK) {
        free(msg.p);
        return fail(w, e);
    }

    w->finished = 1;
    *out = msg.p;
    *out_len = msg.len;
    return TLV_OK;
}
