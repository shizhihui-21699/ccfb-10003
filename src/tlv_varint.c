/* Decoders: LEB128 and strict UTF-8. All functions are total: they only ever
 * read bytes inside [p, p+n) and never trust length fields. */
#include "tlv_internal.h"

/* Decode an unsigned LEB128 from exactly n bytes (the field length is
 * authoritative). A sequence that terminates before n bytes, or that still has
 * the continuation bit set at byte n, is malformed. */
tlv_error tlv_uleb_decode(const uint8_t *p, size_t n, uint64_t *out,
                          int *canonical)
{
    uint64_t v = 0;
    int canon = 1;

    if (p == NULL || out == NULL)
        return TLV_ERR_ARG;
    if (n == 0 || n > 8)
        return TLV_ERR_VALUE;

    for (size_t i = 0; i < n; i++) {
        uint8_t b = p[i];
        unsigned long shift = (unsigned long)i * 7u;

        /* 8 bytes * 7 bits = 56 bits; always inside uint64 for i < 8. */
        v |= (uint64_t)(b & 0x7Fu) << shift;

        if (i == n - 1) {
            if (b & 0x80u)
                return TLV_ERR_VALUE; /* truncated inside the field */
            /* Canonical form: the final byte's payload must be non-zero once
             * the encoding uses more than one byte. Intermediate zero bytes
             * (e.g. 0x80) are required and therefore canonical. */
            if (n > 1 && (b & 0x7Fu) == 0)
                canon = 0;
        } else if ((b & 0x80u) == 0) {
            return TLV_ERR_VALUE; /* terminated early, trailing bytes */
        }
    }
    *out = v;
    if (canonical)
        *canonical = canon;
    return TLV_OK;
}

/* Signed LEB128 from exactly n bytes. */
tlv_error tlv_sleb_decode(const uint8_t *p, size_t n, int64_t *out,
                          int *canonical)
{
    uint64_t v = 0;
    unsigned long shift;
    uint8_t last;
    int canon = 1;

    if (p == NULL || out == NULL)
        return TLV_ERR_ARG;
    if (n == 0 || n > 8)
        return TLV_ERR_VALUE;

    for (size_t i = 0; i < n; i++) {
        uint8_t b = p[i];
        v |= (uint64_t)(b & 0x7Fu) << ((unsigned long)i * 7u);
        if (i == n - 1) {
            if (b & 0x80u)
                return TLV_ERR_VALUE;
        } else if ((b & 0x80u) == 0) {
            return TLV_ERR_VALUE;
        }
    }

    shift = (unsigned long)n * 7u; /* 7..56 */
    last = p[n - 1];

    /* Sign extend from bit (shift-1) if the sign bit of the final byte is set. */
    if (shift < 64 && (last & 0x40u))
        v |= ~(uint64_t)0 << shift;

    if (n > 1) {
        uint8_t prev = p[n - 2];
        uint8_t p7 = last & 0x7Fu;
        if (p7 == 0x00u && (prev & 0x40u) == 0)
            canon = 0; /* redundant positive sign extension */
        else if (p7 == 0x7Fu && (prev & 0x40u) != 0)
            canon = 0; /* redundant negative sign extension */
    }

    *out = (int64_t)v;
    if (canonical)
        *canonical = canon;
    return TLV_OK;
}

/* Streaming unsigned LEB128 for header fields (tags and extended lengths). */
tlv_error tlv_uleb_read(const uint8_t *buf, size_t limit, size_t *pos,
                        unsigned max_bytes, uint64_t *out, int *canonical)
{
    uint64_t v = 0;
    size_t p;
    unsigned i;
    int canon = 1;

    if (buf == NULL || pos == NULL || out == NULL)
        return TLV_ERR_ARG;
    if (max_bytes == 0 || max_bytes > 8)
        return TLV_ERR_ARG;

    p = *pos;
    for (i = 0; i < max_bytes; i++) {
        uint8_t b;

        if (p >= limit)
            return TLV_ERR_TRUNCATED;
        b = buf[p++];
        /* max_bytes is <= 8, and i < 8, so the shift is < 56: no overflow. */
        v |= (uint64_t)(b & 0x7Fu) << (i * 7u);
        if ((b & 0x80u) == 0) {
            /* Shortest form: a multi-byte encoding must not end in a zero
             * payload byte, since the value would fit in fewer bytes. */
            if (i > 0 && (b & 0x7Fu) == 0)
                canon = 0;
            *pos = p;
            *out = v;
            if (canonical)
                *canonical = canon;
            return TLV_OK;
        }
    }
    /* Still continued after max_bytes: overlong / never terminates. */
    return TLV_ERR_VARINT;
}

/* Strict UTF-8 per RFC 3629. Rejects overlongs, surrogates, > U+10FFFF,
 * 5/6-byte forms and any truncated or stray sequence. */
tlv_error tlv_utf8_check(const uint8_t *p, size_t n)
{
    size_t i = 0;

    if (p == NULL && n != 0)
        return TLV_ERR_ARG;

    while (i < n) {
        uint8_t c = p[i];
        uint32_t cp;
        size_t need;

        if (c < 0x80u) {
            i++;
            continue;
        }
        if (c < 0xC2u) {
            /* 0x80..0xBF stray continuation; 0xC0/0xC1 would be overlong. */
            return TLV_ERR_UTF8;
        }
        if (c < 0xE0u) {
            need = 1;
            cp = c & 0x1Fu;
        } else if (c < 0xF0u) {
            need = 2;
            cp = c & 0x0Fu;
        } else if (c < 0xF5u) {
            need = 3;
            cp = c & 0x07u;
        } else {
            return TLV_ERR_UTF8; /* 0xF5..0xFF: > U+10FFFF or invalid */
        }

        if (n - i - 1 < need)
            return TLV_ERR_UTF8; /* truncated multibyte sequence */

        for (size_t k = 1; k <= need; k++) {
            uint8_t cc = p[i + k];
            if ((cc & 0xC0u) != 0x80u)
                return TLV_ERR_UTF8;
            cp = (cp << 6) | (cc & 0x3Fu);
        }

        /* Reject overlong encodings and surrogate halves explicitly. */
        if (need == 2 && cp < 0x800u)
            return TLV_ERR_UTF8;
        if (need == 3 && cp < 0x10000u)
            return TLV_ERR_UTF8;
        if (cp >= 0xD800u && cp <= 0xDFFFu)
            return TLV_ERR_UTF8;
        if (cp > 0x10FFFFu)
            return TLV_ERR_UTF8;

        i += need + 1;
    }
    return TLV_OK;
}
