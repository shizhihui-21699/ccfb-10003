/* Unit and conformance tests for libtlv. The suite is the executable form of
 * docs/PROTOCOL.md: every normative rule has at least one positive and one
 * negative case.
 *
 * Compiled under ASan+UBSan with -fno-sanitize-recover, so any undefined
 * behaviour in the tests' own helper code fails the run loudly. */
#include "tlv.h"
#include "../src/tlv_internal.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures;
static int g_checks;
static const char *g_current;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_checks++;                                                          \
        if (!(cond)) {                                                       \
            g_failures++;                                                    \
            fprintf(stderr, "FAIL %s:%d [%s] %s\n", __FILE__, __LINE__,      \
                    g_current, #cond);                                       \
        }                                                                    \
    } while (0)

#define TEST(name) static void name(void)

/* ---- helpers ---- */

typedef struct blob {
    uint8_t *p;
    size_t len;
} blob;

/* Wrap a field-region payload into a well-formed message. */
static blob wrap_fields(const uint8_t *fields, size_t n)
{
    blob b;
    b.len = TLV_HEADER_SIZE + n;
    b.p = malloc(b.len ? b.len : 1);
    if (b.p == NULL)
        abort();
    b.p[0] = TLV_MAGIC0;
    b.p[1] = TLV_MAGIC1;
    b.p[2] = TLV_MAGIC2;
    b.p[3] = TLV_MAGIC3;
    b.p[4] = TLV_VERSION;
    b.p[5] = 0;
    b.p[6] = 0;
    b.p[7] = (uint8_t)(n >> 24);
    b.p[8] = (uint8_t)(n >> 16);
    b.p[9] = (uint8_t)(n >> 8);
    b.p[10] = (uint8_t)n;
    memcpy(b.p + TLV_HEADER_SIZE, fields, n);
    return b;
}

static tlv_error parse_blob(const blob *b, tlv_document **out)
{
    return tlv_parse_strict(b->p, b->len, out);
}

static void expect_ok(const blob *b, const char *what)
{
    tlv_document *doc = NULL;
    tlv_error e;

    g_current = what;
    e = parse_blob(b, &doc);
    CHECK(e == TLV_OK);
    CHECK(doc != NULL);
    tlv_document_free(doc);
}

static void expect_err(const blob *b, tlv_error want, const char *what)
{
    tlv_document *doc = NULL;
    tlv_error e;

    g_current = what;
    /* Sentinel so a missing reset on failure is visible. */
    doc = (tlv_document *)&g_checks;
    e = parse_blob(b, &doc);
    CHECK(e == want);
    CHECK(doc == NULL);
}

/* ---- LEB128 ---- */

TEST(test_uleb_decode)
{
    uint64_t v;
    int canon;

    g_current = "uleb";
    {
        const uint8_t b[] = {0x00};
        CHECK(tlv_uleb_decode(b, 1, &v, &canon) == TLV_OK && v == 0 && canon);
    }
    {
        const uint8_t b[] = {0x7F};
        CHECK(tlv_uleb_decode(b, 1, &v, &canon) == TLV_OK && v == 127);
    }
    {
        const uint8_t b[] = {0x80, 0x01};
        CHECK(tlv_uleb_decode(b, 2, &v, &canon) == TLV_OK && v == 128 && canon);
    }
    {
        /* 300 = 0b1_0010_1100 */
        const uint8_t b[] = {0xAC, 0x02};
        CHECK(tlv_uleb_decode(b, 2, &v, &canon) == TLV_OK && v == 300);
    }
    {
        /* Non-canonical: 0x80 0x00 == 0 encoded in two bytes. */
        const uint8_t b[] = {0x80, 0x00};
        CHECK(tlv_uleb_decode(b, 2, &v, &canon) == TLV_OK && v == 0 && !canon);
    }
    {
        /* Terminates early: field length says 2 but first byte ends it. */
        const uint8_t b[] = {0x01, 0x00};
        CHECK(tlv_uleb_decode(b, 2, &v, &canon) == TLV_ERR_VALUE);
    }
    {
        /* Continues past the declared length. */
        const uint8_t b[] = {0x81};
        CHECK(tlv_uleb_decode(b, 1, &v, &canon) == TLV_ERR_VALUE);
    }
    {
        /* 8 bytes: max width, value 2^56-1. */
        const uint8_t b[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};
        CHECK(tlv_uleb_decode(b, 8, &v, &canon) == TLV_OK &&
              v == ((1ULL << 56) - 1));
    }
    {
        const uint8_t b[] = {0};
        CHECK(tlv_uleb_decode(b, 0, &v, &canon) == TLV_ERR_VALUE);
    }
    {
        const uint8_t b[] = {0};
        CHECK(tlv_uleb_decode(b, 9, &v, &canon) == TLV_ERR_VALUE);
    }
}

TEST(test_sleb_decode)
{
    int64_t v;
    int canon;

    g_current = "sleb";
    {
        const uint8_t b[] = {0x00};
        CHECK(tlv_sleb_decode(b, 1, &v, &canon) == TLV_OK && v == 0);
    }
    {
        const uint8_t b[] = {0x3F};
        CHECK(tlv_sleb_decode(b, 1, &v, &canon) == TLV_OK && v == 63);
    }
    {
        const uint8_t b[] = {0x40};
        CHECK(tlv_sleb_decode(b, 1, &v, &canon) == TLV_OK && v == -64);
    }
    {
        const uint8_t b[] = {0x7F};
        CHECK(tlv_sleb_decode(b, 1, &v, &canon) == TLV_OK && v == -1 && canon);
    }
    {
        /* 300 in signed LEB128. */
        const uint8_t b[] = {0xAC, 0x02};
        CHECK(tlv_sleb_decode(b, 2, &v, &canon) == TLV_OK && v == 300);
    }
    {
        const uint8_t b[] = {0xBF, 0x7F};
        CHECK(tlv_sleb_decode(b, 2, &v, &canon) == TLV_OK && v == -65 && canon);
    }
    {
        /* Non-canonical -1: 0xFF 0x7F. */
        const uint8_t b[] = {0xFF, 0x7F};
        CHECK(tlv_sleb_decode(b, 2, &v, &canon) == TLV_OK && v == -1 && !canon);
    }
    {
        /* Non-canonical +0 in two bytes: 0x80 0x00. */
        const uint8_t b[] = {0x80, 0x00};
        CHECK(tlv_sleb_decode(b, 2, &v, &canon) == TLV_OK && v == 0 && !canon);
    }
    {
        /* Max positive in 8 bytes: 2^55-1. The last byte's bit 6 is the sign
         * bit, so the payload ends in 0x3F, not 0x7F. */
        const uint8_t b[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F};
        CHECK(tlv_sleb_decode(b, 8, &v, &canon) == TLV_OK &&
              v == (INT64_C(1) << 55) - 1 && canon);
    }
    {
        /* Min negative in 8 bytes: -(2^55). */
        const uint8_t b[] = {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x40};
        CHECK(tlv_sleb_decode(b, 8, &v, &canon) == TLV_OK &&
              v == -(INT64_C(1) << 55) && canon);
    }
}

/* ---- UTF-8 ---- */

static void utf8_case(const uint8_t *s, size_t n, tlv_error want, const char *what)
{
    g_current = what;
    CHECK(tlv_utf8_check(s, n) == want);
}

TEST(test_utf8)
{
    utf8_case((const uint8_t *)"hello", 5, TLV_OK, "ascii");
    utf8_case((const uint8_t *)"", 0, TLV_OK, "empty");
    utf8_case((const uint8_t *)"\xC3\xA9", 2, TLV_OK, "e-acute");
    utf8_case((const uint8_t *)"\xE4\xB8\xAD", 3, TLV_OK, "cjk");
    utf8_case((const uint8_t *)"\xF0\x9F\x98\x80", 4, TLV_OK, "emoji");
    utf8_case((const uint8_t *)"\x00", 1, TLV_OK, "nul");

    utf8_case((const uint8_t *)"\x80", 1, TLV_ERR_UTF8, "stray continuation");
    utf8_case((const uint8_t *)"\xBF\xBF", 2, TLV_ERR_UTF8, "all continuations");
    utf8_case((const uint8_t *)"\xC0\x80", 2, TLV_ERR_UTF8, "overlong 2-byte nul");
    utf8_case((const uint8_t *)"\xC1\xBF", 2, TLV_ERR_UTF8, "overlong 2-byte 0x7f");
    utf8_case((const uint8_t *)"\xE0\x80\x80", 3, TLV_ERR_UTF8, "overlong 3-byte");
    utf8_case((const uint8_t *)"\xE0\x9F\xBF", 3, TLV_ERR_UTF8, "overlong 3-byte edge");
    utf8_case((const uint8_t *)"\xF0\x80\x80\x80", 4, TLV_ERR_UTF8, "overlong 4-byte");
    utf8_case((const uint8_t *)"\xED\xA0\x80", 3, TLV_ERR_UTF8, "high surrogate");
    utf8_case((const uint8_t *)"\xED\xBF\xBF", 3, TLV_ERR_UTF8, "low surrogate");
    utf8_case((const uint8_t *)"\xF4\x90\x80\x80", 4, TLV_ERR_UTF8, "> U+10FFFF");
    utf8_case((const uint8_t *)"\xF5\x80\x80\x80", 4, TLV_ERR_UTF8, "5-byte lead");
    utf8_case((const uint8_t *)"\xFE", 1, TLV_ERR_UTF8, "0xFE lead");
    utf8_case((const uint8_t *)"\xFF", 1, TLV_ERR_UTF8, "0xFF lead");
    utf8_case((const uint8_t *)"\xE4\xB8", 2, TLV_ERR_UTF8, "truncated 3-byte");
    utf8_case((const uint8_t *)"\xE4\xB8\x41", 3, TLV_ERR_UTF8, "bad continuation");
    utf8_case((const uint8_t *)"\xF4\x8F\xBF\xBF", 4, TLV_OK, "U+10FFFF");
}

/* ---- framing ---- */

TEST(test_header)
{
    g_current = "header";
    {
        const uint8_t raw[] = {'T', 'L', 'V', 'X', 1, 0, 0, 0, 0, 0, 1, 0};
        tlv_document *d = NULL;
        CHECK(tlv_parse_strict(raw, sizeof(raw), &d) == TLV_OK);
        tlv_document_free(d);
    }
    {
        /* Bad magic. */
        uint8_t raw[] = {'T', 'L', 'V', 'Y', 1, 0, 0, 0, 0, 0, 1, 0};
        tlv_document *d = NULL;
        CHECK(tlv_parse_strict(raw, sizeof(raw), &d) == TLV_ERR_BAD_MAGIC);
        CHECK(d == NULL);
    }
    {
        /* Bad version. */
        uint8_t raw[] = {'T', 'L', 'V', 'X', 2, 0, 0, 0, 0, 0, 1, 0};
        tlv_document *d = NULL;
        CHECK(tlv_parse_strict(raw, sizeof(raw), &d) == TLV_ERR_BAD_VERSION);
    }
    {
        /* Reserved flag bit. */
        uint8_t raw[] = {'T', 'L', 'V', 'X', 1, 0, 0x02, 0, 0, 0, 1, 0};
        tlv_document *d = NULL;
        CHECK(tlv_parse_strict(raw, sizeof(raw), &d) == TLV_ERR_BAD_FLAGS);
    }
    {
        /* field_region_len == 0 (no bitmap). */
        uint8_t raw[] = {'T', 'L', 'V', 'X', 1, 0, 0, 0, 0, 0, 0};
        tlv_document *d = NULL;
        CHECK(tlv_parse_strict(raw, sizeof(raw), &d) == TLV_ERR_TRUNCATED);
    }
    {
        /* Declared region longer than the buffer. */
        uint8_t raw[] = {'T', 'L', 'V', 'X', 1, 0, 0, 0, 0, 0, 4, 0};
        tlv_document *d = NULL;
        CHECK(tlv_parse_strict(raw, sizeof(raw), &d) == TLV_ERR_TRUNCATED);
    }
    {
        /* Trailing garbage after the declared region: strict rejects. */
        uint8_t raw[] = {'T', 'L', 'V', 'X', 1, 0, 0, 0, 0, 0, 1, 0, 0xFF};
        tlv_document *d = NULL;
        tlv_options opt;
        CHECK(tlv_parse_strict(raw, sizeof(raw), &d) == TLV_ERR_LENGTH_MISMATCH);
        tlv_options_init(&opt);
        opt.strict = 0;
        CHECK(tlv_parse(raw, sizeof(raw), &opt, &d) == TLV_OK);
        tlv_document_free(d);
    }
    {
        /* Short input. */
        const uint8_t raw[] = {'T', 'L', 'V', 'X', 1};
        tlv_document *d = NULL;
        CHECK(tlv_parse_strict(raw, sizeof(raw), &d) == TLV_ERR_TRUNCATED);
    }
    {
        /* max_message_bytes limit. */
        uint8_t raw[] = {'T', 'L', 'V', 'X', 1, 0, 0, 0, 0, 0, 1, 0};
        tlv_options opt;
        tlv_document *d = NULL;
        tlv_options_init(&opt);
        opt.max_message_bytes = 8;
        CHECK(tlv_parse(raw, sizeof(raw), &opt, &d) == TLV_ERR_LIMIT);
    }
}

/* ---- field encoding ---- */

TEST(test_single_fields)
{
    g_current = "fields";
    {
        /* tag 1, UINT, len 1, value 200 (0xC8 0x01) -> canonical needs 2 bytes */
        const uint8_t f[] = {0x00, 0x01, 0x10, 0x02, 0xC8, 0x01};
        blob b = wrap_fields(f, sizeof(f));
        expect_ok(&b, "uint 200");
        free(b.p);
    }
    {
        /* tag 1, INT, len 1, value -1 */
        const uint8_t f[] = {0x00, 0x01, 0x00, 0x01, 0x7F};
        blob b = wrap_fields(f, sizeof(f));
        expect_ok(&b, "int -1");
        free(b.p);
    }
    {
        /* tag 1, BOOL, len 1, value 1 */
        const uint8_t f[] = {0x00, 0x01, 0x40, 0x01, 0x01};
        blob b = wrap_fields(f, sizeof(f));
        expect_ok(&b, "bool 1");
        free(b.p);
    }
    {
        /* BOOL with value 2 -> TLV_ERR_VALUE */
        const uint8_t f[] = {0x00, 0x01, 0x40, 0x01, 0x02};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_VALUE, "bool 2");
        free(b.p);
    }
    {
        /* BOOL with len 0 */
        const uint8_t f[] = {0x00, 0x01, 0x40, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_VALUE, "bool len 0");
        free(b.p);
    }
    {
        /* STRING "hi" */
        const uint8_t f[] = {0x00, 0x02, 0x30, 0x02, 'h', 'i'};
        blob b = wrap_fields(f, sizeof(f));
        expect_ok(&b, "string");
        free(b.p);
    }
    {
        /* STRING with invalid UTF-8 */
        const uint8_t f[] = {0x00, 0x02, 0x30, 0x02, 0xC0, 0x80};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_UTF8, "bad utf8");
        free(b.p);
    }
    {
        /* Tag 0 is reserved. */
        const uint8_t f[] = {0x00, 0x00, 0x10, 0x01, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_BAD_TAG, "tag 0");
        free(b.p);
    }
    {
        /* Reserved kind 7. */
        const uint8_t f[] = {0x00, 0x01, 0x70, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_RESERVED_KIND, "kind 7");
        free(b.p);
    }
    {
        /* Kind 5 without the constructed bit. */
        const uint8_t f[] = {0x00, 0x01, 0x50, 0x01, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_BAD_TYPE, "kind5 no C");
        free(b.p);
    }
    {
        /* Constructed bit with a non-container kind. */
        const uint8_t f[] = {0x00, 0x01, 0x90, 0x01, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_BAD_TYPE, "C on uint");
        free(b.p);
    }
    {
        /* Slot bits set without the optional bit. */
        const uint8_t f[] = {0x00, 0x01, 0x13, 0x01, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_BAD_TYPE, "slot without O");
        free(b.p);
    }
    {
        /* Non-increasing tags. */
        const uint8_t f[] = {0x00, 0x02, 0x40, 0x01, 0x01, 0x02, 0x40, 0x01, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_TAG_ORDER, "dup tag");
        free(b.p);
    }
    {
        /* Duplicate slot 3 in one scope. */
        const uint8_t f[] = {0x08, 0x02, 0x4B, 0x01, 0x01, 0x03, 0x4B, 0x01, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_BAD_OPTIONAL, "dup slot");
        free(b.p);
    }
    {
        /* Optional field whose bitmap bit is clear. */
        const uint8_t f[] = {0x00, 0x02, 0x4B, 0x01, 0x01};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_BAD_OPTIONAL, "bit clear");
        free(b.p);
    }
    {
        /* Bitmap bit set but nothing claims it (strict only). */
        const uint8_t f[] = {0x01, 0x02, 0x40, 0x01, 0x01};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_OPTIONAL_UNUSED, "unused bit");
        {
            tlv_options opt;
            tlv_document *d = NULL;
            tlv_options_init(&opt);
            opt.strict = 0;
            CHECK(tlv_parse(b.p, b.len, &opt, &d) == TLV_OK);
            tlv_document_free(d);
        }
        free(b.p);
    }
    {
        /* Non-canonical UINT (0x80 0x00 for 0) rejected in strict mode only. */
        const uint8_t f[] = {0x00, 0x01, 0x10, 0x02, 0x80, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_VARINT, "non-canonical uint");
        {
            tlv_options opt;
            tlv_document *d = NULL;
            tlv_options_init(&opt);
            opt.strict = 0;
            CHECK(tlv_parse(b.p, b.len, &opt, &d) == TLV_OK);
            tlv_document_free(d);
        }
        free(b.p);
    }
    {
        /* Int value that terminates before the declared length. */
        const uint8_t f[] = {0x00, 0x01, 0x00, 0x02, 0x01, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_VALUE, "int short");
        free(b.p);
    }
    {
        /* Value runs past the field region. */
        const uint8_t f[] = {0x00, 0x01, 0x20, 0x05, 0xAA};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_TRUNCATED, "value past end");
        free(b.p);
    }
}

TEST(test_length_forms)
{
    g_current = "length";
    {
        /* Two-byte length form, len 0: 0x80 0x00 -> BYTES with no payload. */
        const uint8_t f[] = {0x00, 0x01, 0x20, 0x80, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_ok(&b, "2-byte len 0");
        free(b.p);
    }
    {
        /* Two-byte length form claiming 8191 bytes inside a tiny region. */
        const uint8_t f[] = {0x00, 0x01, 0x20, 0x9F, 0xFF, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_TRUNCATED, "2-byte len overflow");
        free(b.p);
    }
    {
        /* Reserved length prefix 0xD0. */
        const uint8_t f[] = {0x00, 0x01, 0x20, 0xD0, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_BAD_LENGTH_ENCODING, "0xD0");
        free(b.p);
    }
    {
        /* Reserved length prefix 0xF1. */
        const uint8_t f[] = {0x00, 0x01, 0x20, 0xF1, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_BAD_LENGTH_ENCODING, "0xF1");
        free(b.p);
    }
    {
        /* 0xE0 extended length, value 0, canonical single byte. */
        const uint8_t f[] = {0x00, 0x01, 0x20, 0xE0, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_ok(&b, "E0 len 0");
        free(b.p);
    }
    {
        /* 0xE0 extended length, non-canonical (0x80 0x00) -> strict error. */
        const uint8_t f[] = {0x00, 0x01, 0x20, 0xE0, 0x80, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_BAD_LENGTH_ENCODING, "E0 non-canonical");
        free(b.p);
    }
    {
        /* 0xE0 length that does not fit in uint32. */
        const uint8_t f[] = {0x00, 0x01, 0x20, 0xE0, 0x84, 0x80, 0x80, 0x80, 0x10};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_BAD_LENGTH_ENCODING, "E0 > uint32");
        free(b.p);
    }
    {
        /* 0xE0 length inside uint32 but far beyond the region. */
        const uint8_t f[] = {0x00, 0x01, 0x20, 0xE0, 0x80, 0x80, 0x80, 0x04};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_TRUNCATED, "E0 beyond region");
        free(b.p);
    }
    {
        /* 0xE0 with a varint that never terminates inside the region. */
        const uint8_t f[] = {0x00, 0x01, 0x20, 0xE0, 0x80, 0x80, 0x80, 0x80, 0x80};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_BAD_LENGTH_ENCODING, "E0 runaway");
        free(b.p);
    }
}

TEST(test_nesting)
{
    g_current = "nesting";
    {
        /* One container, one UINT child. A container's type byte is
         * 0xD0 = C bit | (kind 5 << 4). Its value is
         * [bitmap 0x00][tag 0x02][type 0x10][len 0x01][value 0x05] = 5 bytes. */
        const uint8_t f[] = {0x00, 0x01, 0xD0, 0x05, 0x00, 0x02, 0x10, 0x01, 0x05};
        blob b = wrap_fields(f, sizeof(f));
        tlv_document *d = NULL;
        g_current = "container";
        CHECK(parse_blob(&b, &d) == TLV_OK);
        if (d != NULL) {
            const tlv_node *root = tlv_document_root(d);
            const tlv_node *c = tlv_node_child(root, 1);
            const tlv_node *leaf;
            uint64_t v = 0;

            CHECK(c != NULL && c->kind == TLV_KIND_CONTAINER);
            leaf = c ? tlv_node_child(c, 2) : NULL;
            CHECK(leaf != NULL);
            if (leaf != NULL) {
                CHECK(leaf->depth == 2);
                CHECK(tlv_node_get_uint(leaf, &v) == TLV_OK && v == 5);
            }
            CHECK(tlv_document_node_count(d) == 2);
        }
        tlv_document_free(d);
        free(b.p);
    }
    {
        /* Container whose declared length exceeds the region. */
        const uint8_t f[] = {0x00, 0x01, 0xD0, 0x09, 0x00, 0x02, 0x10, 0x01, 0x05};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_TRUNCATED, "container too long");
        free(b.p);
    }
    {
        /* Container with len 0 (no bitmap). */
        const uint8_t f[] = {0x00, 0x01, 0xD0, 0x00};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_TRUNCATED, "container len0");
        free(b.p);
    }
    {
        /* Container whose declared length ends in the middle of a child. */
        const uint8_t f[] = {0x00, 0x01, 0xD0, 0x03, 0x00, 0x02, 0x10, 0x01, 0x05};
        blob b = wrap_fields(f, sizeof(f));
        expect_err(&b, TLV_ERR_TRUNCATED, "container trailing bytes");
        free(b.p);
    }
}

/* Build N nested containers with a UINT at the bottom using the writer, then
 * parse it back; verify depth accounting and the depth limit. */
TEST(test_deep_nesting)
{
    g_current = "deep";
    for (unsigned limit = 1; limit <= 20; limit += 19) {
        enum { DEPTH = 20 };
        tlv_options opt;
        tlv_writer *w;
        uint8_t *bytes = NULL;
        size_t n = 0;
        tlv_document *d = NULL;
        tlv_error e;

        tlv_options_init(&opt);
        opt.max_depth = limit ? limit : 0;
        w = tlv_writer_new(0, &opt);
        CHECK(w != NULL);
        if (w == NULL)
            continue;

        /* The writer must refuse below/at the limit just like the parser. */
        e = TLV_OK;
        for (unsigned i = 0; i < DEPTH && e == TLV_OK; i++)
            e = tlv_writer_container_begin(w, i + 1);

        if (limit && DEPTH > limit) {
            CHECK(e == TLV_ERR_DEPTH);
            tlv_writer_free(w);
            continue;
        }
        CHECK(e == TLV_OK);
        if (e == TLV_OK) {
            CHECK(tlv_writer_u64(w, DEPTH + 1, 42) == TLV_OK);
            for (unsigned i = 0; i < DEPTH; i++)
                CHECK(tlv_writer_container_end(w) == TLV_OK);
            CHECK(tlv_writer_finish(w, &bytes, &n) == TLV_OK);
        }
        tlv_writer_free(w);
        free(bytes);

        /* Direct 64-deep handcrafted message must be rejected at default
         * settings (default max_depth is 16). */
        (void)d;
    }

    {
        /* Handcraft a 64-deep chain: each container len covers the rest.
         * Rather than compute lengths by hand, use the writer with a raised
         * limit and then parse with the default limit. */
        tlv_options opt;
        tlv_writer *w;
        uint8_t *bytes = NULL;
        size_t n = 0;
        tlv_document *d = NULL;
        tlv_options_init(&opt);
        opt.max_depth = TLV_MAX_DEPTH_HARD;
        w = tlv_writer_new(0, &opt);
        CHECK(w != NULL);
        for (unsigned i = 0; i < 40; i++)
            CHECK(tlv_writer_container_begin(w, i + 1) == TLV_OK);
        CHECK(tlv_writer_u64(w, 100, 1) == TLV_OK);
        for (unsigned i = 0; i < 40; i++)
            CHECK(tlv_writer_container_end(w) == TLV_OK);
        CHECK(tlv_writer_finish(w, &bytes, &n) == TLV_OK);
        tlv_writer_free(w);

        tlv_options_init(&opt); /* default max_depth = 16 */
        CHECK(tlv_parse_strict(bytes, n, &d) == TLV_ERR_DEPTH);
        CHECK(d == NULL);

        opt.max_depth = 40;
        CHECK(tlv_parse(bytes, n, &opt, &d) == TLV_OK);
        if (d != NULL)
            CHECK(tlv_document_node_count(d) == 41);
        tlv_document_free(d);
        free(bytes);
    }
}

TEST(test_roundtrip_encoder)
{
    g_current = "writer/parser";
    {
        tlv_writer *w = tlv_writer_new(0, NULL);
        uint8_t *bytes = NULL;
        size_t n = 0;
        tlv_document *d = NULL;
        tlv_error e;

        CHECK(w != NULL);
        if (w == NULL)
            return;

        CHECK(tlv_writer_u64(w, 1, 0) == TLV_OK);
        CHECK(tlv_writer_u64(w, 2, 127) == TLV_OK);
        CHECK(tlv_writer_u64(w, 3, 128) == TLV_OK);
        CHECK(tlv_writer_u64(w, 4, (1ULL << 56) - 1) == TLV_OK);
        CHECK(tlv_writer_i64(w, 5, -1) == TLV_OK);
        CHECK(tlv_writer_i64(w, 6, -(INT64_C(1) << 55)) == TLV_OK);
        CHECK(tlv_writer_i64(w, 7, (INT64_C(1) << 55) - 1) == TLV_OK);
        CHECK(tlv_writer_bool(w, 8, 1) == TLV_OK);
        CHECK(tlv_writer_string(w, 9, "h\xC3\xA9llo") == TLV_OK);
        CHECK(tlv_writer_bytes(w, 10, "abc", 3) == TLV_OK);
        CHECK(tlv_writer_skip(w, 11, NULL, 0) == TLV_OK);
        CHECK(tlv_writer_u64_opt(w, 12, 5, 9) == TLV_OK);
        CHECK(tlv_writer_container_begin(w, 13) == TLV_OK);
        CHECK(tlv_writer_u64(w, 1, 77) == TLV_OK);
        CHECK(tlv_writer_container_end(w) == TLV_OK);
        CHECK(tlv_writer_finish(w, &bytes, &n) == TLV_OK);
        tlv_writer_free(w);

        e = tlv_parse_strict(bytes, n, &d);
        CHECK(e == TLV_OK);
        if (e == TLV_OK) {
            const tlv_node *r = tlv_document_root(d);
            int64_t iv = 0;
            uint64_t uv = 0;

            CHECK(tlv_node_get_uint(tlv_node_child(r, 4), &uv) == TLV_OK &&
                  uv == (1ULL << 56) - 1);
            CHECK(tlv_node_get_int(tlv_node_child(r, 5), &iv) == TLV_OK && iv == -1);
            CHECK(tlv_node_child(r, 11) != NULL);
            CHECK(tlv_node_child(r, 12) != NULL &&
                  tlv_node_child(r, 12)->is_optional &&
                  tlv_node_child(r, 12)->slot == 5);
            CHECK(tlv_node_child(tlv_node_child(r, 13), 1) != NULL);
            CHECK(tlv_document_find(d, 12) != NULL);
            CHECK(tlv_document_find(d, 999) == NULL);
        }
        tlv_document_free(d);
        free(bytes);
    }
    {
        /* Values outside the documented 8-byte ranges are rejected up front
         * and the writer becomes sticky, so finish must not emit anything. */
        tlv_writer *w = tlv_writer_new(0, NULL);
        uint8_t *bytes = NULL;
        size_t n = 0;
        CHECK(w != NULL);
        if (w == NULL)
            return;
        CHECK(tlv_writer_i64(w, 1, INT64_MAX) == TLV_ERR_VALUE);
        CHECK(tlv_writer_u64(w, 2, 1ULL << 60) == TLV_ERR_VALUE);
        CHECK(tlv_writer_finish(w, &bytes, &n) == TLV_ERR_VALUE);
        CHECK(bytes == NULL);
        tlv_writer_free(w);
    }
    {
        /* Writer rejects out-of-order tags. */
        tlv_writer *w = tlv_writer_new(0, NULL);
        CHECK(w != NULL);
        if (w == NULL)
            return;
        CHECK(tlv_writer_u64(w, 5, 1) == TLV_OK);
        CHECK(tlv_writer_u64(w, 4, 1) == TLV_ERR_TAG_ORDER);
        CHECK(tlv_writer_u64(w, 5, 1) == TLV_ERR_TAG_ORDER);
        CHECK(tlv_writer_u64(w, 6, 1) == TLV_OK);
        tlv_writer_free(w);
    }
    {
        /* Child scope tags are independent of the parent's. */
        tlv_writer *w = tlv_writer_new(0, NULL);
        uint8_t *bytes = NULL;
        size_t n = 0;
        tlv_document *d = NULL;
        CHECK(w != NULL);
        if (w == NULL)
            return;
        CHECK(tlv_writer_u64(w, 10, 1) == TLV_OK);
        CHECK(tlv_writer_container_begin(w, 20) == TLV_OK);
        CHECK(tlv_writer_u64(w, 1, 1) == TLV_OK);
        CHECK(tlv_writer_u64(w, 2, 1) == TLV_OK);
        CHECK(tlv_writer_container_end(w) == TLV_OK);
        CHECK(tlv_writer_finish(w, &bytes, &n) == TLV_OK);
        CHECK(tlv_parse_strict(bytes, n, &d) == TLV_OK);
        tlv_document_free(d);
        tlv_writer_free(w);
        free(bytes);
    }
    {
        /* Unbalanced container is a writer error, and finish must not emit. */
        tlv_writer *w = tlv_writer_new(0, NULL);
        uint8_t *bytes = (uint8_t *)0x1;
        size_t n = 0;
        CHECK(w != NULL);
        if (w == NULL)
            return;
        CHECK(tlv_writer_container_begin(w, 1) == TLV_OK);
        CHECK(tlv_writer_finish(w, &bytes, &n) == TLV_ERR_ARG);
        CHECK(bytes == NULL && n == 0);
        tlv_writer_free(w);
    }
}

/* Round-trip every length-prefix form the encoder can emit, at the exact
 * boundaries where the encoding switches shape (127/128, 8191/8192,
 * 1048575/1048576). A mismatch here would mean the writer and parser disagree
 * about the length grammar. */
TEST(test_length_boundaries)
{
    static const size_t sizes[] = {0, 1, 127, 128, 255, 8191, 8192,
                                   65535, 1048575, 1048576};
    g_current = "length boundaries";
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        tlv_writer *w = tlv_writer_new(0, NULL);
        uint8_t *payload = malloc(sizes[i] ? sizes[i] : 1);
        uint8_t *bytes = NULL;
        size_t n = 0;
        tlv_document *d = NULL;
        const tlv_node *root, *f;
        const uint8_t *got = NULL;
        size_t got_len = 0;

        CHECK(w != NULL);
        CHECK(payload != NULL);
        if (w == NULL || payload == NULL) {
            free(payload);
            tlv_writer_free(w);
            continue;
        }
        memset(payload, 0x5A, sizes[i]);

        CHECK(tlv_writer_bytes(w, 1, payload, sizes[i]) == TLV_OK);
        CHECK(tlv_writer_finish(w, &bytes, &n) == TLV_OK);
        tlv_writer_free(w);

        /* Must be accepted in strict mode: the canonical writer never emits a
         * non-canonical length or a non-minimal varint. */
        CHECK(tlv_parse_strict(bytes, n, &d) == TLV_OK);
        root = tlv_document_root(d);
        f = tlv_node_child(root, 1);
        CHECK(f != NULL && f->value_len == sizes[i]);
        CHECK(tlv_node_get_bytes(f, &got, &got_len) == TLV_OK);
        CHECK(got_len == sizes[i]);
        if (got != NULL && sizes[i] > 0)
            CHECK(memcmp(got, payload, sizes[i]) == 0);

        tlv_document_free(d);
        free(bytes);
        free(payload);
    }
}

/* ---- limit behaviour ---- */

TEST(test_limits)
{
    g_current = "limits";
    {
        /* max_fields = 1, two fields. */
        tlv_options opt;
        tlv_writer *w;
        uint8_t *bytes = NULL;
        size_t n = 0;

        tlv_options_init(&opt);
        opt.max_fields = 1;
        w = tlv_writer_new(0, NULL);
        CHECK(w != NULL);
        if (w == NULL)
            return;
        CHECK(tlv_writer_u64(w, 1, 1) == TLV_OK);
        CHECK(tlv_writer_u64(w, 2, 1) == TLV_OK);
        CHECK(tlv_writer_finish(w, &bytes, &n) == TLV_OK);
        tlv_writer_free(w);

        {
            tlv_document *d = NULL;
            CHECK(tlv_parse_strict(bytes, n, &d) == TLV_OK);
            tlv_document_free(d);
        }
        {
            tlv_document *d = NULL;
            CHECK(tlv_parse(bytes, n, &opt, &d) == TLV_ERR_FIELDS);
            CHECK(d == NULL);
        }
        free(bytes);
    }
    {
        /* max_total_fields counts across scopes. */
        tlv_options opt;
        tlv_writer *w;
        uint8_t *bytes = NULL;
        size_t n = 0;

        tlv_options_init(&opt);
        opt.max_total_fields = 2;
        w = tlv_writer_new(0, NULL);
        CHECK(w != NULL);
        if (w == NULL)
            return;
        CHECK(tlv_writer_container_begin(w, 1) == TLV_OK);
        CHECK(tlv_writer_u64(w, 1, 1) == TLV_OK);
        CHECK(tlv_writer_u64(w, 2, 1) == TLV_OK);
        CHECK(tlv_writer_container_end(w) == TLV_OK);
        CHECK(tlv_writer_finish(w, &bytes, &n) == TLV_OK);
        tlv_writer_free(w);

        {
            tlv_document *d = NULL;
            /* container + 2 children = 3 nodes > 2 */
            CHECK(tlv_parse(bytes, n, &opt, &d) == TLV_ERR_FIELDS);
            CHECK(d == NULL);
        }
        free(bytes);
    }
}

/* ---- accessors ---- */

TEST(test_accessors)
{
    g_current = "accessors";
    {
        tlv_writer *w = tlv_writer_new(0, NULL);
        uint8_t *bytes = NULL;
        size_t n = 0;
        tlv_document *d = NULL;
        CHECK(w != NULL);
        if (w == NULL)
            return;
        CHECK(tlv_writer_u64(w, 1, 7) == TLV_OK);
        CHECK(tlv_writer_bytes(w, 2, "xyz", 3) == TLV_OK);
        CHECK(tlv_writer_finish(w, &bytes, &n) == TLV_OK);
        tlv_writer_free(w);
        CHECK(tlv_parse_strict(bytes, n, &d) == TLV_OK);
        if (d != NULL) {
            const tlv_node *r = tlv_document_root(d);
            const uint8_t *p = NULL;
            size_t len = 0;
            uint64_t v = 0;
            int64_t iv = 0;
            const char *s = NULL;
            int bv = 0;

            CHECK(tlv_node_get_uint(tlv_node_child(r, 1), &v) == TLV_OK && v == 7);
            CHECK(tlv_node_get_int(tlv_node_child(r, 1), &iv) == TLV_ERR_BAD_TYPE);
            CHECK(tlv_node_get_bytes(tlv_node_child(r, 2), &p, &len) == TLV_OK &&
                  len == 3 && memcmp(p, "xyz", 3) == 0);
            CHECK(tlv_node_get_string(tlv_node_child(r, 2), &s, &len) ==
                  TLV_ERR_BAD_TYPE);
            CHECK(tlv_node_get_bool(tlv_node_child(r, 2), &bv) == TLV_ERR_BAD_TYPE);
            CHECK(tlv_node_get_uint(NULL, &v) == TLV_ERR_ARG);
            CHECK(tlv_node_get_uint(tlv_node_child(r, 1), NULL) == TLV_ERR_ARG);
            CHECK(tlv_node_child(NULL, 1) == NULL);
            CHECK(tlv_node_nth_child(r, 99) == NULL);
            CHECK(tlv_node_nth_child(r, 1) != NULL &&
                  tlv_node_nth_child(r, 1)->tag == 2);
            CHECK(tlv_node_child_count(r) == 2);
            CHECK(tlv_node_child_count(NULL) == 0);
        }
        tlv_document_free(d);
        free(bytes);
    }
    {
        /* Freeing NULL is fine; all accessors survive a NULL document. */
        tlv_document_free(NULL);
        CHECK(tlv_document_root(NULL) == NULL);
        CHECK(tlv_document_find(NULL, 1) == NULL);
        CHECK(tlv_document_node_count(NULL) == 0);
        CHECK(tlv_strerror(TLV_ERR_UTF8) != NULL);
        CHECK(tlv_kind_name(TLV_KIND_CONTAINER) != NULL);
    }
}

TEST(test_options_defaults)
{
    tlv_options opt;

    g_current = "options";
    tlv_options_init(&opt);
    CHECK(opt.strict == 1);
    CHECK(opt.max_depth == 0);

    {
        tlv_options norm;
        tlv_options_init(&opt);
        opt.max_depth = 999;
        opt.max_fields = 0;
        tlv_options_normalize(&opt, &norm);
        CHECK(norm.max_depth == TLV_MAX_DEPTH_HARD);
        CHECK(norm.max_fields == TLV_MAX_FIELDS_PER_SCOPE_HARD);

        opt.max_depth = 0;
        tlv_options_normalize(&opt, &norm);
        CHECK(norm.max_depth == 16);
    }
}

/* ---- structured stress: parse every prefix of a valid message ---- */

static void stress_prefixes(void)
{
    tlv_writer *w = tlv_writer_new(0, NULL);
    uint8_t *bytes = NULL;
    size_t n = 0;

    g_current = "prefixes";
    CHECK(w != NULL);
    if (w == NULL)
        return;
    CHECK(tlv_writer_u64(w, 1, 300) == TLV_OK);
    CHECK(tlv_writer_string(w, 2, "nested") == TLV_OK);
    CHECK(tlv_writer_container_begin(w, 3) == TLV_OK);
    CHECK(tlv_writer_bytes(w, 1, "abcd", 4) == TLV_OK);
    CHECK(tlv_writer_bool(w, 2, 0) == TLV_OK);
    CHECK(tlv_writer_container_end(w) == TLV_OK);
    CHECK(tlv_writer_finish(w, &bytes, &n) == TLV_OK);
    tlv_writer_free(w);

    for (size_t cut = 0; cut < n; cut++) {
        tlv_document *d = NULL;
        tlv_error e = tlv_parse_strict(bytes, cut, &d);
        CHECK(e != TLV_OK);
        CHECK(d == NULL);
    }
    {
        tlv_document *d = NULL;
        CHECK(tlv_parse_strict(bytes, n, &d) == TLV_OK);
        tlv_document_free(d);
    }
    free(bytes);
}

/* ---- main ---- */

#define RUN(t)                                                               \
    do {                                                                     \
        int before = g_failures;                                             \
        t();                                                                 \
        printf("%-28s %s\n", #t, g_failures == before ? "ok" : "FAILED");    \
    } while (0)

int main(void)
{
    printf("libtlv test suite (%d checks)\n", 0);
    RUN(test_uleb_decode);
    RUN(test_sleb_decode);
    RUN(test_utf8);
    RUN(test_header);
    RUN(test_single_fields);
    RUN(test_length_forms);
    RUN(test_nesting);
    RUN(test_deep_nesting);
    RUN(test_roundtrip_encoder);
    RUN(test_length_boundaries);
    RUN(test_limits);
    RUN(test_accessors);
    RUN(test_options_defaults);
    stress_prefixes();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
