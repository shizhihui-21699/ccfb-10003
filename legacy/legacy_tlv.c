/* legacy_tlv.c — REFERENCE FIXTURE, NOT THE LIBRARY.
 *
 * A deliberately naive reconstruction of the "hand-written TLV parser" this
 * project replaces. It is written the way parsers usually get written when
 * nobody has thought about hostile input: recursion instead of a depth bound,
 * fixed-size stack buffers instead of length-checked slices, integer
 * arithmetic on untrusted lengths, and pointer lifetimes that survive a free.
 *
 * It exists only to give the fuzzing/triage pipeline *real* crashes to find,
 * so that the crash classes in docs/CRASHES.md can be traced to the specific
 * defence in src/ that retires them. Nothing here ships.
 *
 * Wire format is the v1 format from docs/PROTOCOL.md, parsed leniently.
 */
#include "legacy_tlv.h"

#include <stdlib.h>
#include <string.h>

/* ---- BUG 1: fixed-size decode buffer ---- */
#define LEGACY_TMPBUF 256

typedef struct legacy_scope {
    struct legacy_node children[64];   /* BUG 6: fixed child array */
    int nchildren;
} legacy_scope;

static int legacy_uleb(const uint8_t *p, size_t n, size_t *pos, uint64_t *out)
{
    uint64_t v = 0;
    /* BUG 7: shift amount is not bounded by the word width. */
    for (int i = 0; i < 8; i++) {
        uint8_t b;
        if (*pos >= n)
            return -1;
        b = p[(*pos)++];
        v |= (uint64_t)(b & 0x7Fu) << (7 * i);
        if (!(b & 0x80u)) {
            *out = v;
            return 0;
        }
    }
    return -1;
}

static int legacy_read_len(const uint8_t *p, size_t n, size_t *pos, uint32_t *out)
{
    uint8_t b0;
    if (*pos >= n)
        return -1;
    b0 = p[(*pos)++];
    if ((b0 & 0x80u) == 0) {
        *out = b0;
    } else if ((b0 & 0xE0u) == 0x80u) {
        /* BUG 2: reads b1 before proving it exists. */
        *out = (uint32_t)(b0 & 0x1Fu) << 8 | p[*pos];
        (*pos)++;
    } else if ((b0 & 0xF0u) == 0xC0u) {
        /* BUG 2: same, two unchecked reads. */
        *out = (uint32_t)(b0 & 0x0Fu) << 16 | (uint32_t)p[*pos] << 8 | p[*pos + 1];
        (*pos) += 2;
    } else {
        uint64_t v;
        if (legacy_uleb(p, n, pos, &v) != 0)
            return -1;
        *out = (uint32_t)v;
    }
    return 0;
}

/* Decode the value into a stack scratch buffer (the classic "it's just a
 * small field" assumption). */
static void legacy_decode_value(const uint8_t *value, uint32_t len)
{
    uint8_t tmp[LEGACY_TMPBUF];
    uint32_t i;

    /* BUG 1: `len` is attacker-controlled and can exceed LEGACY_TMPBUF. */
    for (i = 0; i < len; i++)
        tmp[i] = value[i];
    if (len > 0)
        (void)tmp[len - 1]; /* keep the write observable */
}

static int legacy_parse_scope(const uint8_t *buf, size_t n, size_t *pos,
                              legacy_node *out, int depth)
{
    uint8_t bitmap;
    legacy_node *children;
    uint32_t last_tag = 0;
    int nchild = 0;

    /* BUG 3: no depth bound — recursion follows attacker depth. */
    (void)depth;

    if (*pos >= n)
        return -1;
    bitmap = buf[(*pos)++];

    /* BUG 4: heap node array is freed at return while callers keep the
     * pointer; with two or more children the re-read is a use-after-free. */
    children = calloc(64, sizeof(legacy_node));
    if (children == NULL)
        return -1;

    while (*pos < n) {
        uint64_t tag;
        uint8_t type;
        uint32_t vlen;
        uint8_t kind;

        if (legacy_uleb(buf, n, pos, &tag) != 0)
            break;
        if (*pos >= n)
            break;
        type = buf[(*pos)++];
        kind = (uint8_t)((type >> 4) & 7u);

        if (legacy_read_len(buf, n, pos, &vlen) != 0)
            break;
        if ((uint64_t)*pos + vlen > n) {
            /* BUG 5: the addition itself overflows before the comparison. */
            if (*pos + vlen < *pos)
                break;
            break;
        }

        if (kind == 5u) {
            legacy_node *child = &children[nchild];
            child->tag = (uint32_t)tag;
            child->kind = kind;
            child->value_len = vlen;
            if (legacy_parse_scope(buf, *pos + vlen, pos, child, depth + 1) != 0)
                free(children);
                return -1;
        } else if (kind == 6u) {
            /* skip: not interpreted */
            *pos += vlen;
        } else {
            legacy_node *child = &children[nchild];
            child->tag = (uint32_t)tag;
            child->kind = kind;
            child->value_len = vlen;
            child->value = buf + *pos;
            legacy_decode_value(child->value, vlen);
            *pos += vlen;
        }

        if (nchild > 0 && (uint32_t)tag <= last_tag)
            break; /* out-of-order tag: stop, leniently */
        last_tag = (uint32_t)tag;
        nchild++;
        /* BUG 6: fixed child array overruns on a wide scope. */
        if (nchild > 64)
            break;
    }

    out->first_child = children;
    out->child_count = nchild;
    out->bitmap = bitmap;
    free(children); /* BUG 4: children point into freed memory */
    return 0;
}

legacy_doc *legacy_parse(const uint8_t *buf, size_t len)
{
    legacy_doc *doc;
    uint32_t region;
    int overflowed;

    if (buf == NULL || len < 11)
        return NULL;
    if (memcmp(buf, "TLVX", 4) != 0 || buf[4] != 1)
        return NULL;

    region = (uint32_t)buf[7] << 24 | (uint32_t)buf[8] << 16 |
             (uint32_t)buf[9] << 8 | buf[10];

    /* BUG 5: region + 11 is computed in int and wraps for huge region. */
    overflowed = (int)11 + (int)region;
    if (overflowed < 11) {
        /* wrapped; treat as bad */
        return NULL;
    }
    if ((size_t)overflowed > len)
        return NULL;

    doc = calloc(1, sizeof(*doc));
    if (doc == NULL)
        return NULL;
    doc->root = calloc(1, sizeof(legacy_node));
    if (doc->root == NULL) {
        free(doc);
        return NULL;
    }
    {
        size_t pos = 11;
        if (legacy_parse_scope(buf, 11 + (size_t)region, &pos, doc->root, 0) != 0) {
            legacy_doc_free(doc);
            return NULL;
        }
    }
    return doc;
}

void legacy_doc_free(legacy_doc *doc)
{
    if (doc == NULL)
        return;
    free(doc->root);
    free(doc);
}

/* Walk the parsed tree; this is where a dangling child pointer is touched. */
size_t legacy_count(const legacy_node *n)
{
    size_t total = 0;

    if (n == NULL)
        return 0;
    for (int i = 0; i < n->child_count; i++) {
        const legacy_node *c = &n->first_child[i];
        total += 1 + legacy_count(c);
    }
    return total;
}
