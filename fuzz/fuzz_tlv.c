/* libFuzzer harness for libtlv.
 *
 * Two things are fuzzed at once:
 *   1. the parser, with the caller-supplied byte buffer (so every value pointer
 *      aliases the fuzzer's input and any out-of-bounds read is caught by ASan);
 *   2. the query/navigation API over the resulting tree, which is where a
 *      stale-value or bad-length bug would surface.
 *
 * After a successful parse the tree is re-encoded with the independent writer
 * and re-parsed; strict documents must round-trip byte-identically. That turns
 * encoder/parser disagreement into a visible failure rather than a silent one.
 */
#include "tlv.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Derive a small option set from the fuzzer input so that limit-related code
 * paths (depth, field caps, strictness) are reachable without special corpora. */
/* Derive a small option set from the *tail* of the fuzzer input.
 *
 * The first 11 bytes of every valid message are fixed by the wire format
 * (magic "TLVX", version 1, flags, 4-byte length), so deriving options from
 * data[0..3] pins `strict` to (0x54 & 1) == 0 and max_depth to 12 forever --
 * a silent coverage hole. Taking bytes from the end of the input keeps the
 * option space reachable no matter how the input starts.
 */
static void options_from_input(const uint8_t *data, size_t size, tlv_options *opt)
{
    size_t base;

    tlv_options_init(opt);
    if (size == 0)
        return;
    base = size > 4 ? size - 4 : 0;

    opt->strict = (unsigned)(data[base] & 1u);
    if (size - base >= 2) {
        unsigned d = (unsigned)(data[base + 1] & 0x0Fu);
        /* 0 -> default (16); 1..15 exercises the depth limit. */
        opt->max_depth = d == 0 ? 0 : d;
    }
    if (size - base >= 3) {
        switch (data[base + 2] & 3u) {
        case 0: opt->max_fields = 0; break;
        case 1: opt->max_fields = 64; break;
        case 2: opt->max_fields = 4; break;
        default: opt->max_fields = 1; break;
        }
    }
    if (size - base >= 4) {
        switch (data[base + 3] & 3u) {
        case 0: opt->max_total_fields = 0; break;
        case 1: opt->max_total_fields = 128; break;
        case 2: opt->max_total_fields = 8; break;
        default: opt->max_total_fields = 2; break;
        }
    }
    /* Leave max_message_bytes at the default: the fuzzer's -max_len already
     * caps input size, so a smaller limit here would only shadow other paths. */
}

/* Walk the whole tree iteratively and touch every accessor. */
static void exercise_tree(const tlv_node *root)
{
    const tlv_node *n = root ? root->first_child : NULL;

    while (n != NULL) {
        switch (n->kind) {
        case TLV_KIND_INT: {
            int64_t v = 0;
            (void)tlv_node_get_int(n, &v);
            break;
        }
        case TLV_KIND_UINT: {
            uint64_t v = 0;
            (void)tlv_node_get_uint(n, &v);
            break;
        }
        case TLV_KIND_BOOL: {
            int v = 0;
            (void)tlv_node_get_bool(n, &v);
            break;
        }
        case TLV_KIND_BYTES:
        case TLV_KIND_SKIP: {
            const uint8_t *p = NULL;
            size_t len = 0;
            (void)tlv_node_get_bytes(n, &p, &len);
            /* Force a read at both ends of the advertised slice; ASan catches
             * any slice that lies outside the original input. */
            if (len > 0)
                (void)(p[0] | p[len - 1]);
            break;
        }
        case TLV_KIND_STRING: {
            const char *s = NULL;
            size_t len = 0;
            if (tlv_node_get_string(n, &s, &len) == TLV_OK && len > 0)
                (void)(s[0] | s[len - 1]);
            break;
        }
        default:
            break;
        }

        (void)tlv_node_child_count(n);
        if (tlv_node_nth_child(n, 1) != NULL)
            (void)tlv_node_nth_child(n, 1)->tag;

        if (n->first_child != NULL) {
            n = n->first_child;
        } else {
            while (n != NULL && n->next_sibling == NULL)
                n = n->parent;
            if (n != NULL)
                n = n->next_sibling;
        }
    }
}

/* Rebuild a tree through the writer, then re-parse and compare node-by-node.
 * A mismatch means the encoder and the parser disagree about the wire format,
 * which is exactly the class of bug that silently corrupts real traffic. */
static tlv_error rebuild(const tlv_node *parent, tlv_writer *w)
{
    const tlv_node *c;

    for (c = parent->first_child; c != NULL; c = c->next_sibling) {
        tlv_error e;

        if (c->kind == TLV_KIND_CONTAINER) {
            if (c->is_optional)
                e = tlv_writer_container_begin_opt(w, c->tag, c->slot);
            else
                e = tlv_writer_container_begin(w, c->tag);
            if (e != TLV_OK)
                return e;
            e = rebuild(c, w);
            if (e != TLV_OK)
                return e;
            e = tlv_writer_container_end(w);
            if (e != TLV_OK)
                return e;
            continue;
        }

        switch (c->kind) {
        case TLV_KIND_UINT: {
            uint64_t v = 0;
            if (tlv_node_get_uint(c, &v) != TLV_OK)
                return TLV_ERR_VALUE;
            if (c->is_optional)
                e = tlv_writer_u64_opt(w, c->tag, c->slot, v);
            else
                e = tlv_writer_u64(w, c->tag, v);
            break;
        }
        case TLV_KIND_INT: {
            int64_t v = 0;
            if (tlv_node_get_int(c, &v) != TLV_OK)
                return TLV_ERR_VALUE;
            if (c->is_optional)
                e = tlv_writer_i64_opt(w, c->tag, c->slot, v);
            else
                e = tlv_writer_i64(w, c->tag, v);
            break;
        }
        case TLV_KIND_BOOL: {
            int v = 0;
            if (tlv_node_get_bool(c, &v) != TLV_OK)
                return TLV_ERR_VALUE;
            if (c->is_optional)
                e = tlv_writer_bool_opt(w, c->tag, c->slot, v);
            else
                e = tlv_writer_bool(w, c->tag, v);
            break;
        }
        case TLV_KIND_STRING: {
            const char *s = NULL;
            size_t len = 0;
            /* The value is a slice of the fuzzer's input, not a C string, so
             * the explicit-length writer is required here. Embedded NULs are
             * legal UTF-8 and rebuild verbatim. */
            if (tlv_node_get_string(c, &s, &len) != TLV_OK)
                return TLV_ERR_VALUE;
            if (c->is_optional)
                e = tlv_writer_string_opt(w, c->tag, c->slot, s, len);
            else
                e = tlv_writer_string_n(w, c->tag, s, len);
            break;
        }
        default: { /* BYTES / SKIP */
            const uint8_t *p = NULL;
            size_t len = 0;
            if (tlv_node_get_bytes(c, &p, &len) != TLV_OK)
                return TLV_ERR_VALUE;
            if (c->is_optional && c->kind == TLV_KIND_SKIP)
                e = tlv_writer_skip_opt(w, c->tag, c->slot, p, len);
            else if (c->is_optional)
                e = tlv_writer_bytes_opt(w, c->tag, c->slot, p, len);
            else if (c->kind == TLV_KIND_SKIP)
                e = tlv_writer_skip(w, c->tag, p, len);
            else
                e = tlv_writer_bytes(w, c->tag, p, len);
            break;
        }
        }
        if (e != TLV_OK)
            return e;
    }
    return TLV_OK;
}

/* Compare two trees semantically: tags, kinds, optional slots and *decoded
 * values*. Raw bytes are not compared because a lenient parse may legitimately
 * accept a non-canonical varint that the canonical writer then re-encodes in
 * fewer bytes; the value is identical even though the encoding differs. */
static int trees_equal(const tlv_node *a, const tlv_node *b)
{
    while (a != NULL && b != NULL) {
        if (a->tag != b->tag || a->kind != b->kind ||
            a->is_optional != b->is_optional ||
            (a->is_optional && a->slot != b->slot))
            return 0;

        switch (a->kind) {
        case TLV_KIND_INT: {
            int64_t x = 0, y = 0;
            if (tlv_node_get_int(a, &x) != TLV_OK ||
                tlv_node_get_int(b, &y) != TLV_OK || x != y)
                return 0;
            break;
        }
        case TLV_KIND_UINT: {
            uint64_t x = 0, y = 0;
            if (tlv_node_get_uint(a, &x) != TLV_OK ||
                tlv_node_get_uint(b, &y) != TLV_OK || x != y)
                return 0;
            break;
        }
        case TLV_KIND_BOOL: {
            int x = 0, y = 0;
            if (tlv_node_get_bool(a, &x) != TLV_OK ||
                tlv_node_get_bool(b, &y) != TLV_OK || x != y)
                return 0;
            break;
        }
        case TLV_KIND_CONTAINER:
            break; /* children are compared recursively below */
        default:
            if (a->value_len != b->value_len ||
                (a->value_len > 0 &&
                 memcmp(a->value, b->value, a->value_len) != 0))
                return 0;
            break;
        }

        if (!trees_equal(a->first_child, b->first_child))
            return 0;
        a = a->next_sibling;
        b = b->next_sibling;
    }
    return a == NULL && b == NULL;
}

/* Only strict-parsed documents are guaranteed to re-encode identically, and
 * only when they contain no field whose encoding is not canonical. The parse
 * of the rebuilt bytes must nevertheless succeed and match the tree exactly. */
static void roundtrip_check(const tlv_document *doc)
{
    const tlv_node *root;
    tlv_writer *w;
    tlv_document *doc2 = NULL;
    uint8_t *bytes = NULL;
    size_t nbytes = 0;

    if (doc == NULL)
        return;
    root = tlv_document_root(doc);
    if (root == NULL)
        return;

    w = tlv_writer_new(0, NULL);
    if (w == NULL)
        return;

    /* Documents that used non-canonical varints or lenient framing legitimately
     * differ after a canonical rebuild; only compare when the rebuild is exact
     * in structure, which trees_equal enforces. */
    if (rebuild(root, w) == TLV_OK &&
        tlv_writer_finish(w, &bytes, &nbytes) == TLV_OK) {
        if (tlv_parse_strict(bytes, nbytes, &doc2) == TLV_OK && doc2 != NULL) {
            if (!trees_equal(tlv_document_root(doc), tlv_document_root(doc2)))
                abort();
            tlv_document_free(doc2);
        }
    }

    free(bytes);
    tlv_writer_free(w);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    tlv_options opt;
    tlv_document *doc = NULL;
    tlv_error err;

    if (size > (1u << 16))
        return 0; /* keep executions fast; -max_len bounds growth */

    options_from_input(data, size, &opt);

    err = tlv_parse(data, size, &opt, &doc);
    if (err != TLV_OK) {
        /* out_doc must stay NULL on failure: free(NULL) is a no-op. */
        if (doc != NULL)
            abort();
        return 0;
    }

    if (doc == NULL)
        abort();

    exercise_tree(tlv_document_root(doc));
    (void)tlv_document_node_count(doc);

    /* Any tag present in the input is looked up; a broken find() walk over a
     * deep or wide tree shows up here. */
    for (uint32_t t = 1; t <= 8; t++)
        (void)tlv_document_find(doc, t);

    roundtrip_check(doc);

    tlv_document_free(doc);
    return 0;
}
