/* Tree navigation and scalar accessors. Everything is NULL-safe; no pointer
 * arithmetic escapes the node's recorded value slice. */
#include "tlv_internal.h"

const char *tlv_strerror(tlv_error err)
{
    switch (err) {
    case TLV_OK: return "ok";
    case TLV_ERR_ARG: return "invalid argument";
    case TLV_ERR_TRUNCATED: return "truncated input";
    case TLV_ERR_BAD_MAGIC: return "bad magic";
    case TLV_ERR_BAD_VERSION: return "unsupported version";
    case TLV_ERR_BAD_FLAGS: return "reserved flag bits set";
    case TLV_ERR_LENGTH_MISMATCH: return "declared length mismatch";
    case TLV_ERR_BAD_TAG: return "invalid tag";
    case TLV_ERR_TAG_ORDER: return "tags not strictly increasing";
    case TLV_ERR_BAD_TYPE: return "invalid type byte";
    case TLV_ERR_RESERVED_KIND: return "reserved field kind";
    case TLV_ERR_BAD_LENGTH_ENCODING: return "invalid length encoding";
    case TLV_ERR_VARINT: return "non-canonical or malformed varint";
    case TLV_ERR_BAD_OPTIONAL: return "invalid optional-field usage";
    case TLV_ERR_OPTIONAL_UNUSED: return "presence bit set without a field";
    case TLV_ERR_VALUE: return "value violates field constraints";
    case TLV_ERR_UTF8: return "invalid UTF-8";
    case TLV_ERR_DEPTH: return "nesting too deep";
    case TLV_ERR_FIELDS: return "field count limit exceeded";
    case TLV_ERR_LIMIT: return "message size limit exceeded";
    case TLV_ERR_NOMEM: return "out of memory";
    default: return "unknown error";
    }
}

const char *tlv_kind_name(uint8_t kind)
{
    switch (kind) {
    case TLV_KIND_INT: return "int";
    case TLV_KIND_UINT: return "uint";
    case TLV_KIND_BYTES: return "bytes";
    case TLV_KIND_STRING: return "string";
    case TLV_KIND_BOOL: return "bool";
    case TLV_KIND_CONTAINER: return "container";
    case TLV_KIND_SKIP: return "skip";
    default: return "unknown";
    }
}

const tlv_node *tlv_node_child(const tlv_node *n, uint32_t tag)
{
    const tlv_node *c;

    if (n == NULL)
        return NULL;
    for (c = n->first_child; c != NULL; c = c->next_sibling) {
        if (c->tag == tag)
            return c;
    }
    return NULL;
}

const tlv_node *tlv_node_nth_child(const tlv_node *n, size_t index)
{
    const tlv_node *c;

    if (n == NULL)
        return NULL;
    for (c = n->first_child; c != NULL; c = c->next_sibling) {
        if (index == 0)
            return c;
        index--;
    }
    return NULL;
}

size_t tlv_node_child_count(const tlv_node *n)
{
    size_t count = 0;
    const tlv_node *c;

    if (n == NULL)
        return 0;
    for (c = n->first_child; c != NULL; c = c->next_sibling)
        count++;
    return count;
}

/* Depth-first search over the whole document, iterative so that querying a
 * deep tree cannot grow the C stack. */
const tlv_node *tlv_document_find(const tlv_document *doc, uint32_t tag)
{
    const tlv_node *n;

    if (doc == NULL || doc->root == NULL)
        return NULL;

    n = doc->root->first_child;
    while (n != NULL) {
        if (n->tag == tag)
            return n;
        if (n->first_child != NULL) {
            n = n->first_child;
        } else {
            while (n != NULL && n->next_sibling == NULL)
                n = n->parent;
            if (n != NULL)
                n = n->next_sibling;
        }
    }
    return NULL;
}

tlv_error tlv_node_get_int(const tlv_node *n, int64_t *out)
{
    int canon;
    if (n == NULL || out == NULL)
        return TLV_ERR_ARG;
    if (n->kind != TLV_KIND_INT)
        return TLV_ERR_BAD_TYPE;
    return tlv_sleb_decode(n->value, n->value_len, out, &canon);
}

tlv_error tlv_node_get_uint(const tlv_node *n, uint64_t *out)
{
    int canon;
    if (n == NULL || out == NULL)
        return TLV_ERR_ARG;
    if (n->kind != TLV_KIND_UINT)
        return TLV_ERR_BAD_TYPE;
    return tlv_uleb_decode(n->value, n->value_len, out, &canon);
}

tlv_error tlv_node_get_bool(const tlv_node *n, int *out)
{
    if (n == NULL || out == NULL)
        return TLV_ERR_ARG;
    if (n->kind != TLV_KIND_BOOL)
        return TLV_ERR_BAD_TYPE;
    if (n->value_len != 1 || n->value[0] > 1u)
        return TLV_ERR_VALUE;
    *out = n->value[0];
    return TLV_OK;
}

tlv_error tlv_node_get_bytes(const tlv_node *n, const uint8_t **out,
                             size_t *out_len)
{
    if (n == NULL || out == NULL || out_len == NULL)
        return TLV_ERR_ARG;
    if (n->kind != TLV_KIND_BYTES && n->kind != TLV_KIND_SKIP)
        return TLV_ERR_BAD_TYPE;
    *out = n->value;
    *out_len = n->value_len;
    return TLV_OK;
}

tlv_error tlv_node_get_string(const tlv_node *n, const char **out,
                              size_t *out_len)
{
    if (n == NULL || out == NULL || out_len == NULL)
        return TLV_ERR_ARG;
    if (n->kind != TLV_KIND_STRING)
        return TLV_ERR_BAD_TYPE;
    if (tlv_utf8_check(n->value, n->value_len) != TLV_OK)
        return TLV_ERR_UTF8;
    *out = (const char *)n->value;
    *out_len = n->value_len;
    return TLV_OK;
}
