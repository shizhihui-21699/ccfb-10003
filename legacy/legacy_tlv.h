/* legacy_tlv.h — API of the reference fixture parser (see legacy_tlv.c).
 *
 * This is not libtlv. It reproduces the failure modes of the hand-written
 * parser the project replaces, so the fuzzing pipeline has real defects to
 * find. It is never linked into libtlv or its tests.
 */
#ifndef LEGACY_TLV_H
#define LEGACY_TLV_H

#include <stddef.h>
#include <stdint.h>

typedef struct legacy_node {
    uint32_t tag;
    uint8_t kind;
    uint8_t bitmap;
    uint32_t value_len;
    const uint8_t *value;
    struct legacy_node *first_child; /* array of nodes, not a linked list */
    int child_count;
} legacy_node;

typedef struct legacy_doc {
    legacy_node *root;
} legacy_doc;

legacy_doc *legacy_parse(const uint8_t *buf, size_t len);
void legacy_doc_free(legacy_doc *doc);
size_t legacy_count(const legacy_node *n);

#endif /* LEGACY_TLV_H */
