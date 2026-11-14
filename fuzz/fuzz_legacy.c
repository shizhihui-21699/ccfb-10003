/* libFuzzer harness for the legacy fixture parser.
 *
 * Same sanitizer configuration as the real harness, but this one is expected
 * to crash: every distinct crash it produces is a defect the rewritten parser
 * has to be immune to. Keep this harness out of the shipped build.
 */
#include "legacy_tlv.h"

#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    legacy_doc *doc;

    if (size == 0 || size > (1u << 16))
        return 0;

    doc = legacy_parse(data, size);
    if (doc == NULL)
        return 0;

    /* Touch the tree the way a consumer would. A dangling child pointer is
     * read here. */
    (void)legacy_count(doc->root);

    if (doc->root != NULL && doc->root->child_count > 0) {
        const legacy_node *first = &doc->root->first_child[0];
        if (first->value != NULL && first->value_len > 0)
            (void)(first->value[0] | first->value[first->value_len - 1]);
    }

    legacy_doc_free(doc);
    return 0;
}
