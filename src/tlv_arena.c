/* Arena allocator: fixed-size node slabs, all freed together. Node addresses
 * are stable for the liftime of the arena, which is what the tree relies on. */
#include "tlv_internal.h"

#include <stdlib.h>

void tlv_arena_init(tlv_arena *a, size_t limit)
{
    memset(a, 0, sizeof(*a));
    a->limit = limit;
}

tlv_node *tlv_arena_alloc(tlv_arena *a)
{
    tlv_arena_block *blk = a->head;

    if (a->count >= a->limit)
        return NULL;

    if (blk == NULL || blk->used == blk->cap) {
        size_t cap = TLV_ARENA_FIRST_BLOCK;
        tlv_arena_block *nb;

        /* Grow geometrically, but never beyond what `limit` can still need. */
        if (blk != NULL)
            cap = blk->cap * 2u;
        if (cap > a->limit - a->count)
            cap = a->limit - a->count;
        if (cap == 0)
            return NULL;

        if (cap > (SIZE_MAX - sizeof(tlv_arena_block)) / sizeof(tlv_node))
            return NULL;
        nb = malloc(sizeof(tlv_arena_block) + cap * sizeof(tlv_node));
        if (nb == NULL)
            return NULL;
        nb->next = a->head;
        nb->used = 0;
        nb->cap = cap;
        a->head = nb;
        blk = nb;
    }

    tlv_node *n = &blk->nodes[blk->used++];
    memset(n, 0, sizeof(*n));
    a->count++;
    return n;
}

void tlv_arena_free(tlv_arena *a)
{
    tlv_arena_block *blk = a->head;

    while (blk != NULL) {
        tlv_arena_block *next = blk->next;
        free(blk);
        blk = next;
    }
    a->head = NULL;
    a->count = 0;
}
