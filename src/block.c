#include <stdlib.h>
#include "block.h"

block_t *
block_init(size_t size) {

    block_t *block = calloc(1, sizeof(block_t) + size);

    if (!block) return NULL;

    block->size = size;

    return block;
}

void *
block_next(block_t *block, size_t span) {

    if (block->index + span >= block->size) {

    }

    void *next = block->data + block->index;

    block->index += span;

    return next;
}

void
block_return(block_t *block, size_t span) {

}

void
block_free(block_t *block) {
    block_t *next, *curr = block;
    while (curr) {
       next = curr->next;
       free(curr);
       curr = next;
    }
}
