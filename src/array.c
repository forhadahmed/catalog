#include <stdio.h>
#include <stdlib.h>
#include "array.h"

array_t *
array_init(size_t size) {

    array_t *array = calloc(1, sizeof(array_t));
    block_t *block = calloc(1, sizeof(block_t) + size);

    if (!array || !block) return NULL;

    block->size = size;
    array->size = size;
    array->head = block;
    array->tail = block;

    return array;
}

void *
array_next(array_t *array, size_t span) {

    block_t *block = array->tail;

    if (block->index + span >= block->size) {

        size_t nsize = (size_t)(array->size * 0.5);
        block_t *nblock = calloc(1, sizeof(block_t) + nsize);
  
        if (!nblock) return NULL;

        nblock->size = nsize;
        array->tail->next = nblock;
        array->tail = nblock;
        array->size += nsize;

        //printf("resize %-11lu %-11lu %-11lu\n", 
        //        block->size, nsize, array->size);
        
        block = nblock;
    }

    void *next = block->data + block->index;

    block->index += span;
    array->index += span;

    return next;
}

void
array_return(array_t *array, size_t span) {
    array->tail->index -= span;
    array->index -= span;
}

void
array_free(array_t *array) {
    block_t *next, *curr = array->head;
    while (curr) {
       next = curr->next;
       free(curr);
       curr = next;
    }
}

