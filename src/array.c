#include <stdlib.h>
#include "block.h"

array_t *
array_init(size_t size) {

    array_t *block = calloc(1, sizeof(array_t) + size);

    if (!block) return NULL;

    block->size = size;

    return block;
}

void *
array_next(array_t *block, size_t span) {

    if (block->index + span >= block->size) {

        printf("resize\n");

    }

    void *next = block->data + block->index;

    block->index += span;

    return next;
}

void
array_return(array_t *block, size_t span) {
    block->index -= span;
}

void
array_free(array_t *block) {
    array_t *next, *curr = block;
    while (curr) {
       next = curr->next;
       free(curr);
       curr = next;
    }
}
#include <stdlib.h>
#include <stdio.h>
#include "array.h"

array_t *
array_init(size_t capacity, size_t esize) {

    array_t *array = calloc(1, sizeof(array_t));
    uint8_t *data = calloc(capacity, esize);

    if (!array || !data) return NULL;

    array->data = data;
    array->esize = esize;
    array->capacity = capacity;

    return array;
}

void *
array_next(array_t *array, size_t span) {

    if (!array || !array->data) return NULL;

    if (array->index + span >= array->capacity) {

        size_t ncap = (size_t)(array->capacity * 1.6);
        size_t nsize = ncap * array->esize;
        void  *ndata = realloc(array->data, nsize);

        if (!ndata) return NULL;

        

        printf("resize: %lu %lu\n", array->capacity, ncap);

        array->data = ndata;
        array->capacity = ncap;
        
    }

    void *next = (void *)(array->data + (array->index * array->esize));

    array->index += span;

    return next;
}


void
array_return(array_t *array, size_t span) {
    array->index -= span;
}



