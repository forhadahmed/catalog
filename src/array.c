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



