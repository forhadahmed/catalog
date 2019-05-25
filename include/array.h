#ifndef ARRAY_H
#define ARRAH_H

#include <stdint.h>

typedef struct block_t block_t;

struct block_t {
    size_t   size;
    size_t   index;
    block_t *next;
    uint8_t  data[0];
};

typedef struct array_t {
    block_t *head;
    block_t *tail;
    size_t   size;
    size_t   index;
} array_t;

array_t *array_init(size_t);

void *array_next(array_t *, size_t);

void array_return(array_t *, size_t);

#endif

