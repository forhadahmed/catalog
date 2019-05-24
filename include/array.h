#ifndef ARRAY_H
#define ARRAH_H

#include <stdint.h>

typedef struct array_t {
    uint8_t  *data;
    size_t    esize;
    size_t    capacity;
    uint32_t  index;
} array_t;

array_t *array_init(size_t, size_t);

void *array_next(array_t *, size_t);

void array_return(array_t *, size_t);

#endif

