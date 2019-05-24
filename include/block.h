#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>

typedef struct block_t block_t;

struct block_t {
    block_t *next;
    size_t   index;
    size_t   size;
    uint8_t  data[0];
};
 

block_t *block_init(size_t);
void *block_next(block_t *, size_t);
void  block_return(block_t *, size_t);
void  block_free(block_t *);

#endif
