#ifndef HASH_H
#define HASH_H

typedef int (*hash_comp_fn) (void *, void *);
typedef uint32_t (*hash_fn) (void *);

typedef struct hash_entry {
    int                count;
    struct hash_entry *next;
} hash_entry;

typedef struct hash_table {
    uint32_t     count;
    uint32_t     slots;
    hash_entry **table;
    hash_comp_fn comp;
    hash_fn      hash;
} hash_table;

hash_table *hash_init(uint32_t, hash_fn, hash_comp_fn);

hash_entry *hash_insert(hash_table *, hash_entry *);

#endif

