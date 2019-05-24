#include <stdint.h>
#include <stdlib.h>
#include "hash.h"

hash_table *
hash_init(uint32_t slots, hash_fn hash, hash_comp_fn comp) {

    hash_table *ht = calloc(1, sizeof(hash_table));
    hash_entry **t = calloc(slots, sizeof(hash_entry *));

    if (!ht || !t) return NULL;

    ht->table = t;
    ht->slots = slots;
    ht->hash = hash;
    ht->comp = comp;

    return ht;
}


hash_entry *
hash_insert(hash_table *table, hash_entry *entry) {

    uint32_t hash = table->hash(entry);
    uint32_t slot = hash % table->slots;

    hash_entry **head = &table->table[slot];
    hash_entry *curr = *head;

    int found = 0;
    int count = 0;

    while (curr) {

        if (table->comp(curr, entry) == 0) {
            found = 1;
            break;
        }
        
        curr = curr->next;

        count++;
    }

    if (found) return curr;
    
    entry->next = *head;
    *head = entry;
    entry->count = count + 1;
    table->count++;

    return entry;
}

