#ifndef MEMINFO_H
#define MEMINFO_H

#include <string.h>
#include <unistd.h>

#include "token.h"

typedef struct meminfo_t {
    int total;
    int free;
} meminfo_t;

#define MEMINFO_FILE "/proc/meminfo"

static inline int meminfo(meminfo_t *info) 
{
    #if 0
    if (!info) {
        return -1;
    }

    FILE *fd = fopen(MEMINFO_FILE, "r");

    if (!fd) {
        return -1;
    }
    
    char  line[1024];
    char *token = NULL;
    int   found = 0;

    
    while (fgets(line, 1024, fd)) {

        char *cp = line;

        if (strstr(line, "MemTotal")) {
            token = next_token(&cp); // MemTotal:
            token = next_token(&cp); // <number>  
            info->total = atoi(token);
            found++;
        }

        if (strstr(line, "MemFree")) {
            token = next_token(&cp); // MemFree:
            token = next_token(&cp); // <number>  
            info->free = atoi(token);
            found++;
        }
    }
    

    return (found == 2 ? 0 : -1);
    #endif

    return 0;
}

#endif
