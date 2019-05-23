#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "token.h"
#include "meminfo.h"

#define TOKEN_IP
#define TOKEN_TS
#define TOKEN_STR
#define TOKEN_NUM
#define TOKEN_MAX

#define MAX_TOKENS 2

/*
 * count  - number of log lines that hit this bucket
 * ntoken - number of tokens in this bucket
 * tokenc - per token counts (number of lines that had this token)
 * tokens - the tokens in this bucket
 */
typedef struct bucket_t {
    int   count;
    int   ntoken;
    int   tokenc[MAX_TOKENS];
    char *tokens[MAX_TOKENS];
} bucket;

typedef struct fstat_t {
    uint32_t lines;
    uint32_t tokens;
    uint32_t chars;
    uint32_t uchar;
} fstat_t;

#define HASH_TABLE_SIZE (1<<18)

typedef struct hash_entry {
    int                count;
    struct hash_entry *next;
} hash_entry;

typedef struct hash_table {
    uint32_t    size;
    hash_entry *table[HASH_TABLE_SIZE];
} hash_table;

hash_table token_table;

typedef struct token_t {
    hash_entry hash;
    char      *text;
    uint32_t   len;   
} token_t;

int
token_comp(void *a, void *b, void *c) {
    token_t *A = (token_t*)a;
    token_t *B = (token_t*)b;
    return ( 
        A->len == B->len ?
        strncmp(B->text, A->text, A->len) : 
        B->len - A->len
    ); 
}

typedef struct line_t {
    uint32_t line;
    uint32_t start;
    uint32_t len;
} line_t;

typedef struct file_t {
    char     *name;
    FILE     *file;
    fstat_t   stat;
    line_t   *lines;
    token_t  *tokens;
    avl_tree *index;
    char     *chars;
} file_t;


bucket *
find_bucket(char *tokens[], int n)
{
    
    return 0;
}

int 
token_ip(char *token, int len)
{
    
    return 0;
}

int 
token_ts(char *token, int len)
{
   
    return 0; 
}

int
token_num(char *token, int len)
{
    
    return 0;
}

int
match_token(char *token, int len)
{


    return 0; 
}

//int getline(void *file);

int mmap_getline(void *file);

int file_getline(FILE *file);


void file_stat(file_t *file) {

    char line[2056], *cp, *token;
    uint32_t len;

    while ((cp = fgets(line, 2056, file->file))) {

        file->stat.lines++;

        while ((len = next_token(&cp, &token))) {

            file->stat.tokens++;
            file->stat.chars += len;

        }
    }

    rewind(file->file);
}


uint32_t 
hash_calculate(hash_entry *entry) {
    token_t *token = (token_t*)entry;
    uint32_t hash = 5381;
    int i, ch;

    for (i = 0; i < token->len; i++) {
        ch = token->text[i];
        hash = ((hash << 5) + hash) + ch;
    }

    return hash;
}


hash_entry *hash_find_or_create(hash_table *table, hash_entry *entry) {

    uint32_t hash = hash_calculate(entry);
    uint32_t slot = hash % HASH_TABLE_SIZE;

    hash_entry **head = &table->table[slot];
    hash_entry *curr = *head;

    int found = 0;
    int count = 0;

    while (curr) {

        token_t *a = (token_t*)curr;
        token_t *b = (token_t*)entry;
        
        if (a->len == b->len && strncmp(a->text, b->text, a->len) == 0) {
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
    table->size++;

    return entry;
 
}


int 
file_process(file_t *file) {

    file->lines  = calloc(file->stat.lines, sizeof(line_t));
    file->tokens = calloc(file->stat.tokens, sizeof(token_t));
    file->chars  = malloc(file->stat.chars);

    if (!file->lines || !file->tokens || !file->chars) {
        printf("buffer alloc error\n");
        return -1;
    }

    file->index = avl_init(token_comp, 0, AVL_TREE_INTRUSIVE);

    if (!file->index) {
        printf("index alloc error\n");
        return -1;
    }
    
    char line[2056], *cp, *text;
    
    uint32_t nline = 0;  // line count
    uint32_t ntoken = 0; // token count
    uint32_t nchar = 0;  // char count
    uint32_t ntokenline; // token/line count
    uint32_t len;        // token len
    
    while ((cp = fgets(line, 2056, file->file))) {

        file->lines[nline].start = ntoken;
        ntokenline = 0;

        while ((len = next_token(&cp, &text))) {

            char *save = file->chars + nchar;

            memcpy(save, text, len);

            nchar += len;

            token_t *token = &file->tokens[ntoken];
            token->len = len;
            token->text = save;

            // insert into the index

            #if 0

            avl_node *node = avl_lookup(file->index, token, 0);

            if (!node) {
                node = avl_insert(file->index, token, 0);
                file->stat.uchar += len;
            }

            if (!node) {
                printf("avl_insert error\n");
                return -1;
            }

            #else

            hash_entry *entry = hash_find_or_create(&token_table, (hash_entry*)token);

            if (entry == (hash_entry*)token) { // new

                file->stat.uchar += len;
                 
            }

            #endif
            
            ntoken++;
            ntokenline++;
        }
        
        file->lines[nline].len = ntokenline;
        file->lines[nline].line = nline + 1;
        nline++;
    }

    return 0;
}


file_t * 
file_init(char *name) {

    FILE   *fp = fopen(name, "r");
    file_t *file = calloc(1, sizeof(file_t));

    if (!fp || !file) return NULL;

    file->name = strdup(name);
    file->file = fp;
   
    file_stat(file);
    
    return file;
}


void file_dump(file_t *file) {
    printf("name  : %s\n", file->name);
    printf("lines : %u\n", file->stat.lines);
    printf("tokens: %u\n", file->stat.tokens);
    printf("chars : %u\n", file->stat.chars);
    printf("index : %u\n", avl_size(file->index));
    printf("index2: %u\n", token_table.size);
    printf("uchar : %u\n", file->stat.uchar);
}


int 
main(int argc, char *argv[])
{
    // parse opts
    // mmap file

    // get file size

    if (argc < 2) {
        printf("usage\n");
        exit(0);
    }
    
    file_t *file = file_init(argv[1]);

    if (file == NULL) {
        printf("file_init error\n");
        exit(1);
    }

    int rc = file_process(file);

    if (rc < 0) {
        printf("file_process error\n");
        exit(1);
    }

    file_dump(file);
    
    return 0;


    /*

    meminfo_t info;

    int rc = meminfo(&info);

    if (rc < 0) {
        printf("meminfo: %d\n", rc);
    }
    
   
    if (info->free > file_size) {
        // we can do mmap
    } else {
        // read line-by-line
    }
    

    printf("%d %d\n", info.total, info.free);

    return 0;
    
    while (1) {
        // get line from file
        // tokenize line
        // for each bucket - find matching bucket         
 
    }
    */
}
