#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "hash.h"
#include "array.h"
#include "token.h"

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

void
array_return(array_t *array, size_t span) {
    array->index -= span;
}


typedef struct token_t {
    hash_entry hash;
    char      *text;
    uint32_t   refs;
    uint32_t   len;   
} token_t;


typedef struct fstat_t {
    uint32_t lines;
    uint32_t tokens;
    uint32_t chars;
    uint32_t uchar;
} fstat_t;


typedef struct line_t {
    uint32_t line;
    uint32_t start;
    uint32_t len;
} line_t;

typedef struct file_t {
    //
    char    *name;
    FILE    *file;
    fstat_t  stat;

    // 
    line_t   *lines;
    token_t **tlist;

    //
    array_t *tokens;
    array_t *chars;

    //
    hash_table *hash;

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


int
token_comp(void *a, void *b) {
    token_t *A = (token_t*)a;
    token_t *B = (token_t*)b;
    return (
        A->len == B->len ?
        strncmp(A->text, B->text, A->len) :
        B->len - A->len
    );
}

uint32_t 
token_hash(void *entry) {

    token_t *token = (token_t*)entry;
    uint32_t hash = 5381;
    int i, ch;

    for (i = 0; i < token->len; i++) {
        ch = token->text[i];
        hash = ((hash << 5) + hash) + ch;
    }

    return hash;
}


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



int 
file_process(file_t *file) {

    file->lines  = calloc(file->stat.lines, sizeof(line_t));
    file->tlist = calloc(file->stat.tokens, sizeof(token_t*));

    int e_utoken = file->stat.tokens / 7;  // estimated unique tokens
    int e_hslots = file->stat.tokens / 19; // estimated hash table slots (for tokens)
    int e_uchars = file->stat.chars  / 7;  // estimated token char len
     
    file->tokens = array_init(e_utoken, sizeof(token_t));
    file->chars = array_init(e_uchars, sizeof(char));
    file->hash = hash_init(e_hslots, token_hash, token_comp);
    
    if (!file->lines  || 
        !file->tlist  ||
        !file->tokens ||
        !file->chars  ||
        !file->hash) {
        printf("buffer alloc error\n");
        return -1;
    }

    char line[2056], *cp, *text;
    
    uint32_t nline = 0;  // line count
    uint32_t ntoken = 0; // token count
    uint32_t ntokenline; // token/line count
    uint32_t len;        // token len


    while ((cp = fgets(line, 2056, file->file))) {

        file->lines[nline].start = ntoken;
        ntokenline = 0;

        while ((len = next_token(&cp, &text))) {

            char *cp = array_next(file->chars, len);
            memcpy(cp, text, len);

            // temp token entry from token array
            token_t *token = array_next(file->tokens, 1);
            token->len = len;
            token->text = cp;

            // insert into the hash
            token_t *hash_token = hash_insert(file->hash, token);

            if (token != hash_token) { // existing

                array_return(file->chars, len);
                array_return(file->tokens, 1);

            }

            hash_token->refs++;
            
            file->tlist[ntoken++] = hash_token;

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
    printf("utoken: %u\n", file->tokens->index);
    printf("uchar : %u\n", file->chars->index);
    printf("extra1: %lu\n", file->tokens->capacity - file->tokens->index);
    printf("extra2: %lu\n", file->chars->capacity - file->chars->index);
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
