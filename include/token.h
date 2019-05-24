#ifndef TOKEN_H
#define TOKEN_H

#include <ctype.h>

static inline int
next_token(char **head, char **token) {

   char *curr = *head;

   if (curr == NULL) return 0;

   while ( *curr &&  isspace(*curr) ) curr++;

   *token = *curr ? curr : 0;

   while ( *curr && !isspace(*curr) ) curr++;

   *head = *curr ? curr + 1 : 0;

   *curr = 0;

   return *token ? ( curr - *token ) : 0;
}

#endif
