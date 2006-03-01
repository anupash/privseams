#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "dirent.h"
#include "sys/stat.h"
#include "unistd.h"
#include "fcntl.h"
#include "sys/param.h"
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#include "builder.h"
#include "debug.h"

#define MAX_ITEM_LEN 256

/* moved this here from getaddrinfo.c because it's used now in 
   getendpointinfo.c too */

struct gaih_addrtuple
  {
    struct gaih_addrtuple *next;
    int family;
    char addr[16];
    uint32_t scopeid;
};

void free_gaih_addrtuple(struct gaih_addrtuple *tuple);

struct listitem { 
  char data[256];
  struct listitem *next;
};

typedef struct listitem Listitem;

struct list {
  Listitem *head;
};

typedef struct list  List;

void initlist(List *);  
void insert(List *, char *data);
void destroy(List *);
int length(List *);
char *getitem(List *, int n);

char *getwithoutnewline(char *buffer, int count, FILE *f);

char *findsubstring(const char *string, const char *substring);
void findkeyfiles(char *path, List *list);
void extractsubstrings(char *string, List *list);

/* from getendpointinfo.c, make another header file? */
int get_local_hits(const char *servname, struct gaih_addrtuple **adr);
