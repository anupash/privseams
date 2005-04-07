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
#include "libinet6/debug.h"

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

/* very simple linked list */
typedef struct {
  char data[MAX_ITEM_LEN];
  struct listelement *link;
} listelement;

listelement * add_list_item(listelement * listpointer, char *data);
listelement * remove_list_item(listelement * listpointer);
void print_list(listelement * listpointer);
void clear_list(listelement * listpointer);

char *findsubstring(string, substring);
listelement *findkeyfiles(char *path, listelement *file1);

/* from getendpointinfo.c, make another header file? */
int get_local_hits(const char *servname, struct gaih_addrtuple **adr);

			
