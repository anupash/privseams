/** @file
 * A header file for lutil.c. Imported from libinet6.
 *
 * Distributed under
 * <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */
#ifndef HIP_LIB_TOOL_LUTIL_H
#define HIP_LIB_TOOL_LUTIL_H

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"

#define MAX_ITEM_LEN 256

/* moved this here from getaddrinfo.c because it's used now in
 * getendpointinfo.c too */

struct gaih_addrtuple {
    struct gaih_addrtuple *next;
    int                    family;
    char                   addr[16];
    uint32_t               scopeid;
};

void free_gaih_addrtuple(struct gaih_addrtuple *tuple);

struct listitem {
    char             data[256];
    struct listitem *next;
};

typedef struct listitem Listitem;

struct list {
    Listitem *head;
};

typedef struct list List;

void initlist(List *);
void insert(List *, char *data);
void destroy(List *);
int length(List *);

/**
 * Gets an item from a linked list. Gets <code>n</code>th item from a linked
 * list.
 *
 * @param ilist a pointer to a linked list.
 * @param n     the index of the item to get.
 * @return      a pointer to <code>n</code>th item in the list, or NULL if
 *              list is NULL or if there is less than @c n items in the list.
 */
char *getitem(List *, int n);
char *getwithoutnewline(char *buffer, int count, FILE *f);
char *findsubstring(const char *string, const char *substring);

/**
 * Breaks a string into substrings. Breaks @c string into substrings using any
 * number of blanks and/or tab characters as separators. The substrings are
 * stored in a linked list @c list in the order of occurance.
 *
 * @param string a pointer to a string that is to be broken into substrings.
 * @param list   a pointer to a linked list where to the substrings are put.
 */
void extractsubstrings(char *string, List *list);

#endif /* HIP_LIB_TOOL_LUTIL_H */
