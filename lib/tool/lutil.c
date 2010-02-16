/** @file
 * Miscellaneous utility functions.
 *
 * @note    Distributed under
 * <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

/* required for s6_addr32 */
#define _BSD_SOURCE

#include "lutil.h"
#include "lib/conf/hipconf.h"

/*
 * Works like fgets() but removes '\n' from the end.
 */
char *getwithoutnewline(char *buffer, int count, FILE *f)
{
    char *result = buffer, *np;
    if ((buffer == NULL) || (count < 1)) {
        result = NULL;
    } else if (count == 1) {
        *result = '\0';
    } else if ((result = fgets(buffer, count, f)) != NULL) {
        if ((np = strchr(buffer, '\n'))) {
            *np = '\0';
        }
    }
    return result;
}

/*
 * Checks if a string contains a particular substring.
 *
 * If string contains substring, the return value is the location of
 * the first matching instance of substring in string.  If string doesn't
 * contain substring, the return value is NULL.
 */
char *findsubstring(const char *string, const char *substring)
{
    char *str = (char *) string, *sub = (char *) substring;
    char *a, *b;

    for (b = sub; *str != 0; str += 1) {
        if (*str != *b) {
            continue;
        }
        a = str;
        for (;; ) {
            if (*b == 0) {
                return str;
            }
            if (*a++ != *b++) {
                break;
            }
        }
        b = sub;
    }
    return (char *) NULL;
}

void extractsubstrings(char *string, List *list)
{
    char *sub_string;
    char delims[] = " \t";

    sub_string = strtok(string, delims);

    if (sub_string) {
        insert(list, sub_string);
    } else {
        return;
    }

    sub_string = NULL;

    while ((sub_string = strtok(NULL, delims)) != NULL) {
        insert(list, sub_string);
        sub_string = NULL;
    }
}


/* functions for simple linked list */
void initlist(List *ilist)
{
    ilist->head = NULL;
}

void insert(List *ilist, char *data)
{
    Listitem *new;
    new         = (Listitem *) malloc(sizeof(Listitem));
    new->next   = ilist->head;
    strncpy(new->data, data, MAX_ITEM_LEN);
    ilist->head = new;
}

int length(List *ilist)
{
    Listitem *ptr;
    int count = 1;

    if (!ilist->head) {
        return 0;
    }
    ptr = ilist->head;
    while (ptr->next) {
        ptr = ptr->next;
        count++;
    }
    return count;
}

void destroy(List *ilist)
{
    Listitem *ptr1, *ptr2;
    if (!ilist) {
        return;
    }
    ptr1 = ilist->head;
    while (ptr1) {
        ptr2 = ptr1;
        ptr1 = ptr1->next;
        free(ptr2);
    }
    ilist->head = NULL;
}

char *getitem(List *ilist, int n)
{
    Listitem *ptr;
    int count = 0;

    if (!ilist->head) {
        return NULL;
    }
    ptr = ilist->head;
    if (n == 0) {
        return ptr->data;
    }
    while (ptr->next) {
        ptr = ptr->next;
        count++;
        if (n == count) {
            return ptr->data;
        }
    }
    return NULL;
}

char *setdataitem(List *ilist, int n, char *data)
{
    Listitem *ptr;
    int count = 0;

    if (!ilist->head) {
        return NULL;
    }
    ptr = ilist->head;
    if (n == 0) {
        return ptr->data;
    }
    while (ptr->next) {
        ptr = ptr->next;
        count++;
        if (n == count) {
            //memset(new->data, 0, MAX_ITEM_LEN);
            strncpy(ptr->data, data, MAX_ITEM_LEN);
            return ptr->data;
        }
    }
    return NULL;
}
