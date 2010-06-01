/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * One-way linked list implementation operating based on pointers. It is
 * recommended to use lib/core/list.h implementation which supports
 * searching based on indexes (rather than pointers) can later also be
 * easily changed into a hashtable if needed.
 *
 * @brief a simple linked list implementation
 *
 * @author Essi Vehmersalo
 */

#include <stdlib.h>

#include "common_types.h"
#include "hslist.h"

static SList *slist_last(SList *list);

/**
 * allocate a new linked list element
 *
 * @return the allocated linked list element (caller frees)
 */
static SList *alloc_slist(void)
{
    SList *list = malloc(sizeof(SList));
    list->next = NULL;
    list->data = NULL;
    return list;
}

/**
 * append an element to the linked list
 *
 * @param list the linked list
 * @param data contents of the linked list element (stored as a pointer)
 * @return a pointer to the appended element in the linked list
 */
SList *append_to_slist(SList *list,
                       void *data)
{
    SList *new_list;
    SList *last;

    new_list       = alloc_slist();
    new_list->data = data;
    new_list->next = NULL;

    if (list) {
        last       = slist_last(list);
        last->next = new_list;
        return list;
    } else {
        return new_list;
    }
}

/**
 * traverse to the last element of the linked list
 *
 * @param list the linked list to be traversed
 * @return the last element of the linked list
 */
static SList *slist_last(SList *list)
{
    if (list) {
        while (list->next) {
            list = list->next;
        }
    }
    return list;
}

/**
 * remove a linked list item from a list (no deallocation)
 *
 * @param list the linked list
 * @param link the link to be unlinked from the list
 * @return a pointer to the linked list
 */
SList *remove_link_slist(SList *list,
                         SList *link)
{
    SList *tmp;
    SList *prev;

    prev = NULL;
    tmp  = list;

    while (tmp) {
        if (tmp == link) {
            if (prev) {
                prev->next = tmp->next;
            }

            if (list == tmp) {
                list = list->next;
            }

            tmp->next = NULL;
            break;
        }

        prev = tmp;
        tmp  = tmp->next;
    }

    return list;
}
