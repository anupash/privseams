/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file
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

/**
 * allocate a new linked list element
 *
 * @return the allocated linked list element (caller frees)
 */
static struct slist *alloc_slist(void)
{
    struct slist *list = malloc(sizeof(struct slist));
    list->next = NULL;
    list->data = NULL;
    return list;
}

/**
 * traverse to the last element of the linked list
 *
 * @param list the linked list to be traversed
 * @return the last element of the linked list
 */
static struct slist *slist_last(struct slist *list)
{
    if (list) {
        while (list->next) {
            list = list->next;
        }
    }
    return list;
}

/**
 * append an element to the linked list
 *
 * @param list the linked list
 * @param data contents of the linked list element (stored as a pointer)
 * @return a pointer to the appended element in the linked list
 */
struct slist *append_to_slist(struct slist *list, void *data)
{
    struct slist *new_list;
    struct slist *last;

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
 * remove a linked list item from a list (no deallocation)
 *
 * @param list the linked list
 * @param link the link to be unlinked from the list
 * @return a pointer to the linked list
 */
struct slist *remove_link_slist(struct slist *list, struct slist *link)
{
    struct slist *tmp;
    struct slist *prev;

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

/**
 * Find an element in the singly linked list.
 *
 * @param list the linked list
 * @param data the element to find
 * @return     the element in the linked list
 */
struct slist *find_in_slist(struct slist *list, void *data)
{
    while (list) {
        if (list->data == data) {
            break;
        }
        list = list->next;
    }
    return list;
}
