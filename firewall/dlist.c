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
 * Two-way linked list implementation operating based on pointers. It is
 * recommended to use lib/core/list.h implementation which supports
 * searching based on indexes (rather than pointers) can later also be
 * easily changed into a hashtable if needed.
 *
 * @brief Simple linked list implementation
 *
 * @author Essi Vehmersalo
 */

#include "lib/core/debug.h"
#include "dlist.h"

/**
 * Initialize and allocate memory for a new linked list.
 *
 * @return the linked list (caller frees)
 */
static DList *alloc_list(void)
{
    DList *list = malloc(sizeof(DList));
    list->data = NULL;
    list->next = NULL;
    list->prev = NULL;

    return list;
}

/**
 * get a pointer to the previous list item
 *
 * @param list a pointer to the list
 * @return a pointer to the previous list item
 */
DList *list_first(DList *list)
{
    if (list) {
        while (list->prev) {
            list = list->prev;
        }
    }

    return list;
}

/**
 * get a pointer to the next list item
 *
 * @param list a pointer to the list
 * @return a pointer to the next list item
 */
DList *list_last(DList *list)
{
    if (list) {
        while (list->next) {
            list = list->next;
        }
    }

    return list;
}

/**
 * calculate the number of list items
 *
 * @param list the linked list
 * @return the number of items on the linked list
 */
unsigned int list_length(DList *list)
{
    unsigned int length = 0;
    list = list_first(list);
    if (list) {
        while (list->next) {
            length++;
            list = list->next;
        }
    }
    return length;
}

/**
 * append a new element to the linked list
 *
 * @param list the linked list
 * @param data the new item to be appended
 * @return a pointer to the new item in the linked list
 */
DList *append_to_list(DList *list,
                      void *data)
{
    DList *new_list;
    DList *last;

    new_list       = alloc_list();
    new_list->data = data;
    new_list->next = NULL;

    if (list) {
        last           = list_last(list);
        last->next     = new_list;
        new_list->prev = last;

        HIP_DEBUG("List is not empty. Length %d\n", list_length(list));
        return list;
    } else {
        new_list->prev = NULL;
        HIP_DEBUG("List is empty inserting first node\n");
        return new_list;
    }
}

/**
 * remove a given link from the linked list
 *
 * @param list the linked list
 * @param link the link to be removed
 * @return link the link to be removed
 */
DList *remove_link_dlist(DList *list,
                         DList *link)
{
    if (link) {
        if (link->prev) {
            link->prev->next = link->next;
        }
        if (link->next) {
            link->next->prev = link->prev;
        }
        if (link == list) {
            list = list->next;
        }

        link->next = NULL;
        link->prev = NULL;
    }
    return list;
}

/**
 * find an element in the linked list
 *
 * @param list the linked list
 * @param data the element to find
 * @return the element in the linked list
 */
DList *find_in_dlist(DList *list,
                     void *data)
{
    while (list) {
        if (list->data == data) {
            break;
        }
        list = list->next;
    }
    return list;
}
