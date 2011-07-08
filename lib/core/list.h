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

#ifndef HIP_LIB_CORE_LIST_H
#define HIP_LIB_CORE_LIST_H

#include <openssl/lhash.h>

#include "hashtable.h"

/**
 * list_entry - get the struct for this entry
 * @param ptr the &LHASH_NODE pointer.
 */
#define list_entry(ptr) (ptr->data)

/**
 * list_find - find an entry from the list
 * @param entry the entry to find from the list
 * @param head the head for your list.
 */
#define list_find(entry, head) lh_retrieve(LHASH_CAST head, entry)

/**
 * list_for_each - iterate over list of given type
 * @param pos the type * to use as a loop counter.
 * @param head the head for your list.
 * @param counter counter
 */
#define list_for_each(pos, head, counter) \
    for ((counter = ((struct lhash_st *) (head))->num_nodes - 1); counter >= 0; counter--) \
        for (pos = ((struct lhash_st *) (head))->b[counter]; pos != NULL; pos = pos->next)

/**
 * list_for_each_safe
 * Iterates over a list of given type safe against removal of list entry.
 * @param pos the type * to use as a loop counter.
 * @param head the head for your list.
 * @param iter iter
 * @param counter counter
 */
#define list_for_each_safe(pos, iter, head, counter) \
    for ((counter = (((struct lhash_st *) (head)))->num_nodes - 1); counter >= 0; counter--) \
        for (pos = (((struct lhash_st *) (head)))->b[counter], (iter = pos ? pos->next : NULL); \
             pos != NULL; pos = iter, (iter = pos ? pos->next : NULL))

/**
 * list_add - add a new entry
 * @param entry new entry to be added
 * @param head list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
#define list_add(entry, head) lh_insert(LHASH_CAST head, entry)

/**
 * list_del - deletes entry from list.
 * @param entry the element to delete from the list.
 * @param head list head
 * Note: list_empty on entry does not return true after this, the entry is
 * in an undefined state.
 */
#define list_del(entry, head) lh_delete(LHASH_CAST head, entry)

#endif /* HIP_LIB_CORE_LIST_H */
