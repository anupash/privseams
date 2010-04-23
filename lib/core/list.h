/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_LIB_CORE_LIST_H
#define HIP_LIB_CORE_LIST_H

#include <openssl/lhash.h>

typedef LHASH_NODE hip_list_t;

/**
 * list_entry - get the struct for this entry
 * @param ptr the &hip_list_t pointer.
 * @param type the type of the struct this is embedded in.
 * @param member the name of the list_struct within the struct.
 */
#define list_entry(ptr) (ptr->data)

/**
 * list_find - find an entry from the list
 * @param entry the entry to find from the list
 * @param head the head for your list.
 */
#ifdef LHASH_OF
#define list_find(entry, head) lh_retrieve((_LHASH *) head, entry)
#else
#define list_find(entry, head) lh_retrieve(head, entry)
#endif

/**
 * list_for_each - iterate over list of given type
 * @param pos the type * to use as a loop counter.
 * @param head the head for your list.
 * @param member the name of the list_struct within the struct.
 */
#define list_for_each(pos, head, counter) \
    for ((counter = ((struct lhash_st *) (head))->num_nodes - 1); counter >= 0; counter--) \
              for (pos = ((struct lhash_st *) (head))->b[counter]; pos != NULL; pos = pos->next)

/**
 * list_for_each_safe
 * Iterates over a list of given type safe against removal of list entry.
 * @param pos the type * to use as a loop counter.
 * @param head the head for your list.
 * @param member the name of the list_struct within the struct.
 */
#define list_for_each_safe(pos, iter, head, counter) \
    for ((counter = (((struct lhash_st *) (head)))->num_nodes - 1); counter >= 0; counter--) \
              for (pos = (((struct lhash_st *) (head)))->b[counter], (iter = pos ? pos->next : NULL); \
                                                                      pos != NULL; pos = iter, (iter = pos ? pos->next : NULL))

/**
 * list_add - add a new entry
 * @param lnew new entry to be added
 * @param lhead list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
#ifdef LHASH_OF
#define list_add(entry, head) lh_insert((_LHASH *) head, entry)
#else
#define list_add(entry, head) lh_insert(head, entry)
#endif

/**
 * list_del - deletes entry from list.
 * @param entry the element to delete from the list.
 * Note: list_empty on entry does not return true after this, the entry is
 * in an undefined state.
 */
#ifdef LHASH_OF
#define list_del(entry, head) lh_delete((_LHASH *) head, entry)
#else
#define list_del(entry, head) lh_delete(head, entry)
#endif

#endif /* HIP_LIB_CORE_LIST_H */
