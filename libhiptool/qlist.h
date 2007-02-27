#ifndef QLIST_H
#define QLIST_H

#include "kerncompat.h"

#define LIST_HEAD_INIT(name) { 0 } /* XX FIXME */

#define INIT_LIST_HEAD(ptr) /* XX FIXME */

/**
 * list_entry - get the struct for this entry
 * @param ptr the &struct list_head pointer.
 * @param type the type of the struct this is embedded in.
 * @param member the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) NULL /* XX FIXME */

/**
 * list_for_each_entry	-	iterate over list of given type
 * @param pos the type * to use as a loop counter.
 * @param head the head for your list.
 * @param member the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member) for(;;) /* XX FIXME */

/**
 * Iterates over a list of given type safe against removal of list entry.
 *
 * @param pos the type * to use as a loop counter.
 * @param n another type * to use as temporary storage
 * @param head the head for your list.
 * @param member the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member) for(;;) /* XX FIXME */


/**
 * list_for_each_safe	-	iterate over a list safe against removal of list entry
 * @param pos the &struct list_head to use as a loop counter.
 * @param n another &struct list_head to use as temporary storage
 * @param head the head for your list.
 */
#define list_for_each_safe(pos, n, head)  for(;;) /* XX FIXME */

/**
 * list_add - add a new entry
 * @param lnew new entry to be added
 * @param lhead list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void list_add(struct list_head *lnew, struct list_head *lhead)
{
  /* XX FIXME */
}

/**
 * list_del - deletes entry from list.
 * @param entry the element to delete from the list.
 * Note: list_empty on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void list_del(struct list_head *entry)
{
  /* XX FIXME */
}

/**
 * list_add_tail - add a new entry
 * @param lnew new entry to be added
 * @param lhead list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void list_add_tail(struct list_head *lnew, struct list_head *lhead)
{
  /* XX FIXME */
}

/**
 * list_empty - tests whether a list is empty
 * @param head the list to test.
 */
static inline int list_empty(const struct list_head *head)
{
  /* XX FIXME */
}

#endif /* QLIST_H */
