#ifndef HIP_LIST_H
#define HIP_LIST_H

struct list_head {
  struct list_head *next, *prev;
};

/**
 * list_for_each        -       iterate over a list
 * @pos:        the &struct list_head to use as a loop counter.
 * @head:       the head for your list.
 */
#define list_for_each(pos, head) \
        for (pos = (head)->next, prefetch(pos->next); pos != (head); \
                pos = pos->next, prefetch(pos->next))

/**
 * list_for_each_safe   -       iterate over a list safe against removal of list entry
 * @pos:        the &struct list_head to use as a loop counter.
 * @n:          another &struct list_head to use as temporary storage
 * @head:       the head for your list.
 */
#define list_for_each_safe(pos, n, head) \
        for (pos = (head)->next, n = pos->next; pos != (head); \
                pos = n, n = pos->next)

#endif


