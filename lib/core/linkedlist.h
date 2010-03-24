/** @file
 * A header file for linkedlist.c
 *
 * We are using following notation in this file:
 * <pre>
 * +------------+   head   +---------+   next   +---------+
 * | linkedlist |--------->|   node  |--------->|   node  |--  ...  --> NULL
 * +------------+          +--------+-          +---------+
 *                              |                    |
 *                              | ptr                | ptr
 *                              v                    v
 *                         +---------+          +---------+
 *                         | element |          | element |
 *                         +---------+          +---------+
 * </pre>where element contains the payload data.
 * @author  Lauri Silvennoinen
 * @version 1.0
 * @date    21.04.2008
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_LIB_CORE_LINKEDLIST_H
#define HIP_LIB_CORE_LINKEDLIST_H

/** Linked list node. */
typedef struct hip_ll_node {
    void *              ptr; /**< A pointer to node payload data. */
    struct hip_ll_node *next;     /**< A pointer to next node. */
} hip_ll_node_t;

/** Linked list. */
typedef struct {
    unsigned int   element_count;   /**< Total number of nodes in the list. */
    hip_ll_node_t *head;     /**< A pointer to the first node of the list. */
} hip_ll_t;

/** Linked list element memory deallocator function pointer. */
typedef void (*free_elem_fn_t)(void *ptr);

void hip_ll_init(hip_ll_t *linkedlist);
void hip_ll_uninit(hip_ll_t *linkedlist, free_elem_fn_t free_element);
unsigned int hip_ll_get_size(const hip_ll_t *linkedlist);
int hip_ll_add(hip_ll_t *linkedlist, const unsigned int index, void *ptr);
int hip_ll_add_first(hip_ll_t *linkedlist, void *ptr);
int hip_ll_add_last(hip_ll_t *linkedlist, void *ptr);
void *hip_ll_del(hip_ll_t *linkedlist, const unsigned int index,
                 free_elem_fn_t free_element);
void *hip_ll_del_first(hip_ll_t *linkedlist, free_elem_fn_t free_element);
void *hip_ll_del_last(hip_ll_t *linkedlist, free_elem_fn_t free_element);
void *hip_ll_get(hip_ll_t *linkedlist, const unsigned int index);
hip_ll_node_t *hip_ll_iterate(const hip_ll_t *linkedlist,
                              hip_ll_node_t *current);

#endif /* HIP_LIB_CORE_LINKEDLIST_H */
