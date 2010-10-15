/** @file
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
void *hip_ll_get(hip_ll_t *linkedlist, const unsigned int index);
hip_ll_node_t *hip_ll_iterate(const hip_ll_t *linkedlist,
                              hip_ll_node_t *current);

#endif /* HIP_LIB_CORE_LINKEDLIST_H */
