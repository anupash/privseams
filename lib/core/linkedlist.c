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
 * This file defines a linked list for storing pointers.
 *
 * @see     linkedlist.h for usage instructions.
 */

#include <stdlib.h>

#include "debug.h"
#include "linkedlist.h"

/**
 * Initializes a linked list. Sets the parameter @c linkedlist head to NULL if
 * the list itself is not NULL. If the list @c linkedlist is NULL, this function
 * does nothing.
 *
 * @param linkedlist the list to init.
 */
void hip_ll_init(struct hip_ll *const linkedlist)
{
    if (linkedlist != NULL) {
        *linkedlist = (struct hip_ll) HIP_LL_INIT;
    }
}

/**
 * Uninitializes a linked list. Removes each node from the parameter
 * @c linkedlist and frees the memory allocated for the nodes. The parameter
 * @c linkedlist is not itself freed.
 *
 * <ul><li>When @c free_element is <b>non-NULL</b> the memory allocated for the
 * elements itself is also freed by calling the @c free_element function for
 * each node. Make sure that there are no duplicate entries (i.e. nodes whose
 * @c ptr is pointing to the same memory region) in the @c list.</li>
 * <li>When @c free_element is <b>NULL</b> the memory allocated for the elements
 * is not freed, but only the nodes are freed.</li>
 * </ul>
 *
 * @param linkedlist   the list to uninitialize.
 * @param free_element a function pointer to a function for freeing the memory
 *                     allocated for an element stored in a node.
 * @note               If you're storing elements that have different memory
 *                     deallocator functions in the list, you should deallocate
 *                     the memory allocated for the elements manually before
 *                     invoking this function, and then call this function with
 *                     NULL as @c free_element.
 */
void hip_ll_uninit(struct hip_ll *linkedlist, free_elem_fn free_element)
{
    struct hip_ll_node *pointer = NULL;

    if (linkedlist == NULL || linkedlist->head == NULL) {
        return;
    }

    /* Free the node currently at list head and move the next item to list
     * head. Continue this until the item at list head is NULL. If
     * free_element() is non-NULL we also free the memory allocated for the
     * actual element. */
    if (free_element != NULL) {
        while (linkedlist->head != NULL) {
            pointer = linkedlist->head->next;
            free_element(linkedlist->head->ptr);
            free(linkedlist->head);
            linkedlist->head = pointer;
        }
    } else {
        while (linkedlist->head != NULL) {
            pointer = linkedlist->head->next;
            free(linkedlist->head);
            linkedlist->head = pointer;
        }
    }

    linkedlist->element_count = 0;
}

/**
 * Returns the number of nodes in the list.
 *
 * @param  linkedlist the list whose node count is to be returned.
 * @return number of nodes in the list.
 */
unsigned int hip_ll_get_size(const struct hip_ll *const linkedlist)
{
    if (linkedlist == NULL) {
        return 0;
    }

    return linkedlist->element_count;
}

/**
 * Adds a new node to a linked list. Adds a new node at @c index to the
 * parameter @c linkedlist with payload data @c ptr. If there are less than
 * (<code>index  -1</code>) elements in the list, the element will be added as
 * the last element of the list.
 *
 * <b>Example:</b>
 *
 * <code>hip_ll_add(&mylist, 2, mydata);</code> will add @c mydata as the
 * third item of the list when there are more than two elements in @c mylist.
 * When there are less than two items in the list @c mydata will be added as
 * the last element of @c mylist.
 *
 * @param  linkedlist the list where to add the new node.
 * @param  index      the list index where to store the node. Indexing starts
 *                    from zero.
 * @param  ptr        a pointer to the data to be stored.
 * @return            zero on success, -1 if @c linkedlist or @c ptr is NULL or
 *                    if there was an error when allocating memory to the new
 *                    node.
 */
int hip_ll_add(struct hip_ll *linkedlist, const unsigned int index, void *ptr)
{
    struct hip_ll_node *newnode       = NULL, *pointer = NULL;
    unsigned int        current_index = 0;

    if (linkedlist == NULL || ptr == NULL) {
        return -1;
    }

    if ((newnode = malloc(sizeof(struct hip_ll_node))) == NULL) {
        HIP_ERROR("Error on allocating memory for a linked list node.\n");
        return -1;
    }

    newnode->ptr = ptr;
    pointer      = linkedlist->head;

    /* Item to add is the first item of the list or it is to be added as the
     * first one. */
    if (pointer == NULL || index == 0) {
        newnode->next    = pointer;
        linkedlist->head = newnode;
        linkedlist->element_count++;
    }
    /* There exist at least one element in the list and the new element is
     * not to be added as the first one. */
    else {
        struct hip_ll_node *previous = pointer;

        /* Loop until "pointer" is at the last item. */
        while (pointer->next != NULL) {
            previous = pointer;
            pointer  = pointer->next;
            current_index++;

            /* We have reached the target index and the index is not
             * the index of the last item in the list. */
            if (current_index == index) {
                newnode->next  = pointer;
                previous->next = newnode;
                linkedlist->element_count++;
                return 0;
            }
        }
        /* The node is to be added as the last item of the list. */
        newnode->next = NULL;
        pointer->next = newnode;
        linkedlist->element_count++;
    }

    return 0;
}

/**
 * Adds a new node to a linked list. Adds a new node as the first item of
 * the @c linkedlist with payload data @c ptr.
 *
 * @param  linkedlist the list where to add the new node.
 * @param  ptr        a pointer to the data to be stored.
 * @return            zero on success, -1 if @c linkedlist or @c ptr is NULL or
 *                    if there was an error when allocating memory to the new
 *                    node.
 */
int hip_ll_add_first(struct hip_ll *const linkedlist, void *const ptr)
{
    return hip_ll_add(linkedlist, 0, ptr);
}

/**
 * Adds a new node to a linked list. Adds a new node as the last item of
 * the @c linkedlist with payload data @c ptr.
 *
 * @param  linkedlist the list where to add the new node.
 * @param  ptr        a pointer to the data to be stored.
 * @return            zero on success, -1 if @c linkedlist or @c ptr is NULL or
 *                    if there was an error when allocating memory to the new
 *                    node.
 */
int hip_ll_add_last(struct hip_ll *const linkedlist, void *const ptr)
{
    return hip_ll_add(linkedlist, linkedlist->element_count, ptr);
}

/**
 * Deletes a node from a linked list. Deletes a node at @c index and frees the
 * memory allocated for the node from the parameter @c linkedlist. If there are
 * less than (<code>index  -1</code>) nodes in the list no action will be taken. If
 * @c free_element is non-NULL the memory allocated for the element itself is
 * also freed. When @c free_element is non-NULL, make sure that the element
 * being freed is included in the list only once. When there are duplicate entries
 * (i.e. nodes whose @c ptr is pointing to the same memory region) in the
 * @c linkedlist, you will end up having nodes that have NULL pointer as
 * payload. This will mess up further calls of this function.
 *
 * @param linkedlist   the list where from to remove the element.
 * @param index        the list index of the @c node to be deleted. Indexing
 *                     starts from zero.
 * @param free_element a function pointer to a function for freeing the memory
 *                     allocated for an element at a node or NULL if the element
 *                     itself is not to be freed.
 * @return             a pointer to the data stored at the deleted node or NULL
 *                     if there are less than (<code>index  -1</code>) nodes in the list.
 *                     NULL is returned when @c free_element is not NULL i.e. the
 *                     element itself is deleted. NULL is also returned when
 *                     the list @c linkedlist itself is NULL.
 */
void *hip_ll_del(struct hip_ll *linkedlist, const unsigned int index,
                 free_elem_fn free_element)
{
    struct hip_ll_node *pointer       = NULL, *previous = NULL;
    void               *ptr           = NULL;
    unsigned int        current_index = 0;

    if (linkedlist == NULL || linkedlist->head == NULL) {
        return NULL;
    } else if (index > (linkedlist->element_count - 1)) {
        return NULL;
    }

    if (index == 0) {
        ptr     = linkedlist->head->ptr;
        pointer = linkedlist->head->next;
        if (free_element != NULL) {
            free_element(ptr);
            ptr = NULL;
        }
        free(linkedlist->head);
        linkedlist->head = pointer;
        linkedlist->element_count--;
        return ptr;
    }

    pointer = previous = linkedlist->head;

    while (pointer->next != NULL) {
        previous = pointer;
        pointer  = pointer->next;
        current_index++;

        /* We have reached the target index. */
        if (current_index == index) {
            if (pointer == NULL) {
                previous->next = NULL;
            } else {
                previous->next = pointer->next;
            }
            ptr = pointer->ptr;
            if (free_element != NULL) {
                free_element(ptr);
                ptr = NULL;
            }
            free(pointer);
            linkedlist->element_count--;
            break;
        }
    }

    return ptr;
}

/**
 * Deletes the first node from a linked list. If there are no nodes in the list,
 * no action will be taken. If @c free_element is non-NULL the memory allocated
 * for the element itself is also freed. When @c free_element is non-NULL, make
 * sure that the element being freed is included in the list only once. When there
 * are duplicate entries (i.e. nodes whose @c ptr is pointing to the same memory
 * region) in the @c linkedlist, you will end up having nodes that have NULL
 * pointer as payload. This will mess up further calls of this function.
 *
 * @param linkedlist   the list where from to remove the element.
 * @param free_element a function pointer to a function for freeing the memory
 *                     allocated for an element at a node or NULL if the element
 *                     itself is not to be freed.
 * @return             a pointer to the data stored at the deleted node or NULL
 *                     if there are no nodes in the list. NULL is returned when
 *                     @c free_element is not NULL i.e. the element itself is
 *                     deleted. NULL is also returned when the list
 *                     @c linkedlist itself is NULL.
 */
void *hip_ll_del_first(struct hip_ll *linkedlist,
                       free_elem_fn free_element)
{
    return hip_ll_del(linkedlist, 0, free_element);
}

/**
 * Gets an element from a linked list. Returns a pointer to the payload data
 * stored in node at @c index. When there are less than (<code>index  -1</code>)
 * nodes in the list, no action will be taken.
 *
 * @param linkedlist the linked list from where to retrieve the element.
 * @param index      the list index of the @c node from where the element is to
 *                   be retrieved. Indexing starts from zero.
 * @return           the next element or NULL if the list end has been reached
 *                   or if @c linkedlist is NULL.
 */
void *hip_ll_get(const struct hip_ll *const linkedlist, const unsigned int index)
{
    struct hip_ll_node *pointer       = linkedlist->head;
    unsigned int        current_index = 0;

    if (linkedlist == NULL || linkedlist->head == NULL) {
        return NULL;
    } else if (index > (linkedlist->element_count - 1)) {
        return NULL;
    }

    while (pointer != NULL) {
        if (current_index == index) {
            break;
        }

        pointer = pointer->next;
        current_index++;
    }

    return pointer->ptr;
}

/**
 * Enumerate each element in the list. Returns a pointer to the next linked list
 * node in the @c linkedlist or NULL if the list end has been reached. If
 * @c current is NULL, the first node in the list is returned. Do not delete
 * items from the list using this function or you will break the list.
 *
 * <pre>
 * struct hip_ll_node *iter = NULL;
 * while((iter = hip_ll_iterate(&list, iter)) != NULL) {
 *         ... Do stuff with iter ...
 * }
 * </pre>
 *
 * @param  linkedlist the linked list from where to retrieve the node.
 * @param  current    the current node or NULL if the first node from the list
 *                    is to be retrieved.
 * @return            the next node or NULL if the list end has been reached
 *                    or if @c linkedlist is NULL.
 * @note              <span style="color:#f00;">Do not delete nodes from the list
 *                    using this function.</span> Consider hip_ll_del() or
 *                    hip_ll_uninit() for deleting nodes and elements.
 */
const struct hip_ll_node *hip_ll_iterate(const struct hip_ll *const linkedlist,
                                         const struct hip_ll_node *const current)
{
    if (linkedlist == NULL) {
        return NULL;
    }
    if (current == NULL) {
        return linkedlist->head;
    }

    return current->next;
}
