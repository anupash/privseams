/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * Hashtable wrappers for OpenSSL lhash implementation. Originally
 * introduced to HIPL to hide transition of swithing between different
 * hashtable implementations. Now the wrappers are mainly used to hide
 * backward incompatibilities with OpenSSL 1.0.0 which broke the lhash
 * API. Be careful with changes to this file and test all changes with
 * both OpenSSL versions above and below 1.0.0.
 *
 * It should be noticed that lhash is implemented using linked lists
 * and can therefore be used interchangeably also as a linked list.
 * When you are using the lhash wrappers in here as your base for
 * linked lists in new code, it is easier to transition to hash tables
 * when you need the performance boost.
 *
 * @brief Hashtable wrappers for OpenSSL lhash implementation
 *
 * @author Miika Komu <miika@iki.fi>
 * @see lib/opphip/wrap_db.c for a minimal hash table implementation
 *      example
 */
#include "hashtable.h"

/**
 * A generic object hashing function for lib/core/hashtable.c
 *
 * @param ptr an pointer to hash (must be at least 32 bits)
 * @return a hash of the first 32-bits of the ptr's data
 */
static unsigned long hip_hash_generic(const void *ptr)
{
    unsigned long hash = (unsigned long) (*((uint32_t *) ptr));
    return hash % ULONG_MAX;
}

/**
 * A generic matching function for lib/core/hashtable.c
 *
 * @param ptr1 a pointer to an item in the hash table
 * @param ptr2 a pointer to an item in the hash table
 * @return zero if the pointers match or one otherwise
 */
static int hip_match_generic(const void *ptr1, const void *ptr2)
{
    return ptr1 != ptr2;
}

#ifdef HIPL_OPENSSL_100

/**
 * Returns a generic linked list based on the hash table implementation
 *
 * @return an allocated hash table which is caller is responsible to free
 */
LHASH_OF(HIP_HT) * hip_linked_list_init(void)
{
  return (LHASH_OF(HIP_HT) *) hip_ht_init(hip_hash_generic, hip_match_generic);
}

/**
 * Initialize hash table (or linked list)
 *
 * @param hashfunc hash function to calculated the hash
 * @param cmpfunc an equality comparison function
 * @return The allocated hashtable that the caller must free with hip_ht_uninit().
 *         NULL on error.
 */
LHASH_OF(HIP_HT) * hip_ht_init(LHASH_HASH_FN_TYPE hashfunc, LHASH_COMP_FN_TYPE cmpfunc)
{
    return (LHASH_OF(HIP_HT) *)lh_new(hashfunc, cmpfunc);
}

#else /* not HIPL_OPENSSL_100 */

HIP_HASHTABLE *hip_linked_list_init(void)
{
    return (HIP_HASHTABLE *) hip_ht_init(hip_hash_generic, hip_match_generic);
}

HIP_HASHTABLE *hip_ht_init(LHASH_HASH_FN_TYPE hashfunc,
                           LHASH_COMP_FN_TYPE cmpfunc)
{
    return (HIP_HASHTABLE *) lh_new(hashfunc, cmpfunc);
}

#endif /* HIPL_OPENSSL_100 */

/**
 * Unitilialize a hashtable that was allocated using hip_ht_init()
 *
 * @param head a pointer to the hashtable
 */
void hip_ht_uninit(void *head)
{
    lh_free(head);
}

/**
 * Find an element from the hashtable
 *
 * @param head the hashtable
 * @param data the key to find from the hashtable
 * @return a pointer to the value of the found key or NULL otherwise
 */
void *hip_ht_find(void *head, void *data)
{
    return lh_retrieve((LHASH100_CAST *) head, data);
}

/**
 * Add an element to a hash table
 *
 * @param head the hashtable
 * @param data the entry to insert to the hash table
 * @return zero
 * @note This function stores pointers. The data is not copied.
 * @note If the hashtable contains already the same key, the old one is silently
 *       replaced with the new one. Look up first with hip_ht_find() see if
 *       the same key already exists in the hashtable!
 */
int hip_ht_add(void *head, void *data)
{
    if (lh_insert((LHASH100_CAST *) head, data)) {
        HIP_DEBUG("hash replace did not occur\n");
    }
    return 0;
}

/**
 * delete an element from a hash table
 *
 * @param head the hashtable
 * @param data a pointer to the key to delete from the hash table
 * @return the deleted element or NULL when the element was missing
 *         from the hashtable
 */
void *hip_ht_delete(void *head, void *data)
{
    return lh_delete((LHASH100_CAST *) head, data);
}

/**
 * a callback iterator for a hash table
 *
 * @param head the hastable
 * @param func a callback function pointer that will be called for each
 *             element in the hash table
 */
void hip_ht_doall(void *head, LHASH_DOALL_FN_TYPE func)
{
    lh_doall((LHASH100_CAST *) head, func);
}

/**
 * a callback iterator for a hash table with an extra value
 * that can be passed to the callback
 *
 * @param head the hash table
 * @param func the callback function that should be called
 * @param arg an extra argument to be passed to the callback function
 */
void hip_ht_doall_arg(void *head, LHASH_DOALL_ARG_FN_TYPE func, void *arg)
{
    lh_doall_arg((LHASH100_CAST *) head, func, arg);
}
