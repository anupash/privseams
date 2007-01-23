#include "lhashtable.h"

#define hip_ht_get_content(type, ptr, offset) \
        (type *)((u8 *)ptr - offset)

#define hip_ht_get_list(ptr, offset) \
        (struct list_head *)((u8 *)ptr + offset)

/**
 * hip_ht_find - Find an element in a hash table
 * @param ht hash table
 * @param key key
 *
 * @return NULL, or the entry that matches the key
 */
void *hip_ht_find(HIP_HASHTABLE *ht, const void *key)
{
  return NULL;
}

/**
 * hip_ht_add - Add an element to a hash table
 * @param ht hash table
 * @param entry element to add
 *
 * Automatically holds (increases ref count) of the element.
 * [since the hash table stores a reference to the object]
 *
 * Returns 0
 */
int hip_ht_add(HIP_HASHTABLE *ht, void *entry)
{
  return NULL;
}

/**
 * hip_ht_delete - Delete an element from a hash table
 * @param ht hash table
 * @param entry element to delete
 *
 * Automatically puts (decreases ref count) of the element
 * Does not explicitly delete the element.
 */
void hip_ht_delete(HIP_HASHTABLE *ht, void *entry)
{
  return NULL;
}

/**
 * Initializes a hashtable
 * @param ht a hashtable prefilled with following elements:
 * <ul>
 * <li>head: a pointer to memory area to be used as hashtable.</li>
 * <li>hashsize: size of the hashtable (ie. number of chains).</li>
 * <li>offset: offset of the struct list_head that links the elements.</li>
 * <li>hash: a pointer to a function that hashes the key.</li>
 * <li>compare: a pointer to a function that compares two keys.</li>
 * <li>hold: a pointer to a function that increases the element's reference
 * count.</li>
 * <li>put: a pointer to a function that decreases the element's reference
 * count.</li>
 * <li>get_key: function that returns element's key from the element structure.</li>
 * <li>name: name of this hashtable.</li>
 * </ul>
 * @return 0
 */
int hip_ht_init(HIP_HASHTABLE *ht)
{
  return NULL;
}

/**
 * hip_ht_uninit - Uninitialize a hash table
 * @param ht hash table
 *
 * traverses through the hash table and puts every element
 * [= notifies that we no longer have a reference to the element].
 */
void hip_ht_uninit(HIP_HASHTABLE *ht)
{
  return NULL;
}
