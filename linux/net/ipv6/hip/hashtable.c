#include "hashtable.h"
#include "debug.h"

#include <linux/interrupt.h>
#include <linux/list.h>

#define hip_ht_get_content(type, ptr, offset) \
        (type *)((u8 *)ptr - offset)

#define hip_ht_get_list(ptr, offset) \
        (struct list_head *)((u8 *)ptr + offset)

/**
 * hip_ht_find - Find an element in a hash table
 * @ht: hash table
 * @key: key
 *
 * Returns NULL, or the entry that matches the @key
 */
void *hip_ht_find(HIP_HASHTABLE *ht, void *key)
{
	struct list_head *chain;
	void *entry;
	void *key_to_be_matched;
	int hash;

	hash = ht->hash(key, ht->hashsize);
	_HIP_DEBUG("hash=%d HT=%s\n", hash, ht->name);
	HIP_LOCK_HT(ht);
	{
		list_for_each(chain, &ht->head[hash]) {
			entry = hip_ht_get_content(void, chain, ht->offset);

			key_to_be_matched = ht->get_key(entry);
			_HIP_DEBUG("entry=0x%p key=0x%p\n", entry,
				  key_to_be_matched);
			if (ht->compare(key, key_to_be_matched)) {
				ht->hold(entry);
				HIP_UNLOCK_HT(ht);
				return entry;
			}
		}
	}				
	HIP_UNLOCK_HT(ht);
	return NULL;
}

/**
 * hip_ht_add - Add an element to a hash table
 * @ht: hash table
 * @entry: element to add
 *
 * Automatically holds (increases ref count) of the element.
 * [since the hash table stores a reference to the object]
 *
 * Returns 0
 */
int hip_ht_add(HIP_HASHTABLE *ht, void *entry)
{
	int hash = ht->hash(ht->get_key(entry), ht->hashsize);
	_HIP_DEBUG("hash=%d HT=%s\n", hash, ht->name);
	HIP_LOCK_HT(ht);
	list_add(hip_ht_get_list(entry, ht->offset), &ht->head[hash]);
	ht->hold(entry);
	HIP_UNLOCK_HT(ht);

	return 0;
}

/**
 * hip_ht_delete - Delete an element from a hash table
 * @ht: hash table
 * @entry: element to delete
 *
 * Automatically puts (decreases ref count) of the element
 * Does not explicitly delete the element.
 */
void hip_ht_delete(HIP_HASHTABLE *ht, void *entry)
{
	HIP_LOCK_HT(ht);
	list_del(hip_ht_get_list(entry, ht->offset));
	ht->put(entry);
	HIP_UNLOCK_HT(ht);
}


/**
 * hip_ht_init - Initialize a hash table
 * @ht: Prefilled with following elements:
 *      head: Pointer to memory area to be used as hash table
 *      hashsize: Size of the hashtable (ie. number of chains).
 *      offset: offset of the struct list_head that links the elements
 *      hash: function that hashes the key
 *      compare: function that compares two keys
 *      hold: function that increases element's ref count
 *      put: function that decreases element's ref count
 *      get_key: function that returns element's key from the element structure
 *      name: id (for debugging purposes)
 *
 * Returns 0
 */
int hip_ht_init(HIP_HASHTABLE *ht)
{
	int i;

	if (ht->name)
		HIP_DEBUG("Initializing hash table: %s\n",ht->name);
	else
		HIP_DEBUG("Initializing hash table\n");

	HIP_ASSERT(ht);
	HIP_ASSERT(ht->head);
	HIP_ASSERT(ht->hashsize);
	//HIP_ASSERT(ht->offset);
	HIP_ASSERT(ht->hash);
	HIP_ASSERT(ht->compare);
	HIP_ASSERT(ht->hold);
	HIP_ASSERT(ht->put);
	HIP_ASSERT(ht->get_key);

	spin_lock_init(&ht->lock);

	for(i=0; i<ht->hashsize; i++)
		INIT_LIST_HEAD(&ht->head[i]);

	HIP_DEBUG("Initialization of hash table complete\n");
	return 0;
}

/**
 * hip_ht_uninit - Uninitialize a hash table
 * @ht: hash table
 *
 * traverses through the hash table and puts every element
 * [= notifies that we no longer have a reference to the element].
 */
void hip_ht_uninit(HIP_HASHTABLE *ht)
{
	int i;
	struct list_head *item, *tmp;

	for(i=0;i<ht->hashsize;i++) {
		list_for_each_safe(item, tmp, &ht->head[i]) {
			list_del(item);
			ht->put(hip_ht_get_content(void, item, ht->offset));
		}
	}
}
