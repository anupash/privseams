#include "hashtable.h"
#include "debug.h"

#include <linux/interrupt.h>


void *hip_ht_find(HIP_HASHTABLE *ht, void *key)
{
	struct list_head *chain;
	void *entry;
	void *key_to_be_matched;
	int hash;

	hash = ht->hash(key, ht->hashsize);

	HIP_LOCK_HT(ht);
	{
		list_for_each(chain, &ht->head[hash]) {
			entry = hip_ht_get_content(void, chain, ht->offset);

			key_to_be_matched = ht->get_key(entry);
			if (ht->compare(key, key_to_be_matched)) {
				/* true = match */
				ht->hold(entry);
				HIP_UNLOCK_HT(ht);
				return entry;
			}
		}
	}				
	HIP_UNLOCK_HT(ht);
	return NULL;
}


int hip_ht_add(HIP_HASHTABLE *ht, void *entry)
{
	int hash = ht->hash(ht->get_key(entry), ht->hashsize);

	HIP_LOCK_HT(ht);
	list_add(hip_ht_get_list(entry, ht->offset), &ht->head[hash]);
	ht->hold(entry);
	HIP_UNLOCK_HT(ht);

	return 0;
}

void hip_ht_delete(HIP_HASHTABLE *ht, void *entry)
{
	int hash;

	hash = ht->hash(ht->get_key(entry), ht->hashsize);

	HIP_LOCK_HT(ht);
	list_del(hip_ht_get_list(entry, ht->offset));
	ht->put(entry);
	HIP_UNLOCK_HT(ht);
}


/*
 * @ht: Prefilled with following elements:
 *      head: Pointer to memory area to be used as hash table
 *      hashsize: Size of the hashtable (ie. number of chains).
 *
 */
int hip_ht_init(HIP_HASHTABLE *ht)
{
	int i;

	HIP_ASSERT(ht);
	HIP_ASSERT(ht->head);
	HIP_ASSERT(ht->hashsize);

	spin_lock_init(&ht->lock);

	for(i=0; i<ht->hashsize; i++)
		INIT_LIST_HEAD(&ht->head[i]);

	return 0;
}

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

