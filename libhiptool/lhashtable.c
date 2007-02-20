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
	int j;
	int recs,size,ind;
	struct list_head *chain;
	void *entry;
	void *key_to_be_matched;
	int hash;

	hash = ht->hash(key, ht->hashsize);
	_HIP_DEBUG("hash=%d HT=%s\n", hash, ht->name);
	
			
		if (ht->num_items !=0)
		{
			 
			for (j=0;j < ht->num_items;j++)
			{
				entry = hip_ht_get_content(void, chain, ht->offset);
		
			 	lh_retrieve(ht,&key);
			  	ht->hold(entry);
				HIP_UNLOCK_HT(ht);
				return entry;

			}

			
		}
		else
			{
			/*	HIP_DEBUG("no of items: %d\n",ht->num_items);
				HIP_DEBUG("no of key: %d\n",&key);
				
				HIP_DEBUG("no of items retrieved in the retrive function: %d\n",ht->num_retrieve);
				HIP_DEBUG("no of deleted items after  insert : %d\n",ht->num_delete);*/
				return NULL;
			}

		
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
	LHASH *conf;
        char buf[256];
        int i;
	void *ret;
     	LHASH_NODE *insert ,**rn1;
     	
	
	LHASH *nm;
	LHASH_NODE *newentry;
	LHASH_NODE *oldentry;

	
	char *key;
	char *key_to_be_matched1;
	int hipcom;

		nm=lh_new(NULL,NULL);
		int hash = ht->hash(ht->get_key(entry), ht->hashsize);
		_HIP_DEBUG("hash=%d HT=%s\n", hash, ht->name);
		HIP_LOCK_HT(ht);
		lh_insert(nm,&entry);
		ht=nm;
		HIP_DEBUG("Entry inserted in HIP HT %d:\n",ht->num_items);
		HIP_DEBUG("Inserting entry HASH Table sucessfull %d\n", nm->num_items);
		
		return 0;
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
 	
	/*lh_del(hip_ht_get_list(entry, ht->offset));*/
	/*lh_delete(ht, ht->offset);
	ht->put(entry);
	HIP_UNLOCK_HT(ht);*/
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
  int i;
	char *entry;
	char *key;
	char *key_to_be_matched;
	int hipcom;
	
 	if (ht->name)
		HIP_DEBUG("Initializing hash table: %s\n",ht->name);
	else
		HIP_DEBUG("Initializing hash table\n");

	ht=lh_new(ht->hash(key, ht->hashsize),ht->compare(key, key_to_be_matched));
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
  int i;
	struct list_head *item, *tmp;

	for(i=0;i<ht->hashsize;i++) {
		list_for_each_safe(item, tmp, &ht->b[i]) {
			list_del(item);
			ht->put(hip_ht_get_content(void, item, ht->offset));
		}
	}
}
