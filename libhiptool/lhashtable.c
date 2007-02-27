#include "lhashtable.h"

#if 0

#define hip_ht_get_content(type, ptr, offset) \
        (type *)((u8 *)ptr - offset)

#define hip_ht_get_list(ptr, offset) \
        (hip_list_t *)((u8 *)ptr + offset)




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
	hip_list_t *chain;
	void *entry;
	LHASH *retr;
	LHASH *nm;
	LHASH_NODE *hipchain;
	
	/* WTF: leaks memory */
	hipchain=(struct LHASH_NODE *) malloc(sizeof(LHASH_NODE));
	nm=ht->ami;
	hipchain=nm->b;
	
	if (nm->num_items !=0)
	{


		
		for(j=0;j<nm->num_items;j++)
		{	
			
			HIP_DEBUG("The hash entry is %u\n", hipchain->data);
			HIP_DEBUG("the data entry is %u\n", hipchain->hash);
			HIP_DEBUG("the number insert is %d\n", nm->num_insert);
			HIP_DEBUG("the number delete is %d\n", nm->num_delete);
			HIP_DEBUG("the number item is %d\n", nm->num_items);
			
			entry = lh_retrieve(ht->ami,&hipchain->hash);
			nm=ht->ami;
			ht->hipb=nm->b;
			hipchain=nm->b;
			HIP_DEBUG("Entry retrieved in if condition %d:\n",nm->num_retrieve);
						
		
		
		}		
				
		if (entry != NULL)
			return entry;

			

			
	}
	else
	{                     
						
		return 0;
			

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

        int i;
	int hipcom;
	LHASH_NODE *nadd;
	LHASH *nm;
	/*nadd=(struct LHASH_NODE *) malloc(sizeof(LHASH_NODE));*/
	int hash = ht->hash(ht->get_key(entry), ht->hashsize);
	_HIP_DEBUG("hash=%d HT=%s\n", hash, ht->name);
	HIP_LOCK_HT(ht);
	
	nadd=(struct LHASH_NODE *) malloc(sizeof(LHASH_NODE));
	

	nm=ht->ami;
	ht->hipb=nm->b;
	nadd=nm->b;
	nadd->data=entry;
	lh_insert(ht->ami,&entry);
	nm=ht->ami;
	ht->hipb=nm->b;
	nadd=nm->b;
	


	HIP_DEBUG("The hash entry in add function %u\n",entry);
	HIP_DEBUG("The hash entry in add function %u\n", nadd->data);
	HIP_DEBUG("Entry retrieve from AMI HT %d  %d:\n",nm->num_retrieve,nm->num_items);
	
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
 	
	LHASH *nm;
	HIP_DEBUG("I am in delete function %u\n",entry);
	nm=ht->ami;

	lh_delete(ht->ami,&entry);
	ht->put(entry);
	HIP_UNLOCK_HT(ht);
}

/**
 * Initializes a hashtable
 * @param ht a hashtable prefilled with following elements:
 * <ul>
 * <li>head: a pointer to memory area to be used as hashtable.</li>
 * <li>hashsize: size of the hashtable (ie. number of chains).</li>
 * <li>offset: offset of the hip_list_t that links the elements.</li>
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
 
	char *entry;
	char *key;
	char *key_to_be_matched;
	int hipcom;
	
 	if (ht->name)
		HIP_DEBUG("Initializing hash table: %s\n",ht->name);
	else
		HIP_DEBUG("Initializing hash table\n");

	/*ht->ami=lh_new(ht->hash(key, ht->hashsize),ht->compare(key, key_to_be_matched));*/
	ht->ami=lh_new(NULL,NULL);
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
  // XX TODO
}

#endif


