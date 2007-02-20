#ifndef HIP_LHASHTABLE_H
#define HIP_LHASHTABLE_H

#include "list.h"
#include "debug.h"

// XX FIXME: HAS TO BE CONVERTED
struct hip_ht_common {
	/** a pointer to memory area to be used as hashtable. */
	struct list_head *head;
	/** spinlock. */
	spinlock_t lock;
	/** size (number of chains) of the hashtable. */
	int hashsize;
	/** offset of the struct list_head that links the elements. */
	int offset;
	/** a pointer to a function that hashes the key. */
	int (*hash)(const void *key, int range);
	/** a pointer to a function that compares two keys. */
	int (*compare)(const void *key_to_match,
		       const void *key_to_be_matched);
	/** a pointer to a function that increases the element's reference
	    count. */
	void (*hold)(void *entry);
	/** a pointer to a function that decreases the element's reference
	    count. */
	void (*put)(void *entry);
	/** a pointer to a function that returns the element's key from
	    the element structure. */
	void *(*get_key)(void *entry);
	/** name of the hashtable. */
	char name[16];
};

typedef struct hip_ht_common HIP_HASHTABLE;

int hip_ht_init(HIP_HASHTABLE *ht);
void hip_ht_uninit(HIP_HASHTABLE *ht);

void *hip_ht_find(HIP_HASHTABLE *ht, const void *key);
int hip_ht_add(HIP_HASHTABLE *ht, void *entry);
void hip_ht_delete(HIP_HASHTABLE *ht, void *entry);

#define HIP_LOCK_HT(hash)
#define HIP_UNLOCK_HT(hash)

#endif

