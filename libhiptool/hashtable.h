#ifndef HIP_HASHTABLE_H
#define HIP_HASHTABLE_H

#include "list.h"
#include "debug.h"

struct hip_ht_common {
	struct list_head *head;
	spinlock_t lock;
	int hashsize;
	int offset;
	int (*hash)(const void *key, int range);
	int (*compare)(const void *key_to_match,
		       const void *key_to_be_matched);
	void (*hold)(void *entry);
	void (*put)(void *entry);
	void *(*get_key)(void *entry);
	char name[16];
};

typedef struct hip_ht_common HIP_HASHTABLE;

/************ primitives *************/
int hip_ht_init(HIP_HASHTABLE *ht);
void hip_ht_uninit(HIP_HASHTABLE *ht);

void *hip_ht_find(HIP_HASHTABLE *ht, const void *key);
int hip_ht_add(HIP_HASHTABLE *ht, void *entry);
void hip_ht_delete(HIP_HASHTABLE *ht, void *entry);

#define HIP_LOCK_HT(hash)
#define HIP_UNLOCK_HT(hash)

#endif

