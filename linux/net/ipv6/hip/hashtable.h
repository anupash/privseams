#ifndef HIP_HASHTABLE_H
#define HIP_HASHTABLE_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/list.h>

struct hip_ht_common {
	struct list_head *head;
	spinlock_t lock;
	size_t hashsize;
	int offset;
	int (*hash)(void *key, int range);
	int (*compare)(void *key_to_match, void *key_to_be_matched);
	void (*hold)(void *entry);
	void (*put)(void *entry);
	void *(*get_key)(void *entry);
	char name[16];
};

typedef struct hip_ht_common HIP_HASHTABLE;

/************ primitives *************/

int hip_ht_init(HIP_HASHTABLE *ht);
void hip_ht_uninit(HIP_HASHTABLE *ht);

void *hip_ht_find(HIP_HASHTABLE *ht, void *key);
int hip_ht_add(HIP_HASHTABLE *ht, void *entry);
void hip_ht_delete(HIP_HASHTABLE *ht, void *entry);

#define HIP_LOCK_HT(hash) do { \
	spin_lock_bh(&(hash)->lock); \
} while(0)

#define HIP_UNLOCK_HT(hash) do { \
	spin_unlock_bh(&(hash)->lock); \
} while(0)

#endif

