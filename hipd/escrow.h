#ifndef ESCROW_H_
#define ESCROW_H_

#include "hadb.h"
#include "hashtable.h"
#include "misc.h"

#define HIP_KEA_SIZE 10

typedef enum { HIP_KEASTATE_INVALID=0, HIP_KEASTATE_INITIALIZED=1, 
		HIP_KEASTATE_VALID=1 } hip_keastate_t;

struct hip_key_escrow_association 
{
	struct list_head		list_hit;

	atomic_t				refcnt;
	spinlock_t            	lock;

	struct in6_addr       	hash_key; // HITs xorred
	
	hip_keastate_t			keastate;
	struct in6_addr       	hit1;
	struct in6_addr       	hit2;
	
	struct in6_addr       	ip1;
	struct in6_addr       	ip2;
	
	int                  	esp_transform;
	uint32_t			    spi; 
	uint16_t				key_len; 	//?
	struct hip_crypto_key	esp_key;	

};

typedef struct hip_key_escrow_association HIP_KEA;

void hip_init_keadb(void);
void hip_uninit_keadb(void);

HIP_KEA *hip_kea_allocate(int gfpmask);

// TODO: Not ready!!
HIP_KEA *hip_kea_create(struct in6_addr *hit1, struct in6_addr *hit2, 
						int esp_transform, uint32_t spi, uint16_t key_len, 
						struct hip_crypto_key * key, int gfpmask);

int hip_keadb_add_entry(HIP_KEA *kea);
void hip_keadb_remove_entry(HIP_KEA *kea);
void hip_keadb_delete_entry(HIP_KEA *kea);

HIP_KEA *hip_kea_find_byhits(struct in6_addr *hit1, struct in6_addr *hit2);

void hip_keadb_hold_entry(void *entry);
void hip_keadb_put_entry(void *entry);


/************* macros *****************/

#define hip_hold_kea(kea) do { \
	atomic_inc(&kea->refcnt); \
    HIP_DEBUG("KEA: %p, refcnt increased to: %d\n",kea, atomic_read(&kea->refcnt)); \
} while(0) 

#define hip_put_kea(kea) do { \
	if (atomic_dec_and_test(&kea->refcnt)) { \
        HIP_DEBUG("KEA: %p, refcnt reached zero. Deleting...\n",kea); \
		hip_keadb_delete_entry(kea); \
	} else { \
        HIP_DEBUG("KEA: %p, refcnt decremented to: %d\n", kea, atomic_read(&kea->refcnt)); \
    } \
} while(0) 

#endif /*ESCROW_H_*/
