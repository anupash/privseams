#ifndef ESCROW_H_
#define ESCROW_H_

#include "hadb.h"
#include "hashtable.h"
#include "misc.h"

#define HIP_KEA_SIZE 10
#define HIP_KEA_EP_SIZE 10

typedef enum { HIP_KEASTATE_INVALID=0, HIP_KEASTATE_REGISTERING=1, 
		HIP_KEASTATE_VALID=2 } hip_keastate_t;




struct hip_key_escrow_association 
{
	struct list_head		list_hit;

	atomic_t				refcnt;
	spinlock_t            	lock;

	struct in6_addr			hit; /* if we are the server, this is client hit,
									if we are the client, this is our own hit */
	// TODO: Find better key. Client HIT used for now.  
	//struct in6_addr       	client_hit; 
	//struct in6_addr       	peer_hit; //? 
	struct in6_addr			server_hit;
	
	uint32_t 				spi_in;//?
	uint32_t				spi_out;//?
	
	hip_keastate_t			keastate;
};

// Contains endpoint HIT and SPI
struct hip_kea_ep_id
{
	uint32_t value[5]; 
};

typedef struct hip_kea_ep_id HIP_KEA_EP_ID;


struct hip_kea_endpoint 
{
	struct list_head		list_hit;
	
	atomic_t				refcnt;
	spinlock_t            	lock;
	
	// Hash key for this
	HIP_KEA_EP_ID	ep_id;	
	
	struct in6_addr       	hit;
	struct in6_addr       	ip;
	int                  	esp_transform;
	uint32_t			    spi; 
	uint16_t				key_len; 	//?
	struct hip_crypto_key	esp_key;	
};


typedef struct hip_key_escrow_association HIP_KEA;
typedef struct hip_kea_endpoint HIP_KEA_EP;


/***************************************/

int hip_send_escrow_update(hip_ha_t *entry, int operation, 
	struct in6_addr *addr, struct in6_addr *hit, uint32_t spi, uint32_t old_spi,
	int ealg, uint16_t key_len, struct hip_crypto_key * enc);


int hip_handle_escrow_registration(struct in6_addr *hit);

/****** KEA ****************************/


HIP_KEA *hip_kea_get_base_entry(void);

int hip_kea_create_base_entry(struct hip_host_id_entry *entry, 
	void *server_hit);

int hip_kea_remove(struct hip_host_id_entry *entry, void *hit); 

int hip_kea_remove_base_entries(struct in6_addr *hit);

void hip_init_keadb(void);
void hip_uninit_keadb(void);

HIP_KEA *hip_kea_allocate(int gfpmask);

// TODO: Not ready!!
HIP_KEA *hip_kea_create(struct in6_addr *hit1, int gfpmask);

int hip_keadb_add_entry(HIP_KEA *kea);
void hip_keadb_remove_entry(HIP_KEA *kea);
void hip_keadb_delete_entry(HIP_KEA *kea);

HIP_KEA *hip_kea_find(struct in6_addr *hit);

void hip_keadb_hold_entry(void *entry);
void hip_keadb_put_entry(void *entry);

void hip_kea_set_state_registering(HIP_KEA *kea);

/*********** KEA_EP ********************/

void hip_init_kea_endpoints(void);
void hip_uninit_kea_endpoints(void);

int hip_kea_ep_hash(const void * key, int range);

int hip_kea_ep_match(const void * ep1, const void * ep2);

HIP_KEA_EP *hip_kea_ep_allocate(int gfpmask);

HIP_KEA_EP *hip_kea_ep_create(struct in6_addr *hit, struct in6_addr *ip, int esp_transform, 
							  uint32_t spi, uint16_t key_len, 
							  struct hip_crypto_key * key, int gfpmask);

int hip_kea_add_endpoint(HIP_KEA_EP *kea_ep);
void hip_kea_remove_endpoint(HIP_KEA_EP *kea_ep);
void hip_kea_delete_endpoint(HIP_KEA_EP *kea_ep);

HIP_KEA_EP *hip_kea_ep_find(struct in6_addr *hit, uint32_t spi);

void hip_kea_hold_ep(void *entry);
void hip_kea_put_ep(void *entry);



/************* macros *****************/

#define hip_hold_kea(entry) do { \
	atomic_inc(&entry->refcnt); \
    HIP_DEBUG("KEA: %p, refcnt increased to: %d\n",entry, atomic_read(&entry->refcnt)); \
} while(0) 

#define hip_put_kea(entry) do { \
	if (atomic_dec_and_test(&entry->refcnt)) { \
        HIP_DEBUG("KEA: %p, refcnt reached zero. Deleting...\n",entry); \
		hip_keadb_delete_entry(entry); \
	} else { \
        HIP_DEBUG("KEA: %p, refcnt decremented to: %d\n", entry, atomic_read(&entry->refcnt)); \
    } \
} while(0) 

#define hip_hold_kea_ep(entry) do { \
	atomic_inc(&entry->refcnt); \
    HIP_DEBUG("KEA EP: %p, refcnt increased to: %d\n",entry, atomic_read(&entry->refcnt)); \
} while(0) 

#define hip_put_kea_ep(entry) do { \
	if (atomic_dec_and_test(&entry->refcnt)) { \
        HIP_DEBUG("KEA EP: %p, refcnt reached zero. Deleting...\n",entry); \
		hip_kea_delete_endpoint(entry); \
	} else { \
        HIP_DEBUG("KEA EP: %p, refcnt decremented to: %d\n", entry, atomic_read(&entry->refcnt)); \
    } \
} while(0) 

#endif /*ESCROW_H_*/
