#ifndef HIP_SAVA_API
#define HIP_SAVA_API

#include "hashtable.h"
#include "ife.h"
#include <openssl/sha.h>
//#include <in6.h>

typedef struct hip_sava_ip_entry {
  struct in6_addr * src_addr;
} hip_sava_ip_entry_t;

static DECLARE_LHASH_HASH_FN(hip_sava_ip_entry_hash, const hip_sava_ip_entry_t *);
static DECLARE_LHASH_COMP_FN(hip_sava_ip_entries_compare, const hip_sava_ip_entry_t *);

unsigned long hip_sava_ip_entry_hash(const hip_sava_ip_entry_t * entry);


int hip_sava_ip_entries_compare(const hip_sava_ip_entry_t * entry1,
				const hip_sava_ip_entry_t * entry2);

int hip_sava_ip_db_init();
int hip_sava_ip_db_uninit();

hip_sava_ip_entry_t *hip_sava_ip_entry_find(struct in6_addr * src_addr);

int hip_sava_ip_entry_add(struct in6_addr *src_addr);

int hip_sava_ip_entry_delete(struct in6_addr * src_addr);

#endif //HIP_SAVA_API
