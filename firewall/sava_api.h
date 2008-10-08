#ifndef HIP_SAVA_API
#define HIP_SAVA_API

#include "hashtable.h"
#include "ife.h"

#include "builder.h"
#include "message.h"

#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/blowfish.h>



typedef struct hip_sava_peer_info {
/*struct in6_addr *src_addr; */          /* original IP address     */
  int ealg; 		              /* crypto transform in use */    
  struct hip_crypto_key *ip_enc_key;  /* raw crypto keys         */
  des_key_schedule ks[3];	      /* 3-DES keys              */
  AES_KEY *aes_key;		      /* AES key                 */
  BF_KEY *bf_key;		      /* BLOWFISH key            */
} hip_sava_peer_info_t;

typedef struct hip_sava_enc_ip_entry {
  struct in6_addr * src_enc;
  struct hip_sava_hit_entry * hit_link;
  struct hip_sava_ip_entry  * ip_link;
  struct hip_sava_peer_info * peer_info;
} hip_sava_enc_ip_entry_t;

typedef struct hip_sava_hit_entry {
  struct in6_addr          * src_hit;
  struct hip_sava_ip_entry * link;
} hip_sava_hit_entry_t;

typedef struct hip_sava_ip_entry {
  struct in6_addr * src_addr;
  struct hip_sava_hit_entry * link;
} hip_sava_ip_entry_t;

int hip_sava_init_all();

static DECLARE_LHASH_HASH_FN(hip_sava_ip_entry_hash, const hip_sava_ip_entry_t *);
static DECLARE_LHASH_COMP_FN(hip_sava_ip_entries_compare, const hip_sava_ip_entry_t *);

static DECLARE_LHASH_HASH_FN(hip_sava_hit_entry_hash, const hip_sava_ip_entry_t *);
static DECLARE_LHASH_COMP_FN(hip_sava_hit_entries_compare, const hip_sava_ip_entry_t *);

static DECLARE_LHASH_HASH_FN(hip_sava_enc_ip_entry_hash, const hip_sava_enc_ip_entry_t *);
static DECLARE_LHASH_COMP_FN(hip_sava_enc_ip_entries_compare, const hip_sava_enc_ip_entry_t *);

unsigned long hip_sava_enc_ip_entry_hash(const hip_sava_enc_ip_entry_t * entry);

int hip_sava_enc_ip_entries_compare(const hip_sava_enc_ip_entry_t * entry1,
				const hip_sava_enc_ip_entry_t * entry2);

int hip_sava_enc_ip_db_init();
int hip_sava_enc_ip_db_uninit();

hip_sava_enc_ip_entry_t * hip_sava_enc_ip_entry_find(struct in6_addr * src_enc);

int hip_sava_enc_ip_entry_add(struct in6_addr *src_enc,
			   hip_sava_ip_entry_t * ip_link,
			   hip_sava_hit_entry_t * hit_link);

int hip_sava_enc_ip_entry_delete(struct in6_addr * src_enc);

unsigned long hip_sava_hit_entry_hash(const hip_sava_hit_entry_t * entry);

int hip_sava_hit_entries_compare(const hip_sava_hit_entry_t * entry1,
				const hip_sava_hit_entry_t * entry2);

int hip_sava_hit_db_init();
int hip_sava_hit_db_uninit();

hip_sava_hit_entry_t *hip_sava_hit_entry_find(struct in6_addr * src_hit);

int hip_sava_hit_entry_add(struct in6_addr *src_hit,
			  hip_sava_ip_entry_t * link);

int hip_sava_hit_entry_delete(struct in6_addr * src_addr);

unsigned long hip_sava_ip_entry_hash(const hip_sava_ip_entry_t * entry);

int hip_sava_ip_entries_compare(const hip_sava_ip_entry_t * entry1,
				const hip_sava_ip_entry_t * entry2);

int hip_sava_ip_db_init();
int hip_sava_ip_db_uninit();

hip_sava_ip_entry_t *hip_sava_ip_entry_find(struct in6_addr * src_addr);

int hip_sava_ip_entry_add(struct in6_addr *src_addr,
			  hip_sava_hit_entry_t * link);

int hip_sava_ip_entry_delete(struct in6_addr * src_addr);

struct in6_addr * hip_sava_find_hit_by_enc(struct in6_addr * src_enc);

int hip_sava_verify_ip(struct in6_addr * enc_addr);


hip_common_t * hip_sava_get_keys_build_msg(const struct in6_addr * hit);

hip_common_t * hip_sava_make_key_request(hip_common_t *msg);

#endif //HIP_SAVA_API
