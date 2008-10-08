#include "sava_api.h"

/* database storing shortcuts to sa entries for incoming packets */
HIP_HASHTABLE *sava_ip_db = NULL;

HIP_HASHTABLE *sava_hit_db = NULL;

HIP_HASHTABLE *sava_enc_ip_db = NULL;

/* hash functions used for calculating the entries' hashes */
#define INDEX_HASH_FN		HIP_DIGEST_SHA1
/* the length of the hash value used for indexing */
#define INDEX_HASH_LENGTH	SHA_DIGEST_LENGTH

static IMPLEMENT_LHASH_HASH_FN(hip_sava_ip_entry_hash, 
			       const hip_sava_ip_entry_t *)

static IMPLEMENT_LHASH_COMP_FN(hip_sava_ip_entries_compare, 
			       const hip_sava_ip_entry_t *)

static IMPLEMENT_LHASH_HASH_FN(hip_sava_hit_entry_hash, 
			       const hip_sava_hit_entry_t *)

static IMPLEMENT_LHASH_COMP_FN(hip_sava_hit_entries_compare, 
			       const hip_sava_hit_entry_t *)

static IMPLEMENT_LHASH_HASH_FN(hip_sava_enc_ip_entry_hash, 
			       const hip_sava_enc_ip_entry_t *)

static IMPLEMENT_LHASH_COMP_FN(hip_sava_enc_ip_entries_compare, 
			       const hip_sava_enc_ip_entry_t *)

unsigned long hip_sava_enc_ip_entry_hash(const hip_sava_enc_ip_entry_t * entry) {
  unsigned char hash[INDEX_HASH_LENGTH];
  int err = 0;

  // values have to be present
  HIP_ASSERT(entry != NULL && entry->src_enc != NULL);

  memset(hash, 0, INDEX_HASH_LENGTH);

  HIP_IFEL(hip_build_digest(INDEX_HASH_FN, (void *)entry->src_enc, 
			    sizeof(struct in6_addr), hash),
	   -1, "failed to hash addresses\n");

  out_err:
  if (err) {
    *hash = 0;
  }

  return *((unsigned long *)hash);
}

int hip_sava_enc_ip_entries_compare(const hip_sava_enc_ip_entry_t * entry1,
				    const hip_sava_enc_ip_entry_t * entry2) {
    int err = 0;
  unsigned long hash1 = 0;
  unsigned long hash2 = 0;

  // values have to be present
  HIP_ASSERT(entry1 != NULL && entry1->src_enc != NULL);
  HIP_ASSERT(entry2 != NULL && entry2->src_enc != NULL);

  HIP_IFEL(!(hash1 = hip_sava_ip_entry_hash(entry1)), 
	   -1, "failed to hash sa entry\n");

  HIP_IFEL(!(hash2 = hip_sava_ip_entry_hash(entry2)), 
	   -1, "failed to hash sa entry\n");

  err = (hash1 != hash2);

  out_err:
    return err;
  return 0;
}

int hip_sava_enc_ip_db_init() {
  int err = 0;
  HIP_IFEL(!(sava_enc_ip_db = hip_ht_init(LHASH_HASH_FN(hip_sava_enc_ip_entry_hash),
	     LHASH_COMP_FN(hip_sava_enc_ip_entries_compare))), -1,
	     "failed to initialize sava_ip_db \n");
  HIP_DEBUG("sava ip db initialized\n");
 out_err:
  return err;
}
int hip_sava_enc_ip_db_uninit() {
  return 0;
}

hip_sava_enc_ip_entry_t *hip_sava_enc_ip_entry_find(struct in6_addr * src_enc) {
  hip_sava_enc_ip_entry_t *search_link = NULL, *stored_link = NULL;
  int err = 0;

  HIP_IFEL(!(search_link = 
	     (hip_sava_enc_ip_entry_t *) malloc(sizeof(hip_sava_enc_ip_entry_t))),
	     -1, "failed to allocate memory\n");
  memset(search_link, 0, sizeof(hip_sava_enc_ip_entry_t));

  // search the linkdb for the link to the corresponding entry
  search_link->src_enc = src_enc;

  HIP_DEBUG("looking up link entry with following index attributes:\n");
  HIP_DEBUG_HIT("src_enc", search_link->src_enc);

  //hip_linkdb_print();

  HIP_IFEL(!(stored_link = hip_ht_find(sava_enc_ip_db, search_link)), -1,
				"failed to retrieve link entry\n");

 out_err:
  if (err)
    stored_link = NULL;
  
  if (search_link)
    free(search_link);

  return stored_link;
}

int hip_sava_enc_ip_entry_add(struct in6_addr *src_enc,
			   hip_sava_ip_entry_t * ip_link,
			      hip_sava_hit_entry_t * hit_link) {

  hip_sava_enc_ip_entry_t  entry;

  HIP_ASSERT(src_enc != NULL);
  
  memset(&entry, 0, sizeof(hip_sava_enc_ip_entry_t));

  memcpy(&entry.src_enc, src_enc,
	 sizeof(struct in6_addr));

  entry.hit_link = hit_link;
  entry.ip_link = ip_link;

  hip_ht_add(sava_enc_ip_db, &entry);

  return 0;
}

int hip_sava_enc_ip_entry_delete(struct in6_addr * src_enc) {
  hip_sava_enc_ip_entry_t *stored_link = NULL;
  int err = 0;
  
  // find link entry and free members
  HIP_IFEL(!(stored_link = hip_sava_enc_ip_entry_find(src_enc)), -1,
	   "failed to retrieve sava enc ip entry\n");

  hip_ht_delete(sava_enc_ip_db, stored_link);
  // we still have to free the link itself
  free(stored_link);

  HIP_DEBUG("sava IP entry deleted\n");

 out_err:
  return err;
}


unsigned long hip_sava_hit_entry_hash(const hip_sava_hit_entry_t * entry) {
  unsigned char hash[INDEX_HASH_LENGTH];
  int err = 0;

  // values have to be present
  HIP_ASSERT(entry != NULL && entry->src_hit != NULL);

  memset(hash, 0, INDEX_HASH_LENGTH);

  HIP_IFEL(hip_build_digest(INDEX_HASH_FN, (void *)entry->src_hit, 
			    sizeof(struct in6_addr), hash),
	   -1, "failed to hash addresses\n");

  out_err:
  if (err) {
    *hash = 0;
  }

  
  return *((unsigned long *)hash);
}

unsigned long hip_sava_ip_entry_hash(const hip_sava_ip_entry_t * entry) {
  unsigned char hash[INDEX_HASH_LENGTH];
  int err = 0;

  // values have to be present
  HIP_ASSERT(entry != NULL && entry->src_addr != NULL);

  memset(hash, 0, INDEX_HASH_LENGTH);

  HIP_IFEL(hip_build_digest(INDEX_HASH_FN, (void *)entry->src_addr, 
			    sizeof(struct in6_addr), hash),
	   -1, "failed to hash addresses\n");

  out_err:
  if (err) {
    *hash = 0;
  }

  
  return *((unsigned long *)hash);
}

int hip_sava_ip_entries_compare(const hip_sava_ip_entry_t * entry1,
				const hip_sava_ip_entry_t * entry2) {

  int err = 0;
  unsigned long hash1 = 0;
  unsigned long hash2 = 0;

  // values have to be present
  HIP_ASSERT(entry1 != NULL && entry1->src_addr != NULL);
  HIP_ASSERT(entry2 != NULL && entry2->src_addr != NULL);

  HIP_IFEL(!(hash1 = hip_sava_ip_entry_hash(entry1)), 
	   -1, "failed to hash sa entry\n");

  HIP_IFEL(!(hash2 = hip_sava_ip_entry_hash(entry2)), 
	   -1, "failed to hash sa entry\n");

  err = (hash1 != hash2);

  out_err:
    return err;
  return 0;
}

int hip_sava_hit_entries_compare(const hip_sava_hit_entry_t * entry1,
				const hip_sava_hit_entry_t * entry2) {

  int err = 0;
  unsigned long hash1 = 0;
  unsigned long hash2 = 0;

  // values have to be present
  HIP_ASSERT(entry1 != NULL && entry1->src_hit != NULL);
  HIP_ASSERT(entry2 != NULL && entry2->src_hit != NULL);

  HIP_IFEL(!(hash1 = hip_sava_hit_entry_hash(entry1)), 
	   -1, "failed to hash sa entry\n");

  HIP_IFEL(!(hash2 = hip_sava_hit_entry_hash(entry2)), 
	   -1, "failed to hash sa entry\n");

  err = (hash1 != hash2);

  out_err:
    return err;
  return 0;
}

int hip_sava_hit_db_init() {
  int err = 0;
  HIP_IFEL(!(sava_hit_db = hip_ht_init(LHASH_HASH_FN(hip_sava_hit_entry_hash),
	     LHASH_COMP_FN(hip_sava_hit_entries_compare))), -1,
	     "failed to initialize sava_ip_db \n");
  HIP_DEBUG("sava ip db initialized\n");
 out_err:
  return err;
}

int hip_sava_ip_db_init() {
  int err = 0;
  HIP_IFEL(!(sava_ip_db = hip_ht_init(LHASH_HASH_FN(hip_sava_ip_entry_hash),
	     LHASH_COMP_FN(hip_sava_ip_entries_compare))), -1,
	     "failed to initialize sava_ip_db \n");
  HIP_DEBUG("sava ip db initialized\n");
 out_err:
  return err;
}

int hip_sava_ip_db_uninit() {
  /* TODO: check wether we need to free the db structure */
  return 0;
}

int hip_sava_hit_db_uninit() {

  return 0;
}

hip_sava_ip_entry_t *hip_sava_ip_entry_find(struct in6_addr *src_addr) {

  hip_sava_ip_entry_t *search_link = NULL, *stored_link = NULL;
  int err = 0;

  HIP_IFEL(!(search_link = 
	     (hip_sava_ip_entry_t *) malloc(sizeof(hip_sava_ip_entry_t))),
	     -1, "failed to allocate memory\n");
  memset(search_link, 0, sizeof(hip_sava_ip_entry_t));

  // search the linkdb for the link to the corresponding entry
  search_link->src_addr = src_addr;

  HIP_DEBUG("looking up link entry with following index attributes:\n");
  HIP_DEBUG_HIT("dst_addr", search_link->src_addr);

  //hip_linkdb_print();

  HIP_IFEL(!(stored_link = hip_ht_find(sava_ip_db, search_link)), -1,
				"failed to retrieve link entry\n");

 out_err:
  if (err)
    stored_link = NULL;
  
  if (search_link)
    free(search_link);

  return stored_link;
}

hip_sava_hit_entry_t *hip_sava_hit_entry_find(struct in6_addr *src_hit) {

  hip_sava_hit_entry_t *search_link = NULL, *stored_link = NULL;
  int err = 0;

  HIP_IFEL(!(search_link = 
	     (hip_sava_hit_entry_t *) malloc(sizeof(hip_sava_hit_entry_t))),
	     -1, "failed to allocate memory\n");
  memset(search_link, 0, sizeof(hip_sava_hit_entry_t));

  // search the linkdb for the link to the corresponding entry
  search_link->src_hit = src_hit;

  HIP_DEBUG("looking up link entry with following index attributes:\n");
  HIP_DEBUG_HIT("dst_addr", search_link->src_hit);

  //hip_linkdb_print();

  HIP_IFEL(!(stored_link = hip_ht_find(sava_hit_db, search_link)), -1,
				"failed to retrieve link entry\n");

 out_err:
  if (err)
    stored_link = NULL;
  
  if (search_link)
    free(search_link);

  return stored_link;
}

int hip_sava_ip_entry_add(struct in6_addr * src_addr, 
			  hip_sava_hit_entry_t * link) {
  hip_sava_ip_entry_t  entry;

  HIP_ASSERT(src_addr != NULL);
  
  memset(&entry, 0, sizeof(hip_sava_ip_entry_t));

  memcpy(&entry.src_addr, src_addr,
	 sizeof(struct in6_addr));

  entry.link = link;

  hip_ht_add(sava_ip_db, &entry);

  return 0;
}

int hip_sava_hit_entry_add(struct in6_addr * src_hit,    
			  hip_sava_ip_entry_t * link) {
  hip_sava_hit_entry_t  entry;

  HIP_ASSERT(src_hit != NULL);
  
  memset(&entry, 0, sizeof(hip_sava_hit_entry_t));

  memcpy(&entry.src_hit, src_hit,
	 sizeof(struct in6_addr));

  entry.link = link;

  hip_ht_add(sava_hit_db, &entry);

  return 0;
}

int hip_sava_ip_entry_delete(struct in6_addr * src_addr) {
  hip_sava_ip_entry_t *stored_link = NULL;
  int err = 0;
  
  // find link entry and free members
  HIP_IFEL(!(stored_link = hip_sava_ip_entry_find(src_addr)), -1,
	   "failed to retrieve sava ip entry\n");

  hip_ht_delete(sava_ip_db, stored_link);
  // we still have to free the link itself
  free(stored_link);

  HIP_DEBUG("sava IP entry deleted\n");

 out_err:
  return err;
}

int hip_sava_hit_entry_delete(struct in6_addr * src_hit) {
  hip_sava_ip_entry_t *stored_link = NULL;
  int err = 0;
  
  // find link entry and free members
  HIP_IFEL(!(stored_link = hip_sava_hit_entry_find(src_hit)), -1,
	   "failed to retrieve sava ip entry\n");

  hip_ht_delete(sava_hit_db, stored_link);
  // we still have to free the link itself
  free(stored_link);

  HIP_DEBUG("sava IP entry deleted\n");

 out_err:
  return err;
}


int hip_sava_init_all() {
  int err;
  HIP_IFEL(hip_sava_ip_db_init(), -1, "error init ip db \n");
  HIP_IFEL(hip_sava_enc_ip_db_init(), -1, "error init enc ip db \n");
  HIP_IFEL(hip_sava_hit_db_init(), -1, "error init hit db \n"); 
 out_err:
  return err;
}

struct in6_addr * hip_sava_find_hit_by_enc(struct in6_addr * src_enc) {
  hip_sava_enc_ip_entry_t * entry; 
  
  entry = hip_sava_enc_ip_entry_find(src_enc);
  
  if (entry)
    return entry->hit_link->src_hit;

  return NULL;
}

struct in6_addr * hip_sava_find_ip_by_enc(struct in6_addr * src_enc) {
  hip_sava_enc_ip_entry_t * entry; 
  
  entry = hip_sava_enc_ip_entry_find(src_enc);
  
  if (entry)
    return entry->ip_link->src_addr;

  return NULL;
}


hip_common_t * hip_sava_get_keys_build_msg(const struct in6_addr * hit) {

  int err = 0;
  hip_common_t * msg = NULL;
  HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, "malloc failed.\n");
  memset(msg, 0, HIP_MAX_PACKET);
  
  HIP_IFEL(hip_build_param_contents(msg, (void *) hit, HIP_PARAM_HIT,
				    sizeof(in6_addr_t)), -1,
	   "build param hit failed\n");
  
  HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_SAVAHR,
			      0), -1, "add peer map failed\n");
 out_err:
  return msg;

}

hip_common_t * hip_sava_make_keys_request(hip_common_t *msg) {
  if(hip_send_recv_daemon_info(msg) > 0)
    return msg;
  return NULL;
}
