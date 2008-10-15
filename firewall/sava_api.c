#include "sava_api.h"



/* database storing shortcuts to sa entries for incoming packets */
HIP_HASHTABLE *sava_ip_db = NULL;

HIP_HASHTABLE *sava_hit_db = NULL;

HIP_HASHTABLE *sava_enc_ip_db = NULL;

HIP_HASHTABLE *sava_conn_db = NULL;

int ipv6_raw_sock = 0;
int ipv4_raw_sock = 0;

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

static IMPLEMENT_LHASH_HASH_FN(hip_sava_conn_entry_hash, 
			       const hip_sava_conn_entry_t *)

static IMPLEMENT_LHASH_COMP_FN(hip_sava_conn_entries_compare, 
			       const hip_sava_conn_entry_t *)

unsigned long hip_sava_conn_entry_hash(const hip_sava_conn_entry_t * entry) {
  unsigned char hash[INDEX_HASH_LENGTH];
  struct in6_addr addrs[2];
  int err = 0;
  
  // values have to be present
  HIP_ASSERT(entry != NULL && entry->src != NULL && entry->dst);

  memcpy(&addrs[0], entry->src, sizeof(struct in6_addr));
  memcpy(&addrs[1], entry->dst, sizeof(struct in6_addr));
  
  memset(hash, 0, INDEX_HASH_LENGTH);

  HIP_IFEL(hip_build_digest(INDEX_HASH_FN, (void *)addrs, 
			    sizeof(addrs), hash),
	   -1, "failed to hash addresses\n");
  
 out_err:
  if (err) {
    *hash = 0;
  }

  return *((unsigned long *)hash);
}

int hip_sava_conn_entries_compare(const hip_sava_conn_entry_t * entry1,
				  const hip_sava_conn_entry_t * entry2) {
  int err = 0;
  unsigned long hash1 = 0;
  unsigned long hash2 = 0;

  // values have to be present
  HIP_ASSERT(entry1 != NULL && entry1->src != NULL && entry1->dst != NULL);
  HIP_ASSERT(entry2 != NULL && entry2->src != NULL && entry2->dst != NULL);

  HIP_IFEL(!(hash1 = hip_sava_conn_entry_hash(entry1)), 
	   -1, "failed to hash sa entry\n");

  HIP_IFEL(!(hash2 = hip_sava_conn_entry_hash(entry2)), 
	   -1, "failed to hash sa entry\n");

  err = (hash1 != hash2);

  out_err:
    return err;
  return 0;
}

int hip_sava_conn_db_init() {
  int err = 0;
  HIP_IFEL(!(sava_conn_db = hip_ht_init(LHASH_HASH_FN(hip_sava_conn_entry_hash),
	     LHASH_COMP_FN(hip_sava_conn_entries_compare))), -1,
	     "failed to initialize sava_ip_db \n");
  HIP_DEBUG("sava ip db initialized\n");
 out_err:
  return err;
}

int hip_sava_conn_db_uninit() {
  return 0;
}

hip_sava_conn_entry_t * hip_sava_conn_entry_find(struct in6_addr * src,
						 struct in6_addr * dst) {
  hip_sava_conn_entry_t *search_link = NULL, *stored_link = NULL;
  int err = 0;

  HIP_IFEL(!(search_link = 
	     (hip_sava_conn_entry_t *) malloc(sizeof(hip_sava_conn_entry_t))),
	     -1, "failed to allocate memory\n");
  memset(search_link, 0, sizeof(hip_sava_conn_entry_t));

  // search the linkdb for the link to the corresponding entry
  search_link->src = src;
  search_link->dst = dst;

  HIP_DEBUG("looking up link entry with following index attributes:\n");
  HIP_DEBUG_HIT("src", search_link->src);
  HIP_DEBUG_HIT("dst", search_link->dst);

  HIP_IFEL(!(stored_link = hip_ht_find(sava_conn_db, search_link)), -1,
				"failed to retrieve link entry\n");

 out_err:
  if (err)
    stored_link = NULL;
  
  if (search_link)
    free(search_link);

  return stored_link;
}

int hip_sava_conn_entry_add(struct in6_addr *src,
			    struct in6_addr * dst) {
  hip_sava_conn_entry_t *  entry = malloc(sizeof(hip_sava_conn_entry_t));

  HIP_ASSERT(src != NULL && dst != NULL);
  
  memset(entry, 0, sizeof(hip_sava_conn_entry_t));
  
  entry->src = 
    (struct in6_addr *) malloc(sizeof(struct in6_addr));
  entry->dst = 
    (struct in6_addr *) malloc(sizeof(struct in6_addr));
  
  memcpy(entry->src, src,
  	 sizeof(struct in6_addr));
  
  memcpy(entry->dst, dst,
  	 sizeof(struct in6_addr));

  hip_ht_add(sava_conn_db, entry);

  return 0;
}

int hip_sava_conn_entry_delete(struct in6_addr * src,
			       struct in6_addr * dst) {
  hip_sava_conn_entry_t *stored_link = NULL;
  int err = 0;
  
  // find link entry and free members
  HIP_IFEL(!(stored_link = hip_sava_conn_entry_find(src, dst)), -1,
	   "failed to retrieve sava enc ip entry\n");

  hip_ht_delete(sava_conn_db, stored_link);
  // we still have to free the link itself
  free(stored_link);

 out_err:
  return err;
  return 0;
}

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
			      hip_sava_hit_entry_t * hit_link,
			      hip_sava_peer_info_t * info_link) {

  hip_sava_enc_ip_entry_t  * entry = (hip_sava_enc_ip_entry_t *)
    malloc(sizeof(hip_sava_enc_ip_entry_t));
  
  HIP_ASSERT(src_enc != NULL);
  
  memset(entry, 0, sizeof(hip_sava_enc_ip_entry_t));

  entry->src_enc =  (struct in6_addr *) malloc(sizeof(struct in6_addr));

  memcpy(entry->src_enc, src_enc,
	 sizeof(struct in6_addr));

  entry->hit_link = hit_link;

  entry->ip_link = ip_link;

  entry->peer_info = info_link;

  hip_ht_add(sava_enc_ip_db, entry);

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
  
  /* memcpy(search_link->src_addr, 
	 src_addr, 
	 sizeof(struct in6_addr));*/

  HIP_DEBUG("looking up link entry with following index attributes:\n");
  HIP_DEBUG_HIT("src_addr", search_link->src_addr);

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
  hip_sava_ip_entry_t *  entry = malloc(sizeof(hip_sava_ip_entry_t));

  HIP_ASSERT(src_addr != NULL);
  
  memset(entry, 0, sizeof(hip_sava_ip_entry_t));
  
  entry->src_addr = 
    (struct in6_addr *) malloc(sizeof(struct in6_addr));
  
  memcpy(entry->src_addr, src_addr,
  	 sizeof(struct in6_addr));
 
  entry->link = link;
  
  hip_ht_add(sava_ip_db, entry);

  return 0;
}

int hip_sava_hit_entry_add(struct in6_addr * src_hit,    
			  hip_sava_ip_entry_t * link) {
  hip_sava_hit_entry_t * entry = malloc(sizeof(hip_sava_hit_entry_t));

  HIP_ASSERT(src_hit != NULL);
  
  memset(entry, 0, sizeof(hip_sava_hit_entry_t));

  entry->src_hit =  (struct in6_addr *) malloc(sizeof(struct in6_addr));
  
  memcpy(entry->src_hit, src_hit,
	 sizeof(struct in6_addr));

  entry->link = link;

  hip_ht_add(sava_hit_db, entry);

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
  int err = 0;
  HIP_IFEL(hip_sava_ip_db_init(), -1, "error init ip db \n");
  HIP_IFEL(hip_sava_enc_ip_db_init(), -1, "error init enc ip db \n");
  HIP_IFEL(hip_sava_hit_db_init(), -1, "error init hit db \n"); 
  HIP_IFEL(hip_sava_conn_db_init(), -1, "error init sava conn db \n");
  HIP_IFEL(hip_sava_init_ip6_raw_socket(&ipv6_raw_sock), -1, "error creating raw IPv6 socket \n");
  HIP_IFEL(hip_sava_init_ip4_raw_socket(&ipv4_raw_sock), -1, "error creating raw IPv4 socket \n");

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
  return NULL;
}

hip_common_t * hip_sava_make_keys_request(const struct in6_addr * hit, 
					  int direction) {
  int err = 0;
  hip_common_t * msg = NULL;
  HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, "malloc failed.\n");
  memset(msg, 0, HIP_MAX_PACKET);
  
  HIP_IFEL(hip_build_param_contents(msg, (void *) hit, HIP_PARAM_HIT,
				    sizeof(in6_addr_t)), -1,
	   "build param hit failed\n");
  if (direction == SAVA_INBOUND_KEY) {
    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_SAVAHR_IN_KEYS,
				0), -1, "Failed to buid user header\n");
  }else {
    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_SAVAHR_OUT_KEYS,
				0), -1, "Failed to buid user header\n");
  }

  if(hip_send_recv_daemon_info(msg) == 0)
    return msg;

 out_err:
  return NULL;
}

hip_common_t * hip_sava_make_hit_request() {
  int err = 0;
  hip_common_t * msg = NULL;
  HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, "malloc failed.\n");
  memset(msg, 0, HIP_MAX_PACKET);
  
  HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_SAVAHR_HIT,
			      0), -1, "Failed to buid user header\n");

  if(hip_send_recv_daemon_info(msg) == 0)
    return msg;

 out_err:
  return NULL;
}



hip_sava_peer_info_t * hip_sava_get_key_params(hip_common_t * msg) {
  hip_sava_peer_info_t * peer_info;

  struct hip_tlv_common *param = NULL;

  int ealg = 0, err = 0;

  struct hip_crypto_key *auth_key = NULL;
  
  peer_info = (hip_sava_peer_info_t *)malloc(sizeof(hip_sava_peer_info_t));
  
  memset (peer_info, 0, sizeof(hip_sava_peer_info_t));
  
  param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_KEYS);

  auth_key = (struct hip_crypto_key *) hip_get_param_contents_direct(param);

  if (auth_key == NULL)
    return NULL;
  HIP_HEXDUMP("crypto key:", auth_key, sizeof(struct hip_crypto_key));
  
  param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_INT);
  ealg = *((int *) hip_get_param_contents_direct(param));
  HIP_DEBUG("ealg value is %d \n", ealg);

  peer_info->ip_enc_key = auth_key;
  peer_info->ealg = ealg;
    
  return peer_info;
}

struct in6_addr * hip_sava_auth_ip(struct in6_addr * orig_addr, 
				      hip_sava_peer_info_t * info_entry) {

  int err = 0;
  struct in6_addr enc_addr;
  char out[EVP_MAX_MD_SIZE];
  int out_len;
  char in_len = sizeof(struct in6_addr);

  memset(&enc_addr, 0, sizeof(struct in6_addr));
  
  switch(info_entry->ealg) {
  case HIP_ESP_3DES_MD5:
    // same authentication chiper as next transform
  case HIP_ESP_NULL_MD5:
    if (!info_entry->ip_enc_key) {
      HIP_ERROR("authentication keys missing\n");
      err = -1;
      goto out_err;
    }
    HMAC(EVP_md5(), info_entry->ip_enc_key,
	 hip_auth_key_length_esp(info_entry->ealg),
	 (void *)orig_addr, in_len, out, &out_len);
    HIP_DEBUG("alen: %i \n", out_len);
    break;
  case HIP_ESP_3DES_SHA1:
  case HIP_ESP_NULL_SHA1:
  case HIP_ESP_AES_SHA1:
    if (!info_entry->ip_enc_key) {
      HIP_ERROR("authentication keys missing\n");
      
      err = -1;
      goto out_err;
    }
    
    HMAC(EVP_sha1(), info_entry->ip_enc_key,
	 hip_auth_key_length_esp(info_entry->ealg),
	 (void *)orig_addr, in_len, out, &out_len);
    
    HIP_DEBUG("alen: %i \n", out_len);
    
    break;
  default:
    HIP_DEBUG("Unsupported authentication algorithm: %i\n", info_entry->ealg);
    err = -1;
    goto out_err;
  }
  if (out_len > 0) {
    memset (&enc_addr, 0, in_len);
    memcpy(&enc_addr, out, (out_len < in_len ? out_len : in_len));
    return &enc_addr;
  } else {
    goto out_err;
  }
 out_err:
  return NULL;
}

int hip_sava_handle_output (struct hip_fw_context *ctx) {
  int verdict = DROP;
  int err = 0, sent = 0;
  struct hip_common * msg = NULL;
  struct in6_addr * sava_hit;
  struct hip_sava_peer_info * info_entry;
  
  struct ip6_hdr * ip6hdr= NULL;	
  struct ip * iphdr= NULL;

  struct in6_addr * enc_addr = NULL;

  struct sockaddr_storage dst;

  struct sockaddr_in *dst4 = (struct sockaddr_in *)&dst;

  struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)&dst;


  memset(&dst, 0, sizeof(struct sockaddr_storage));

  HIP_IFEL((msg = hip_sava_make_hit_request()) == NULL, DROP,
	   "HIT request from daemon failed \n");
  
  HIP_IFEL((sava_hit = hip_get_param_contents(msg,HIP_PARAM_HIT)) == NULL, DROP,
	   "Failed to get SAVA HIT from the daemon \n");
  
  HIP_IFEL((msg = hip_sava_make_keys_request(sava_hit, SAVA_OUTBOUND_KEY)) == NULL, DROP,
	   "Key request from daemon failed \n");
  
  HIP_DEBUG("Secret key acquired. Lets encrypt the src IP address \n");
  
  HIP_IFEL((info_entry = hip_sava_get_key_params(msg)) == NULL, DROP,
	   "Error parsing user message");

  enc_addr = hip_sava_auth_ip(&ctx->src, info_entry);

  if (ctx->ip_version == 6) { //IPv6
    
    ip6hdr = (struct ip6_hdr*) ctx->ipq_packet->payload;

    memcpy(&ip6hdr->ip6_src, (void *)enc_addr, sizeof(struct in6_addr));

    dst6->sin6_family = AF_INET6;

    memcpy(&dst6->sin6_addr, &ctx->src, sizeof(struct in6_addr));

    sent = sendto(ipv6_raw_sock, ip6hdr, ctx->ipq_packet->data_len, 0,
		  (struct sockaddr *) &dst, sizeof(struct sockaddr_in6));

  }else { //IPv4
    iphdr = (struct ip *) ctx->ipq_packet->payload;
    //    memcpy(&iphdr->ip_src, (void *)enc_addr, sizeof(struct in_addr));
    IPV6_TO_IPV4_MAP(enc_addr, &iphdr->ip_src);
    iphdr->ip_sum = 0;
    IPV6_TO_IPV4_MAP(&ctx->dst, &dst4->sin_addr);
    dst4->sin_family = AF_INET;
    HIP_DEBUG_INADDR("dst4", &dst4->sin_addr);
    sent = sendto(ipv4_raw_sock, iphdr, ctx->ipq_packet->data_len, 0,
		  (struct sockaddr *) &dst, sizeof(struct sockaddr_in));
  }

  if (sent != ctx->ipq_packet->data_len) {
    HIP_ERROR("Could not send the all requested"			\
	      " data (%d/%d)\n", sent, ctx->ipq_packet->data_len);
    HIP_DEBUG("ERROR NUMBER: %d\n", errno);
  } else {
    HIP_DEBUG("sent=%d/%d \n",
	      sent, ctx->ipq_packet->data_len);
    HIP_DEBUG("Packet sent ok\n");
  }

 out_err:
  return verdict; 
}

int hip_sava_handle_router_forward(struct hip_fw_context *ctx) {
  int err = 0, verdict = 0, auth_len = 0, sent = 0;
  struct in6_addr * enc_addr = NULL;
  hip_sava_ip_entry_t  * ip_entry     = NULL;
  hip_sava_enc_ip_entry_t * enc_entry = NULL;
  struct sockaddr_storage dst;
  struct sockaddr_in *dst4 = (struct sockaddr_in *)&dst;
  struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)&dst;

  struct ip6_hdr * ip6hdr= NULL;	
  struct ip * iphdr= NULL;

  memset(&dst, 0, sizeof(struct sockaddr_storage));

  HIP_DEBUG("CHECK IP ON FORWARD\n");
  if (hip_sava_conn_entry_find(&ctx->src, &ctx->dst) != NULL) {
    HIP_DEBUG("BYPASS THE PACKET THIS IS AN INBOUND TRAFFIC FOR AUTHENTICATED OUTBOUND \n");
    verdict = ACCEPT;
    goto out_err;
  }
  HIP_DEBUG("NOT AN INBOUND TRAFFIC OR NOT AUTHENTICATED TRAFFIC \n");
  HIP_DEBUG("Authenticating source address \n");
  
  enc_entry = hip_sava_enc_ip_entry_find(&ctx->src);

  auth_len = (ctx->ip_version == 6) ? sizeof(struct in6_addr): sizeof(struct in_addr);
  
  if (enc_entry) {
    HIP_DEBUG("ENCRYPTED ENTRY FOUND \n");
    HIP_DEBUG("Secret key acquired. Lets encrypt the src IP address \n");
    
    enc_addr = hip_sava_auth_ip(enc_entry->ip_link->src_addr, enc_entry->peer_info);
    
    if (!memcmp(&ctx->src, enc_addr, auth_len)) {
      //PLACE ORIGINAL IP, RECALCULATE CHECKSUM AND REINJECT THE PACKET 
      //VERDICT DROP PACKET BECAUSE IT CONTAINS ENCRYPTED IP
      //ONLY NEW PACKET WILL GO OUT
      HIP_DEBUG("Adding <src, dst> tuple to connection db \n");
      hip_sava_conn_entry_add(enc_entry->ip_link->src_addr, &ctx->dst);
      HIP_DEBUG("Source address is authenticated \n");
      HIP_DEBUG("Reinject the traffic to network stack \n");
      if (ctx->ip_version == 6) { //IPv6
    	ip6hdr = (struct ip6_hdr*) ctx->ipq_packet->payload;
	memcpy(&ip6hdr->ip6_src, (void *)enc_entry->ip_link->src_addr, sizeof(struct in6_addr));
	dst6->sin6_family = AF_INET6;
	memcpy(&dst6->sin6_addr, &ctx->src, sizeof(struct in6_addr));
	sent = sendto(ipv6_raw_sock, ip6hdr, ctx->ipq_packet->data_len, 0,
		      (struct sockaddr *) &dst, sizeof(struct sockaddr_in6));
      }else { //IPv4
	iphdr = (struct ip *) ctx->ipq_packet->payload;
	IPV6_TO_IPV4_MAP(enc_entry->ip_link->src_addr, &iphdr->ip_src);
	iphdr->ip_sum = 0;
	IPV6_TO_IPV4_MAP(&ctx->dst, &dst4->sin_addr);
	dst4->sin_family = AF_INET;
	HIP_DEBUG_INADDR("dst4", &dst4->sin_addr);
	sent = sendto(ipv4_raw_sock, iphdr, ctx->ipq_packet->data_len, 0,
		      (struct sockaddr *) &dst, sizeof(struct sockaddr_in));
      }
    } else {
      HIP_DEBUG("Source address authentication failed. Dropping packet \n");
      verdict = DROP;
      goto out_err;
    }

    
  } else {
    HIP_DEBUG("Source address authentication failed \n");
    verdict = DROP;
    goto out_err;
  }
 out_err:
  return verdict;
}


int hip_sava_init_ip4_raw_socket(int * ip4_raw_socket) {
  int on = 1, err = 0;
  int off = 0;
  
  *ip4_raw_socket = socket(AF_INET, SOCK_RAW, 0);
  HIP_IFEL(*ip4_raw_socket <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

  /* see bug id 212 why RECV_ERR is off */
  err = setsockopt(*ip4_raw_socket, IPPROTO_IP, IP_RECVERR, &off, sizeof(on));
  HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
  err = setsockopt(*ip4_raw_socket, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
  HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
  err = setsockopt(*ip4_raw_socket, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
  HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
  err = setsockopt(*ip4_raw_socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");
  
 out_err:
  return err;
}

int hip_sava_init_ip6_raw_socket(int * ip6_raw_socket) {
  int on = 1, err = 0;
  int off = 0;
  
  *ip6_raw_socket = socket(AF_INET6, SOCK_RAW, 0);
  HIP_IFEL(*ip6_raw_socket <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

  /* see bug id 212 why RECV_ERR is off */
  err = setsockopt(*ip6_raw_socket, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(on));
  HIP_IFEL(err, -1, "setsockopt v6 recverr failed\n");
  err = setsockopt(*ip6_raw_socket, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
  HIP_IFEL(err, -1, "setsockopt v6 pktinfo failed\n");
  err = setsockopt(*ip6_raw_socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");
  
 out_err:
  return err;
}
