#include "blind.h"

int hip_set_blind_on_sa(hip_ha_t *entry, void *not_used)
{
  int err = 0;
  
  if(entry) {
    entry->blind = 1;
  }
 out_err:
  return err;
}

int hip_set_blind_off_sa(hip_ha_t *entry, void *not_used)
{
  int err = 0;
  
  if(entry) {
    entry->blind = 0;
  }
 out_err:
  return err;
}

int hip_set_blind_on(void)
{
  int err = 0;
  
  hip_blind_status = 1;
  HIP_IFEL(hip_for_each_ha(hip_set_blind_on_sa, NULL), 0,
	   "for_each_ha err.\n");
  
 out_err:
  return err;
}

int hip_set_blind_off(void)
{
  int err = 0;
  
  hip_blind_status = 0;
  HIP_IFEL(hip_for_each_ha(hip_set_blind_off_sa, NULL), 0,
	   "for_each_ha err.\n");
  
 out_err:
  return err;
}


int hip_blind_get_status(void)
{
  return hip_blind_status;
}

struct hip_common *hip_build_blinded_i1(hip_ha_t *entry, int *mask)
{
  struct hip_common *i1;
  int err = 0;

  i1 = hip_msg_alloc();
  if(i1 == NULL) {
    HIP_ERROR("Out of memory\n");
    return NULL;
  }
  *mask |= HIP_CONTROL_BLIND;

  // Set blinded fingerprints
  err = hip_blind_fingerprints(entry);
  if(err) {
    HIP_ERROR("hip_blind_fingerprints failed\n");
    return NULL;
  }
  // Build network header by using blinded HITs
  entry->hadb_misc_func->hip_build_network_hdr(i1, HIP_I1, *mask,
					       &entry->hit_our_blind,
					       &entry->hit_peer_blind);
  HIP_DEBUG("add nonce to the message\n");
  err = hip_build_param_blind_nonce(i1, entry->blind_nonce_i);
  if(err) {
    HIP_ERROR("Unable to attach nonce to the message.\n");
    return NULL;
  }
  return i1;
}

struct hip_common *hip_build_blinded_r2(struct hip_common *r2, hip_ha_t *entry, int *mask)
{
  int err = 0;

  HIP_ASSERT(r2);
  *mask |= HIP_CONTROL_BLIND;

  HIP_DEBUG_HIT("entry->hit_our_blind", &entry->hip_our_blind);
  HIP_DEBUG_HIT("entry->hit_peer_blind", &entry->hip_peer_blind);

  // Build network header by using blinded HITs
  entry->hadb_misc_func->
    hip_build_network_hdr(r2, HIP_R2, mask, &entry->hit_our_blind,
			  &entry->hit_peer_blind);
  
  /********** HIP transform. **********/
  HIP_IFE(!(param = hip_get_param(ctx->input, HIP_PARAM_HIP_TRANSFORM)), -ENOENT);
  HIP_IFEL((transform_hip_suite =
	    hip_select_hip_transform((struct hip_hip_transform *) param)) == 0, 
	   -EINVAL, "Could not find acceptable hip transform suite\n");
  entry->hip_transform = transform_hip_suite;
  
  /************ Encrypted ***********/
  switch (transform_hip_suite) {
  case HIP_HIP_AES_SHA1:
    HIP_IFEL(hip_build_param_encrypted_aes_sha1(i2, (struct hip_tlv_common *)entry->our_pub), 
	     -1, "Building of param encrypted failed.\n");
    enc_in_msg = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
    HIP_ASSERT(enc_in_msg); /* Builder internal error. */
    iv = ((struct hip_encrypted_aes_sha1 *) enc_in_msg)->iv;
    get_random_bytes(iv, 16);
    host_id_in_enc = enc_in_msg +
      sizeof(struct hip_encrypted_aes_sha1);
    break;
  case HIP_HIP_3DES_SHA1:
    HIP_IFEL(hip_build_param_encrypted_3des_sha1(i2, (struct hip_tlv_common *)entry->our_pub), 
	     -1, "Building of param encrypted failed.\n");
    enc_in_msg = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
    HIP_ASSERT(enc_in_msg); /* Builder internal error. */
    iv = ((struct hip_encrypted_3des_sha1 *) enc_in_msg)->iv;
    get_random_bytes(iv, 8);
    host_id_in_enc = enc_in_msg +
      sizeof(struct hip_encrypted_3des_sha1);
    break;
  case HIP_HIP_NULL_SHA1:
    HIP_IFEL(hip_build_param_encrypted_null_sha1(i2, (struct hip_tlv_common *)entry->our_pub), 
	     -1, "Building of param encrypted failed.\n");
    enc_in_msg = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
    HIP_ASSERT(enc_in_msg); /* Builder internal error. */
    iv = NULL;
    host_id_in_enc = enc_in_msg +
      sizeof(struct hip_encrypted_null_sha1);
		break;
  default:
    HIP_IFEL(1, -ENOSYS, "HIP transform not supported (%d)\n",
	     transform_hip_suite);
  }
    
  HIP_DEBUG("add host id to the message nonce to the message\n");
  err = hip_build_param_blind_nonce(i1, entry->blind_nonce_i);
  if(err) {
    HIP_ERROR("Unable to attach nonce to the message.\n");
    return NULL;
  }
  return i1;
}


int hip_blind_get_nonce(struct hip_common *msg, uint16_t *msg_nonce)
{
  int err = 0;
  struct hip_blind_nonce *nonce = NULL;

  // get value of the nonce from the i1 message
  HIP_IFEL((nonce = hip_get_param(msg, HIP_PARAM_BLIND_NONCE)) == NULL, 
	   -1, "hip_get_param_nonce failed\n");
  *msg_nonce = ntohs(&nonce->nonce);
 out_err:
  return err;
}


int hip_plain_fingerprint(uint16_t *nonce, 
			  struct in6_addr *blind_hit, 
			  struct in6_addr *plain_hit)
{
  int err = 0;
    
  HIP_DEBUG("\n");
    
  HIP_IFEL(hip_blind_find_local_hi(nonce, blind_hit, plain_hit), 
	   -1, "hip_blind_find_local_hit failed\n");
  HIP_DEBUG_HIT("local hit_found", plain_hit);

 out_err:
  return err;
}

int hip_do_blind(char *key, unsigned int key_len, struct in6_addr *blind_hit) 
{
  int err = 0;
  u8 digest[HIP_AH_SHA_LEN];

  HIP_DEBUG("\n");
  
  HIP_IFEL((err = hip_build_digest(HIP_DIGEST_SHA1, key, key_len, digest)), 
	   err, "Building of digest failed\n");
  memcpy(blind_hit, digest, sizeof(struct in6_addr));  

 out_err:
  return err;
}

/* This function sets nonce and calculates the blinded 
 * fingerprints for the hip_ha_t entry.
*/
int hip_blind_fingerprints(hip_ha_t *entry)
{
  int err = 0;
  char *key_our = NULL, *key_peer = NULL;
  unsigned int key_len = sizeof(struct in6_addr);

  HIP_DEBUG("\n");
  
  // get nonce
  get_random_bytes(&entry->blind_nonce_i, sizeof(uint16_t));

  // generate key = nonce|hit_our
  HIP_IFEL((key_our = HIP_MALLOC(sizeof(uint16_t)+ sizeof(struct in6_addr), 0)) == NULL, 
	   -1, "Couldn't allocate memory\n");
  memcpy(key_our, &entry->hit_our, sizeof(struct in6_addr));
  memcpy(key_our + sizeof(struct in6_addr), &entry->blind_nonce_i, sizeof(uint16_t));
  
  // generate key = nonce|hit_peer
  HIP_IFEL((key_peer = HIP_MALLOC(sizeof(uint16_t)+ sizeof(struct in6_addr), 0)) == NULL, 
	   -1, "Couldn't allocate memory\n");
  memcpy(key_peer, &entry->hit_peer, sizeof(struct in6_addr));
  memcpy(key_peer + sizeof(struct in6_addr), &entry->blind_nonce_i, sizeof(uint16_t));
  
  // build digests
  HIP_IFEL((err = hip_do_blind(key_our, key_len, &entry->hit_our_blind)), 
	   err, "Building of digest failed\n");
  HIP_IFEL((err = hip_do_blind(key_peer, key_len, &entry->hit_peer_blind)), 
	   err, "Building of digest failed\n");

 out_err:
  return err;
}
/* Tests if @plain_hit blinded with nonce is same as @blind_hit*/
int hip_blind_verify(uint16_t *nonce, struct in6_addr *plain_hit, struct in6_addr *blind_hit)
{
  int ret = 0;
  char *key = NULL;
  unsigned int key_len = sizeof(struct in6_addr);
  struct in6_addr *test_hit = NULL;

  HIP_DEBUG("\n");
  
  test_hit = HIP_MALLOC(sizeof(struct in6_addr), 0);
  if (test_hit == NULL) {
    HIP_ERROR("Couldn't allocate memory\n");
    ret = -1;
    goto out_err;
  }

  // generate key = nonce|hit_our
  key = HIP_MALLOC(sizeof(uint16_t)+ sizeof(struct in6_addr), 0); 
  if (key == NULL) { 
     HIP_ERROR("Couldn't allocate memory\n");
     ret = -1;
     goto out_err;
  }
  
  memcpy(key, plain_hit, sizeof(struct in6_addr));
  memcpy(key + sizeof(struct in6_addr), nonce, sizeof(uint16_t));
  
  // build digests
  ret = hip_do_blind(key, key_len, test_hit);
  if (ret == -1) {
    HIP_ERROR("Building of digest failed\n");
    goto out_err;
  } 
  HIP_DEBUG_HIT("test_hit", test_hit);
  HIP_DEBUG_HIT("blind_hit", blind_hit);
  ret = ipv6_addr_cmp(test_hit, blind_hit);//memcmp return 0 if equal
 
 out_err: 
  if (test_hit)
    HIP_FREE(test_hit);
  return (ret == 0);
}
