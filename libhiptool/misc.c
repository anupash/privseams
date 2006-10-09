/*
 * Miscellaneous functions
 *
 * Licence: GNU/GPL
 * Authors:
 * - Miika Komu <miika@iki.fi>
 * - Mika Kousa <mkousa@cc.hut.fi>
 * - Bing Zhou <bingzhou@cc.hut.fi>
 */

#include "misc.h"
#ifdef CONFIG_HIP_OPPORTUNISTIC
int hip_opportunistic_ipv6_to_hit(const struct in6_addr *ip, struct in6_addr *hit, int hit_type)
{
  int err = 0;
  u8 digest[HIP_AH_SHA_LEN];
  char *key = (char *) (ip);
  unsigned int key_len = sizeof(struct in6_addr);

  HIP_IFE(hit_type != HIP_HIT_TYPE_HASH100, -ENOSYS);
  _HIP_HEXDUMP("key", key, key_len);
  HIP_IFEL((err = hip_build_digest(HIP_DIGEST_SHA1, key, key_len, digest)), err, 
	   "Building of digest failed\n");
  
  memcpy(hit, digest + (HIP_AH_SHA_LEN - sizeof(struct in6_addr)),
	 sizeof(struct in6_addr));

  hit->s6_addr32[3] = 0; // this separates phit from normal hit

  set_hit_prefix(hit);
  
 out_err:
  
       return err;
}
#endif //CONFIG_HIP_OPPORTUNISTIC

#ifdef CONFIG_HIP_BLIND
int hip_do_blind(char *key, unsigned int key_len, struct in6_addr *blind_hit) 
{
  int err = 0;
  u8 digest[HIP_AH_SHA_LEN];
  
  HIP_IFEL((err = hip_build_digest(HIP_DIGEST_SHA1, key, key_len, digest)), 
	   err, "Building of digest failed\n");
  memcpy(blind_hit, digest, sizeof(struct in6_addr));  

 out_err:
  return err;
}

/*This function calcutates blinded fingerprints*/
int hip_blind_fingerprints(hip_ha_t *entry)
{
  int err = 0;
  char *key_our = NULL, *key_peer = NULL;
  unsigned int key_len = sizeof(struct in6_addr);

  // get nonce
  get_random_bytes(&entry->blind_nonce_i, sizeof(uint16_t));

  // generate key = nonce|hit_our)
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

int hip_plain_fingerprints(struct hip_common *msg, hip_ha_t *entry, struct hip_db_struct *db)
{
  int err = 0;
  struct hip_blind_nonce *nonce = NULL;
  struct list_head *curr, *iter;
  struct hip_host_id_entry *tmp;
  struct endpoint_hip *hits = NULL;
  char *key = NULL;
  unsigned int key_len = sizeof(struct in6_addr);
  struct in6_addr *blind_hit = NULL;
  //struct hip_db_struct *db = HIP_DB_LOCAL_HID;


  // get value of the nonce from the i1 message
  HIP_IFEL(!(nonce = hip_get_param(msg, HIP_PARAM_BLIND_NONCE)), 
	   -1, "hip_get_param_nonce failed\n");
  
  // generate key = nonce|hit_our)
  HIP_IFEL((key = HIP_MALLOC(sizeof(uint16_t)+ sizeof(struct in6_addr), 0)) == NULL, 
	   -1, "Couldn't allocate memory\n");
 
  HIP_READ_LOCK_DB(db);
  
  // iterate the hidb through the find the local plain hit
  list_for_each_safe(curr, iter, &db->db_head)
    {
      tmp = list_entry(curr,struct hip_host_id_entry,next);
      HIP_HEXDUMP("Found HIT:", &tmp->lhi.hit, 16);
  
      // let's test the hit
      memcpy(key, &tmp->lhi.hit, sizeof(struct in6_addr));
      memcpy(key + sizeof(struct in6_addr), &nonce->nonce, sizeof(uint16_t));
      HIP_IFEL(hip_do_blind(key, key_len, blind_hit), -1, "hip_do_blind failed \n");
      if (blind_hit == NULL) {
	err = -1;
	goto out_err;
      }
      HIP_HEXDUMP("Test blind HIT:", blind_hit, 16);
      if (hip_match_hit(&msg->hitr, blind_hit)) {
	HIP_HEXDUMP("Plain HIT found:", &tmp->lhi.hit, 16);
      }
    }
  
  HIP_READ_UNLOCK_DB(db);

out_err:
	return err;
}
#endif

/** hip_timeval_diff - calculate difference between two timevalues
 * @param t1 timevalue 1
 * @param t2 timevalue 2
 * @param result where the result is stored
 *
 * ** CHECK comments **
 * result = t1 - t2
 *
 * Code taken from http://www.gnu.org/manual/glibc-2.2.5/html_node/Elapsed-Time.html
 *
 * @return 1 if t1 is equal or later than t2, else 0.
 */
int hip_timeval_diff(const struct timeval *t1, const struct timeval *t2,
		     struct timeval *result)
{
	struct timeval _t1, _t2;
	_t1 = *t1;
	_t2 = *t2;

	if (_t1.tv_usec < _t2.tv_usec) {
		int nsec = (_t2.tv_usec - _t1.tv_usec) / 1000000 + 1;
		_t2.tv_usec -= 1000000 * nsec;
		_t2.tv_sec += nsec;
	}
	if (_t1.tv_usec - _t2.tv_usec > 1000000) {
		int nsec = (_t1.tv_usec - _t2.tv_usec) / 1000000;
		_t2.tv_usec += 1000000 * nsec;
		_t2.tv_sec -= nsec;
	}

	result->tv_sec = _t1.tv_sec - _t2.tv_sec;
	result->tv_usec = _t1.tv_usec - _t2.tv_usec;

	return _t1.tv_sec >= _t2.tv_sec;
}

char *hip_convert_hit_to_str(const hip_hit_t *local_hit, const char *prefix)
{
	int err = 0;
	char *hit_str = NULL;
	/* aaaa:bbbb:cccc:dddd:eeee:ffff:gggg:eeee/128\0  */
	const int max_str_len = INET6_ADDRSTRLEN + 5;

	HIP_IFE((!(hit_str = HIP_MALLOC(max_str_len, 0))), -1);
	memset(hit_str, 0, max_str_len);
	hip_in6_ntop(local_hit, hit_str);

	if (prefix)
		memcpy(hit_str + strlen(hit_str), prefix, strlen(prefix));


 out_err:

	if (err && hit_str) {
		HIP_FREE(hit_str);
		hit_str = NULL;
	}
	
	return hit_str;
}

/*
 * function maxof()
 *
 * in:          num_args = number of items
 *              ... = list of integers
 * out:         Returns the integer with the largest value from the
 *              list provided.
 */
int maxof(int num_args, ...)
{
        int max, i, a;
        va_list ap;

        va_start(ap, num_args);
        max = va_arg(ap, int);
        for (i = 2; i <= num_args; i++) {
                if ((a = va_arg(ap, int)) > max)
                        max = a;
        }
        va_end(ap);
        return(max);
}


/**
 * hip_hit_is_bigger - compare two HITs
 * @param hit1 the first HIT to be compared
 * @param hit2 the second HIT to be compared
 *
 * @return 1 if hit1 was bigger than hit2, or else 0
 */
int hip_hit_is_bigger(const struct in6_addr *hit1,
		      const struct in6_addr *hit2)
{
	return (ipv6_addr_cmp(hit1, hit2) > 0);
}


char* hip_in6_ntop(const struct in6_addr *in6, char *buf)
{
        if (!buf)
                return NULL;
        sprintf(buf,
                "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
                ntohs(in6->s6_addr16[0]), ntohs(in6->s6_addr16[1]),
                ntohs(in6->s6_addr16[2]), ntohs(in6->s6_addr16[3]),
                ntohs(in6->s6_addr16[4]), ntohs(in6->s6_addr16[5]),
                ntohs(in6->s6_addr16[6]), ntohs(in6->s6_addr16[7]));
        return buf;
}

int hip_in6_ntop2(const struct in6_addr *in6, char *buf)
{
	if (!buf)
		return 0;
	return sprintf(buf,
		       "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
		       ntohs(in6->s6_addr16[0]), ntohs(in6->s6_addr16[1]),
		       ntohs(in6->s6_addr16[2]), ntohs(in6->s6_addr16[3]),
		       ntohs(in6->s6_addr16[4]), ntohs(in6->s6_addr16[5]),
		       ntohs(in6->s6_addr16[6]), ntohs(in6->s6_addr16[7]));
}

void hip_xor_hits(hip_hit_t *res, const hip_hit_t *hit1, const hip_hit_t *hit2)
{
	res->s6_addr32[0] = hit1->s6_addr32[0] ^ hit2->s6_addr32[0];
	res->s6_addr32[1] = hit1->s6_addr32[1] ^ hit2->s6_addr32[1];
	res->s6_addr32[2] = hit1->s6_addr32[2] ^ hit2->s6_addr32[2];
	res->s6_addr32[3] = hit1->s6_addr32[3] ^ hit2->s6_addr32[3];
}

/**
 * hip_hash_spi - calculate a hash from SPI value
 * @param key 32-bit SPI value
 * @param range range of the hash
 *
 * Returns value in range: 0 <= x < range
 */
int hip_hash_spi(const void *key, int range)
{
	u32 spi = (u32) key;
	/* SPIs are random, so simple modulo is enough? */
	return spi % range;
}

/**
 * hip_hash_hit - calculate a hash from a HIT
 * @param key pointer to a HIT
 * @param range range of the hash
 *
 * Returns value in range: 0 <= x < range
 */
int hip_hash_hit(const void *key, int range)
{
	hip_hit_t *hit = (hip_hit_t *)key;

	/* HITs are random. (at least the 64 LSBs)  */
	return (hit->s6_addr32[2] ^ hit->s6_addr32[3]) % range;
}

int hip_match_hit(const void *hitA, const void *hitB)
{
	hip_hit_t *key_1, *key_2;

	key_1 = (hip_hit_t *)hitA;
	key_2 = (hip_hit_t *)hitB;

	return !ipv6_addr_cmp(key_1, key_2);
}

const char *hip_algorithm_to_string(int algo) 
{
	const char *str = "UNKNOWN";
	static const char *algos[] = { "DSA", "RSA" };
	if(algo == HIP_HI_DSA)
		str = algos[0];
	else if(algo == HIP_HI_RSA)
		str = algos[1];
	return str;
}

/**
 * hip_birthday_success - compare two birthday counters
 * @param old_bd birthday counter
 * @param new_bd birthday counter used when comparing against old_bd
 *
 * @return 1 (true) if new_bd is newer than old_bd, 0 (false) otherwise.
 */
int hip_birthday_success(uint64_t old_bd, uint64_t new_bd)
{
	return new_bd > old_bd;
}


/**
 * hip_enc_key_length - get encryption key length of a transform
 * @param tid transform
 *
 * @return the encryption key length based on the chosen transform,
 * otherwise < 0 on error.
 */
int hip_enc_key_length(int tid)
{
	int ret = -1;

	switch(tid) {
	case HIP_ESP_AES_SHA1:
		ret = 16;
		break;
	case HIP_ESP_3DES_SHA1:
		ret = 24;
		break;
	case HIP_ESP_NULL_SHA1:
	case HIP_ESP_NULL_NULL:
		ret = 0;
		break;
	default:
		HIP_ERROR("unknown tid=%d\n", tid);
		HIP_ASSERT(0);
		break;
	}

	return ret;
}


int hip_hmac_key_length(int tid)
{
	int ret = -1;
	switch(tid) {
       	case HIP_ESP_AES_SHA1:
	case HIP_ESP_3DES_SHA1:
	case HIP_ESP_NULL_SHA1:
		ret = 20;
		break;
	case HIP_ESP_NULL_NULL:
		ret = 0;
		break;
	default:
		HIP_ERROR("unknown tid=%d\n", tid);
		HIP_ASSERT(0);
		break;
	}

	return ret;
}

/**
 * hip_transform_key_length - get transform key length of a transform
 * @param tid transform
 *
 * @return the transform key length based on the chosen transform,
 * otherwise < 0 on error.
 */
int hip_transform_key_length(int tid)
{
	int ret = -1;

	switch(tid) {
	case HIP_HIP_AES_SHA1:
		ret = 16;
		break;
	case HIP_HIP_3DES_SHA1:
		ret = 24;
		break;
	case HIP_HIP_NULL_SHA1: // XX FIXME: SHOULD BE NULL_SHA1? 
		ret = 0;
		break;
	default:
		HIP_ERROR("unknown tid=%d\n", tid);
		HIP_ASSERT(0);
		break;
	}

	return ret;
}


/**
 * hip_auth_key_length_esp - get authentication key length of a transform
 * @param tid transform
 *
 * @return the authentication key length based on the chosen transform.
 * otherwise < 0 on error.
 */
int hip_auth_key_length_esp(int tid)
{
	int ret = -1;

	switch(tid) {
	case HIP_ESP_AES_SHA1:
		//ret = 16;
		//break;
	case HIP_ESP_NULL_SHA1:
	case HIP_ESP_3DES_SHA1:
		ret = 20;
		break;
	case HIP_ESP_NULL_NULL:
		ret = 0;
		break;
	default:
		HIP_ERROR("unknown tid=%d\n", tid);
		HIP_ASSERT(0);
		break;
	}

	return ret;
}

/**
 * hip_select_hip_transform - select a HIP transform to use
 * @param ht HIP_TRANSFORM payload where the transform is selected from
 *
 * @return the first acceptable Transform-ID, otherwise < 0 if no
 * acceptable transform was found. The return value is in host byte order.
 */
hip_transform_suite_t hip_select_hip_transform(struct hip_hip_transform *ht)
{
	hip_transform_suite_t tid = 0;
	int i;
	int length;
	hip_transform_suite_t *suggestion;

	length = ntohs(ht->length);
	suggestion = (hip_transform_suite_t *) &ht->suite_id[0];

	if ( (length >> 1) > 6) {
		HIP_ERROR("Too many transforms (%d)\n", length >> 1);
		goto out;
	}

	for (i=0; i<length; i++) {
		switch(ntohs(*suggestion)) {

		case HIP_HIP_AES_SHA1:
		case HIP_HIP_3DES_SHA1:
		case HIP_HIP_NULL_SHA1:
			tid = ntohs(*suggestion);
			goto out;
			break;

		default:
			/* Specs don't say what to do when unknown are found. 
			 * We ignore.
			 */
			HIP_ERROR("Unknown HIP suite id suggestion (%u)\n",
				  ntohs(*suggestion));
			break;
		}
		suggestion++;
	}

 out:
	if(tid == 0)
		HIP_ERROR("None HIP transforms accepted\n");
	else
		HIP_DEBUG("Chose HIP transform: %d\n", tid);

	return tid;
}


/**
 * hip_select_esp_transform - select an ESP transform to use
 * @param ht ESP_TRANSFORM payload where the transform is selected from
 *
 * @return the first acceptable Suite-ID. otherwise < 0 if no
 * acceptable Suite-ID was found.
 */
hip_transform_suite_t hip_select_esp_transform(struct hip_esp_transform *ht)
{
	hip_transform_suite_t tid = 0;
	int i;
	int length;
	hip_transform_suite_t *suggestion;

	length = hip_get_param_contents_len(ht);
	suggestion = (uint16_t*) &ht->suite_id[0];

	if (length > sizeof(struct hip_esp_transform) -
	    sizeof(struct hip_common)) {
		HIP_ERROR("Too many transforms\n");
		goto out;
	}

	for (i=0; i<length; i++) {
		switch(ntohs(*suggestion)) {

		case HIP_ESP_AES_SHA1:
		case HIP_ESP_NULL_NULL:
		case HIP_ESP_3DES_SHA1:
		case HIP_ESP_NULL_SHA1:
			tid = ntohs(*suggestion);
			goto out;
			break;
		default:
			/* Specs don't say what to do when unknowns are found. 
			 * We ignore.
			 */
			HIP_ERROR("Unknown ESP suite id suggestion (%u)\n",
				  ntohs(*suggestion));
			break;
		}
		suggestion++;
	}

 out:
	HIP_DEBUG("Took ESP transform %d\n", tid);

	if(tid == 0)
		HIP_ERROR("Faulty ESP transform\n");

	return tid;
}

#ifndef __KERNEL__

int convert_string_to_address(const char *str, struct in6_addr *ip6) {
	int ret = 0, err = 0;
	struct in_addr ip4;

	ret = inet_pton(AF_INET6, str, ip6);
	HIP_IFEL((ret < 0 && errno == EAFNOSUPPORT),
		 err = -1,
		 "inet_pton: not a valid address family\n");
	if (ret > 0) {
                /* IPv6 address conversion was ok */
		HIP_DEBUG_IN6ADDR("id", ip6);
		goto out_err;
	}

	/* Might be an ipv4 address (ret == 0). Lets catch it here. */
		
	ret = inet_pton(AF_INET, str, &ip4);
	HIP_IFEL((ret < 0 && errno == EAFNOSUPPORT), -1,
		 "inet_pton: not a valid address family\n");
	HIP_IFEL((ret == 0), -1,
		 "inet_pton: %s: not a valid network address\n", str);
		
	IPV4_TO_IPV6_MAP(&ip4, ip6);
	HIP_DEBUG("Mapped v4 to v6\n");
	HIP_DEBUG_IN6ADDR("mapped v6", ip6); 	

 out_err:
	return err;
}

/* the lengths are in bits */
int khi_encode(unsigned char *orig, int orig_len, unsigned char *encoded,
	       int encoded_len) {
	BIGNUM *bn = NULL;
	int err = 0, shift = (orig_len - encoded_len) / 2,
	  len = encoded_len / 8 + ((encoded_len % 8) ? 1 : 0);

	HIP_IFEL((encoded_len > orig_len), -1, "len mismatch\n");
	HIP_IFEL((!(bn = BN_bin2bn(orig, orig_len / 8, NULL))), -1,
		 "BN_bin2bn\n");
	HIP_IFEL(!BN_rshift(bn, bn, shift), -1, "BN_lshift\n");
	HIP_IFEL(!BN_mask_bits(bn, encoded_len), -1,
		"BN_mask_bits\n");
	HIP_IFEL((bn2bin_safe(bn, encoded, len) != len), -1,
		  "BN_bn2bin_safe\n");

	HIP_HEXDUMP("encoded: ", encoded, len);

 out_err:
	if(bn)
		BN_free(bn);
	return err;
}

int hip_dsa_host_id_to_hit(const struct hip_host_id *host_id,
			   struct in6_addr *hit, int hit_type)
{
       int err = 0, index;
       u8 digest[HIP_AH_SHA_LEN];
       u8 *key_rr = (u8 *) (host_id + 1); /* skip the header */
       /* hit excludes rdata but it is included in hi_length;
	  subtract rdata */
       unsigned int key_rr_len = ntohs(host_id->hi_length) -
 	 sizeof(struct hip_host_id_key_rdata);
       u8 *khi_data = NULL;
       u8 khi_context_id[] = HIP_KHI_CONTEXT_ID_INIT;
       int khi_data_len = key_rr_len + sizeof(khi_context_id);
       int khi_index = 0;

       HIP_DEBUG("key_rr_len=%u\n", key_rr_len);
       HIP_IFE(hit_type != HIP_HIT_TYPE_HASH100, -ENOSYS);
       HIP_HEXDUMP("key_rr", key_rr, key_rr_len);

       /* Hash Input :=  Context ID | Input */
       khi_data = HIP_MALLOC(khi_data_len, 0);
       khi_index = 0;
       memcpy(khi_data + khi_index, khi_context_id, sizeof(khi_context_id));
       khi_index += sizeof(khi_context_id);
       memcpy(khi_data + khi_index, key_rr, key_rr_len);
       khi_index += key_rr_len;

       HIP_ASSERT(khi_index == khi_data_len);

       HIP_HEXDUMP("khi data", khi_data, khi_data_len);

       /* Hash :=  SHA1( Expand( Hash Input ) ) */
       HIP_IFEL((err = hip_build_digest(HIP_DIGEST_SHA1, khi_data,
					khi_data_len, digest)), err,
		"Building of digest failed\n");

       HIP_HEXDUMP("digest", digest, sizeof(digest));

       bzero(hit, sizeof(hip_hit_t));
       HIP_IFEL(khi_encode(digest, sizeof(digest) * 8,
			   ((u8 *) hit) + 3,
			   sizeof(hip_hit_t) * 8 - HIP_HIT_PREFIX_LEN),
		-1, "encoding failed\n");

       HIP_DEBUG_HIT("HIT before prefix: ", hit);
       set_hit_prefix(hit);
       HIP_DEBUG_HIT("HIT after prefix: ", hit);

 out_err:
       if (khi_data)
	       HIP_FREE(khi_data);

       return err;
}

int hip_rsa_host_id_to_hit(const struct hip_host_id *host_id,
			   struct in6_addr *hit, int hit_type)
{
	int err;
	err = hip_dsa_host_id_to_hit(host_id, hit, hit_type);
	return err;
}

int hip_host_id_to_hit(const struct hip_host_id *host_id,
		       struct in6_addr *hit, int hit_type)
{
	int algo = hip_get_host_id_algo(host_id);
	int err = 0;

	if (algo == HIP_HI_DSA) {
		err = hip_dsa_host_id_to_hit(host_id, hit, hit_type);
	} else if (algo == HIP_HI_RSA) {
		err = hip_rsa_host_id_to_hit(host_id, hit, hit_type);
	} else {
		err = -ENOSYS;
	}

	return err;
}

int hip_private_dsa_host_id_to_hit(const struct hip_host_id *host_id,
				   struct in6_addr *hit, int hit_type)
{
	int err = 0;
	struct hip_host_id *host_id_pub = NULL;
	int contents_len;
	int total_len;

	contents_len = hip_get_param_contents_len(host_id);
	total_len = hip_get_param_total_len(host_id);

	/*! \todo add an extra check for the T val */

	if (contents_len <= 20) {
		err = -EMSGSIZE;
		HIP_ERROR("Host id too short\n");
		goto out_err;
	}

	/* Allocate enough space for host id; there will be 20 bytes extra
	   to avoid hassle with padding. */
	host_id_pub = (struct hip_host_id *)HIP_MALLOC(total_len, GFP_KERNEL);
	if (!host_id_pub) {
		err = -EFAULT;
		goto out_err;
	}
	memset(host_id_pub, 0, total_len);

	memcpy(host_id_pub, host_id,
	       sizeof(struct hip_tlv_common) + contents_len - 20);

	host_id_pub->hi_length = htons(ntohs(host_id_pub->hi_length) - 20);
	hip_set_param_contents_len(host_id_pub, contents_len - 20);

	_HIP_HEXDUMP("extracted pubkey", host_id_pub,
		     hip_get_param_total_len(host_id_pub));

	err = hip_dsa_host_id_to_hit(host_id_pub, hit, hit_type);
	if (err) {
		HIP_ERROR("Failed to convert HI to HIT.\n");
		goto out_err;
	}

 out_err:

	if (host_id_pub)
		HIP_FREE(host_id_pub);

	return err;
}

int hip_private_rsa_host_id_to_hit(const struct hip_host_id *host_id,
				   struct in6_addr *hit, int hit_type)
{
	int err = 0;
	struct hip_host_id *host_id_pub = NULL;
	int contents_len;
	int total_len;

	contents_len = hip_get_param_contents_len(host_id);
	total_len = hip_get_param_total_len(host_id);
	
	/* XX FIX: REMOVE PRIVATE KEY? */

	/* Allocate space for public key */
	host_id_pub = (struct hip_host_id *)HIP_MALLOC(total_len, GFP_KERNEL);
	if (!host_id_pub) {
		err = -EFAULT;
		goto out_err;
	}
	memset(host_id_pub, 0, total_len);

	/* How do we extract the public key from the hip_host_id 
	   struct? TODO: CHECK THIS */
	memcpy(host_id_pub, host_id,
	       sizeof(struct hip_tlv_common) + contents_len - 128 * 2);

	host_id_pub->hi_length = htons(ntohs(host_id_pub->hi_length) - 128*2);
	hip_set_param_contents_len(host_id_pub, contents_len - 128*2);	

	_HIP_HEXDUMP("extracted pubkey", host_id_pub,
				 hip_get_param_total_len(host_id_pub));

	err = hip_rsa_host_id_to_hit(host_id_pub, hit, hit_type);

	if (err) {
			HIP_ERROR("Failed to convert HI to HIT.\n");
			goto out_err;
	}

 out_err:
	
	if (host_id_pub)
			HIP_FREE(host_id_pub);
	
	return err;
}

int hip_private_host_id_to_hit(const struct hip_host_id *host_id,
			       struct in6_addr *hit, int hit_type)
{
	int algo = hip_get_host_id_algo(host_id);
	int err = 0;

	if (algo == HIP_HI_DSA) {
		err = hip_private_dsa_host_id_to_hit(host_id, hit,
						     hit_type);
	} else if (algo == HIP_HI_RSA) {
		err = hip_private_rsa_host_id_to_hit(host_id, hit,
						     hit_type);
	} else {
		err = -ENOSYS;
	}

	return err;
}


/**
 * check_and_create_dir - check and create a directory
 * @param dirname the name of the directory
 * @param mode creation mode for the directory, if it does not exist
 *
 * @return 0 if successful, or negative on error.
 */
int check_and_create_dir(char *dirname, mode_t mode) {
	int err = 0;
	struct stat dir_stat;

	HIP_INFO("dirname=%s mode=%o\n", dirname, mode);
	err = stat(dirname, &dir_stat);
	if (err && errno == ENOENT) { /* no such file or directory */
		err = mkdir(dirname, mode);
		if (err) {
			HIP_ERROR("mkdir %s failed: %s\n", dirname,
				  strerror(errno));
		}
	} else if (err) {
		HIP_ERROR("stat %s failed: %s\n", dirname,
			  strerror(errno));
	}

	return err;
}

int hip_host_id_contains_private_key(struct hip_host_id *host_id)
{
	uint16_t len = hip_get_param_contents_len(host_id);
	u8 *buf = (u8 *)(host_id + 1);
	u8 t = *buf;

	return len >= 3 * (64 + 8 * t) + 2 * 20; /* PQGXY 3*(64+8*t) + 2*20 */
}

void change_key_file_perms(char *filenamebase) {
  char *pubfilename = NULL;
  int pubfilename_len;

  pubfilename_len =
    strlen(filenamebase) + strlen(DEFAULT_PUB_FILE_SUFFIX) + 1;
  pubfilename = malloc(pubfilename_len);
  if (!pubfilename) {
    HIP_ERROR("malloc(%d) failed\n", pubfilename_len);
    goto out_err;
  }

  /* check retval */
  snprintf(pubfilename, pubfilename_len, "%s%s", filenamebase,
	   DEFAULT_PUB_FILE_SUFFIX);

  chmod(filenamebase, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
  chmod(pubfilename, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);

 out_err:
  if (pubfilename)
    HIP_FREE(pubfilename);

  return;
}

int hip_serialize_host_id_action(struct hip_common *msg, int action, int anon,
				 int use_default, const char *hi_fmt,
				 const char *hi_file) {
  int err, ret;
  hip_hdr_type_t numeric_action = 0;
  char addrstr[INET6_ADDRSTRLEN];
  char *dsa_filenamebase = NULL, *rsa_filenamebase = NULL, 
    *dsa_filenamebase_pub = NULL, *rsa_filenamebase_pub = NULL;
  struct hip_lhi rsa_lhi, dsa_lhi, rsa_pub_lhi, dsa_pub_lhi;
  struct hip_host_id *dsa_host_id = NULL, *rsa_host_id = NULL,
    *dsa_pub_host_id = NULL, *rsa_pub_host_id = NULL;
  unsigned char *dsa_key_rr = NULL, *rsa_key_rr = NULL, 
    *dsa_pub_key_rr = NULL, *rsa_pub_key_rr = NULL;
  int dsa_key_rr_len, rsa_key_rr_len, dsa_pub_key_rr_len, rsa_pub_key_rr_len;
  DSA *dsa_key = NULL, *dsa_pub_key = NULL;
  RSA *rsa_key = NULL, *rsa_pub_key = NULL;
  char hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
  int fmt;
  struct endpoint_hip *endpoint_dsa_hip = NULL, *endpoint_dsa_pub_hip = NULL;
  struct endpoint_hip *endpoint_rsa_hip = NULL, *endpoint_rsa_pub_hip = NULL;
  struct in6_addr *dsa_hit = NULL;

  memset(hostname, 0, HIP_HOST_ID_HOSTNAME_LEN_MAX);
  err = -gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1);
  if (err) {
    HIP_ERROR("gethostname failed (%d)\n", err);
    goto out;
  }

  HIP_INFO("Using hostname: %s\n", hostname);

  fmt = HIP_KEYFILE_FMT_HIP_PEM;
  if (!use_default && strcmp(hi_fmt, "rsa") && 
      strcmp(hi_fmt, "dsa")) {
    HIP_ERROR("Only rsa or dsa keys are supported\n");
    err = -ENOSYS;
    goto out;
  }

  /* Set filenamebase (depending on whether the user supplied a
     filenamebase or not) */
  if (use_default == 0) {
    if(!strcmp(hi_fmt, "dsa")) {
      dsa_filenamebase = malloc(strlen(hi_file) + 1);
      memcpy(dsa_filenamebase, hi_file, strlen(hi_file));
    } else /*rsa*/ {
      rsa_filenamebase = malloc(strlen(hi_file) + 1);
      memcpy(rsa_filenamebase, hi_file, strlen(hi_file));
    }
  } else { /* create dynamically default filenamebase */
    int rsa_filenamebase_len, dsa_filenamebase_len, ret;

    HIP_INFO("No key file given, use default\n");

    dsa_filenamebase_len = strlen(DEFAULT_CONFIG_DIR) + strlen("/") +
      strlen(DEFAULT_HOST_DSA_KEY_FILE_BASE) + 1;
    rsa_filenamebase_len = strlen(DEFAULT_CONFIG_DIR) + strlen("/") +
      strlen(DEFAULT_HOST_RSA_KEY_FILE_BASE) + 1;
    
    /* DEFAULT_CONFIG_DIR/DEFAULT_HOST_DSA_KEY_FILE_BASE.DEFAULT_ANON_HI_FILE_NAME_SUFFIX)\0 */
    dsa_filenamebase = malloc(HOST_ID_FILENAME_MAX_LEN);
    if (!dsa_filenamebase) {
      HIP_ERROR("Could allocate DSA file name\n");
      err = -ENOMEM;
      goto out;
    }
    rsa_filenamebase = malloc(HOST_ID_FILENAME_MAX_LEN);
    if (!rsa_filenamebase) {
      HIP_ERROR("Could allocate RSA file name\n");
      err = -ENOMEM;
      goto out;
    }
    dsa_filenamebase_pub = malloc(HOST_ID_FILENAME_MAX_LEN);
    if (!dsa_filenamebase) {
      HIP_ERROR("Could allocate DSA (pub) file name\n");
      err = -ENOMEM;
      goto out;
    }
    rsa_filenamebase_pub = malloc(HOST_ID_FILENAME_MAX_LEN);
    if (!rsa_filenamebase) {
      HIP_ERROR("Could allocate RSA (pub) file name\n");
      err = -ENOMEM;
      goto out;
    }

    ret = snprintf(dsa_filenamebase,
		   dsa_filenamebase_len +
		   strlen(DEFAULT_ANON_HI_FILE_NAME_SUFFIX),
		   "%s/%s%s",
                   DEFAULT_CONFIG_DIR,
		   DEFAULT_HOST_DSA_KEY_FILE_BASE,
		   DEFAULT_ANON_HI_FILE_NAME_SUFFIX);
    if (ret <= 0) {
      err = -EINVAL;
      goto out;
    }
    ret = snprintf(rsa_filenamebase, HOST_ID_FILENAME_MAX_LEN, "%s/%s%s",
                   DEFAULT_CONFIG_DIR,
		   DEFAULT_HOST_RSA_KEY_FILE_BASE,
		   DEFAULT_ANON_HI_FILE_NAME_SUFFIX);
    if (ret <= 0) {
      err = -EINVAL;
      goto out;
    }
    ret = snprintf(dsa_filenamebase_pub, HOST_ID_FILENAME_MAX_LEN, "%s/%s%s",
		   DEFAULT_CONFIG_DIR,
		   DEFAULT_HOST_DSA_KEY_FILE_BASE,
		   DEFAULT_PUB_HI_FILE_NAME_SUFFIX);
    if (ret <= 0) {
      err = -EINVAL;
      goto out;
    }
    ret = snprintf(rsa_filenamebase_pub,
		   rsa_filenamebase_len+
		   strlen(DEFAULT_PUB_HI_FILE_NAME_SUFFIX),
		   "%s/%s%s",
                   DEFAULT_CONFIG_DIR,
		   DEFAULT_HOST_RSA_KEY_FILE_BASE,
		   DEFAULT_PUB_HI_FILE_NAME_SUFFIX);
    if (ret <= 0) {
      err = -EINVAL;
      goto out;
    }
    
  }

  dsa_lhi.anonymous = htons(anon);
  rsa_lhi.anonymous = htons(anon);
  
  if (use_default) {
    HIP_DEBUG("Using dsa (anon hi) filenamebase: %s\n", dsa_filenamebase);
    HIP_DEBUG("Using rsa (anon hi) filenamebase: %s\n", rsa_filenamebase);
    HIP_DEBUG("Using dsa (pub hi) filenamebase: %s\n", dsa_filenamebase_pub);
    HIP_DEBUG("Using rsa (pub hi) filenamebase: %s\n", rsa_filenamebase_pub);
  }
  
  switch(action) {
  case ACTION_NEW:
    /* zero means "do not send any message to kernel */
    numeric_action = 0;

    /* Default directory is created only in "hipconf new default hi" */
    if (use_default) {
      err = check_and_create_dir(DEFAULT_CONFIG_DIR,
				 DEFAULT_CONFIG_DIR_MODE);
      if (err) {
	HIP_ERROR("Could not create default directory\n", err);
	goto out;
      }
    }

    if (!use_default) {
      if (!strcmp(hi_fmt, "dsa")) {
	dsa_key = create_dsa_key(DSA_KEY_DEFAULT_BITS);
	if (!dsa_key) {
	  HIP_ERROR("creation of dsa key failed\n");
	  err = -EINVAL;
	  goto out;  
	}
	err = save_dsa_private_key(dsa_filenamebase, dsa_key);
	if (err) {
	  HIP_ERROR("saving of dsa key failed\n");
	  goto out;
	}
	
      } else { /*RSA*/
	rsa_key = create_rsa_key(RSA_KEY_DEFAULT_BITS);
	if (!rsa_key) {
	  HIP_ERROR("creation of rsa key failed\n");
	  err = -EINVAL;
	  goto out;  
	}
	 err = save_rsa_private_key(rsa_filenamebase, rsa_key);
	 if (err) {
	   HIP_ERROR("saving of rsa key failed\n");
	   goto out;
	 }
      }
      HIP_DEBUG("saved key\n");
      break;
    }

    dsa_key = create_dsa_key(DSA_KEY_DEFAULT_BITS);
    if (!dsa_key) {
      HIP_ERROR("creation of dsa key failed\n");
      err = -EINVAL;
      goto out;  
    }

    dsa_pub_key = create_dsa_key(DSA_KEY_DEFAULT_BITS);
    if (!dsa_key) {
      HIP_ERROR("creation of dsa key (pub) failed\n");
      err = -EINVAL;
      goto out;  
    }

    rsa_key = create_rsa_key(RSA_KEY_DEFAULT_BITS);
    if (!rsa_key) {
      HIP_ERROR("creation of rsa key failed\n");
      err = -EINVAL;
      goto out;  
    }

    rsa_pub_key = create_rsa_key(RSA_KEY_DEFAULT_BITS);
    if (!rsa_pub_key) {
      HIP_ERROR("creation of rsa key (pub) failed\n");
      err = -EINVAL;
      goto out;  
    }

    err = save_dsa_private_key(dsa_filenamebase, dsa_key);
    if (err) {
      HIP_ERROR("saving of dsa key failed\n");
      goto out;
    }

    err = save_dsa_private_key(dsa_filenamebase_pub, dsa_pub_key);
    if (err) {
      HIP_ERROR("saving of dsa key failed\n");
      goto out;
    }

    err = save_rsa_private_key(rsa_filenamebase, rsa_key);
    if (err) {
      HIP_ERROR("saving of rsa key failed\n");
      goto out;
    }

    err = save_rsa_private_key(rsa_filenamebase_pub, rsa_pub_key);
    if (err) {
      HIP_ERROR("saving of rsa key failed\n");
      goto out;
    }
    break;
  case ACTION_ADD:
    numeric_action = SO_HIP_ADD_LOCAL_HI;

    if (!use_default) {
      if (!strcmp(hi_fmt, "dsa")) {
	err = load_dsa_private_key(dsa_filenamebase, &dsa_key);
	if (err) {
	  HIP_ERROR("Loading of the DSA key failed\n");
	  goto out;
	}
	dsa_key_rr_len = dsa_to_dns_key_rr(dsa_key, &dsa_key_rr);
	if (dsa_key_rr_len <= 0) {
	  HIP_ERROR("dsa_key_rr_len <= 0\n");
	  err = -EFAULT;
	  goto out;
	}
	err = dsa_to_hip_endpoint(dsa_key, &endpoint_dsa_hip, 
				  anon ? HIP_ENDPOINT_FLAG_ANON : 0, 
				  hostname);
	if (err) {
	  HIP_ERROR("Failed to allocate and build DSA endpoint.\n");
	  goto out;
	}
	err = hip_build_param_eid_endpoint(msg, endpoint_dsa_hip);
	if (err) {
	  HIP_ERROR("Building of host id failed\n");
	  goto out;
	}
          
      } else { /*RSA*/
	err = load_rsa_private_key(rsa_filenamebase, &rsa_key);
	if (err) {
	  HIP_ERROR("Loading of the RSA key failed\n");
	  goto out;
	}
	rsa_key_rr_len = rsa_to_dns_key_rr(rsa_key, &rsa_key_rr);
	if (rsa_key_rr_len <= 0) {
	  HIP_ERROR("rsa_key_rr_len <= 0\n");
	  err = -EFAULT;
	  goto out;
	}
	err = rsa_to_hip_endpoint(rsa_key, &endpoint_rsa_hip, 
				  anon ? HIP_ENDPOINT_FLAG_ANON : 0,
				  hostname);
	if (err) {
	  HIP_ERROR("Failed to allocate and build RSA endpoint.\n");
	  goto out;
	}
	err = hip_build_param_eid_endpoint(msg, endpoint_rsa_hip);
	if (err) {
	  HIP_ERROR("Building of host id failed\n");
	  goto out;
	}
	
      }
      goto skip_host_id;
    }

    err = load_dsa_private_key(dsa_filenamebase, &dsa_key);
    if (err) {
      HIP_ERROR("Loading of the DSA key failed\n");
      goto out;
    }

    err = load_rsa_private_key(rsa_filenamebase, &rsa_key);
    if (err) {
      HIP_ERROR("Loading of the RSA key failed\n");
      goto out;
    }

    err = load_dsa_private_key(dsa_filenamebase_pub, &dsa_pub_key);
    if (err) {
      HIP_ERROR("Loading of the DSA key (pub) failed\n");
      goto out;
    }

    err = load_rsa_private_key(rsa_filenamebase_pub, &rsa_pub_key);
    if (err) {
      HIP_ERROR("Loading of the RSA key (pub) failed\n");
      goto out;
    }

    dsa_key_rr_len = dsa_to_dns_key_rr(dsa_key, &dsa_key_rr);
    if (dsa_key_rr_len <= 0) {
      HIP_ERROR("dsa_key_rr_len <= 0\n");
      err = -EFAULT;
      goto out;
    }

    rsa_key_rr_len = rsa_to_dns_key_rr(rsa_key, &rsa_key_rr);
    if (rsa_key_rr_len <= 0) {
      HIP_ERROR("rsa_key_rr_len <= 0\n");
      err = -EFAULT;
      goto out;
    }

    dsa_pub_key_rr_len = dsa_to_dns_key_rr(dsa_pub_key, &dsa_pub_key_rr);
    if (dsa_pub_key_rr_len <= 0) {
      HIP_ERROR("dsa_key_rr_len <= 0\n");
      err = -EFAULT;
      goto out;
    }

    rsa_pub_key_rr_len = rsa_to_dns_key_rr(rsa_pub_key, &rsa_pub_key_rr);
    if (rsa_pub_key_rr_len <= 0) {
      HIP_ERROR("rsa_key_rr_len <= 0\n");
      err = -EFAULT;
      goto out;
    }
    
    err = dsa_to_hip_endpoint(dsa_key, &endpoint_dsa_hip, 
			      HIP_ENDPOINT_FLAG_ANON, 
			      hostname);
    if (err) {
      HIP_ERROR("Failed to allocate and build DSA endpoint.\n");
      goto out;
    }
    
    err = rsa_to_hip_endpoint(rsa_key, &endpoint_rsa_hip, 
			      HIP_ENDPOINT_FLAG_ANON,
			      hostname);
    if (err) {
      HIP_ERROR("Failed to allocate and build RSA endpoint.\n");
      goto out;
    }
    
    err = dsa_to_hip_endpoint(dsa_pub_key, &endpoint_dsa_pub_hip, 
			      0, 
			      hostname);
    if (err) {
      HIP_ERROR("Failed to allocate and build DSA endpoint (pub).\n");
      goto out;
    }
    
    err = rsa_to_hip_endpoint(rsa_pub_key, &endpoint_rsa_pub_hip, 
			      0,
			      hostname);
    if (err) {
      HIP_ERROR("Failed to allocate and build RSA endpoint (pub).\n");
      goto out;
    }

    err = hip_private_dsa_to_hit(dsa_key, dsa_key_rr, HIP_HIT_TYPE_HASH100,
				 &dsa_lhi.hit);
    if (err) {
      HIP_ERROR("Conversion from DSA to HIT failed\n");
      goto out;
    }

    HIP_DEBUG_HIT("DSA HIT", &dsa_lhi.hit);

    err = hip_private_dsa_to_hit(dsa_pub_key, dsa_pub_key_rr,
				 HIP_HIT_TYPE_HASH100, 
				 &dsa_pub_lhi.hit);
    if (err) {
      HIP_ERROR("Conversion from DSA to HIT failed\n");
      goto out;
    }
    HIP_DEBUG_HIT("DSA HIT", &dsa_pub_lhi.hit);
    
    err = hip_private_rsa_to_hit(rsa_key, rsa_key_rr, HIP_HIT_TYPE_HASH100,
				 &rsa_lhi.hit);
    if (err) {
      HIP_ERROR("Conversion from RSA to HIT failed\n");
      goto out;
    }
    HIP_DEBUG_HIT("RSA HIT", &rsa_lhi.hit);

    err = hip_private_rsa_to_hit(rsa_pub_key, rsa_pub_key_rr,
				 HIP_HIT_TYPE_HASH100, 
				 &rsa_pub_lhi.hit);
    if (err) {
      HIP_ERROR("Conversion from RSA to HIT failed\n");
      goto out;
    }
    HIP_DEBUG_HIT("RSA HIT", &rsa_pub_lhi.hit);
    break;
  }

  if (numeric_action == 0)
    goto skip_msg;

  err = hip_build_param_eid_endpoint(msg, endpoint_dsa_hip);
  if (err) {
    HIP_ERROR("Building of host id failed\n");
    goto out;
  }
  
  err = hip_build_param_eid_endpoint(msg, endpoint_rsa_hip);
  if (err) {
    HIP_ERROR("Building of host id failed\n");
    goto out;
  }

  err = hip_build_param_eid_endpoint(msg, endpoint_dsa_pub_hip);
  if (err) {
    HIP_ERROR("Building of host id failed\n");
    goto out;
  }
  
  err = hip_build_param_eid_endpoint(msg, endpoint_rsa_pub_hip);
  if (err) {
    HIP_ERROR("Building of host id failed\n");
    goto out;
  }

 skip_host_id:
  err = hip_build_user_hdr(msg, numeric_action, 0);
  if (err) {
    HIP_ERROR("build hdr error %d\n", err);
    goto out;
  }

 skip_msg:

 out:

  change_key_file_perms(dsa_filenamebase);
  change_key_file_perms(rsa_filenamebase);
  change_key_file_perms(dsa_filenamebase_pub);
  change_key_file_perms(rsa_filenamebase_pub);

  if (dsa_host_id)
    free(dsa_host_id);
  if (dsa_pub_host_id)
    free(dsa_pub_host_id);
  if (rsa_host_id)
    free(rsa_host_id);
  if (rsa_pub_host_id)
    free(rsa_pub_host_id);
  if ((use_default || strcmp(hi_fmt,"dsa")) && dsa_key)
    DSA_free(dsa_key);
  if ((use_default || strcmp(hi_fmt,"rsa")) && rsa_key)
    RSA_free(rsa_key);
  if (use_default && dsa_pub_key)
    DSA_free(dsa_pub_key);
  if (use_default && rsa_pub_key)
    RSA_free(rsa_pub_key);
  if (dsa_key_rr)
    free(dsa_key_rr);
  if (rsa_key_rr)
    free(rsa_key_rr);
  if (dsa_pub_key_rr)
    free(dsa_pub_key_rr);
  if (rsa_pub_key_rr)
    free(rsa_pub_key_rr);
  if (dsa_filenamebase)
    free(dsa_filenamebase);
  if (rsa_filenamebase)
    free(rsa_filenamebase);
  if (dsa_filenamebase_pub)
    free(dsa_filenamebase_pub);
  if (rsa_filenamebase_pub)
    free(rsa_filenamebase_pub);
  if (endpoint_dsa_hip)
    free(endpoint_dsa_hip);
  if (endpoint_rsa_hip)
    free(endpoint_rsa_hip);
  if (endpoint_dsa_pub_hip)
    free(endpoint_dsa_pub_hip);
  if (endpoint_rsa_pub_hip)
    free(endpoint_rsa_pub_hip);
  
  return err;
}

int hip_any_sa_to_hit_sa(const struct sockaddr *from,
		     const hip_hit_t *use_hit,
		     struct sockaddr_in6 *to) {
	to->sin6_family = AF_INET6;
	ipv6_addr_copy(&to->sin6_addr, use_hit);
	if (from->sa_family == AF_INET)
		to->sin6_port = ((struct sockaddr_in *) from)->sin_port;
	else if (from->sa_family == AF_INET6)
		to->sin6_port = ((struct sockaddr_in6 *) from)->sin6_port;
	else
		return -1;
	
	return 0;
}

#endif /* ! __KERNEL__ */
