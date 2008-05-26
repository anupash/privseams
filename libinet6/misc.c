/*
 * Miscellaneous functions
 *
 * Licence: GNU/GPL
 * Authors:
 * - Miika Komu <miika@iki.fi>
 * - Mika Kousa <mkousa@iki.fi>
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

	result->tv_sec = _t2.tv_sec - _t1.tv_sec;
	result->tv_usec = _t2.tv_usec - _t1.tv_usec;

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
unsigned long hip_hash_spi(const void *ptr)
{
	u32 spi = * (u32 *) ptr;
	unsigned long hash = (unsigned long)(*((uint32_t *)ptr));
	return (hash % ULONG_MAX);
}

/**
 * Match spis.
 */
int hip_match_spi(const void *ptr1, const void *ptr2)
{
	unsigned long hash1 = (unsigned long)(*((uint32_t *)ptr1));
	unsigned long hash2 = (unsigned long)(*((uint32_t *)ptr2));

	/* SPIs are random, so simple modulo is enough? */
	return (hash1 != hash2);
}

/**
 * hip_hash_hit - calculate a hash from a HIT
 * @param key pointer to a HIT
 * @param range range of the hash
 *
 * Returns value in range: 0 <= x < range
 */
unsigned long hip_hash_hit(const void *ptr)
{
      uint8_t hash[HIP_AH_SHA_LEN];
      
      hip_build_digest(HIP_DIGEST_SHA1, ptr + sizeof(uint16_t),
	7 * sizeof(uint16_t), hash);
      //hip_build_digest(HIP_DIGEST_SHA1, ptr, sizeof(hip_hit_t), hash);

      return *((unsigned long *)hash);
}

int hip_match_hit(const void *ptr1, const void *ptr2)
{
	return (hip_hash_hit(ptr1) != hip_hash_hit(ptr2));
}

/*
unsigned long hip_hidb_hash(const void *ptr) {
	hip_hit_t *hit = &(((struct hip_host_id_entry *) ptr)->lhi.hit);
	unsigned long hash;

	hip_build_digest(HIP_DIGEST_SHA1, hit, sizeof(hip_hit_t), &hash);

	return hash;
}

int hip_hidb_match(const void *ptr1, const void *ptr2) {
	return (hip_hidb_hash(ptr1) != hip_hidb_hash(ptr2));
}
*/

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
	HIP_IFEL((ret < 0 && errno == EAFNOSUPPORT), -1,
		 "\"%s\" is not of valid address family.\n", str);
	if (ret > 0) {
                /* IPv6 address conversion was ok */
		HIP_DEBUG_IN6ADDR("Converted IPv6", ip6);
		goto out_err;
	}

	/* Might be an ipv4 address (ret == 0). Lets catch it here. */
		
	ret = inet_pton(AF_INET, str, &ip4);
	HIP_IFEL((ret < 0 && errno == EAFNOSUPPORT), -1,
		 "\"%s\" is not of valid address family.\n", str);
	HIP_IFEL((ret == 0), -1,
		 "\"%s\" is not a valid network address.\n", str);
		
	IPV4_TO_IPV6_MAP(&ip4, ip6);
	HIP_DEBUG("Mapped v4 to v6.\n");
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

	_HIP_HEXDUMP("encoded: ", encoded, len);

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

       _HIP_DEBUG("key_rr_len=%u\n", key_rr_len);
       HIP_IFE(hit_type != HIP_HIT_TYPE_HASH100, -ENOSYS);
       _HIP_HEXDUMP("key_rr", key_rr, key_rr_len);

       /* Hash Input :=  Context ID | Input */
       khi_data = HIP_MALLOC(khi_data_len, 0);
       khi_index = 0;
       memcpy(khi_data + khi_index, khi_context_id, sizeof(khi_context_id));
       khi_index += sizeof(khi_context_id);
       memcpy(khi_data + khi_index, key_rr, key_rr_len);
       khi_index += key_rr_len;

       HIP_ASSERT(khi_index == khi_data_len);

       _HIP_HEXDUMP("khi data", khi_data, khi_data_len);

       /* Hash :=  SHA1( Expand( Hash Input ) ) */
       HIP_IFEL((err = hip_build_digest(HIP_DIGEST_SHA1, khi_data,
					khi_data_len, digest)), err,
		"Building of digest failed\n");

       _HIP_HEXDUMP("digest", digest, sizeof(digest));

       bzero(hit, sizeof(hip_hit_t));
       HIP_IFEL(khi_encode(digest, sizeof(digest) * 8,
			   ((u8 *) hit) + 3,
			   sizeof(hip_hit_t) * 8 - HIP_HIT_PREFIX_LEN),
		-1, "encoding failed\n");

       _HIP_DEBUG_HIT("HIT before prefix: ", hit);
       set_hit_prefix(hit);
       _HIP_DEBUG_HIT("HIT after prefix: ", hit);

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


  
  if (use_default) {
    HIP_DEBUG("Using dsa (anon hi) filenamebase: %s\n", dsa_filenamebase);
    HIP_DEBUG("Using rsa (anon hi) filenamebase: %s\n", rsa_filenamebase);
    HIP_DEBUG("Using dsa (pub hi) filenamebase: %s\n", dsa_filenamebase_pub);
    HIP_DEBUG("Using rsa (pub hi) filenamebase: %s\n", rsa_filenamebase_pub);
  }
  
  switch(action) {
  case ACTION_NEW:
    /* zero means "do not send any message to hipd */
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
      HIP_ERROR("Failed to allocate and build DSA endpoint (anon).\n");
      goto out;
    }
    
    err = rsa_to_hip_endpoint(rsa_key, &endpoint_rsa_hip, 
			      HIP_ENDPOINT_FLAG_ANON,
			      hostname);
    if (err) {
      HIP_ERROR("Failed to allocate and build RSA endpoint (anon).\n");
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

void get_random_bytes(void *buf, int n)
{
	RAND_bytes(buf, n);
}

/**
 * hip_build_digest - calculate a digest over given data
 * @param type the type of digest, e.g. "sha1"
 * @param in the beginning of the data to be digested
 * @param in_len the length of data to be digested in octets
 * @param out the digest
 *
 * @param out should be long enough to hold the digest. This cannot be
 * checked!
 *
 * @return 0 on success, otherwise < 0.
 */
int hip_build_digest(const int type, const void *in, int in_len, void *out) {
	SHA_CTX sha;
	MD5_CTX md5;

	switch(type) {
	case HIP_DIGEST_SHA1:
		SHA1_Init(&sha);
		SHA1_Update(&sha, in, in_len);
		SHA1_Final(out, &sha);
		break;

	case HIP_DIGEST_MD5:
		MD5_Init(&md5);
		MD5_Update(&md5, in, in_len);
		MD5_Final(out, &md5);
		break;

	default:
		HIP_ERROR("Unknown digest: %x\n",type);
		return -EFAULT;
	}

	return 0;
}

/**
 * dsa_to_dns_key_rr - create DNS KEY RR record from host DSA key
 * @param dsa the DSA structure from where the KEY RR record is to be created
 * @param dsa_key_rr where the resultin KEY RR is stored
 *
 * Caller must free dsa_key_rr when it is not used anymore.
 *
 * @return On successful operation, the length of the KEY RR buffer is
 * returned (greater than zero) and pointer to the buffer containing
 * DNS KEY RR is stored at dsa_key_rr. On error function returns negative
 * and sets dsa_key_rr to NULL.
 */
int dsa_to_dns_key_rr(DSA *dsa, unsigned char **dsa_key_rr) {
  int err = 0;
  int dsa_key_rr_len = -1;
  signed char t; /* in units of 8 bytes */
  unsigned char *p;
  unsigned char *bn_buf = NULL;
  int bn_buf_len;
  int bn2bin_len;

  HIP_ASSERT(dsa != NULL); /* should not happen */

  *dsa_key_rr = NULL;

  _HIP_DEBUG("numbytes p=%d\n", BN_num_bytes(dsa->p));
  _HIP_DEBUG("numbytes q=%d\n", BN_num_bytes(dsa->q));
  _HIP_DEBUG("numbytes g=%d\n", BN_num_bytes(dsa->g));
  _HIP_DEBUG("numbytes pubkey=%d\n", BN_num_bytes(dsa->pub_key)); // shouldn't this be NULL also?

  /* notice that these functions allocate memory */
  _HIP_DEBUG("p=%s\n", BN_bn2hex(dsa->p));
  _HIP_DEBUG("q=%s\n", BN_bn2hex(dsa->q));
  _HIP_DEBUG("g=%s\n", BN_bn2hex(dsa->g));
  _HIP_DEBUG("pubkey=%s\n", BN_bn2hex(dsa->pub_key));

  /* ***** is use of BN_num_bytes ok ? ***** */
  t = (BN_num_bytes(dsa->p) - 64) / 8;
  if (t < 0 || t > 8) {
    HIP_ERROR("t=%d < 0 || t > 8\n", t);
    err = -EINVAL;
    goto out_err;
  }
  _HIP_DEBUG("t=%d\n", t);

  /* RFC 2536 section 2 */
  /*
           Field     Size
           -----     ----
            T         1  octet
            Q        20  octets
            P        64 + T*8  octets
            G        64 + T*8  octets
            Y        64 + T*8  octets
	  [ X        20 optional octets (private key hack) ]
	
  */
  dsa_key_rr_len = 1 + 20 + 3 * (64 + t * 8);

  if (dsa->priv_key) {
    dsa_key_rr_len += 20; /* private key hack */
    _HIP_DEBUG("Private key included\n");
  } else {
    _HIP_DEBUG("No private key\n");
  }

  _HIP_DEBUG("dsa key rr len = %d\n", dsa_key_rr_len);
  *dsa_key_rr = malloc(dsa_key_rr_len);
  if (!*dsa_key_rr) {
    HIP_ERROR("malloc\n");
    err = -ENOMEM;
    goto out_err;
  }

  /* side-effect: does also padding for Q, P, G, and Y */
  memset(*dsa_key_rr, 0, dsa_key_rr_len);

  /* copy header */
  p = *dsa_key_rr;

  /* set T */
  memset(p, t, 1); // XX FIX: WTF MEMSET?
  p += 1;
  _HIP_HEXDUMP("DSA KEY RR after T:", *dsa_key_rr, p - *dsa_key_rr);

  /* minimum number of bytes needed to store P, G or Y */
  bn_buf_len = BN_num_bytes(dsa->p);
  if (bn_buf_len <= 0) {
    HIP_ERROR("bn_buf_len p <= 0\n");
    err = -EINVAL;
    goto out_err_free_rr;
  }

  bn_buf = malloc(bn_buf_len);
  if (!bn_buf) {
    HIP_ERROR("malloc\n");
    err = -ENOMEM;
    goto out_err_free_rr;
  }
  
  /* Q */
  bn2bin_len = bn2bin_safe(dsa->q, bn_buf, 20);
  _HIP_DEBUG("q len=%d\n", bn2bin_len);
  if (!bn2bin_len) {
    HIP_ERROR("bn2bin\n");
    err = -ENOMEM;
    goto out_err;
  }
  HIP_ASSERT(bn2bin_len == 20);
  memcpy(p, bn_buf, bn2bin_len);
  p += bn2bin_len;
  _HIP_HEXDUMP("DSA KEY RR after Q:", *dsa_key_rr, p-*dsa_key_rr);

  /* add given dsa_param to the *dsa_key_rr */
#define DSA_ADD_PGY_PARAM_TO_RR(dsa_param, t)            \
  bn2bin_len = bn2bin_safe(dsa_param, bn_buf, 64 + t*8); \
  _HIP_DEBUG("len=%d\n", bn2bin_len);                    \
  if (!bn2bin_len) {                                     \
    HIP_ERROR("bn2bin\n");                               \
    err = -ENOMEM;                                       \
    goto out_err_free_rr;                                \
  }                                                      \
  HIP_ASSERT(bn_buf_len-bn2bin_len >= 0);                \
  p += bn_buf_len-bn2bin_len; /* skip pad */             \
  memcpy(p, bn_buf, bn2bin_len);                         \
  p += bn2bin_len;

  /* padding + P */
  DSA_ADD_PGY_PARAM_TO_RR(dsa->p, t);
  _HIP_HEXDUMP("DSA KEY RR after P:", *dsa_key_rr, p-*dsa_key_rr);
  /* padding + G */
  DSA_ADD_PGY_PARAM_TO_RR(dsa->g, t);
  _HIP_HEXDUMP("DSA KEY RR after G:", *dsa_key_rr, p-*dsa_key_rr);
  /* padding + Y */
  DSA_ADD_PGY_PARAM_TO_RR(dsa->pub_key, t);
  _HIP_HEXDUMP("DSA KEY RR after Y:", *dsa_key_rr, p-*dsa_key_rr);
  /* padding + X */

#undef DSA_ADD_PGY_PARAM_TO_RR


  if(dsa->priv_key){
    bn2bin_len = bn2bin_safe(dsa->priv_key, bn_buf, 20);
    memcpy(p,bn_buf,bn2bin_len);
    
    p += bn2bin_len;
    _HIP_HEXDUMP("DSA KEY RR after X:", *dsa_key_rr, p-*dsa_key_rr);

  }

  goto out_err;

 out_err_free_rr:
  if (*dsa_key_rr)
    free(*dsa_key_rr);

 out_err:
  if (bn_buf)
    free(bn_buf);
  return dsa_key_rr_len;
}


/**
 * rsa_to_dns_key_rr - This is a new version of the function above. This function 
 *                     assumes that RSA given as a parameter is always public (Laura/10.4.2006)
                       Creates DNS KEY RR record from host RSA public key
 * @param rsa the RSA structure from where the KEY RR record is to be created
 * @param rsa_key_rr where the resultin KEY RR is stored
 *
 * Caller must free rsa_key_rr when it is not used anymore.
 *
 * @return On successful operation, the length of the KEY RR buffer is
 * returned (greater than zero) and pointer to the buffer containing
 * DNS KEY RR is stored at rsa_key_rr. On error function returns negative
 * and sets rsa_key_rr to NULL.
 */
int rsa_to_dns_key_rr(RSA *rsa, unsigned char **rsa_key_rr) {
  int err = 0, len;
  int rsa_key_rr_len = -1;
  signed char t; // in units of 8 bytes
  unsigned char *p;
  int bn2bin_len;
  unsigned char *c;
  int public = -1;
  
  HIP_ASSERT(rsa != NULL); // should not happen
  
  *rsa_key_rr = NULL;
  
  HIP_ASSERT(BN_num_bytes(rsa->e) < 255); // is this correct?
  
  //let's check if the RSA key is public or private
  //private exponent is NULL in public keys
  if(rsa->d == NULL){ 
    public = 1;
  
    // see RFC 2537
  
    //FIXME there may be something funny
    rsa_key_rr_len = 4; // 4 four bytes for flags, protocol and algorithm // XX CHECK: LAURA
    rsa_key_rr_len += 1; // public key exponent length 
    rsa_key_rr_len += BN_num_bytes(rsa->e); // public key exponent (3 bytes)
    rsa_key_rr_len += BN_num_bytes(rsa->n); // public key modulus (128 bytes)
    
  } else{
    public = 0;
    rsa_key_rr_len = 1 + BN_num_bytes(rsa->e) + BN_num_bytes(rsa->n) +  
      BN_num_bytes(rsa->d) + BN_num_bytes(rsa->p) + BN_num_bytes(rsa->q);
    
  }
  *rsa_key_rr = malloc(rsa_key_rr_len);
  if (!*rsa_key_rr) {
    HIP_ERROR("malloc\n");
    err = -ENOMEM;
    goto out_err;
  }

  memset(*rsa_key_rr, 0, rsa_key_rr_len);

  c = *rsa_key_rr;
  *c = (unsigned char) BN_num_bytes(rsa->e);
  c++; // = e_length 

  len = bn2bin_safe(rsa->e, c, 3);
  c += len;

  len = bn2bin_safe(rsa->n, c, 128);
  c += len;  

  if(!public){
    len = bn2bin_safe(rsa->d, c, 128);
    c += len;
    
    len = bn2bin_safe(rsa->p, c, 64);
    c += len;
    
    len = bn2bin_safe(rsa->q, c, 64);
    c += len;
  }
  
  rsa_key_rr_len = c - *rsa_key_rr;

 out_err:

  return rsa_key_rr_len;
}

void *hip_cast_sa_addr(void *sockaddr) {
  struct sockaddr *sa = (struct sockaddr *) sockaddr;
  void *ret;
  
  switch(sa->sa_family) {
  case AF_INET:
    ret = &(((struct sockaddr_in *) sockaddr)->sin_addr);
    break;
  case AF_INET6:
    ret = &(((struct sockaddr_in6 *) sockaddr)->sin6_addr);
    break;
  default:
    ret = NULL;
  }
  return ret;
}

int hip_sockaddr_len(void *sockaddr) {
  struct sockaddr *sa = (struct sockaddr *) sockaddr;
  int len;
  
  switch(sa->sa_family) {
  case AF_INET:
    len = sizeof(struct sockaddr_in);
    break;
  case AF_INET6:
    len = sizeof(struct sockaddr_in6);
    break;
  case_AF_UNIX:
    len = sizeof(struct sockaddr_un);
    break;
  default:
    len = 0;
  }
  return len;
}

int hip_sa_addr_len(void *sockaddr) {
  struct sockaddr *sa = (struct sockaddr *) sockaddr;
  int len;
  
  switch(sa->sa_family) {
  case AF_INET:
    len = 4;
    break;
  case AF_INET6:
    len = 16;
    break;
  default:
    len = 0;
  }
  return len;
}


/* conversion function from in6_addr to sockaddr */
void hip_addr_to_sockaddr(struct in6_addr *addr, struct sockaddr *sa)
{
	if (IN6_IS_ADDR_V4MAPPED(addr)) {
		struct sockaddr_in *in = (struct sockaddr_in *) sa;
		memset(in, 0, sizeof(struct sockaddr_in));
		in->sin_family = AF_INET;
		IPV6_TO_IPV4_MAP(addr, &in->sin_addr);
	} else {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) sa;
		memset(in6, 0, sizeof(struct sockaddr_in6));
		in6->sin6_family = AF_INET6;
		ipv6_addr_copy(&in6->sin6_addr, addr);
	}
}





int hip_remove_lock_file(char *filename) {
	return unlink(filename);
}

int hip_create_lock_file(char *filename, int killold) {
	int err = 0, fd = 0, old_pid = 0;
	char old_pid_str[64], new_pid_str[64];
	int new_pid_str_len;
	
	memset(old_pid_str, 0, sizeof(old_pid_str));
	memset(new_pid_str, 0, sizeof(new_pid_str));

	/* New pid */
	snprintf(new_pid_str, sizeof(new_pid_str)-1, "%d\n", getpid());
	new_pid_str_len = strnlen(new_pid_str, sizeof(new_pid_str)-1);
	HIP_IFEL((new_pid_str_len <= 0), -1, "pid length\n");
		
	/* Read old pid */
	fd = open(filename, O_RDWR | O_CREAT, 0644);
	HIP_IFEL((fd <= 0), -1, "opening lock file failed\n");

	read(fd, old_pid_str, sizeof(old_pid_str) - 1);
	old_pid = atoi(old_pid_str);
       
	if (lockf(fd, F_TLOCK, 0) < 0)
	{ 
		HIP_IFEL(!killold, -12,
			 "\nHIP daemon already running with pid %d\n"
			 "Give: -k option to kill old daemon.\n",old_pid);
		
		HIP_INFO("\nDaemon is already running with pid %d\n"
			 "-k option given, terminating old one...\n", old_pid);
		/* Erase the old lock file to avoid having multiple pids
		   in the file */
		lockf(fd, F_ULOCK, 0);
		close(fd);
		HIP_IFEL(hip_remove_lock_file(filename), -1,"remove lock file\n");
                /* fd = open(filename, O_RDWR | O_CREAT, 0644); */
		fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
                /* don't close file descriptor because new started process is running */
		HIP_IFEL((fd <= 0), -1, "Opening lock file failed\n");
		HIP_IFEL(lockf(fd, F_TLOCK, 0), -1,"lock attempt failed\n");  
                 /* HIP_IFEL(kill(old_pid, SIGKILL), -1, "kill failed\n"); */
		err = kill(old_pid, SIGKILL);
		if (err != 0)
		{
                 HIP_INFO("\nError %d while trying to kill pid %d\n", err,old_pid);
		} 
	}
	/* else if (killold)
	{	
		lseek(fd,0,SEEK_SET);
		write(fd, new_pid_str, new_pid_str_len);
                system("NEW_PID=$(sudo awk NR==1 /var/lock/hipd.lock)");
		system("OLD_PID=$(/bin/pidof -o $NEW_PID hipd)");
		system("kill -9 $OLD_PID"); 
	} */

	lseek(fd,0,SEEK_SET);
	HIP_IFEL((write(fd, new_pid_str, new_pid_str_len) != new_pid_str_len),
		 "Writing new pid failed\n", -1);

out_err:
	if (err == -12)
	{
	  exit(0);
	}

	return err;
}

#endif /* ! __KERNEL__ */

/**
 * hip_solve_puzzle - Solve puzzle.
 * @param puzzle_or_solution Either a pointer to hip_puzzle or hip_solution structure
 * @param hdr The incoming R1/I2 packet header.
 * @param mode Either HIP_VERIFY_PUZZLE of HIP_SOLVE_PUZZLE
 *
 * The K and I is read from the @c puzzle_or_solution. 
 *
 * The J that solves the puzzle is returned, or 0 to indicate an error.
 * NOTE! I don't see why 0 couldn't solve the puzzle too, but since the
 * odds are 1/2^64 to try 0, I don't see the point in improving this now.
 */
uint64_t hip_solve_puzzle(void *puzzle_or_solution, struct hip_common *hdr,
			  int mode)
{
	uint64_t mask = 0;
	uint64_t randval = 0;
	uint64_t maxtries = 0;
	uint64_t digest = 0;
	u8 cookie[48];
	int err = 0;
	union {
		struct hip_puzzle pz;
		struct hip_solution sl;
	} *u;

	HIP_HEXDUMP("puzzle", puzzle_or_solution,
		    (mode == HIP_VERIFY_PUZZLE ? sizeof(struct hip_solution) : sizeof(struct hip_puzzle)));

	_HIP_DEBUG("\n");
	/* pre-create cookie */
	u = puzzle_or_solution;

	_HIP_DEBUG("current hip_cookie_max_k_r1=%d\n", max_k);
	HIP_IFEL(u->pz.K > HIP_PUZZLE_MAX_K, 0, 
		 "Cookie K %u is higher than we are willing to calculate"
		 " (current max K=%d)\n", u->pz.K, HIP_PUZZLE_MAX_K);

	mask = hton64((1ULL << u->pz.K) - 1);
	memcpy(cookie, (u8 *)&(u->pz.I), sizeof(uint64_t));

	HIP_DEBUG("(u->pz.I: 0x%llx\n", u->pz.I);

	if (mode == HIP_VERIFY_PUZZLE) {
		ipv6_addr_copy((hip_hit_t *)(cookie+8), &hdr->hits);
		ipv6_addr_copy((hip_hit_t *)(cookie+24), &hdr->hitr);
		//randval = ntoh64(u->sl.J);
		randval = u->sl.J;
		_HIP_DEBUG("u->sl.J: 0x%llx\n", randval);
		maxtries = 1;
	} else if (mode == HIP_SOLVE_PUZZLE) {
		ipv6_addr_copy((hip_hit_t *)(cookie+8), &hdr->hitr);
		ipv6_addr_copy((hip_hit_t *)(cookie+24), &hdr->hits);
		maxtries = 1ULL << (u->pz.K + 3);
		get_random_bytes(&randval, sizeof(u_int64_t));
	} else {
		HIP_IFEL(1, 0, "Unknown mode: %d\n", mode);
	}

	HIP_DEBUG("K=%u, maxtries (with k+2)=%llu\n", u->pz.K, maxtries);
	/* while loops should work even if the maxtries is unsigned
	 * if maxtries = 1 ---> while(1 > 0) [maxtries == 0 now]... 
	 * the next round while (0 > 0) [maxtries > 0 now]
	 */
	while(maxtries-- > 0) {
	 	u8 sha_digest[HIP_AH_SHA_LEN];
		
		/* must be 8 */
		memcpy(cookie + 40, (u8*) &randval, sizeof(uint64_t));

		hip_build_digest(HIP_DIGEST_SHA1, cookie, 48, sha_digest);

                /* copy the last 8 bytes for checking */
		memcpy(&digest, sha_digest + 12, sizeof(uint64_t));

		/* now, in order to be able to do correctly the bitwise
		 * AND-operation we have to remember that little endian
		 * processors will interpret the digest and mask reversely.
		 * digest is the last 64 bits of the sha1-digest.. how that is
		 * ordered in processors registers etc.. does not matter to us.
		 * If the last 64 bits of the sha1-digest is
		 * 0x12345678DEADBEEF, whether we have 0xEFBEADDE78563412
		 * doesn't matter because the mask matters... if the mask is
		 * 0x000000000000FFFF (or in other endianness
		 * 0xFFFF000000000000). Either ways... the result is
		 * 0x000000000000BEEF or 0xEFBE000000000000, which the cpu
		 * interprets as 0xBEEF. The mask is converted to network byte
		 * order (above).
		 */
		if ((digest & mask) == 0) {
			_HIP_DEBUG("*** Puzzle solved ***: 0x%llx\n",randval);
			_HIP_HEXDUMP("digest", sha_digest, HIP_AH_SHA_LEN);
			_HIP_HEXDUMP("cookie", cookie, sizeof(cookie));
			return randval;
		}

		/* It seems like the puzzle was not correctly solved */
		HIP_IFEL(mode == HIP_VERIFY_PUZZLE, 0, "Puzzle incorrect\n");
		randval++;
	}

	HIP_ERROR("Could not solve the puzzle, no solution found\n");
 out_err:
	return err;
}

/* This builds a msg wich will be sent to the HIPd in order to trigger
 * a BEX there.
 * 
 * NOTE: Either destination HIT or IP (for opportunistic BEX) has to be provided */
int hip_trigger_bex(struct in6_addr *src_hit, struct in6_addr *dst_hit,
		struct in6_addr *src_ip, struct in6_addr *dst_ip)
{
	struct hip_common *msg = NULL;
	int err = 0;

	HIP_DEBUG_HIT("src hit is: ", src_hit);
	HIP_DEBUG_IN6ADDR("src ip is: ", src_ip);
	HIP_DEBUG_HIT("dst hit is: ", dst_hit);
	HIP_DEBUG_IN6ADDR("dst ip  is: ", dst_ip);
	
	HIP_IFE(!(msg = hip_msg_alloc()), -1);
	
	HIP_IFEL(!dst_hit && !dst_ip, -1, "neither destination hit nor ip provided\n");
	
	// NOTE: we need this order in order to process the icoming message correctly
	// destination HIT is obligatory or opportunistic BEX
	if (dst_hit)
		HIP_IFEL(hip_build_param_contents(msg, (void *)(dst_hit),
						  HIP_PARAM_HIT,
						  sizeof(struct in6_addr)), -1,
		 "build param HIP_PARAM_HIT failed\n");
	
	// source HIT is optional
	if (src_hit)
			HIP_IFEL(hip_build_param_contents(msg, (void *)(src_hit),
							  HIP_PARAM_HIT,
							  sizeof(struct in6_addr)), -1,
				 "build param HIP_PARAM_HIT failed\n");
	
	// if no destination HIT is provided this has to be there
	if (dst_ip)
		HIP_IFEL(hip_build_param_contents(msg, (void *)(dst_ip),
						  HIP_PARAM_IPV6_ADDR,
						  sizeof(struct in6_addr)), -1,
			 "build param HIP_PARAM_IPV6_ADDR failed\n");
	
	// this again is optional
	if (src_ip)
			HIP_IFEL(hip_build_param_contents(msg, (void *)(src_ip),
							  HIP_PARAM_IPV6_ADDR,
							  sizeof(struct in6_addr)), -1,
				 "build param HIP_PARAM_IPV6_ADDR failed\n");
	
	/* build the message header */
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_TRIGGER_BEX, 0), -1,
		 "build hdr failed\n");

	HIP_DUMP_MSG(msg);
	
	/* send and receive msg to/from hipd */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");
	_HIP_DEBUG("send_recv msg succeed\n");


	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "Got erroneous message!\n");
	
	HIP_DEBUG("Send_recv msg succeed \n");
	
 out_err:
	if (msg)
		free(msg);
	return err;
}
