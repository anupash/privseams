/*
 * Miscellaneous functions
 *
 * Licence: GNU/GPL
 * Authors:
 * - Miika Komu <miika@iki.fi>
 * - Mika Kousa <mkousa@cc.hut.fi>
 */

#include "misc.h"

/*
 * XX TODO: HAA
 * XX TODO: which one to use: this or the function just below?
 */
int hip_dsa_host_id_to_hit(const struct hip_host_id *host_id,
		       struct in6_addr *hit, int hit_type)
{
       int err = 0;
       u8 digest[HIP_AH_SHA_LEN];
       char *key_rr = (char *) (host_id + 1); /* skip the header */
       /* hit excludes rdata but it is included in hi_length;
	  subtract rdata */
       unsigned int key_rr_len = ntohs(host_id->hi_length) -
 	 sizeof(struct hip_host_id_key_rdata);

       _HIP_DEBUG("key_rr_len=%u\n", key_rr_len);
       HIP_IFE(hit_type != HIP_HIT_TYPE_HASH126, -ENOSYS);
       _HIP_HEXDUMP("key_rr", key_rr, key_rr_len);
       HIP_IFEL((err = hip_build_digest(HIP_DIGEST_SHA1, key_rr, key_rr_len, digest)), err, 
		"Building of digest failed\n");

       /* hit_126 := concatenate ( 01 , low_order_bits ( digest, 126 ) ) */

       memcpy(hit, digest + (HIP_AH_SHA_LEN - sizeof(struct in6_addr)),
	      sizeof(struct in6_addr));
       hit->in6_u.u6_addr8[0] &= 0x3f; // clear the upmost bits
       hit->in6_u.u6_addr8[0] |= HIP_HIT_TYPE_MASK_126;

 out_err:

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

	/* XX TODO: add an extra check for the T val */

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

/** hip_timeval_diff - calculate difference between two timevalues
 * @t1: timevalue 1
 * @t2: timevalue 2
 * @result: where the result is stored
 *
 * ** CHECK comments **
 * @result = @t1 - @t2
 *
 * Code taken from http://www.gnu.org/manual/glibc-2.2.5/html_node/Elapsed-Time.html
 *
 * Returns: 1 if @t1 is equal or later than @t2, else 0.
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

/*
 * Returns 1 if the host_id contains also the "hidden" private key, else
 * returns 0.
 */
int hip_host_id_contains_private_key(struct hip_host_id *host_id)
{
	uint16_t len = hip_get_param_contents_len(host_id);
	u8 *buf = (u8 *)(host_id + 1);
	u8 t = *buf;

	return len >= 3 * (64 + 8 * t) + 2 * 20; /* PQGXY 3*(64+8*t) + 2*20 */
}

/**
 * hip_hit_is_bigger - compare two HITs
 * @hit1: the first HIT to be compared
 * @hit2: the second HIT to be compared
 *
 * Returns: 1 if @hit1 was bigger than @hit2, or else 0
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

int hip_is_hit(const hip_hit_t *hit) 
{
	return ipv6_addr_is_hit((struct in6_addr *)hit);
}

/**
 * hip_hash_spi - calculate a hash from SPI value
 * @key: 32-bit SPI value
 * @range: range of the hash
 *
 * Returns value in range: 0 <= x < @range
 */
int hip_hash_spi(const void *key, int range)
{
	u32 spi = (u32) key;
	/* SPIs are random, so simple modulo is enough? */
	return spi % range;
}

/**
 * hip_hash_hit - calculate a hash from a HIT
 * @key: pointer to a HIT
 * @range: range of the hash
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
 * hip_get_current_birthday - set the current birthday counter into the cookie
 * @bc: cookie where the birthday field is set to
 *
 * Birthday is stored in network byte order.
 *
 * This function never touches the other fields of the cookie @bc.
 */
#if 0
uint64_t hip_get_current_birthday(void)
{
	return ((uint64_t)load_time << 32) | jiffies;
}
#endif

/**
 * hip_birthday_success - compare two birthday counters
 * @old_bd: birthday counter
 * @new_bd: birthday counter used when comparing against @old_bd
 *
 * Returns: 1 (true) if new_bd is newer than old_bd, 0 (false) otherwise.
 */
int hip_birthday_success(uint64_t old_bd, uint64_t new_bd)
{
	return new_bd > old_bd;
}


/**
 * hip_enc_key_length - get encryption key length of a transform
 * @tid: transform
 *
 * Returns: the encryption key length based on the chosen transform,
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
 * @tid: transform
 *
 * Returns: the transform key length based on the chosen transform,
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
 * @tid: transform
 *
 * Returns: the authentication key length based on the chosen transform.
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
 * @ht: HIP_TRANSFORM payload where the transform is selected from
 *
 * Returns: the first acceptable Transform-ID, otherwise < 0 if no
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
 * @ht: ESP_TRANSFORM payload where the transform is selected from
 *
 * Returns: the first acceptable Suite-ID. otherwise < 0 if no
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
