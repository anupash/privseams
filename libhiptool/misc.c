/*
 * Miscellaneous functions
 *
 * Licence: GNU/GPL
 * Authors:
 * - Miika Komu <miika@iki.fi>
 * - Mika Kousa <mkousa@cc.hut.fi>
 */

#include "misc.h"



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

void hip_xor_hits(hip_hit_t *res, const hip_hit_t *hit1, const hip_hit_t *hit2)
{
	res->s6_addr32[0] = hit1->s6_addr32[0] ^ hit2->s6_addr32[0];
	res->s6_addr32[1] = hit1->s6_addr32[1] ^ hit2->s6_addr32[1];
	res->s6_addr32[2] = hit1->s6_addr32[2] ^ hit2->s6_addr32[2];
	res->s6_addr32[3] = hit1->s6_addr32[3] ^ hit2->s6_addr32[3];
}

int hip_is_hit(const hip_hit_t *hit) 
{
	HIP_DEBUG_IN6ADDR("received hit", (struct in6_addr *)hit);
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

void khi_expand(unsigned char *dst, int *dst_index, unsigned char *src,
		int src_len) {
	int index; 

	for (index = 0; index < src_len; ) {
		if ((*dst_index % 16) > 11) {
			dst[*dst_index] = 0;
			(*dst_index)++;
		} else {
			dst[*dst_index] = src[index];
			index++;
			(*dst_index)++;
		}
	}
}

/* the lengths are in bits */
int khi_encode(unsigned char *orig, int orig_len, unsigned char *encoded,
	       int encoded_len) {
	BIGNUM *bn = NULL;
	int err = 0, shift = (orig_len - encoded_len) / 2, len;

	HIP_IFEL((encoded_len > orig_len), -1, "len mismatch\n");
	HIP_IFEL((!(bn = BN_bin2bn(orig, orig_len / 8, NULL))), -1,
		 "BN_bin2bn\n");
	HIP_IFEL(!BN_rshift(bn, bn, shift), -1, "BN_lshift\n");
	HIP_IFEL(!BN_mask_bits(bn, encoded_len), -1,
		"BN_mask_bits\n");
	HIP_IFEL((bn2bin_safe(bn, encoded, encoded_len / 8)
		  != encoded_len / 8), -1,
		  "BN_bn2bin_safe\n");

	HIP_HEXDUMP("encoded: ", encoded, encoded_len / 8);

 out_err:
	if(bn)
		BN_free(bn);
	return err;
}

/* draft-laganier-khi-00:
 *
 * A KHI is generated using the algorithm below, which takes as input a
 * bitstring and a context identifier:
 *   
 * Input      :=  any bitstring
 * Hash Input :=  Context ID | Input
 * Hash       :=  SHA1( Expand( Hash Input ) )
 * KHI        :=  Prefix | Encode_n( Hash )
 *
 * where:
 *   
 * | : Denotes concatenation of bitstrings
 *   
 * Input :      A bitstring unique or statistically unique within a
 *              given context intended to be associated with the
 *              to-be-created KHI in the given context.
 *   
 * Context ID : A randomly generated value defining the expected usage
 *              context the the particular KHI.
 *   
 *              As a baseline (TO BE DISCUSSED), we propose sharing 
 *              the name space introduced for CGA Type Tags; see
 *              http://www.iana.org/assignments/cga-message-types
 *              and RFC 3972.
 *   
 * Expand( ) :  An expansion function designed to overcome recent
 *              attacks on SHA1.
 *   
 *              As a baseline (TO BE DISCUSSED), we propose inserting
 *              four (4) zero (0) bytes after every twelve (12) bytes
 *              of the argument bitstring.
 *   
 * Encode_n( ): An extraction function which output is obtained by
 *              extracting an <n>-bits-long bitstring from the 
 *              argument bitstring.
 *   
 *              As a baseline (TO BE DISCUSSED), we propose taking
 *              <n> middlemost bits from the SHA1 output.
 */
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

       /* some extra space for the zeroes */
       khi_data_len += (khi_data_len / 12) * 4;
       
       _HIP_DEBUG("key_rr_len=%u\n", key_rr_len);
       HIP_IFE(hit_type != HIP_HIT_TYPE_HASH120, -ENOSYS);
       _HIP_HEXDUMP("key_rr", key_rr, key_rr_len);

       /* Hash Input :=  Context ID | Input */
       khi_data = HIP_MALLOC(khi_data_len, 0);
       khi_index = 0;

       /* Expand( Hash Input ): As a baseline (TO BE DISCUSSED), we propose
	  inserting four (4) zero (0) bytes after every twelve (12) bytes
	  of the argument bitstring. */
       khi_expand(khi_data, &khi_index, khi_context_id,
		  sizeof(khi_context_id));
       khi_expand(khi_data, &khi_index, key_rr, key_rr_len);

       HIP_ASSERT(khi_index == khi_data_len);

       HIP_HEXDUMP("khi data", khi_data, khi_data_len);

       /* Hash :=  SHA1( Expand( Hash Input ) ) */
       HIP_IFEL((err = hip_build_digest(HIP_DIGEST_SHA1, khi_data,
					khi_data_len, digest)), err,
		"Building of digest failed\n");

       HIP_HEXDUMP("digest", digest, sizeof(digest));

       /* Encode_n( ): An extraction function which output is obtained by
	  extracting an <n>-bits-long bitstring from the 
	  argument bitstring. As a baseline (TO BE DISCUSSED), we propose
	  taking <n> middlemost bits from the SHA1 output. */
       HIP_ASSERT(HIP_HIT_PREFIX_LEN == 8);
       HIP_IFEL(khi_encode(digest, sizeof(digest) * 8,
			   ((u8 *) hit) + 1,
			   sizeof(hip_hit_t) * 8 - HIP_HIT_PREFIX_LEN),
		-1, "encoding failed\n");

       hit->in6_u.u6_addr8[0] = 0x00;
       hit->in6_u.u6_addr8[0] |= HIP_HIT_TYPE_MASK_120;

       HIP_DEBUG_HIT("calculated HIT: ", hit);

 out_err:
       if (khi_data)
	       HIP_FREE(khi_data);

       return err;
}

/*
 * XX TODO: HAA
 */
int hip_dsa_host_id_to_hit_old(const struct hip_host_id *host_id,
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
       HIP_IFE(hit_type != HIP_HIT_TYPE_HASH120, -ENOSYS);
       _HIP_HEXDUMP("key_rr", key_rr, key_rr_len);
       HIP_IFEL((err = hip_build_digest(HIP_DIGEST_SHA1, key_rr, key_rr_len, digest)), err, 
		"Building of digest failed\n");

       /* hit_120 := concatenate ( 01000000 , low_order_bits ( digest, 120 ) ) */

       memcpy(hit, digest + (HIP_AH_SHA_LEN - sizeof(struct in6_addr)),
	      sizeof(struct in6_addr));

       //hit->in6_u.u6_addr8[0] &= 0x3f; // clear the upmost bits

       hit->in6_u.u6_addr8[0] = 0x00; // clear all the upmost bits - draft-ietf-hip-base-03
       hit->in6_u.u6_addr8[0] |= HIP_HIT_TYPE_MASK_120;

 out_err:

       return err;
}

/*
 * XX TODO: HAA
 * XX TODO: which one to use: this or the function just below?
 */
int hip_dsa_host_id_to_hit_old2(const struct hip_host_id *host_id,
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
       HIP_IFE(hit_type != HIP_HIT_TYPE_HASH120, -ENOSYS);
       _HIP_HEXDUMP("key_rr", key_rr, key_rr_len);
       HIP_IFEL((err = hip_build_digest(HIP_DIGEST_SHA1, key_rr, key_rr_len, digest)), err, 
		"Building of digest failed\n");

       /* hit_120 := concatenate ( 01000000 , low_order_bits ( digest, 120 ) ) */

       memcpy(hit, digest + (HIP_AH_SHA_LEN - sizeof(struct in6_addr)),
	      sizeof(struct in6_addr));

       //hit->in6_u.u6_addr8[0] &= 0x3f; // clear the upmost bits

       hit->in6_u.u6_addr8[0] = 0x00; // clear all the upmost bits - draft-ietf-hip-base-03
       hit->in6_u.u6_addr8[0] |= HIP_HIT_TYPE_MASK_120;

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


/**
 * check_and_create_dir - check and create a directory
 * @dirname: the name of the directory
 * @mode:    creation mode for the directory, if it does not exist
 *
 * Returns: 0 if successful, or negative on error.
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
  char *pubfilename;
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

    err = hip_private_dsa_to_hit(dsa_key, dsa_key_rr, HIP_HIT_TYPE_HASH120,
				 &dsa_lhi.hit);
    if (err) {
      HIP_ERROR("Conversion from DSA to HIT failed\n");
      goto out;
    }

    HIP_DEBUG_HIT("DSA HIT", &dsa_lhi.hit);

    err = hip_private_dsa_to_hit(dsa_pub_key, dsa_pub_key_rr,
				 HIP_HIT_TYPE_HASH120, 
				 &dsa_pub_lhi.hit);
    if (err) {
      HIP_ERROR("Conversion from DSA to HIT failed\n");
      goto out;
    }
    HIP_DEBUG_HIT("DSA HIT", &dsa_pub_lhi.hit);
    
    err = hip_private_rsa_to_hit(rsa_key, rsa_key_rr, HIP_HIT_TYPE_HASH120,
				 &rsa_lhi.hit);
    if (err) {
      HIP_ERROR("Conversion from RSA to HIT failed\n");
      goto out;
    }
    HIP_DEBUG_HIT("RSA HIT", &rsa_lhi.hit);

    err = hip_private_rsa_to_hit(rsa_pub_key, rsa_pub_key_rr,
				 HIP_HIT_TYPE_HASH120, 
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
  
  return err;
}

#endif /* ! __KERNEL__ */
