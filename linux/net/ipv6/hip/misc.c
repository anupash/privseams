/*
 * Miscellaneous functions
 *
 * Licence: GNU/GPL
 * Authors:
 * - Miika Komu <miika@iki.fi>
 * - Mika Kousa <mkousa@cc.hut.fi>
 */

#include <net/ipv6.h>

#include "misc.h"
#include "debug.h"
#include "builder.h"
#include "hip.h"

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

       HIP_DEBUG("key_rr_len=%u\n", key_rr_len);

       if (hit_type != HIP_HIT_TYPE_HASH126) {
               err = -ENOSYS;
               goto out_err;
       }

       _HIP_HEXDUMP("key_rr", key_rr, key_rr_len);

       err = hip_build_digest(HIP_DIGEST_SHA1, key_rr, key_rr_len, digest);
       if (err) {
               HIP_ERROR("Building of digest failed\n");
               goto out_err;
       }

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
	int err = 0;
	u8 digest[HIP_AH_SHA_LEN];

	char *key_rr = (char *) (host_id + 1); /* skip the header, 
											  Is this right? */

	/* hit excludes rdata but it is included in hi_length;
	   subtract rdata */
	unsigned int key_rr_len = ntohs(host_id->hi_length) -
			sizeof(struct hip_host_id_key_rdata);
	
	HIP_DEBUG("key_rr_len=%u\n", key_rr_len);
	
	if (hit_type != HIP_HIT_TYPE_HASH126) {
		err = -ENOSYS;
		goto out_err;
	}

	_HIP_HEXDUMP("key_rr", key_rr, key_rr_len);
	
	err = hip_build_digest(HIP_DIGEST_SHA1, key_rr, key_rr_len, digest);
	if (err) {
			HIP_ERROR("Building of digest failed\n");
			goto out_err;
	}
	
	/* XX FIXME: THIS WRONG (JUST FOR RSA TESTING) */

	memcpy(hit,  digest + (HIP_AH_SHA_LEN - sizeof(struct in6_addr)),
		   sizeof(struct in6_addr));

	hit->in6_u.u6_addr8[0] &= 0x3f; // clear the upmost bits
	hit->in6_u.u6_addr8[0] |= HIP_HIT_TYPE_MASK_126;
 
 out_err:
	return err;
}

int hip_host_id_to_hit(const struct hip_host_id *host_id,
		       struct in6_addr *hit, int hit_type)
{
	int algo = hip_get_host_id_algo(host_id);
	int err = 0;

	if (algo == HIP_HI_DSA) {
		err = hip_dsa_host_id_to_hit(host_id, hit,
						     hit_type);
	} else if (algo == HIP_HI_RSA) {
		err = hip_rsa_host_id_to_hit(host_id, hit,
						     hit_type);
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
	host_id_pub = kmalloc(total_len, GFP_KERNEL);
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
		kfree(host_id_pub);

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
	host_id_pub = kmalloc(total_len, GFP_KERNEL);
	if (!host_id_pub) {
		err = -EFAULT;
		goto out_err;
	}
	memset(host_id_pub, 0, total_len);

	/* How do we extract the public key from the hip_host_id 
	   struct? TODO: CHECK THIS */
	memcpy(host_id_pub, host_id,
	       sizeof(struct hip_tlv_common) + contents_len);

	_HIP_HEXDUMP("extracted pubkey", host_id_pub,
				 hip_get_param_total_len(host_id_pub));

	err = hip_rsa_host_id_to_hit(host_id_pub, hit, hit_type);

	if (err) {
			HIP_ERROR("Failed to convert HI to HIT.\n");
			goto out_err;
	}

 out_err:
	
	if (host_id_pub)
			kfree(host_id_pub);
	
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
 * hip_set_sockaddr - init sockaddr and copy given address to it
 * @addr: IPv6 address to be copied
 * @sin: sockaddr where @addr is copied
 */
void hip_set_sockaddr(struct sockaddr_in6 *sin, struct in6_addr *addr)
{
	memset(sin, 0, sizeof(struct sockaddr_in6));

	sin->sin6_family = AF_INET6;
	sin->sin6_port = 0;  // Is this needed?

	ipv6_addr_copy(&sin->sin6_addr, addr);

	return;
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
/**
 * hip_lhi_are_equal - compare two LHIs (Localhost Host Identity)
 * @lhi1: the first LHI used in comparison
 * @lhi2: the second LHI used in comparison
 *
 * Returns: 1 if @lhi1 and @lhi2 are equal, else 0.
 */
int hip_lhi_are_equal(const struct hip_lhi *lhi1,
		      const struct hip_lhi *lhi2) 
{
	return !ipv6_addr_cmp(&lhi1->hit, &lhi2->hit);
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
int hip_hash_spi(void *key, int range)
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
int hip_hash_hit(void *key, int range)
{
	hip_hit_t *hit = (hip_hit_t *)key;

	/* HITs are random. (at least the 64 LSBs)  */
	return (hit->s6_addr32[2] ^ hit->s6_addr32[3]) % range;
}

int hip_match_hit(void *hitA, void *hitB)
{
	hip_hit_t *key_1, *key_2;

	key_1 = (hip_hit_t *)hitA;
	key_2 = (hip_hit_t *)hitB;

	return !ipv6_addr_cmp(key_1, key_2);
}
