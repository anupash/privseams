/*
 * This file contains SHA support and for HIPL.
 *
 * SHA-1 was copied from 2.4.18 (public domain)
 *  
 *  TODO:
 *  - the copy of the SHA-XX algos are not needed, remove them!
 *  - remove SHA-1 and use cryptoapi
 *  - this file is a kludge: update HIPL kernel version or import the
 *    required sha modules
 *  - include copyright information here
 *  - change the running number (1,2,3...) to keymat
 */

/****************************** SHA-1 ********************************/

#define SHA1HANDSOFF /* Copies data before messing with it. */

#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/byteorder.h>

#include <net/hip.h>

#include "debug.h"
#include "hip.h"

/**
 * keymat_hit_is_bigger - compare two HITs
 * @hit1: the first HIT to be compared
 * @hit2: the second HIT to be compared
 *
 * Returns: 1 if @hit1 was bigger than @hit2, or else 0
 */
int keymat_hit_is_bigger(const struct in6_addr *hit1,
			 const struct in6_addr *hit2)
{
	int i;

	for (i=0; i<sizeof(struct in6_addr); i++) {
		if (hit1->s6_addr[i] > hit2->s6_addr[i])
			return 1;
		if (hit1->s6_addr[i] < hit2->s6_addr[i])
			return 0;
	}

	return 0;
}

u8 *hip_create_keymat_buffer(u8 *kij, size_t kij_len, size_t hash_len, 
			     struct in6_addr *smaller_hit,
			     struct in6_addr *bigger_hit)

{
	u8 *buffer;
	size_t requiredmem;

	if (2 * sizeof(struct in6_addr) < hash_len)
		requiredmem = kij_len + hash_len + sizeof(u8);
	else
		requiredmem = kij_len + 2 * sizeof(struct in6_addr) +
			sizeof(u8);


	buffer = kmalloc(requiredmem, GFP_KERNEL);
	if (!buffer) {
		HIP_ERROR("Out of memory\n");
		return buffer;
	}

	memcpy(buffer,kij,kij_len);
	memcpy(buffer+kij_len,(u8 *)smaller_hit,sizeof(struct in6_addr));
	memcpy(buffer+kij_len+sizeof(struct in6_addr),(u8 *)bigger_hit,
	       sizeof(struct in6_addr));
	*(buffer+kij_len+sizeof(struct in6_addr)*2) = 1;

	return buffer;
}

void hip_update_keymat_buffer(u8 *keybuf, u8 *Kold, size_t Kold_len, 
			      size_t Kij_len, u8 cnt)
{
	HIP_ASSERT(keybuf);

	memcpy(keybuf+Kij_len, Kold, Kold_len);
	*(keybuf + Kij_len + Kold_len) = cnt;

	return;
}

/**
 * hip_make_keymat - generate HIP keying material
 * @kij:     Diffie-Hellman Kij (as in the HIP drafts)
 * @kij_len: the length of the Kij material
 * @keymat:  pointer to a keymat structure which will be updated according
 *           to the generated keymaterial
 * @dstbuf:  the generated keymaterial will be written here
 * @hit1:    source HIT
 * @hit2:    destination HIT
 *
 * Dstbuflen must be a multiple of 32.
 */
void hip_make_keymat(char *kij, int kij_len, struct keymat_keymat *keymat, 
		     void *dstbuf, int dstbuflen, struct in6_addr *hit1,
		     struct in6_addr *hit2)
{
	int err;
	struct crypto_tfm *sha = impl_sha1;
	uint8_t index_nbr = 1;
	int dstoffset = 0;
	void *seedkey;
	struct in6_addr *smaller_hit, *bigger_hit;
	int hit1_is_bigger;
	u8 *shabuffer;
	struct scatterlist sg[HIP_MAX_SCATTERLISTS];
	int nsg = HIP_MAX_SCATTERLISTS;

	/* XX TODO: is this the correct one to test for 32 bit multiplicity? */
	HIP_ASSERT(dstbuflen % 32 == 0);
	HIP_ASSERT(sizeof(index_nbr) == HIP_KEYMAT_INDEX_NBR_SIZE);

	hit1_is_bigger = keymat_hit_is_bigger(hit1, hit2);

	bigger_hit =  hit1_is_bigger ? hit1 : hit2;
	smaller_hit = hit1_is_bigger ? hit2 : hit1;

	HIP_HEXDUMP("bigger hit", bigger_hit, 16);
	HIP_HEXDUMP("smaller hit", smaller_hit, 16);
	HIP_HEXDUMP("index_nbr", (char *) &index_nbr,
		    HIP_KEYMAT_INDEX_NBR_SIZE);

	shabuffer = hip_create_keymat_buffer(kij, kij_len, HIP_AH_SHA_LEN,
					     smaller_hit, bigger_hit);
	if (!shabuffer) {
		HIP_ERROR("No memory for keymat\n");
		return;
	}
	
	err = hip_map_virtual_to_pages(sg, &nsg, shabuffer, 
				       kij_len+2*sizeof(struct in6_addr)+1);
	HIP_ASSERT(!err);

	crypto_digest_digest(sha, sg, nsg, dstbuf);

	dstoffset = HIP_AH_SHA_LEN;
	index_nbr++;

	/*
	 * K2 = SHA1(Kij | K1 | 2)
	 * K3 = SHA1(Kij | K2 | 3)
	 * ...
	 */
	seedkey = dstbuf;
	hip_update_keymat_buffer(shabuffer, seedkey, HIP_AH_SHA_LEN,
				 kij_len, index_nbr);
	nsg = HIP_MAX_SCATTERLISTS;
	err = hip_map_virtual_to_pages(sg, &nsg, shabuffer, kij_len + HIP_AH_SHA_LEN + 1);
	HIP_ASSERT(!err);
	
	while (dstoffset < dstbuflen) {

		crypto_digest_digest(sha, sg, nsg, dstbuf + dstoffset);
		seedkey = dstbuf + dstoffset;

		dstoffset += HIP_AH_SHA_LEN;
		index_nbr++;

		hip_update_keymat_buffer(shabuffer, seedkey, HIP_AH_SHA_LEN,
					 kij_len, index_nbr);
	}

	keymat->offset = 0;
	keymat->keymatlen = dstoffset;
	keymat->keymatdst = dstbuf;

	_HIP_HEXDUMP("GENERATED KEYMAT: ", dstbuf, dstbuflen);

	return;
}

/**
 * hip_keymat_draw - draw keying material
 * @keymat: pointer to the keymat structure which contains information
 *          about the actual
 * @data:   currently not used
 * @length: size of keymat structure
 *
 * Returns: pointer the next point where one can draw the next keymaterial
 */
void* hip_keymat_draw(struct keymat_keymat* keymat, void* data, int length)
{
	void *ret = NULL;

	if (length > keymat->keymatlen - keymat->offset) {
		_HIP_INFO("Tried to draw more keys than are available\n");
		goto out_err;
	}

	ret = keymat->keymatdst + keymat->offset;

	keymat->offset += length;

 out_err:
	return ret;
}

