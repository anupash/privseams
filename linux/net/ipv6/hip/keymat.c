/*
 * This file contains KEYMAT handling functions for HIPL.
 *  
 * Authors:
 * - Mika Kousa <mkousa@cc.hut.fi>
 * - Kristian Slavov <ksl@iki.fi>
 *
 *  TODO:
 *  - include copyright information here
 */

#include <linux/crypto.h>
#include <asm/scatterlist.h>


#include "keymat.h"
#include "misc.h"
#include "debug.h"
#include "hip.h"


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
 * @calc_index: where the one byte index is stored (n of Kn)
 *
 */
void hip_make_keymat(char *kij, size_t kij_len, struct hip_keymat_keymat *keymat, 
		     void *dstbuf, size_t dstbuflen, struct in6_addr *hit1,
		     struct in6_addr *hit2, u8 *calc_index)
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

	if (dstbuflen < HIP_AH_SHA_LEN) {
		HIP_ERROR("dstbuf is too short (%d)\n", dstbuflen);
		return;
	}

	_HIP_ASSERT(dstbuflen % 32 == 0);
	HIP_ASSERT(sizeof(index_nbr) == HIP_KEYMAT_INDEX_NBR_SIZE);

	hit1_is_bigger = hip_hit_is_bigger(hit1, hit2);

	bigger_hit =  hit1_is_bigger ? hit1 : hit2;
	smaller_hit = hit1_is_bigger ? hit2 : hit1;

	_HIP_HEXDUMP("bigger hit", bigger_hit, 16);
	_HIP_HEXDUMP("smaller hit", smaller_hit, 16);
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

	if (calc_index)
		*calc_index = index_nbr;
	else
		HIP_ERROR("NULL calc_index\n");

	_HIP_DEBUG("keymat index_nbr=%u\n", index_nbr);
	HIP_HEXDUMP("GENERATED KEYMAT: ", dstbuf, dstbuflen);
	if (shabuffer)
		kfree(shabuffer);

	return;
}

/**
 * hip_keymat_draw - draw keying material
 * @keymat: pointer to the keymat structure which contains information
 *          about the actual
 * @length: size of keymat structure
 *
 * Returns: pointer the next point where one can draw the next keymaterial
 */
void* hip_keymat_draw(struct hip_keymat_keymat* keymat, int length)
{
	/* todo: remove this function */
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

/** hip_keymat_get_new - calculate new keying material
 * @key: buffer where the created KEYMAT is stored
 * @key_len: length of @key in bytes
 * @kij: Kij, shared key
 * @kij_len: length of @kij in bytes
 * @keymat_index: Keymat Index
 * @calc_index: the one byte index value
 * @calc_index_keymat: Kn
 * @Kn_is_at: the byte offset where @calc_index_keymat starts
 *
 * This function gets next @key_len bytes of KEYMAT to @key starting
 * from requested offset @keymat_index. On entry of this function
 * @calc_index tells the one byte index value which is related to
 * @calc_index_keymat (for example, if @calc_index_keymat is K3, then
 * @calc_index is 3).
 *
 * On successful return @keymat_index and @calc_index contain the
 * values used in the last round of calculating Kn of KEYMAT,
 * @calc_index_keymat contains the last Kn, and @Kn_is_at contains the
 * byte offset value of @calc_index_keymat.
 *
 * Returns: 0 on success, < 0 otherwise.
*/
int hip_keymat_get_new(void *key, size_t key_len, char *kij, size_t kij_len,
		       uint16_t *keymat_index, uint8_t *calc_index,
		       unsigned char *calc_index_keymat, uint16_t *Kn_is_at)
{
	/* must have the hadb lock when calling this function */
	int err = 0;
	int copied = 0;
	u8 *tmp_data = NULL;
	size_t tmp_data_len;

	HIP_DEBUG("key_len=%d, requested keymat_index=%u calc_index=%u Kn_is_at=%u\n",
		  key_len, *keymat_index, *calc_index, *Kn_is_at);
	HIP_HEXDUMP("calc_index_keymat", calc_index_keymat, HIP_AH_SHA_LEN);

 	if (key_len == 0 || kij_len == 0) {
		HIP_ERROR("key_len = 0 or kij_len = 0\n");
		err = -EINVAL;
		goto out_err;
	}

	_HIP_DEBUG("one byte index at req'd index in the end should be %u\n",
		  (*keymat_index / HIP_AH_SHA_LEN + 1) % 256);

	if (*keymat_index < *Kn_is_at) {
		HIP_ERROR("requested keymat index %u is lower than lowest keymat index of Kn (%u)\n",
			  *keymat_index, *Kn_is_at);
		err = -EINVAL;
		goto out_err;
	}
	/* todo: check here if we have to test *keymat_index < entry->current_keymat_index ? */

	/* before calculating any hashes test if we already have
	 * needed amount of ready keymat
	 *
	 * must first check that the requested keymat_index is within the ready keymat
	 */
	if (*keymat_index - *Kn_is_at < HIP_AH_SHA_LEN) {
		int tmp = HIP_AH_SHA_LEN - (*keymat_index - *Kn_is_at);
		HIP_DEBUG("test: can copy %d bytes from the end of sha K\n", tmp);
		if (tmp > HIP_AH_SHA_LEN) {
			HIP_ERROR("bug: tmp > 20\n");
			err = -EINVAL;
			goto out_err;
		}

		if (tmp > 0) {
			memcpy(key, calc_index_keymat + HIP_AH_SHA_LEN - tmp, tmp);
			copied += tmp;
		}
	}

	HIP_DEBUG("copied=%d\n", copied);
	HIP_HEXDUMP("KEY (0)", key, copied);

	if (copied == key_len) {
		HIP_DEBUG("copied all, return\n");
		goto out;
	}

	HIP_DEBUG("need %d bytes more data\n", key_len-copied);

	tmp_data_len = kij_len + HIP_AH_SHA_LEN + 1;
	tmp_data = kmalloc(tmp_data_len, GFP_KERNEL);
	if (!tmp_data) {
		HIP_ERROR("kmalloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	memcpy(tmp_data, kij, kij_len); /* fixed part of every Kn round */

	while (copied < key_len) {
		(*calc_index)++;
		HIP_DEBUG("calc_index=%u\n", *calc_index);
		/* create Kn = SHA-1( Kij | Kn-1 | calc_index) */

		/* Kij | Kn-1 */
		memcpy(tmp_data+kij_len, calc_index_keymat, HIP_AH_SHA_LEN);
		/* Kij | Kn-1 | calc_index */
		memcpy(tmp_data+kij_len+HIP_AH_SHA_LEN, calc_index, HIP_KEYMAT_INDEX_NBR_SIZE);
		/* SHA-1( Kij | Kn-1 | calc_index) */
		err = hip_build_digest(HIP_DIGEST_SHA1, tmp_data, tmp_data_len, calc_index_keymat);
		if (err) {
			HIP_ERROR("build_digest failed (K%u)\n", *calc_index);
			goto out_err;
		}
		*Kn_is_at += HIP_AH_SHA_LEN;
#if 1
		HIP_DEBUG("keymat K%u from offset %u\n", *calc_index, *Kn_is_at);
		HIP_HEXDUMP("", calc_index_keymat, HIP_AH_SHA_LEN);
#endif
		if (*Kn_is_at + HIP_AH_SHA_LEN < *keymat_index) {
			HIP_DEBUG("skip until we are at right offset\n");
			continue;
		}

		HIP_DEBUG("copied=%u, key_len=%u calc_index=%u dst to 0x%p\n", copied, key_len, *calc_index, key+copied);
		if (copied + HIP_AH_SHA_LEN <= key_len) {
			HIP_DEBUG("copy whole sha block\n");
			memcpy(key+copied, calc_index_keymat, HIP_AH_SHA_LEN);
			copied += HIP_AH_SHA_LEN;
		} else {
			int t = HIP_AH_SHA_LEN - key_len % HIP_AH_SHA_LEN;
			t = key_len - copied;
			HIP_DEBUG("copy partial %d bytes\n", t);
			memcpy(key+copied, calc_index_keymat, t);
			copied += t;
		}
	}

	HIP_DEBUG("end: copied=%u\n", copied);

 out:
	HIP_HEXDUMP("CALCULATED KEY", key, key_len);
	HIP_DEBUG("at end: *keymat_index=%u *calc_index=%u\n",
		  *keymat_index, *calc_index);
 out_err:
	if(tmp_data)
		kfree(tmp_data);
	return err;
}


/** hip_update_entry_keymat - update HADB's KEYMAT related information
 * @entry: HADB entry to be update
 * @new_keymat_index: new Keymat Index value
 * @new_calc_index: new one byte value
 * @new_current_keymat: Kn related to @new_calc_index
 *
 */
void hip_update_entry_keymat(struct hip_hadb_state *entry, 
			     uint16_t new_keymat_index, uint8_t new_calc_index,
			     unsigned char *new_current_keymat)
{
	/* must have the hadb lock when calling this function */
	entry->current_keymat_index = new_keymat_index;
	entry->keymat_calc_index = new_calc_index;
	HIP_DEBUG("New Entry keymat data: current_keymat_index=%u keymat_calc_index=%u\n",
		  entry->current_keymat_index, entry->keymat_calc_index);
	if (new_current_keymat) {
		memcpy(entry->current_keymat_K, new_current_keymat, HIP_AH_SHA_LEN);
		HIP_HEXDUMP("new_current_keymat", new_current_keymat, HIP_AH_SHA_LEN);
	}
}
