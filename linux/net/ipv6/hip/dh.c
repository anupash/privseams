/*
 * HIPL security related functions
 *
 * Licence: GNU/GPL
 *
 * Authors:
 * - Mika Kousa <mkousa@cc.hut.fi>
 * - Kristian Slavov <ksl@iki.fi>
 */ 

#ifdef __KERNEL__
#  include <linux/in6.h>
#  include <linux/xfrm.h>
#  include <net/xfrm.h>
#  include <net/ipv6.h>
#endif /* __KERNEL__ */

#include "dh.h"
#include "crypto/dh.h"
#include "hip.h"
#include "debug.h"

spinlock_t dh_table_lock = SPIN_LOCK_UNLOCKED;
DH *dh_table[HIP_MAX_DH_GROUP_ID] = {0};

/**
 * hip_insert_dh - Insert the current DH-key into the buffer
 *
 * If a DH-key does not exist, we will create one.
 * Returns: >0 if ok, -1 if errors
 */
int hip_insert_dh(u8 *buffer, int bufsize, int group_id)
{
	size_t res;
	DH *tmp;

/*
 * First check that we have the key available.
 * Then encode it into the buffer
 */

	if (dh_table[group_id] == NULL) {
		tmp = hip_generate_dh_key(group_id);

		spin_lock(&dh_table_lock);
		dh_table[group_id] = tmp;
		spin_unlock(&dh_table_lock);

		if (dh_table[group_id] == NULL) {
			HIP_ERROR("DH key %d not found and could not create it\n",
				  group_id);
			return -1;
		}
	}

	/* race condition problem... */
	tmp = hip_dh_clone(dh_table[group_id]);

	if (!tmp) {
		HIP_ERROR("Could not clone DH-key\n");
		return -2;
	}

	res = hip_encode_dh_publickey(tmp,buffer,bufsize);
	if (res < 0) {
		HIP_ERROR("Encoding error\n");
		hip_free_dh_structure(tmp);
		return -3;
	}

	hip_free_dh_structure(tmp);
	return res;
}



/**
 * hip_generate_shared_secret - Generate Diffie-Hellman shared secret
 * @group_id: DH group id
 * @peerkey: Peer's DH public key
 * @peer_len: Length of the peer's DH public key
 * @out: Shared secret buffer
 * @outlen: Length of the output buffer
 *
 * Returns 0, if ok, <0 if error occurs.
 */
int hip_generate_shared_secret(int group_id, u8* peerkey, size_t peer_len, u8 *out, size_t outlen)
{
	DH *tmp;
	int k;

	if (dh_table[group_id] == NULL) {
		HIP_ERROR("No DH-key found for group_id: %d\n",group_id);
		return -1;
	}

	/* race */
	tmp = hip_dh_clone(dh_table[group_id]);

	if (!tmp) {
		HIP_ERROR("Error cloning DH key\n");
		return -3;
	}

	k = hip_gen_dh_shared_key(tmp,peerkey,peer_len,out,outlen);
	if (k < 0) {
		HIP_ERROR("Shared key failed\n");
		hip_free_dh_structure(tmp);
		return -2;
	}

	hip_free_dh_structure(tmp);
	return k;
}       

/**
 * hip_calculate_shared_secret - Creates a shared secret based on the
 * public key of the peer (passed as an argument) and own DH private key
 * (created beforehand).
 * @dhf: Peer's Diffie-Hellman public key
 * @buffer: Buffer that holds enough space for the shared secret.
 *
 * Returns the length of the shared secret in octets if successful,
 * or -1 if an error occured.
 */
int hip_calculate_shared_secret(struct hip_diffie_hellman *dhf, u8* buffer, 
				int bufsize)
{
	signed int len;
	int err;

	if (dh_table[dhf->group_id] == NULL) {
		HIP_ERROR("Unsupported DH group: %d\n",dhf->group_id);
		return -1;
        }

	len = hip_get_param_contents_len(dhf) - 1;
	_HIP_HEXDUMP("PEER DH key:",(dhf + 1),len);
	err = hip_gen_dh_shared_key(dh_table[dhf->group_id], (u8*)(dhf+1), len,
				    buffer, bufsize);
	if (err < 0) {
                HIP_ERROR("Could not create shared secret\n");
		return -1;
        }

	return err;
}


/**
 * hip_regen_dh_keys - Regenerate Diffie-Hellman keys for HIP
 * @bitmask: Mask of groups to generate.
 *
 * Use only this function to generate DH keys.
 */
void hip_regen_dh_keys(u32 bitmask)
{
	DH *tmp,*okey;
	int maxmask,i;
	int cnt = 0;

	/* if MAX_DH_GROUP_ID = 4 --> maxmask = 0...01111 */
	maxmask = (1 << (HIP_MAX_DH_GROUP_ID+1)) - 1;
	bitmask &= maxmask;

	for(i=1; i<=HIP_MAX_DH_GROUP_ID; i++) {
		if (bitmask & (1 << i)) {
			tmp = hip_generate_dh_key(i);
			if (!tmp) {
				HIP_INFO("Error while generating group: %d\n",i);
				continue;
			}

			spin_lock(&dh_table_lock);
			okey = dh_table[i];
			dh_table[i] = tmp;
			spin_unlock(&dh_table_lock);

			hip_free_dh_structure(okey);

			cnt++;

			HIP_DEBUG("DH key for group %d generated\n",i);
		} 
	}
	HIP_DEBUG("%d keys generated\n",cnt);
}

/**
 * hip_get_dh_size - determine the size for required to store DH shared secret
 * @hip_dh_group_type: the group type from DIFFIE_HELLMAN parameter
 *
 * Returns: 0 on failure, or the size for storing DH shared secret in bytes
 */
uint16_t hip_get_dh_size(uint8_t hip_dh_group_type)
{
	/* the same values as are supported ? HIP_DH_.. */
	int dh_size[] = { 0, 384, 768, 1536, 3072, 6144, 8192 };
	uint16_t ret = -1;

	_HIP_DEBUG("dh_group_type=%u\n", hip_dh_group_type);
	if (hip_dh_group_type == 0) 
		HIP_ERROR("Trying to use reserved DH group type 0\n");
	else if (hip_dh_group_type == HIP_DH_384)
		HIP_ERROR("draft-09: Group ID 1 does not exist yet\n");
	else if (hip_dh_group_type > ARRAY_SIZE(dh_size))
		HIP_ERROR("Unknown/unsupported MODP group %d\n", hip_dh_group_type);
	else
		ret = dh_size[hip_dh_group_type] / 8;

	return ret + 1;
}

void hip_dh_uninit(void) {
	int i;
	for(i=1;i<HIP_MAX_DH_GROUP_ID;i++) {
		if (dh_table[i] != NULL) {
			hip_free_dh_structure(dh_table[i]);
			dh_table[i] = NULL;
		}
	}	
}

