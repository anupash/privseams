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

#include "security.h"
#include "crypto/dh.h"
#include "hip.h"
#include "debug.h"

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
