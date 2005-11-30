#include "xfrm.h"
#include "debug.h"

int hip_delete_sa(u32 spi, struct in6_addr *dst) {
	return -1; /* XX FIXME: REWRITE USING XFRM */
}

uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit) {
	return -1; /* XX FIXME: REWRITE USING XFRM */
}

/* Security associations in the kernel with BEET are bounded to the outer
 * address, meaning IP addresses. As a result the parameters to be given
 * should be such an addresses and not the HITs.
 */
uint32_t hip_add_sa(struct in6_addr *saddr, struct in6_addr *daddr,
		    struct in6_addr *src_hit, struct in6_addr *dst_hit,
		     uint32_t *spi, int ealg,
		     struct hip_crypto_key *enckey,
		     struct hip_crypto_key *authkey,
		     int already_acquired,
		     int direction) {
	/* XX FIX: how to deal with the direction? */

	int err = 0, enckey_len, authkey_len;
	int aalg = ealg;

	HIP_ASSERT(spi);

	enckey_len = hip_enc_key_length(ealg);
	authkey_len = hip_auth_key_length_esp(aalg);
	if (enckey <= 0 || authkey_len <= 0) {
		err = -1;
		HIP_ERROR("Bad enc or auth key len\n");
		goto out_err;
	}

	/* XX CHECK: is there some kind of range for the SPIs ? */
	if (!already_acquired)
		get_random_bytes(spi, sizeof(uint32_t));

	HIP_IFE(hip_xfrm_state_modify(XFRM_MSG_NEWSA, saddr, daddr, 
				      src_hit, dst_hit, *spi,
				      ealg, enckey, enckey_len, aalg,
				      authkey, authkey_len), -1);
 out_err:
	return err;
}

int hip_setup_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit,
			  struct in6_addr *src_addr,
			  struct in6_addr *dst_addr, u8 proto,
			  int use_full_prefix)
{
	int err = 0;
	u8 prefix = (use_full_prefix) ? 128 : HIP_HIT_PREFIX_LEN;

	/* XX FIXME: remove the proto argument */

	HIP_IFE(hip_xfrm_policy_modify(XFRM_MSG_NEWPOLICY, dst_hit, src_hit,
				       src_addr, dst_addr,
				       XFRM_POLICY_IN, proto, prefix), -1);
	HIP_IFE(hip_xfrm_policy_modify(XFRM_MSG_NEWPOLICY, src_hit, dst_hit,
				       dst_addr, src_addr,
				       XFRM_POLICY_OUT, proto, prefix), -1);
 out_err:
	return err;
}

void hip_delete_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit, u8 proto,
			    int use_full_prefix)
{
	u8 prefix = (use_full_prefix) ? 128 : HIP_HIT_PREFIX_LEN;

	hip_xfrm_policy_delete(src_hit, src_hit, XFRM_POLICY_IN, proto,
			       prefix);
	hip_xfrm_policy_delete(dst_hit, dst_hit, XFRM_POLICY_OUT, proto,
			       prefix);
}

void hip_delete_default_prefix_sp_pair() {
	hip_hit_t src_hit, dst_hit;
	memset(&src_hit, 0, sizeof(hip_hit_t));
	memset(&dst_hit, 0, sizeof(hip_hit_t));

	/* See the comment in hip_setup_sp_prefix_pair() */
	src_hit.s6_addr32[0] = htons(HIP_HIT_PREFIX);
	dst_hit.s6_addr32[0] = htons(HIP_HIT_PREFIX);

	hip_delete_hit_sp_pair(&src_hit, &dst_hit, 0, 0);
}

int hip_setup_default_sp_prefix_pair() {
	int err = 0;
	hip_hit_t src_hit, dst_hit;

	memset(&src_hit, 0, sizeof(hip_hit_t));
	memset(&dst_hit, 0, sizeof(hip_hit_t));

	/* The OUTGOING and INCOMING policy is set to the generic value */

	src_hit.s6_addr32[0] = htons(HIP_HIT_PREFIX);
	dst_hit.s6_addr32[0] = htons(HIP_HIT_PREFIX);

	HIP_IFE(hip_setup_hit_sp_pair(&src_hit, &dst_hit, NULL, NULL, 0, 0),
		-1);

 out_err:
	return err;
}
