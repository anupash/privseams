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

	HIP_IFE(hip_xfrm_state_modify(XFRM_MSG_NEWSA, saddr, daddr, *spi,
				      ealg, enckey, enckey_len, aalg,
				      authkey, authkey_len), -1);
 out_err:
	return err;
}

int hip_setup_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit,
			  struct in6_addr *src_addr,
			  struct in6_addr *dst_addr) {
	int err = 0;
	HIP_IFE(hip_xfrm_policy_modify(XFRM_MSG_NEWPOLICY, dst_hit, src_hit,
				       dst_addr, src_addr,
				       XFRM_POLICY_IN), -1);
	HIP_IFE(hip_xfrm_policy_modify(XFRM_MSG_NEWPOLICY, src_hit, dst_hit,
				       src_addr, dst_addr,
				       XFRM_POLICY_OUT), -1);
 out_err:
	return err;
}

void hip_delete_prefix_sp_pair() {
	hip_hit_t src_hit, dst_hit;

	src_hit.s6_addr32[0] = htonl(HIP_HIT_TYPE_MASK_120);
	dst_hit.s6_addr32[0] = htonl(HIP_HIT_TYPE_MASK_120);

	hip_xfrm_policy_delete(&src_hit, &src_hit, XFRM_POLICY_IN);
	hip_xfrm_policy_delete(&dst_hit, &dst_hit, XFRM_POLICY_OUT);
}

int hip_setup_sp_prefix_pair() {
	int err = 0;
	hip_hit_t src_hit, dst_hit;
	memset(&src_hit, 0, sizeof(hip_hit_t));
	memset(&dst_hit, 0, sizeof(hip_hit_t));

	/* The OUTGOING and INCOMING policy is set to the generic value */

	/** FIXME: I am not that sure if the macro HIP_HIT_TYPE_MASK_120 is correct 
	 * at the moment I opt for hardcoding the general policy 
	 */
	src_hit.s6_addr32[0] = htonl(0x40000000); //HIP_HIT_TYPE_MASK_120
	dst_hit.s6_addr32[0] = htonl(0x40000000); //HIP_HIT_TYPE_MASK_120

	HIP_IFE(hip_setup_hit_sp_pair(&dst_hit, &src_hit, NULL, NULL), -1);

 out_err:
	return err;
}
