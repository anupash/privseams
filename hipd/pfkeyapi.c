#include "beet.h"
#ifdef CONFIG_HIP_PFKEY

int hip_flush_all_policy() {
	int so, len, err = 0;
	HIP_DEBUG("\n");
	HIP_IFEL(((so = pfkey_open()) < 0), -1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

	HIP_DEBUG("FLushing all SP's\n");
	HIP_IFEBL(((len = pfkey_send_spdflush(so))<0), -1, pfkey_close(so), "ERROR in flushing %s", ipsec_strerror());
	return len;
out_err:
	return err;
}

int hip_flush_all_sa() {
	int so;
	HIP_DEBUG("\n");
	if ((so = pfkey_open()) < 0) {
		HIP_ERROR("ERROR: %s\n", ipsec_strerror());
		goto out_err;
	}
	HIP_DEBUG("Flushing all SA's\n");
out_err:
	return -1; // pfkey_send_x3
}

void hip_delete_sa(u32 spi, struct in6_addr *peer_addr, int family,
		   int sport, int dport) {
	// pfkey_send_delete
}

uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit) {

	uint32_t spi;
	get_random_bytes(&spi, sizeof(uint32_t));
	return spi;
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
		    int direction, int update,
		    int sport, int dport) {

	// pfkey_send_add when update = 0 and sport == 0
	// pfkey_send_add_nat when update = 0 and sport != 0 
	// pfkey_send_update when update = 1 and sport == 0
	// pfkey_send_update_nat when update = 1 and sport != 0
	return 1;
}

int hip_setup_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit,
			  struct in6_addr *src_addr,
			  struct in6_addr *dst_addr, u8 proto,
			  int use_full_prefix, int update)
{
	// call twice pfkey_send_x4
	return 1;
}

void hip_delete_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit, u8 proto,
			    int use_full_prefix)
{
	// call twice pfkey_send_x5
}

void hip_delete_default_prefix_sp_pair() {
	// you don't have to implement this, currently unused
}

int hip_setup_default_sp_prefix_pair() {
	return -1; // currently this function is not needed
}

#endif /* CONFIG_HIP_PFKEY */
