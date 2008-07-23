#include "user_ipsec_sadb_api.h"
#include "esp_prot_common.h"

int hip_firewall_sock_fd = -1;

/* hipd sends a packet to the firewall making it add a new sa entry
 *
 * this function is called by hip daemon */
uint32_t hip_userspace_ipsec_add_sa(struct in6_addr *saddr,
				    struct in6_addr *daddr,
				    struct in6_addr *src_hit,
				    struct in6_addr *dst_hit,
				    uint32_t spi, int ealg,
				    struct hip_crypto_key *enckey,
				    struct hip_crypto_key *authkey,
				    int retransmission,
				    int direction, int update,
				    hip_ha_t *entry) {

	struct hip_common *msg = NULL;
	struct sockaddr_in6 hip_firewall_addr;
	struct in6_addr loopback = in6addr_loopback;
	int err = 0;

	HIP_ASSERT(spi != 0);

	HIP_IFEL(!(msg = create_add_sa_msg(saddr, daddr, src_hit, dst_hit, spi, ealg, enckey,
		    authkey, retransmission, direction, update, entry)), -1,
		    "failed to create add_sa message\n");

	hip_firewall_addr.sin6_family = AF_INET6;
	hip_firewall_addr.sin6_port = htons(HIP_FIREWALL_PORT);
	ipv6_addr_copy(&(hip_firewall_addr.sin6_addr.s6_addr), &loopback);

	HIP_DEBUG_IN6ADDR("sending message to loopback: ",
			  hip_firewall_addr.sin6_addr.s6_addr);

	err = sendto(hip_firewall_sock_fd, msg, hip_get_msg_total_len(msg), 0,
		   &hip_firewall_addr, sizeof(hip_firewall_addr));
	if (err < 0)
	{
		HIP_ERROR("Sendto firewall failed.\n");
		err = -1;
		goto out_err;
	} else
	{
		HIP_DEBUG("hipd ipsec_add_sa --> Sendto firewall OK.\n");
		// this is needed if we want to use HIP_IFEL
		err = 0;
	}

 out_err:
	return err;
}

int hip_userspace_ipsec_setup_hit_sp_pair(hip_hit_t *src_hit,
					  hip_hit_t *dst_hit,
					  struct in6_addr *src_addr,
					  struct in6_addr *dst_addr, u8 proto,
					  int use_full_prefix, int update) {
	/* XX FIXME: TAO */
	return 0;
}

void hip_userspace_ipsec_delete_hit_sp_pair(hip_hit_t *src_hit,
					    hip_hit_t *dst_hit, u8 proto,
					    int use_full_prefix) {
	/* XX FIXME: TAO */
}

int hip_userspace_ipsec_flush_all_policy() {
	/* XX FIXME: TAO */
}

int hip_userspace_ipsec_flush_all_sa() {
	/* XX FIXME: TAO */
}

uint32_t hip_userspace_ipsec_acquire_spi(hip_hit_t *srchit,
					 hip_hit_t *dsthit) {
	return hip_acquire_spi(srchit, dsthit);
}

void hip_userspace_ipsec_delete_default_prefix_sp_pair() {
	/* XX FIXME: TAO */
}

int hip_userspace_ipsec_setup_default_sp_prefix_pair() {
	/* XX FIXME: TAO */
	return 0;
}
