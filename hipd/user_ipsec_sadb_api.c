#include "user_ipsec_sadb_api.h"
#include "esp_prot_common.h"

int hip_firewall_sock_fd = -1;

/* adds a new SA entry for the specified direction to the sadb in userspace ipsec */
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

/* deletes the specified SA entry from the sadb in userspace ipsec */
void hip_userspace_ipsec_delete_sa(u32 spi, struct in6_addr *peer_addr,
		struct in6_addr *dst_addr, int family, int sport, int dport)
{
	// TODO implement
	HIP_DEBUG("THIS HAS TO BE IMPLEMENTED\n");
}

/* deletes all SA entries in the sadb in userspace ipsec */
int hip_userspace_ipsec_flush_all_sa()
{
	// TODO implement
	HIP_DEBUG("THIS HAS TO BE IMPLEMENTED\n");
}

/* security policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all matching packets */
int hip_userspace_ipsec_setup_hit_sp_pair(hip_hit_t *src_hit,
					  hip_hit_t *dst_hit,
					  struct in6_addr *src_addr,
					  struct in6_addr *dst_addr, u8 proto,
					  int use_full_prefix, int update)
{
	/* if called anywhere in hipd code, we pretend to have had a successful
	 * operation */
	return 0;
}

/* security policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all matching packets */
void hip_userspace_ipsec_delete_hit_sp_pair(hip_hit_t *src_hit,
					    hip_hit_t *dst_hit, u8 proto,
					    int use_full_prefix)
{
	// nothing to do here
}

/* security policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all matching packets */
int hip_userspace_ipsec_flush_all_policy()
{
	/* if called anywhere in hipd code, we pretend to have had a successful
	 * operation */
	return 0;
}

/* returns a random SPI value */
uint32_t hip_userspace_ipsec_acquire_spi(hip_hit_t *srchit,
					 hip_hit_t *dsthit)
{
	uint32_t spi = 0;

	get_random_bytes(&spi, sizeof(uint32_t));

	return spi;
}

/* securitiy policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all packets matching HITs.
 *
 * @note we could delete the iptables rules here instead of at firewall exit */
void hip_userspace_ipsec_delete_default_prefix_sp_pair()
{
	// nothing to do here
}

/* securitiy policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all packets matching HITs.
 *
 * @note we could set up the iptables rules here instead of at firewall init */
int hip_userspace_ipsec_setup_default_sp_prefix_pair()
{
	/* if called anywhere in hipd code, we pretend to have had a successful
	 * operation */
	return 0;
}
