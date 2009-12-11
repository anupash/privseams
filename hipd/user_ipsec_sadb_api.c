/**
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#include "user_ipsec_sadb_api.h"
#include "esp_prot_common.h"
#include "user_ipsec_hipd_msg.h"


/** generic send function used to send the below created messages
 *
 * @param	msg the message to be sent
 * @return	0, if correct, else != 0
 */
int hip_userspace_ipsec_send_to_fw(struct hip_common *msg)
{
	struct sockaddr_in6 hip_firewall_addr;
	struct in6_addr loopback = in6addr_loopback;
	int err = 0;

	HIP_ASSERT(msg != NULL);

	// destination is firewall
	hip_firewall_addr.sin6_family = AF_INET6;
	hip_firewall_addr.sin6_port = htons(HIP_FIREWALL_PORT);
	ipv6_addr_copy(&hip_firewall_addr.sin6_addr, &loopback);

	err = hip_sendto_user(msg, (struct sockaddr *) &hip_firewall_addr);
	if (err < 0)
	{
		HIP_ERROR("sending of message to firewall failed\n");

		err = -1;
		goto out_err;
	} else
	{
		HIP_DEBUG("sending of message to firewall successful\n");

		// this is needed if we want to use HIP_IFEL
		err = 0;
	}

  out_err:
	return err;
}



/** adds a new SA entry for the specified direction to the sadb in userspace ipsec
 * @note  If you make changes to this function, please change also hip_add_sa()
 *
 * @param	...
 * @return	0, if correct, else != 0
 */
uint32_t hip_userspace_ipsec_add_sa(struct in6_addr *saddr,
				    struct in6_addr *daddr,
				    struct in6_addr *src_hit,
				    struct in6_addr *dst_hit,
				    uint32_t spi, int ealg,
				    struct hip_crypto_key *enckey,
				    struct hip_crypto_key *authkey,
				    int retransmission,
				    int direction, int update,
				    hip_ha_t *entry)
{
	struct hip_common *msg = NULL;
	in_port_t sport, dport;
	int err = 0;

	HIP_ASSERT(spi != 0);

	if (direction == HIP_SPI_DIRECTION_OUT)
	{
		sport = entry->local_udp_port;
		dport = entry->peer_udp_port;
		entry->outbound_sa_count++;
	}
	else
	{
		sport = entry->peer_udp_port;
		dport = entry->local_udp_port;
		entry->inbound_sa_count++;
	}

	HIP_IFEL(!(msg = create_add_sa_msg(saddr, daddr, src_hit, dst_hit, spi, ealg, enckey,
		    authkey, retransmission, direction, update, entry)), -1,
		    "failed to create add_sa message\n");

	HIP_IFEL(hip_userspace_ipsec_send_to_fw(msg), -1, "failed to send msg to fw\n");

 out_err:
	return err;
}

/** deletes the specified SA entry from the sadb in userspace ipsec
 *  TODO: Doxygen documentation incomplete.
 */
void hip_userspace_ipsec_delete_sa(uint32_t spi, struct in6_addr *not_used,
		struct in6_addr *dst_addr, int direction, hip_ha_t *entry)
{
	struct hip_common *msg = NULL;
	in_port_t sport, dport;
	int err = 0;

	if (direction == HIP_SPI_DIRECTION_OUT)
	{
		sport = entry->local_udp_port;
		dport = entry->peer_udp_port;
		entry->outbound_sa_count--;
		if (entry->outbound_sa_count < 0) {
			HIP_ERROR("Warning: out sa count negative\n");
			entry->outbound_sa_count = 0;
		}
	}
	else
	{
		sport = entry->peer_udp_port;
		dport = entry->local_udp_port;
		entry->inbound_sa_count--;
		if (entry->inbound_sa_count < 0) {
			HIP_ERROR("Warning: in sa count negative\n");
			entry->inbound_sa_count = 0;
		}
	}

	HIP_IFEL(!(msg = create_delete_sa_msg(spi, not_used, dst_addr, AF_INET6, sport, dport)),
			-1, "failed to create delete_sa message\n");

	HIP_IFEL(hip_userspace_ipsec_send_to_fw(msg), -1, "failed to send msg to fw\n");

  out_err:
	return;
}

/** flushes all SA entries in the sadb in userspace ipsec
 *  TODO: Doxygen documentation incomplete.
 * @return	0, if correct, else != 0
 */

int hip_userspace_ipsec_flush_all_sa()
{
	struct hip_common *msg = NULL;
	int err = 0;

	HIP_IFEL(!(msg = create_flush_all_sa_msg()), -1,
			"failed to create delete_sa message\n");

	HIP_IFEL(hip_userspace_ipsec_send_to_fw(msg), -1, "failed to send msg to fw\n");

  out_err:
	return err;
}

/**
 * TODO: Doxygen documentation incomplete.
/* @note security policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all matching packets 
 **/
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

/**
 * TODO: Doxygen documentation incomplete.
 * @note security policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all matching packets 
 **/
void hip_userspace_ipsec_delete_hit_sp_pair(hip_hit_t *src_hit,
					    hip_hit_t *dst_hit, u8 proto,
					    int use_full_prefix)
{
	// nothing to do here
}

/**
 * @note: security policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all matching packets 
 **/
int hip_userspace_ipsec_flush_all_policy()
{
	/* if called anywhere in hipd code, we pretend to have had a successful
	   operation */
	return 0;
}

/**
 * TODO: Doxygen documentation incomplete.
 * return a random SPI value 
 **/
uint32_t hip_userspace_ipsec_acquire_spi(hip_hit_t *srchit,
					 hip_hit_t *dsthit)
{
	uint32_t spi = 0;

	get_random_bytes(&spi, sizeof(uint32_t));

	return spi;
}

/**
 * TODO: Doxygen documentation incomplete.
 * securitiy policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all packets matching HITs.
 *
 * @note we could delete the iptables rules here instead of at firewall exit 
 **/
void hip_userspace_ipsec_delete_default_prefix_sp_pair()
{
	// nothing to do here
}

/**
 * TODO: Doxygen documentation incomplete.
 * securitiy policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all packets matching HITs.
 *
 * @note we could set up the iptables rules here instead of at firewall init 
 **/
int hip_userspace_ipsec_setup_default_sp_prefix_pair()
{
	/* if called anywhere in hipd code, we pretend to have had a successful
	 * operation */
	return 0;
}
