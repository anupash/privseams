/** @file
 * This file defines extensions to Host Identity Protocol (HIP) to support
 * traversal of Network Address Translator (NAT) middleboxes.
 * 
 * The traversal mechanism tunnels HIP control and data traffic over UDP
 * and enables HIP initiators which may be behind NATs to contact HIP
 * responders which may be behind another NAT. Three basic cases exist for NAT
 * traversal. In the first case, only the initiator of a HIP base exchange is
 * located behind a NAT. In the second case, only the responder of a HIP base
 * exchange is located behind a NAT. In the third case, both parties are
 * located behind (different) NATs. The use rendezvous server is mandatory
 * when the responder is behind a NAT.
 * 
 * @author  (version 1.0) Abhinav Pathak
 * @author  (version 1.1) Lauri Silvennoinen
 * @version 1.1
 * @date    12.09.2006
 * @note    Related drafts:
 *          <ul>
 *          <li><a href="http://www.ietf.org/internet-drafts/draft-schmitt-hip-nat-traversal-01.txt">
 *          draft-schmitt-hip-nat-traversal-01</a></li>
 *          <li><a href="http://www.ietf.org/internet-drafts/draft-irtf-hiprg-nat-03.txt">
 *          draft-irtf-hiprg-nat-03</a></li>
 *          </ul>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 * @note    All Doxygen comments have been added in version 1.1.
 */ 
#include "nat.h"

/** Port used for NAT travelsal NAT-P random port simulation.
    If random port simulation is of, 50500 is used. */
in_port_t hip_nat_rand_port1 = HIP_NAT_UDP_PORT;
/** Port used for NAT travelsal NAT-P' random port simulation.
    If random port simulation is of, 50500 is used. */
in_port_t hip_nat_rand_port2 = HIP_NAT_UDP_PORT;

/**
 * Sets NAT status "on".
 * 
 * Sets NAT status "on" for each host association in the host association
 * database.
 *
 * @return zero on success, or negative error value on error.
 * @todo   Extend this to handle peer_hit case for
 *         <code>"hipconf hip nat peer_hit"</code> This would be helpful in
 *         multihoming case.
 */ 
int hip_nat_on()
{
	int err = 0;
#if HIP_UDP_PORT_RANDOMIZING 
	hip_nat_randomize_nat_ports();
#endif
	hip_nat_status = 1;
	HIP_IFEL(hip_for_each_ha(hip_nat_on_for_ha, NULL), 0,
		 "Error from for_each_ha().\n");
 out_err:
	return err;
}

/**
 * Sets NAT status "off".
 *
 * Sets NAT status "off" for each host association in the host association
 * database.
 * 
 * @return zero on success, or negative error value on error.
 * @todo   Extend this to handle peer_hit case for
 *         <code>"hipconf hip nat peer_hit"</code> This would be helpful in
 *         multihoming case.
 */
int hip_nat_off()
{
	int err = 0;

	hip_nat_status = 0;
	HIP_IFEL(hip_for_each_ha(hip_nat_off_for_ha, NULL), 0,
		 "Error from for_each_ha().\n");
 out_err:
	return err;
}

/**
 * Sets NAT status "on" for a single host association.
 *
 * @param entry    a pointer to a host association for which to set NAT status.
 * @param not_used this parameter is not used (but it's needed).
 * @return         zero.
 * @note           the status is changed just for the parameter host 
 *                 association. This function does @b not insert the host
 *                 association into the host association database.
 */
int hip_nat_on_for_ha(hip_ha_t *entry, void *not_used)
{
	/* Parameter not_used is needed because this function is called from
	   hip_nat_on() which calls hip_for_each_ha(). hip_for_each_ha()
	   requires a function pointer as parameter which in turn has two
	   parameters. */
	HIP_DEBUG("hip_nat_on_for_ha() invoked.\n");
	int err = 0;

	if(entry)
	{
		entry->peer_udp_port = HIP_NAT_UDP_PORT;
		entry->nat_mode = 1;
		HIP_DEBUG("NAT status of host association %p: %d\n",
			  entry, entry->nat_mode);
	}
 out_err:
	return err;
}

/**
 * Sets NAT status "off" for a single host association.
 *
 * @param entry    a pointer to a host association for which to set NAT status.
 * @param not_used this parameter is not used (but it's needed).
 * @return         zero.
 * @note           the status is changed just for the parameter host 
 *                 association. This function does @b not insert the host
 *                 association into the host association database.
 */
int hip_nat_off_for_ha(hip_ha_t *entry, void *not_used)
{
	/* Check hip_nat_on_for_ha() for further explanation on "not_used". */
	HIP_DEBUG("hip_nat_off_for_ha() invoked.\n");
	 int err = 0;

	if(entry)
	{
		entry->peer_udp_port = 0;
		entry->nat_mode = 0;
		HIP_DEBUG("NAT status of host association %p: %d\n",
			  entry, entry->nat_mode);
	}
 out_err:
	return err;
}

/**
 * Logic specific to HIP control packets received on UDP.
 *
 * Does the logic specific to HIP control packets received on UDP and calls
 * hip_receive_control_packet() after the UDP specific logic.
 * hip_receive_control_packet() is called with different IP source address
 * depending on whether the current machine is a rendezvous server or not:
 * 
 * <ol>
 * <li>If the current machine is @b NOT a rendezvous server the source address
 * of hip_receive_control_packet() is the @c preferred_address of the matching
 * host association.</li> 
 * <li>If the current machine @b IS a rendezvous server the source address
 * of hip_receive_control_packet() is the @c saddr of this function.</li>
 * </ol>
 *
 * @param msg   a pointer to the received HIP control packet common header with
 *              source and destination HITs.
 * @param saddr a pointer to the source address from where the packet was
 *              received.
 * @param daddr a pointer to the destination address where to the packet was
 *              sent to (own address).
 * @param info  a pointer to the source and destination ports.
 * @return      zero on success, or negative error value on error.
 */ 
int hip_nat_receive_udp_control_packet(struct hip_common *msg,
				       struct in6_addr *saddr,
				       struct in6_addr *daddr,
				       struct hip_stateless_info *info)
{
        HIP_DEBUG("hip_nat_receive_udp_control_packet() invoked.\n");
	HIP_DEBUG_IN6ADDR("hip_nat_receive_udp_control_packet(): "\
			  "source address", saddr);
	HIP_DEBUG_IN6ADDR("hip_nat_receive_udp_control_packet(): "\
			  "destination address", daddr);
	HIP_DEBUG("Source port: %u, destination port: %u\n",
		  info->src_port, info->dst_port);
	HIP_DUMP_MSG(msg);

	hip_ha_t *entry;
        int err = 0, type, skip_sync = 0;
	struct in6_addr *saddr_public = saddr;

        type = hip_get_msg_type(msg);
        entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);

	if(entry) {
		/* XX FIXME: this information is unreliable. We should
		   be able to cancel it if hip_receive_control_packet fails */
		entry->nat_mode = 1;
		entry->peer_udp_port = info->src_port;
		HIP_DEBUG("entry found src port %d\n",
			  entry->peer_udp_port);
	}

#ifndef CONFIG_HIP_RVS
	/* The ip of RVS is taken to be ip of the peer while using RVS server
	   to relay R1. Hence have removed this part for RVS --Abi */
	if (entry && (type == HIP_R1 || type == HIP_R2)) {
		/* When the responder equals to the NAT host, it can reply from
		   the private address instead of the public address. In this
		   case, the saddr will point to the private address, and using
		   it for I2 will fail the puzzle indexing (I1 was sent to the
		   public address). So, we make sure here that we're using the
		   same dst address for the I2 as for I1. Also, this address is
		   used for setting up the SAs: handle_r1 creates one-way SA and
		   handle_i2 the other way; let's make sure that they are the
		   same. */
		saddr_public = &entry->preferred_address;
	}
#endif

	HIP_IFEL(hip_receive_control_packet(msg, saddr_public, daddr,info), -1,
		 "receiving of control packet failed\n");
 out_err:
	return err;
}

/**
 * Refreshes the port state of all NATs related to this host.
 *
 * Refreshes the port state of all NATs between current host and all its peer
 * hosts by calling hip_nat_send_keep_alive() for each host association in
 * the host association database.
 *
 * @return zero on success, or negative error value on error.
 */ 
int hip_nat_refresh_port()
{
	int err = 0 ;
	/** @todo Is this "if" needed? */
	if(hip_nat_status == 1)
	{
		HIP_DEBUG("Sending keepalives\n");
		HIP_IFEL(hip_for_each_ha(hip_nat_send_keep_alive, NULL), 0,
        	         "for_each_ha err.\n");
	}
	
 out_err:
	return err;
}

/**
 * Sends an NAT Keep-Alive packet.
 *
 * Sends an UPDATE packet with nothing but @c HMAC parameter in it to the peer's
 * preferred address. If the @c entry is @b not in state ESTABLISHED or if there
 * is no NAT between this host and the peer (@c entry->nat_mode = 0), then no
 * packet is sent. The packet is send on UDP with source and destination ports
 * set as @c HIP_NAT_UDP_PORT .
 * 
 * @param entry    a pointer to a host association which links current host and
 *                 the peer.
 * @param not_used this parameter is not used (but it's needed).
 * @return         zero on success, or negative error value on error.
 * @note           If the state of @c entry is not ESTABLISHED or if
 *                 @c entry->nat_mode = 0 this function still returns zero
 *                 because these conditions are not errors. Negative error
 *                 value is only returned when the creation of the new UPDATE
 *                 message fails in some way.
 */
int hip_nat_send_keep_alive(hip_ha_t *entry, void *not_used)
{
	HIP_DEBUG("hip_nat_send_keep_alive() invoked.\n");
	HIP_DEBUG("entry @ %p, entry->nat_mode %d.\n",
		  entry, entry->nat_mode);
	HIP_DEBUG_HIT("&entry->hit_our", &entry->hit_our);

	int err = 0;
	struct hip_common *update_packet = NULL;
		
	/* Check that the host association is in correct state and that there is
	   a NAT between this host and the peer. Note, that there is no error
	   (err is set to zero) if the condition does not hold. We just don't
	   send the packet in that case. */
	HIP_IFEL((entry->state != HIP_STATE_ESTABLISHED), 0, 
		 "Not sending NAT keepalive, invalid hip state "\
		 "in current host association. State is %s.\n", 
		 hip_state_str(entry->state));
	
	HIP_IFEL(!(entry->nat_mode), 0, 
		 "Not sending NAT keepalive, there is no NAT between this "\
		 "host and the peer in current host association.\n");

	/* Create an empty update packet. */
	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "No memory to create an UPDATE packet.\n");
	
	entry->hadb_misc_func->
		hip_build_network_hdr(update_packet, HIP_UPDATE,
				      0, &entry->hit_our,
				      &entry->hit_peer);
	
	/* Add a HMAC parameter to the UPDATE packet. */
        HIP_IFEL(hip_build_param_hmac_contents(
			 update_packet, &entry->hip_hmac_out), -1,
                 "Building of HMAC failed.\n");
        
	/* Send the UPDATE packet using 50500 as source and destination ports.
	   Only outgoing traffic acts refresh the NAT port state. We could
	   choose to use other than 50500 as source port, but we must use 50500
	   as destination port. However, because it is recommended to use
	   50500 as source port also, we choose to do so here. */
	entry->hadb_xmit_func->
		hip_send_udp(&entry->local_address, &entry->preferred_address,
			     HIP_NAT_UDP_PORT, HIP_NAT_UDP_PORT, update_packet,
			     entry, 0);

	HIP_DEBUG_HIT("hip_nat_send_keep_alive(): Sent UPDATE packet to",
		      &entry->preferred_address);
 out_err:
	if(update_packet)
	{
		HIP_FREE(update_packet);
	}
	return err;
}

#if HIP_UDP_PORT_RANDOMIZING
/**
 * Randomizes @b source ports NAT-P and NAT-P'.
 *
 * This function randomizes ports @c hip_nat_rand_port1 and
 * @c hip_nat_rand_port2 used in NAT-travelsal. NATs choose randomly a port
 * when HIP control traffic goes through them. Internet Draft 
 * [draft-schmitt-hip-nat-traversal-01] defines these random chosen ports as
 * NAT-P and NAT-P'. This function serves as a helper function to simulate
 * these random chosen ports in a non-NATed environment where UPD encapsulation
 * is used.
 *
 * @note According to [draft-schmitt-hip-nat-traversal-01] HIP daemons use
 *       one random port and NATs use two random ports. The value of
 *       @c hip_nat_rand_port1 can be considered as the random port of
 *       HIP daemon also. A scenario where HIP daemons use random source port
 *       and real life NATs randomize the NAT-P and NAT-P' ports is achieved by
 *       removing the @c hip_nat_rand_port2 randomization from this function.
 * @note Not used currently.
 */ 
void hip_nat_randomize_nat_ports()
{
	HIP_DEBUG("Randomizing UDP ports to be used.\n");
	unsigned int secs_since_epoch = (unsigned int) time(NULL);
	srand(secs_since_epoch);
	hip_nat_rand_port1 = HIP_UDP_PORT_RAND_MIN + (int)
		(((HIP_UDP_PORT_RAND_MAX - HIP_UDP_PORT_RAND_MIN + 1) * 
		  rand()) / (RAND_MAX + 1.0));
#if HIP_SIMULATE_NATS
	hip_nat_rand_port2 = HIP_UDP_PORT_RAND_MIN + (int)
		(((HIP_UDP_PORT_RAND_MAX - HIP_UDP_PORT_RAND_MIN + 1) *
		  rand()) / (RAND_MAX + 1.0));
#else
	hip_nat_rand_port2 = hip_nat_rand_port1;
#endif
	HIP_DEBUG("Randomized ports are NAT-P: %u, NAT-P': %u.\n",
		  hip_nat_rand_port1, hip_nat_rand_port2);
}
#endif
