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
 * @date    07.09.2006
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
		entry->nat = 1;
		HIP_DEBUG("NAT status of host association %p: %d\n",
			  entry, entry->nat);
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
		entry->nat = 0;
		HIP_DEBUG("NAT status of host association %p: %d\n",
			  entry, entry->nat);
	}
 out_err:
	return err;
}

int hip_nat_receive_udp_ctrl_msg(struct hip_common *msg,
				 struct in6_addr *src_addr_orig,
				 struct in6_addr *dst_addr,
				 struct hip_stateless_info *info)
{
        HIP_DEBUG("hip_nat_receive_udp_ctrl_msg() invoked.\n");
	HIP_DEBUG_IN6ADDR("hip_nat_receive_udp_ctrl_msg(): source address",
			  src_addr_orig);
	HIP_DEBUG_IN6ADDR("hip_nat_receive_udp_ctrl_msg(): destination address",
			  dst_addr);
	HIP_DEBUG("Source port: %u, destination port: %u\n",
		  info->src_port, info->dst_port);
	HIP_DUMP_MSG(msg);

	hip_ha_t *entry;
        int err = 0, type, skip_sync = 0;
	struct in6_addr *src_addr = src_addr_orig;

        type = hip_get_msg_type(msg);
        entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);

	if(entry) {
		/* XX FIXME: this information is unreliable. We should
		   be able to cancel it if hip_receive_control_packet fails */
		entry->nat = 1;
		entry->peer_udp_port = info->src_port;
		HIP_DEBUG("entry found src port %d\n",
			  entry->peer_udp_port);
	}
#ifndef CONFIG_HIP_RVS

	/* The ip of RVS is taken to be ip of the peer while using RVS server to relay R1.
	 * Hence have removed this part for RVS --Abi
	 */

	
	if (entry && (type == HIP_R1 || type == HIP_R2)) {
		/* When the responder equals to the NAT host, it can
		   reply from the private address instead of the public
		   address. In this case, the src_addr_orig will point to
		   the private address, and using it for I2 will fail the
		   puzzle indexing (I1 was sent to the public address). So,
		   we make sure here that we're using the same dst address
		   for the I2 as for I1. Also, this address is used for setting
		   up the SAs: handle_r1 creates one-way SA and handle_i2 the
		   other way; let's make sure that they are the same. */
		src_addr = &entry->preferred_address;
	}
#endif
	HIP_IFEL(hip_receive_control_packet(msg,
					    src_addr,
					    dst_addr,
					    info), -1,
		 "receiving of control packet failed\n");
 out_err:

        return err;
}


int hip_send_udp(struct in6_addr *my_addr, 
		 struct in6_addr *peer_addr,
		 uint32_t src_port, uint32_t dst_port,
		 struct hip_common* msg,
		 hip_ha_t *entry,
		 int retransmit)
{

	struct sockaddr_in src, dst;
	struct in_addr any = {INADDR_ANY};
	struct in6_addr local_addr;
        int sockfd = 0, n, len = 0 , err = 0;
	int type = 0;
	int i = 0;

	len = hip_get_msg_total_len(msg);

	HIP_DEBUG("Sending a packet to peer using UDP\n");
	if(my_addr)
		HIP_DEBUG_IN6ADDR("localAddr:", my_addr);
	if(peer_addr)
		HIP_DEBUG_IN6ADDR("peerAddr:", peer_addr);
	HIP_DEBUG("given src port=%d, dst port=%d\n", src_port, dst_port);

	src.sin_family = AF_INET;

        if (my_addr) {
		IPV6_TO_IPV4_MAP(&local_addr, &src.sin_addr);
	} else {
		IPV6_TO_IPV4_MAP(&local_addr, &any);
		src.sin_addr.s_addr = INADDR_ANY;
	}

        HIP_IFEL(((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0), -1,
		 "Error getting a socket for sending\n");

        dst.sin_family=AF_INET;
       	type = hip_get_msg_type(msg);

	switch(type) {
        case HIP_I1:
	case HIP_I2:
		if(entry)
			HIP_DEBUG("Entry Found: nat %d\n", entry->nat);
		else
			HIP_DEBUG("Entry not found\n");
        	src.sin_port = htons(HIP_NAT_UDP_PORT);
        	dst.sin_port = htons(HIP_NAT_UDP_PORT);
		/* Note: If we change this src.sin_port we need to put a
		   listener to that port */
		IPV6_TO_IPV4_MAP(peer_addr, &dst.sin_addr);
		break;
        case HIP_R1:
	case HIP_R2:
		if(entry)
			HIP_DEBUG("Entry Found: nat %d\n", entry->nat);
		else
			HIP_DEBUG("Entry not found\n");
	       	
		src.sin_port = htons(HIP_NAT_UDP_PORT);
       		dst.sin_port = htons(dst_port);
		IPV6_TO_IPV4_MAP(peer_addr, &dst.sin_addr);
		break;
        case HIP_NOTIFY:
        case HIP_BOS:
        case HIP_CLOSE:
        case HIP_CLOSE_ACK:
        case HIP_UPDATE:
		/* The logic below has been tested only with CLOSE */
		if (!entry) {
			err = -1;
			HIP_ERROR("No entry, bailing out\n");
			break;
		}
		IPV6_TO_IPV4_MAP(peer_addr, &dst.sin_addr);
		src.sin_port = htons(HIP_NAT_UDP_PORT);
		if(dst_port)
			dst.sin_port = htons(dst_port);
		else
			dst.sin_port = htons(entry->peer_udp_port);
		break;
	 default:
                HIP_ERROR("Unhandled packet type %d\n", type);
		err = -1;
		goto out_err;
	}			

	/* Probably required for mobility -miika */
#if 0	
	if(bind(sockfd, (struct sockaddr *)&src, sizeof(src))< 0)
        {
                HIP_ERROR("Error binding socket to port %d\n", src.sin_port);
                return -1;
        }
#endif

        hip_zero_msg_checksum(msg);
        msg->checksum = checksum_packet((char*) msg, &src, &dst);

	HIP_DEBUG("sending with src port=%d, dst port=%d\n", src.sin_port,
		  dst.sin_port);
	for(i = 0; i < HIP_NAT_NUM_RETRANSMISSION; i++)
	{
        	n = sendto( hip_nat_sock_udp, msg, len, 0,
			    (struct sockaddr *) &dst, sizeof(dst));
		if(n<0)
		{
			HIP_DEBUG("Some problem in sending packet ! Check route - Sleeping 2 seconds\n");
			sleep(2);
		}
		else
			break;
	}
	HIP_IFEL(( n < 0), -1, "Error in sending packet to server %d\n",n);
        HIP_DEBUG("Packet sent successfully over UDP n=%d d=%d\n",
				n, len);
 out_err:
	if (sockfd)
		close(sockfd);
	return err;
}

int hip_nat_keep_alive()
{
	int err = 0 ;
	if(hip_nat_status == 1)
	{
		HIP_DEBUG("Sending keepalives\n");
		HIP_IFEL(hip_for_each_ha(hip_handle_keep_alive, NULL), 0,
        	         "for_each_ha err.\n");
	}
	
 out_err:
	return err;
}

int hip_handle_keep_alive(hip_ha_t *entry, void *not_used)
{
	int err = 0;
	int n = 0, len, mask = 0;
	struct hip_common *update_packet;
	
	if(entry->state != HIP_STATE_ESTABLISHED)
		goto out_err;
	//Create an empty update packet and send to all the peer of the hip association;
	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
        	         "Out of memory.\n");

	entry->hadb_misc_func->hip_build_network_hdr(update_packet, HIP_UPDATE,
                                                     mask, &entry->hit_our,
                                                     &entry->hit_peer);

	/* Add HMAC */
        HIP_IFEL(hip_build_param_hmac_contents(update_packet,
                                               &entry->hip_hmac_out), -1,
                 "Building of HMAC failed\n");

        /* Add SIGNATURE */
        //HIP_IFEL(entry->sign(entry->our_priv, update_packet), -EINVAL,
          //       "Could not sign UPDATE. Failing\n");


	//Initialize sockets

//#if 0
	n = hip_send_udp(&entry->local_address, 
                  		&entry->preferred_address,
                  		HIP_NAT_UDP_PORT, HIP_NAT_UDP_PORT,	//Sending keepalives on 50500 !! --Abi
                  		update_packet,
        			entry, 0);

//#endif
	//n = hip_send_update(entry, NULL, 0,0, 0 );
	//HIP_DEBUG("Keep alive status %d\n", n);
	//HIP_DEBUG_IN6ADDR("Peer address \n", &entry->preferred_address);
	//Send the packet
	//len = hip_get_msg_total_len(msg);
	//n = sendto(hip_nat_sock_udp, msg, len, 0,
	//		(struct sockaddr *) &dst, sizeof(dst)); 
		

 out_err:
	return err;
}
