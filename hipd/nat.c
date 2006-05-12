#include "nat.h"

int hip_nat_on(struct hip_common *msg)
{
	hip_nat_status = 1;
	// Extend it to handle peer_hit case for "hipconf hip nat peer_hit"
	// This would be helpful in multihoming case --Abi
	return 0;
}


int hip_nat_off(struct hip_common *msg)
{
	hip_nat_status = 0;
	return 0;
}

int hip_receive_control_packet_udp(struct hip_common *msg,
				   struct in6_addr *src_addr_orig,
				   struct in6_addr *dst_addr,
				   struct hip_stateless_info *info)
{
        hip_ha_t tmp, *entry;
        int err = 0, type, skip_sync = 0;
	struct in6_addr *src_addr = src_addr_orig;

        type = hip_get_msg_type(msg);

        HIP_DEBUG("Received packet type %d\n", type);
        _HIP_DUMP_MSG(msg);
        _HIP_HEXDUMP("dumping packet", msg,  40);

        entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);

	if(entry) {
		/* XX FIXME: this information is unreliable. We should
		   be able to cancel it if hip_receive_control_packet fails */
		entry->nat = 1;
		entry->peer_udp_port = info->src_port;
		HIP_DEBUG("entry found src port %d\n",
			  entry->peer_udp_port);
	}

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
        n = sendto( hip_nat_sock_udp, msg, len, 0,
		    (struct sockaddr *) &dst, sizeof(dst));
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
