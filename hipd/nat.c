#include "nat.h"

int hip_nat_on(struct hip_common *msg)
{
	hip_nat_status = 1;
	// Extend it to handle peer_hit case for "hipconf hip nat peer_hit"
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
	struct in6_addr *src_addr;

        type = hip_get_msg_type(msg);

        HIP_DEBUG("Received packet type %d\n", type);
        _HIP_DUMP_MSG(msg);
        _HIP_HEXDUMP("dumping packet", msg,  40);

        entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);

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
	} else {
		src_addr = src_addr_orig;
	}

        switch(type) {
        case HIP_I1:
		if(entry) /* no state */
		{
			entry->nat = 1;
			entry->nat_mangled_port = info->src_port;
			memcpy(&(entry->nat_address), src_addr,
			       sizeof(struct in6_addr));
			HIP_DEBUG("entry found src port %d\n",
				  entry->nat_mangled_port);
			HIP_DEBUG_IN6ADDR("NAT mangled address:",
					  &(entry->nat_address));
		}
			
		else
		  HIP_ERROR("No entry found\n");
                break;

        case HIP_I2:
		/* possibly state */
                HIP_DEBUG("\n-- RECEIVED I2. State: %d--\n");
                if(entry){
			HIP_DEBUG("entry found in received I2\n");
			entry->nat = 1;
			memcpy(&(entry->nat_address), src_addr, sizeof(struct in6_addr));
			entry->nat_mangled_port = info->src_port;
                } else {
			HIP_DEBUG("Entry not found\n");
                }
                break;
        default:
                HIP_ERROR("Received some other packet %d\n", type);
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

	HIP_DEBUG("--------------Sending peer using UDP-----------\n");
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
		   listener to that port*/
		IPV6_TO_IPV4_MAP(peer_addr, &dst.sin_addr);
		
		if(entry) {
			entry->I_udp_src_port = ntohs(src.sin_port);
		}
		break;
        case HIP_R1:
	case HIP_R2:
		if(entry)
			HIP_DEBUG("Entry Found: nat %d\n", entry->nat);
		else
			HIP_DEBUG("Entry not found\n");
	       	
		src.sin_port = htons(HIP_NAT_UDP_PORT);
		if(entry) {
			entry->I_udp_src_port = dst_port;
			memcpy(&(entry->nat_address), peer_addr,
			       sizeof(struct in6_addr));
		}
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
		src.sin_port = htons(HIP_NAT_UDP_PORT);
		IPV6_TO_IPV4_MAP(peer_addr, &dst.sin_addr);

		if (hip_nat_status) /* works only when one host behing nat */
			dst.sin_port = htons(HIP_NAT_UDP_PORT);
		else
			dst.sin_port = htons(entry->nat_mangled_port);
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

