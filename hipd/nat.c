#include "nat.h"


int hip_receive_control_packet_udp(struct hip_common *msg,
                               struct in6_addr *src_addr,
                               struct in6_addr *dst_addr,
				int src_port)
{
        hip_ha_t tmp;

        int err = 0, type, skip_sync = 0;

        type = hip_get_msg_type(msg);

        HIP_DEBUG("Received packet type %d\n", type);
        _HIP_DUMP_MSG(msg);
        _HIP_HEXDUMP("dumping packet", msg,  40);
        // XX FIXME: CHECK PACKET CSUM

        /* fetch the state from the hadb database to be able to choose the
           appropriate message handling functions */
        hip_ha_t *entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);

        if (entry)
                err = entry->hadb_input_filter_func->hip_input_filter(msg);
        else
                err = ((hip_input_filter_func_set_t *)hip_get_input_filter_default_func_set())->hip_input_filter(msg);
        if (err == -ENOENT) {
                HIP_DEBUG("No agent running, continuing\n");
                err = 0;
        } else if (err == 0) {
                HIP_DEBUG("Agent accepted packet\n");
        } else if (err) {
                HIP_ERROR("Agent reject packet\n");
        }

        switch(type) {
        case HIP_I1:
                // no state
		if(entry)
		{
			entry->nat_mangled_port = src_port;
			memcpy(&(entry->nat_address), src_addr, sizeof(struct in6_addr));
			HIP_DEBUG("entry found src port %d\n", entry->nat_mangled_port);
			HIP_DEBUG_IN6ADDR("NAT mangled address:", &(entry->nat_address));
		}
			
		else HIP_ERROR("No entry found\n");
                err = ((hip_rcv_func_set_t *)hip_get_rcv_default_func_set())->hip_receive_i1(msg, src_addr, dst_addr, entry);
                break;

        case HIP_I2:
                // possibly state
                HIP_DEBUG("\n-- RECEIVED I2. State: %d--\n");
                if(entry){
			memcpy(&(entry->nat_address), src_addr, sizeof(struct in6_addr));
			entry->nat_mangled_port = src_port;
                        err = entry->hadb_rcv_func->hip_receive_i2(msg,
                                                        src_addr,
                                                        dst_addr,
                                                        entry);
                } else {
                        err = ((hip_rcv_func_set_t *)hip_get_rcv_default_func_set())->hip_receive_i2(msg, src_addr, dst_addr, entry);
                }
                break;

        case HIP_R1:
                // state
                HIP_DEBUG("\n-- RECEIVED R2. State: %d--\n");
                HIP_IFCS(entry,
                         err = entry->hadb_rcv_func->hip_receive_r1(msg,
                                                        src_addr,
                                                        dst_addr,
                                                        entry))
                //err = hip_receive_r1(msg, src_addr, dst_addr);
                break;

        case HIP_R2:
                HIP_DEBUG("\n-- RECEIVED R2. State: %d--\n");
                HIP_IFCS(entry,
                         err = entry->hadb_rcv_func->hip_receive_r2(msg,
                                                        src_addr,
                                                        dst_addr,
                                                        entry))
                //err = hip_receive_r2(msg, src_addr, dst_addr);
                HIP_STOP_TIMER(KMM_GLOBAL,"Base Exchange");
                break;

        case HIP_UPDATE:
                HIP_DEBUG("\n-- RECEIVED Update message. State: %d--\n");
                HIP_IFCS(entry,
                         err = entry->hadb_rcv_func->hip_receive_update(msg,
                                                        src_addr,
                                                        dst_addr,
                                                        entry))
                break;

        case HIP_NOTIFY:
                HIP_DEBUG("\n-- RECEIVED Notify message --\n");
                HIP_IFCS(entry,
                         err = entry->hadb_rcv_func->hip_receive_notify(
                                                        msg,
                                                        src_addr,
                                                        dst_addr,
                                                        entry))
                break;


        case HIP_BOS:
                HIP_DEBUG("\n-- RECEIVED BOS message --\n");
                HIP_IFCS(entry,
                         err = entry->hadb_rcv_func->hip_receive_bos(msg,
                                                        src_addr,
                                                        dst_addr,
                                                        entry))
                /*In case of BOS the msg->hitr is null, therefore it is replaced
                  with our own HIT, so that the beet state can also be
                  synchronized */
                ipv6_addr_copy(&tmp.hit_peer, &msg->hits);
                hip_init_us(&tmp, NULL);
                ipv6_addr_copy(&msg->hitr, &tmp.hit_our);
                skip_sync = 0;
                break;
        case HIP_CLOSE:
                HIP_DEBUG("\n-- RECEIVED CLOSE message --\n");
                HIP_IFCS(entry,
                         err = entry->hadb_rcv_func->hip_receive_close(msg,
                                                        entry))
                break;

        case HIP_CLOSE_ACK:
                HIP_DEBUG("\n-- RECEIVED CLOSE_ACK message --\n");
                HIP_IFCS(entry,
                         err = entry->hadb_rcv_func->hip_receive_close_ack(
                                                        msg,
                                                        entry))
                break;

        default:
                HIP_ERROR("Unknown packet %d\n", type);
                err = -ENOSYS;
        }

        HIP_DEBUG("Done with control packet (%d).\n", err);
        HIP_HEXDUMP("msg->hits=", &msg->hits, 16);
        HIP_HEXDUMP("msg->hitr=", &msg->hitr, 16);

        if (err)
                goto out_err;


 out_err:

        return err;
}


int hip_read_control_msg_udp(int socket, struct hip_common *hip_msg,
                         int read_addr, struct in6_addr *saddr,
                         struct in6_addr *daddr)
{

	struct sockaddr_in peer_addr;
        int peer_addr_len, n, err = 0 ;
	int type = 0;
	
        HIP_DEBUG("Preparing to listen for UDP Traffic\n");

        peer_addr_len = sizeof(peer_addr); 
        n = recvfrom(socket, hip_msg, HIP_MAX_LENGTH_UDP_PACKET, 
			0, (struct sockaddr *)&peer_addr, &peer_addr_len);


        if(n<0)
        {
                HIP_ERROR("Error in recieving %d\n", n);
        	return -1;
        }

        HIP_DEBUG("UDP Packet recieved\n");
	
	if(read_addr)
	{
		saddr->s6_addr32[0] = 0;
		saddr->s6_addr32[1] = 0;
		saddr->s6_addr32[2] = htonl(0xffff); 
		saddr->s6_addr32[3] = peer_addr.sin_addr.s_addr;
	
		daddr->s6_addr32[0] = 0;
		daddr->s6_addr32[1] = 0;
		daddr->s6_addr32[2] = htonl(0xffff); 
		daddr->s6_addr32[3] = INADDR_ANY;	//Temporary fix --Abi
	}

	HIP_DEBUG_IN6ADDR("---udp src---:", saddr);
	HIP_DEBUG_IN6ADDR("---udp dst---:", daddr);
	
	type = hip_get_msg_type(hip_msg);
	

	switch(type) {
        
	case HIP_I1:
                break;
        case HIP_I2:
                break;
        case HIP_R1:
                break;
        case HIP_R2:
                break;
        case HIP_UPDATE:
                break;
        case HIP_NOTIFY:
                break;
        case HIP_BOS:
                break;
        case HIP_CLOSE:
                break;
        case HIP_CLOSE_ACK:
                break;
         default:
                HIP_ERROR("Unknown packet %d\n", type);
                err = -ENOSYS;
        }

	return 0;

 out_err:
	return err;
}



int hip_send_udp(struct in6_addr *local_addr, 
                  struct in6_addr *peer_addr,
                  struct hip_common* msg,
                  hip_ha_t *entry,
                  int retransmit)
{

	struct sockaddr_in src, dst;
        int sockfd, n, len = 0 , err = 0;
	int type = 0;

	len = hip_get_msg_total_len(msg);

	HIP_DEBUG("--------------Sending peer using UDP-----------\n");
	src.sin_family=AF_INET;

        if (local_addr)
		src.sin_addr.s_addr = local_addr->s6_addr32[3];
	else
		src.sin_addr.s_addr = INADDR_ANY;


        if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        {
                HIP_ERROR("Error getting a socket for sending\n");
                return -1;
        }

        dst.sin_family=AF_INET;
      
       	type = hip_get_msg_type(msg);

	switch(type) {
	case HIP_I1:
        	src.sin_port = htons(0);	/* Choose a random source port --Abi*/
        	//src.sin_port = htons(HIP_NAT_UDP_PORT);	
		entry->I_udp_src_port = ntohs(src.sin_port);
		dst.sin_addr.s_addr = peer_addr->s6_addr32[3];
        	dst.sin_port = htons(HIP_NAT_UDP_PORT);
		break;
	case HIP_I2:
		src.sin_port = htons(entry->I_udp_src_port);
		dst.sin_addr.s_addr = peer_addr->s6_addr32[3];
        	dst.sin_port = htons(HIP_NAT_UDP_PORT);
		break;
	case HIP_R1:
	       	src.sin_port = htons(HIP_NAT_UDP_PORT);
		//entry->R_udp_src_port = ntohs(src.sin_port);
		dst.sin_addr.s_addr = (&(entry->nat_address))->s6_addr32[3]; //peer_addr->s6_addr32[3];
		dst.sin_port = htons(entry->nat_mangled_port);
		break;
	case HIP_R2:
		src.sin_port = htons(HIP_NAT_UDP_PORT);
		dst.sin_addr.s_addr = (&(entry->nat_address))->s6_addr32[3]; //peer_addr->s6_addr32[3];
		dst.sin_port = htons(entry->nat_mangled_port);
		break;
	case HIP_UPDATE:
	case HIP_NOTIFY:
	case HIP_BOS:
	case HIP_CLOSE:
	case HIP_CLOSE_ACK:
		src.sin_port = htons(entry->I_udp_src_port);        /* Choose a random source port --Abi*/
		break;
	/* Deal with update, notify, bos, close, and close_ack later... They seem to be a bit tricky*/
	 default:
                HIP_ERROR("Unknown packet %d\n", type);
                err = -ENOSYS;
	}			
	
	if(bind(sockfd, (struct sockaddr *)&src, sizeof(src))< 0)
        {
                HIP_ERROR("Error binding socket to port %d\n", src.sin_port);
                return -1;
        }


        hip_zero_msg_checksum(msg);
        msg->checksum = checksum_packet((char*)msg, &src, &dst);


        n = sendto(sockfd, msg, len, 0, (struct sockaddr *)&dst, sizeof(dst));

        if(n<0)
        {
                HIP_ERROR("Error in sending packet to server %d\n",n);
                return -1;
        }
        HIP_DEBUG("Packet sent successfully over UDP to peer..Yahoo %d, buf len %d\n",
				n, len);


	close(sockfd);
	return 0;

 out_err:
	return err;
}

