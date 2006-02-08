#include "nat.h"


int hip_read_control_msg_udp(int socket, struct hip_common *hip_msg,
                         int read_addr, struct in6_addr *saddr,
                         struct in6_addr *daddr)
{

	struct sockaddr_in peer_addr;
        int peer_addr_len, n, err = 0 ;

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

	len = hip_get_msg_total_len(msg);

	HIP_DEBUG("--------------Sending peer using UDP-----------\n");
	src.sin_family=AF_INET;
        src.sin_port = htons(0);

        if (local_addr)
		src.sin_addr.s_addr = local_addr->s6_addr32[3];
	else
		src.sin_addr.s_addr = INADDR_ANY;


        if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        {
                HIP_ERROR("Error getting a socket for sending\n");
                return -1;
        }

        if(bind(sockfd, (struct sockaddr *)&src, sizeof(src))< 0)
        {
                HIP_ERROR("Error binding socket to port %d\n", src.sin_port);
                return -1;
        }

        dst.sin_family=AF_INET;
        dst.sin_addr.s_addr = peer_addr->s6_addr32[3];
        dst.sin_port = htons(HIP_NAT_UDP_PORT);

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

