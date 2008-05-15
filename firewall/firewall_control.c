/*
 * Firewall control
 * 
 */
 
#include "firewall_control.h"


int hip_firewall_sock = 0;
int firewall_raw_sock_tcp_v4 = 0;
int firewall_raw_sock_udp_v4 = 0;
int firewall_raw_sock_icmp_v4 = 0;
int firewall_raw_sock_tcp_v6 = 0;
int firewall_raw_sock_udp_v6 = 0;
int firewall_raw_sock_icmp_v6 = 0;
int firewall_raw_sock_icmp_outbound = 0;
int control_thread_started = 0;
GThread * control_thread = NULL; 


gpointer run_control_thread(gpointer data)
{
	/* Variables. */
	int err = 0;
	int n;
	int len;
	int ret;
	int max_fd;
	struct sockaddr_in6 sock_addr;
	struct hip_common *msg = (struct hip_common *)data;
	socklen_t alen;
	fd_set read_fdset;
	struct timeval tv;

	HIP_DEBUG("Executing connection thread\n");

	HIP_DEBUG("Waiting messages...\n\n");

	/* Start handling. */
	control_thread_started = 1;
	while (control_thread_started)
	{
		FD_ZERO(&read_fdset);
		FD_SET(hip_firewall_sock, &read_fdset);
		max_fd = hip_firewall_sock;
		tv.tv_sec = HIP_SELECT_TIMEOUT;
		tv.tv_usec = 0;

		/* Wait for incoming packets. */
		if ((err = HIPD_SELECT((max_fd + 1), &read_fdset, 
				       NULL, NULL, &tv)) < 0) {
			HIP_ERROR("select() error: %s.\n", strerror(errno));
		} 
		else if (err == 0) {
			/* idle cycle - select() timeout */
			_HIP_DEBUG("Idle\n");
		}
		else if (FD_ISSET(hip_firewall_sock, &read_fdset))
		{
			HIP_DEBUG("****** Received HIPD message ******\n");
			bzero(&sock_addr, sizeof(sock_addr));
			alen = sizeof(sock_addr);
			n = recvfrom(hip_firewall_sock, msg, sizeof(struct hip_common), MSG_PEEK,
		             (struct sockaddr *)&sock_addr, &alen);
			if (n < 0)
			{
				HIP_ERROR("Error receiving message header from daemon.\n");
				err = -1;
				goto out_err;
			}

			_HIP_DEBUG("Header received successfully\n");
			alen = sizeof(sock_addr);
			len = hip_get_msg_total_len(msg);

			_HIP_DEBUG("Receiving message (%d bytes)\n", len);
			n = recvfrom(hip_firewall_sock, msg, len, 0,
		             (struct sockaddr *)&sock_addr, &alen);

			if (n < 0)
			{
				HIP_ERROR("Error receiving message parameters from daemon.\n");
				err = -1;
				goto out_err;
			}

			HIP_ASSERT(n == len);
		
			err = handle_msg(msg, &sock_addr);
			if (err < 0){
				HIP_ERROR("Error handling message\n");
				//goto out_err;	 
			}
		}
		else {
			HIP_INFO("Unknown socket activity.\n");
		}
	}
out_err:
	/* Send quit message to daemon. */
	hip_build_user_hdr(msg, HIP_FIREWALL_QUIT, 0);
	n = sendto_hipd(msg, sizeof(struct hip_common));
	if (n < 0) HIP_ERROR("Could not send quit message to daemon.\n");
	
	if (hip_firewall_sock) close(hip_firewall_sock);
	if (msg != NULL) HIP_FREE(msg);

	control_thread_started = 0;
	
	HIP_DEBUG("Connection thread exit.\n");

	return NULL;	
	
}

int handle_msg(struct hip_common * msg, struct sockaddr_in6 * sock_addr)
{
	/* Variables. */
	struct hip_tlv_common *param = NULL;
	socklen_t alen;
	int type, err = 0;
	struct hip_keys *keys = NULL;
	struct in6_addr *hit_s = NULL;
	struct in6_addr *hit_r = NULL;	
	

	_HIP_DEBUG("Handling message from hipd\n");
	type = hip_get_msg_type(msg);
	
	switch(type)
	{
	case HIP_ADD_ESCROW_DATA:
		while((param = hip_get_next_param(msg, param)))
		{
			if (hip_get_param_type(param) == HIP_PARAM_HIT)
			{
				_HIP_DEBUG("Handling HIP_PARAM_HIT\n");
				if (!hit_s)
					hit_s = hip_get_param_contents_direct(param);
				else 
					hit_r =hip_get_param_contents_direct(param);
			}
			if (hip_get_param_type(param) == HIP_PARAM_KEYS)
			{
				_HIP_DEBUG("Handling HIP_PARAM_KEYS\n");	
				int alg;
				int auth_len;
				int key_len;
				int spi;
			
				keys = (struct hip_keys *)param;
				
				// TODO: Check values!!
				auth_len = 0;
				//op = ntohs(keys->operation);
		 		//spi = ntohl(keys->spi);
		 		spi = ntohl(keys->spi);
		 		//spi_old = ntohl(keys->spi_old);
		 		key_len = ntohs(keys->key_len);
		 		alg = ntohs(keys->alg_id);
			
				if (alg == HIP_ESP_3DES_SHA1)
					auth_len = 24;
				else if (alg == HIP_ESP_AES_SHA1)
					auth_len = 32;	
				else if (alg == HIP_ESP_NULL_SHA1)	
					auth_len = 32;	
				else	
					HIP_DEBUG("Authentication algorithm unsupported\n");
				err = add_esp_decryption_data(hit_s, hit_r, (struct in6_addr *)&keys->address, 
		     					      spi, alg, auth_len, key_len, &keys->enc);
		     		
				HIP_IFEL(err < 0, -1,"Adding esp decryption data failed"); 
				_HIP_DEBUG("Successfully added esp decryption data\n");	
			}
		}
		break;
	case HIP_DELETE_ESCROW_DATA:
		HIP_DEBUG("Received delete message from hipd\n\n");
	        struct in6_addr * addr = NULL;
	        uint32_t * spi = NULL;
                
	        while((param = hip_get_next_param(msg, param)))
	        {       
	                if (hip_get_param_type(param) == HIP_PARAM_HIT)
	                {
	                        HIP_DEBUG("Handling HIP_PARAM_HIT\n");
	                        addr = hip_get_param_contents_direct(param);
	                }
	                if (hip_get_param_type(param) == HIP_PARAM_UINT)
	                {
	                        HIP_DEBUG("Handling HIP_PARAM_UINT\n");
	                        spi = hip_get_param_contents(msg, HIP_PARAM_UINT);
	                }
	        }
	        if ((addr != NULL) && (spi != NULL)) {
	                HIP_IFEL(remove_esp_decryption_data(addr, *spi), -1, 
	                        "Error while removing decryption data\n");
	        }
               	break;
	case HIP_SET_ESCROW_ACTIVE:
               	HIP_DEBUG("Received activate escrow message from hipd\n\n");
               	set_escrow_active(1);
               	break;              
	case HIP_SET_ESCROW_INACTIVE:
	        HIP_DEBUG("Received deactivate escrow message from hipd\n\n");
	        set_escrow_active(0);
               	break;
        case HIP_BEX_DONE:
		HIP_DEBUG("Received bex done from hipd\n\n");
	        while((param = hip_get_next_param(msg, param))){
			if (hip_get_param_type(param) == HIP_PARAM_HIT){
				if (!hit_s)
					hit_s = (struct in6_addr *)hip_get_param_contents_direct(param);
			    	else 
		      			hit_r = (struct in6_addr *)hip_get_param_contents_direct(param);
		  	}
	  	}
		HIP_DEBUG("2. Received bex done from hipd\n\n");
		HIP_DEBUG_HIT(" hit_s ",hit_s);
		HIP_DEBUG_HIT(" hit_r ",hit_r);
		if (hit_r)
			err = firewall_set_bex_state(hit_s, hit_r, 1);
		else
			err = firewall_set_bex_state(hit_s, hit_r, -1);
		break;
	default:
		HIP_DEBUG("Type of message not handled\n");
		err = -1;
		break;
	}
out_err:	
	return err;

}


int sendto_hipd(void *msg, size_t len)
{
	/* Variables. */
	struct sockaddr_in6 sock_addr;
	int n, alen;
	
	bzero(&sock_addr, sizeof(sock_addr));
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = HIP_DAEMON_LOCAL_PORT;
	sock_addr.sin6_addr = in6addr_loopback;
    
	alen = sizeof(sock_addr);
	n = sendto(hip_firewall_sock, msg, len, 0, (struct sockaddr *)&sock_addr, alen);

	return (n);
}


/*Init functions raw_sockets ipv4*/
int firewall_init_raw_sock_tcp_v4(int *firewall_raw_sock_v4)
{
	int on = 1, err = 0;
	int off = 0;

	*firewall_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	HIP_IFEL(*firewall_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

	/* see bug id 212 why RECV_ERR is off */
	err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP, IP_RECVERR, &off, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
	err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
	err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
	err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

out_err:
	return err;
}

int firewall_init_raw_sock_udp_v4(int *firewall_raw_sock_v4)
{
	int on = 1, err = 0;
	int off = 0;

	*firewall_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	HIP_IFEL(*firewall_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

	/* see bug id 212 why RECV_ERR is off */
	err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP, IP_RECVERR, &off, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
	err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
	err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
	err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

out_err:
	return err;
}

int firewall_init_raw_sock_icmp_v4(int *firewall_raw_sock_v4)
{
	int on = 1, err = 0;
	int off = 0;

	*firewall_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	HIP_IFEL(*firewall_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

	/* see bug id 212 why RECV_ERR is off */
	err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP, IP_RECVERR, &off, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
	err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
	err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
	err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

	out_err:
	return err;
}

/*Init functions for raw sockets ipv6*/
int firewall_init_raw_sock_tcp_v6(int *firewall_raw_sock_v6)
{
    	int on = 1, off = 0, err = 0;

    	*firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    	HIP_IFEL(*firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");
	
    	/* see bug id 212 why RECV_ERR is off */
    	err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(on));
    	HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    	err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
    	HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    	err = setsockopt(*firewall_raw_sock_v6, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    	HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

 out_err:
	return err;
}

int firewall_init_raw_sock_udp_v6(int *firewall_raw_sock_v6)
{
	int on = 1, off = 0, err = 0;

	*firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
    	HIP_IFEL(*firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    	/* see bug id 212 why RECV_ERR is off */
	err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt recverr failed\n");
	err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
	err = setsockopt(*firewall_raw_sock_v6, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

 out_err:
	return err;
}

int firewall_init_raw_sock_icmp_v6(int *firewall_raw_sock_v6)
{
    	int on = 1, off = 0, err = 0;

    	*firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    	HIP_IFEL(*firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    	err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt recverr failed\n");
	err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
    	HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    	err = setsockopt(*firewall_raw_sock_v6, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    	HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

 out_err:
	return err;
}


int firewall_init_raw_sock_icmp_outbound(int *firewall_raw_sock_v6)
{
    int on = 1, off = 0, err = 0;

    *firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMP);
    HIP_IFEL(*firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    err = setsockopt(*firewall_raw_sock_v6, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

    out_err:
    return err;
}


void firewall_init_raw_sockets(void)
{
	firewall_init_raw_sock_tcp_v4(&firewall_raw_sock_tcp_v4);
	firewall_init_raw_sock_udp_v4(&firewall_raw_sock_udp_v4);
	firewall_init_raw_sock_icmp_v4(&firewall_raw_sock_icmp_v4);
	firewall_init_raw_sock_icmp_outbound(&firewall_raw_sock_icmp_outbound);
	firewall_init_raw_sock_tcp_v6(&firewall_raw_sock_tcp_v6);
	firewall_init_raw_sock_udp_v6(&firewall_raw_sock_udp_v6);
	firewall_init_raw_sock_icmp_v6(&firewall_raw_sock_icmp_v6); 
}

int initialise_firewall_socket()
{
        int err = 0;
        struct sockaddr_in6 sock_addr;
	socklen_t alen;
	
	/*New UDP socket for communication with HIPD*/
	hip_firewall_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	HIP_IFEL((hip_firewall_sock < 0), 1, "Could not create socket for firewall.\n");
	bzero(&sock_addr, sizeof(sock_addr));
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = HIP_FIREWALL_PORT;
	sock_addr.sin6_addr = in6addr_loopback;
	
	HIP_IFEL(bind(hip_firewall_sock, (struct sockaddr *)& sock_addr,
		      sizeof(sock_addr)), -1, "Bind on firewall socket addr failed\n");
 out_err:
	return err;
}

static inline u16 inchksum(const void *data, u32 length) {
	long sum = 0;
    	const u16 *wrd =  (u16 *) data;
    	long slen = (long) length;

    	while (slen > 1) {
        	sum += *wrd++;
        	slen -= 2;
    	}

    	if (slen > 0)
        	sum += * ((u8 *)wrd);

    	while (sum >> 16)
        	sum = (sum & 0xffff) + (sum >> 16);

    	return (u16) sum;
}

u16 ipv4_checksum(u8 protocol, u8 src[], u8 dst[], u8 data[], u16 len)
{

	u16 word16;
	u32 sum;	
	u16 i;

	//initialize sum to zero
	sum=0;

	// make 16 bit words out of every two adjacent 8 bit words and 
	// calculate the sum of all 16 vit words
	for (i=0;i<len;i=i+2){
		word16 =((((u16)(data[i]<<8)))&0xFF00)+(((u16)data[i+1])&0xFF);
		sum = sum + (unsigned long)word16;
	}	
	// add the TCP pseudo header which contains:
	// the IP source and destination addresses,
	for (i=0;i<4;i=i+2){
		word16 =((src[i]<<8)&0xFF00)+(src[i+1]&0xFF);
		sum=sum+word16;	
	}
	for (i=0;i<4;i=i+2)
	{
		word16 =((dst[i]<<8)&0xFF00)+(dst[i+1]&0xFF);
		sum=sum+word16; 	
	}
	// the protocol number and the length of the TCP packet
	sum = sum + protocol + len;

	// keep only the last 16 bits of the 32 bit calculated sum and add the carries
	while (sum>>16)
		sum = (sum & 0xFFFF)+(sum >> 16);

	// Take the one's complement of sum
	sum = ~sum;
	return (htons((unsigned short) sum));
}

u16 ipv6_checksum(u8 protocol, struct in6_addr *src, struct in6_addr *dst, void *data, u16 len)
{   
	u32 chksum = 0;
    	pseudo_v6 pseudo;
    	memset(&pseudo, 0, sizeof(pseudo_v6));

    	pseudo.src = *src;
    	pseudo.dst = *dst;
    	pseudo.length = htons(len);
    	pseudo.next = protocol;

    	chksum = inchksum(&pseudo, sizeof(pseudo_v6));
    	chksum += inchksum(data, len);

    	chksum = (chksum >> 16) + (chksum & 0xffff);
    	chksum += (chksum >> 16);

    	chksum = (u16)(~chksum);
    	if (chksum == 0)
    	    chksum = 0xffff;

    	return chksum;
}

int firewall_send_incoming_pkt(struct in6_addr *src_hit, struct in6_addr *dst_hit, u8 *msg, u16 len, int proto, int ttl){
        int err, dupl, try_again, sent, sa_size;
	int firewall_raw_sock = 0, is_ipv6 = 0, on = 1;
	struct ip *iphdr = NULL;
	struct udphdr *udp = NULL;
	struct tcphdr *tcp = NULL;
	struct icmphdr *icmp = NULL;
	struct icmp6hdr *icmpv6 = NULL;


	struct sockaddr_storage src, dst;
	struct sockaddr_in6 *sock_src6, *sock_dst6;

	struct sockaddr_in *sock_src4, *sock_dst4;
	struct in_addr src_aux, dst_aux;
	struct in6_addr any = IN6ADDR_ANY_INIT;

	HIP_ASSERT(src_hit != NULL && dst_hit != NULL);
	sock_src4 = (struct sockaddr_in *) &src;
	sock_dst4 = (struct sockaddr_in *) &dst;
	sock_src6 = (struct sockaddr_in6 *) &src;
	sock_dst6 = (struct sockaddr_in6 *) &dst;

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));

	if (IN6_IS_ADDR_V4MAPPED(src_hit)){
		sock_src4->sin_family = AF_INET;
		sock_dst4->sin_family = AF_INET;
		//IPV6_TO_IPV4_MAP(src_hit, &src_aux);
		//IPV6_TO_IPV4_MAP(dst_hit, &dst_aux);
		//memcpy(&(sock_src4->sin_addr), &src_aux, sizeof(src_aux));
		//memcpy(&(sock_dst4->sin_addr), &dst_aux, sizeof(dst_aux));

		IPV6_TO_IPV4_MAP(src_hit,&(sock_src4->sin_addr));
		IPV6_TO_IPV4_MAP(dst_hit,&(sock_dst4->sin_addr));
		sa_size = sizeof(struct sockaddr_in);

	}else{
		sock_src6->sin6_family = AF_INET6;
		ipv6_addr_copy(&sock_src6->sin6_addr, src_hit);
		sock_dst6->sin6_family = AF_INET6;
		ipv6_addr_copy(&sock_dst6->sin6_addr, dst_hit);
		sa_size = sizeof(struct sockaddr_in6);
		is_ipv6 = 1;
	}

	switch(proto){
		case IPPROTO_UDP:
			HIP_DEBUG("IPPROTO_UDP\n");
			if (is_ipv6){
				HIP_DEBUG(".............. IPPROTO_UDP v6\n");
			  	firewall_raw_sock = firewall_raw_sock_udp_v6;
			  	((struct udphdr*)msg)->check = ipv6_checksum(IPPROTO_UDP, &sock_src6->sin6_addr, 
								     	     &sock_dst6->sin6_addr, msg, len);
			}else{
				HIP_DEBUG(" IPPROTO_UDP v4\n");
			  	firewall_raw_sock = firewall_raw_sock_udp_v4;
				HIP_DEBUG_LSI("src@ ",&(sock_src4->sin_addr));
				HIP_DEBUG_LSI("dst@ ",&(sock_dst4->sin_addr));
			  	udp = (struct udphdr *)msg;

				sa_size = sizeof(struct sockaddr_in);
				msg = (u8 *) HIP_MALLOC((len + sizeof(struct ip)), 0);
				memset(msg, 0, (len + sizeof(struct ip)));

		   		udp->check = htons(0);
				udp->check = ipv4_checksum(IPPROTO_UDP, &(sock_src4->sin_addr), &(sock_dst4->sin_addr), udp, len);		
				memcpy((msg+sizeof(struct ip)), (u8*)udp, len);
			}
			break;
		case IPPROTO_TCP:
		        HIP_DEBUG("IPPROTO_TCP\n");
			if (is_ipv6){
				HIP_DEBUG(".............. IPPROTO_TCP v6\n");
			  	firewall_raw_sock = firewall_raw_sock_tcp_v6;
			  	((struct tcphdr*)msg)->check = ipv6_checksum(IPPROTO_TCP, &sock_src6->sin6_addr, 
								     	     &sock_dst6->sin6_addr, msg, len);
			}else{
				HIP_DEBUG(" IPPROTO_TCP v4\n");
			  	firewall_raw_sock = firewall_raw_sock_tcp_v4;
				HIP_DEBUG_LSI("src@ ",&(sock_src4->sin_addr));
				HIP_DEBUG_LSI("dst@ ",&(sock_dst4->sin_addr));
			  	tcp = (struct tcphdr *)msg;

				msg = (u8 *) HIP_MALLOC((len + sizeof(struct ip)), 0);
				memset(msg, 0, (len + sizeof(struct ip)));

		   		tcp->check = htons(0);
				tcp->check = ipv4_checksum(IPPROTO_TCP, &(sock_src4->sin_addr), &(sock_dst4->sin_addr), tcp, len);		
				memcpy((msg+sizeof(struct ip)), (u8*)tcp, len);
			}	
			break;
		case IPPROTO_ICMP:
		        firewall_raw_sock = firewall_raw_sock_icmp_v4;
			icmp = (struct icmphdr *)msg;
			msg = (u8 *) HIP_MALLOC((len + sizeof(struct ip)), 0);
			memset(msg, 0, (len + sizeof(struct ip)));
			icmp->checksum = htons(0);
			icmp->checksum = inchksum(icmp, len);
			memcpy((msg+sizeof(struct ip)), (u8*)icmp, len);
			break;
	        case IPPROTO_ICMPV6:
			  HIP_DEBUG(".............. IPPROTO_icmp v6\n");
			  firewall_raw_sock = firewall_raw_sock_icmp_v6;
			  ((struct icmp6hdr*)msg)->icmp6_cksum = htons(0);
			  ((struct icmp6hdr*)msg)->icmp6_cksum = ipv6_checksum(IPPROTO_ICMPV6, &sock_src6->sin6_addr, 
									       &sock_dst6->sin6_addr, msg, len);
			break;
		default:
		        HIP_ERROR("Protocol number not defined %d\n",proto);
		        break;
	}

	if (!is_ipv6){
		iphdr = (struct ip *) msg;	
		if (setsockopt(firewall_raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)))
		        HIP_IFEL(err, -1, "setsockopt IP_HDRINCL ERROR\n");  
		iphdr->ip_v = 4;
		iphdr->ip_hl = sizeof(struct ip) >> 2;
		iphdr->ip_tos = 0;
		iphdr->ip_len = len + iphdr->ip_hl*4;
		iphdr->ip_id = htons(0);
		iphdr->ip_off = 0;
		iphdr->ip_ttl = ttl;
		iphdr->ip_p = proto;
		iphdr->ip_src = sock_src4->sin_addr;
		iphdr->ip_dst = sock_dst4->sin_addr;
		iphdr->ip_sum = htons(0);
			
		HIP_HEXDUMP("hex", iphdr, (len + sizeof(struct ip)));
		for (dupl = 0; dupl < HIP_PACKET_DUPLICATES; dupl++) {
			for (try_again = 0; try_again < 2; try_again++) {
		    		sent = sendto(firewall_raw_sock, iphdr, 
					      iphdr->ip_len, 0,
					      (struct sockaddr *) &dst, sa_size);
			   	if (sent !=(len + sizeof(struct ip))) {
			     		HIP_ERROR("Could not send the all requested" \
				       		  " data (%d/%d)\n", sent, 
						  iphdr->ip_len);
			     		HIP_DEBUG("ERROR NUMBER: %d\n", errno);
			     		sleep(2);
			    	} else {
			     		HIP_DEBUG("sent=%d/%d \n",
						  sent, (len + sizeof(struct ip)));
			     		HIP_DEBUG("Packet sent ok\n");
			     		break;
			    	}
			}
		}
	}//if !is_ipv6

 out_err:
	if (is_ipv6){
		ipv6_addr_copy(&sock_src6->sin6_addr, &any);
	}else{
		sock_src4->sin_addr.s_addr = INADDR_ANY;
		sock_src4->sin_family = AF_INET;
	}

	bind(firewall_raw_sock, (struct sockaddr *) &src, sa_size);
	if (err)
		HIP_DEBUG("sterror %s\n",strerror(errno));
	return err;
	
}


int firewall_send_outgoing_pkt(struct in6_addr *src_hit, struct in6_addr *dst_hit, u8 *msg, u16 len, int proto)
{
        int err, dupl, try_again, sent, sa_size;
	int firewall_raw_sock = 0, is_ipv6 = 0, on = 1;
	struct ip *iphdr = NULL;

	struct sockaddr_storage src, dst;
	struct sockaddr_in6 *sock_src6, *sock_dst6;
	struct icmp6hdr *icmpv6 = NULL;
	struct icmphdr *icmp = NULL;
	struct sockaddr_in *sock_src4, *sock_dst4;
	struct in6_addr any = IN6ADDR_ANY_INIT;

	HIP_ASSERT(src_hit != NULL && dst_hit != NULL);

	sock_src4 = (struct sockaddr_in *) &src;
	sock_dst4 = (struct sockaddr_in *) &dst;
	sock_src6 = (struct sockaddr_in6 *) &src;
	sock_dst6 = (struct sockaddr_in6 *) &dst;

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));

	if (IN6_IS_ADDR_V4MAPPED(src_hit)){
		sock_src4->sin_family = AF_INET;
		IPV6_TO_IPV4_MAP(src_hit, &sock_src4->sin_addr);
		sock_dst4->sin_family = AF_INET;
		IPV6_TO_IPV4_MAP(dst_hit, &sock_dst4->sin_addr);
		sa_size = sizeof(struct sockaddr_in);
	}else{
		sock_src6->sin6_family = AF_INET6;
		ipv6_addr_copy(&sock_src6->sin6_addr, src_hit);
		sock_dst6->sin6_family = AF_INET6;
		ipv6_addr_copy(&sock_dst6->sin6_addr, dst_hit);
		sa_size = sizeof(struct sockaddr_in6);
		is_ipv6 = 1;
	}
	
	switch(proto){
		case IPPROTO_TCP:
  			HIP_DEBUG("IPPROTO_TCP\n");
			((struct tcphdr*)msg)->check = htons(0);
			
			if (is_ipv6){
			        HIP_DEBUG(".............. IPPROTO_TCP v6\n");
				HIP_DEBUG_HIT("orig@ ", &sock_src6->sin6_addr);
				HIP_DEBUG_HIT("dst@ ", &sock_dst6->sin6_addr);
				firewall_raw_sock = firewall_raw_sock_tcp_v6;
			  	((struct tcphdr*)msg)->check = ipv6_checksum(IPPROTO_TCP, &sock_src6->sin6_addr, 
								      	     &sock_dst6->sin6_addr, msg, len);
				HIP_DEBUG("After ipv6 checksum \n");
			}else{
			  	HIP_DEBUG(".............. IPPROTO_TCP v4\n");
			  	firewall_raw_sock = firewall_raw_sock_tcp_v4;
				HIP_DEBUG_LSI("&(sock_src4->sin_addr) == ", &(sock_src4->sin_addr));
				HIP_DEBUG_LSI("&(sock_dst4->sin_addr) == ", &(sock_dst4->sin_addr));
			  	((struct tcphdr*)msg)->check = ipv4_checksum(IPPROTO_TCP, &(sock_src4->sin_addr), 
								      	     &(sock_dst4->sin_addr), msg, len);
			}
    			break;
		case IPPROTO_UDP:
		        _HIP_DEBUG("IPPROTO_UDP\n");
			if (is_ipv6){
			        HIP_DEBUG(".............. IPPROTO_UDP v6\n");
				HIP_DEBUG_HIT("src@ ",&(sock_src6->sin6_addr));
                                HIP_DEBUG_HIT("dst@ ",&(sock_dst6->sin6_addr));
			  	firewall_raw_sock = firewall_raw_sock_udp_v6;
			  	((struct udphdr*)msg)->check = ipv6_checksum(IPPROTO_UDP, &sock_src6->sin6_addr, 
								     	     &sock_dst6->sin6_addr, msg, len);
				HIP_DEBUG(">>>src_port is %d\n",((struct udphdr*)msg)->source);
				HIP_DEBUG(">>>dst_port is %d\n",((struct udphdr*)msg)->dest);
			}else{
			        HIP_DEBUG(" IPPROTO_UDP v4\n");
			  	firewall_raw_sock = firewall_raw_sock_udp_v4;
				HIP_DEBUG_LSI("src@ ",&(sock_src4->sin_addr));
				HIP_DEBUG_LSI("dst@ ",&(sock_dst4->sin_addr));
			}
			break;
		case IPPROTO_ICMP:
		        if (is_ipv6)
			  firewall_raw_sock = firewall_raw_sock_icmp_outbound;
			else
			  firewall_raw_sock = firewall_raw_sock_icmp_v4;
			((struct icmphdr*)msg)->checksum = htons(0);
			((struct icmphdr*)msg)->checksum = inchksum(msg, len);
			break;
	        case IPPROTO_ICMPV6:
		        firewall_raw_sock = firewall_raw_sock_icmp_v6;
			((struct icmp6hdr*)msg)->icmp6_cksum = htons(0);
			((struct icmp6hdr*)msg)->icmp6_cksum = ipv6_checksum(IPPROTO_ICMPV6, &sock_src6->sin6_addr, 
									     &sock_dst6->sin6_addr, msg, len);
	                break;
		default:
		        HIP_DEBUG("No protocol family found\n");
			break;
	}

	
	HIP_IFEL(bind(firewall_raw_sock, (struct sockaddr *) &src, sa_size),
		 -1, "Binding to raw sock failed\n");
	HIP_DEBUG("After binding the @\n");	
	for (dupl = 0; dupl < HIP_PACKET_DUPLICATES; dupl++) {
	  HIP_DEBUG("Inside the first loop\n");
		for (try_again = 0; try_again < 2; try_again++) {
		        HIP_DEBUG("Inside the second loop, before sending \n");
		        sent = sendto(firewall_raw_sock, msg, len, 0,
			              (struct sockaddr *) &dst, sa_size);
			HIP_DEBUG("Inside the second loop, after sending \n");
			if (sent != len) {
                		HIP_ERROR("Could not send the all requested"\
                        	" data (%d/%d)\n", sent, len);
				HIP_ERROR("errno %s\n",strerror(errno));
                	sleep(2);
            		} else {
                		HIP_DEBUG("sent=%d/%d\n", sent, len);
                		HIP_DEBUG("Packet sent ok\n");
                		break;
            		}
        	}
		HIP_DEBUG(" dupl are %d\n",dupl);
	}
	HIP_DEBUG("\nAfter sending the packet \n");

 out_err:
	/* Reset the interface to wildcard*/
	if (is_ipv6){
	  // HIP_DEBUG_HIT("orig@ ", &sock_src6->sin6_addr);
	  //HIP_DEBUG_HIT("dst@ ", &sock_dst6->sin6_addr);
		ipv6_addr_copy(&sock_src6->sin6_addr, &any);
	}else{
		sock_src4->sin_addr.s_addr = INADDR_ANY;
		sock_src4->sin_family = AF_INET;
	}

	bind(firewall_raw_sock, (struct sockaddr *) &src, sa_size);
	if (err)
		HIP_DEBUG("sterror %s\n",strerror(errno));
	return err;
}



int control_thread_init(void)
{
	int err = 0;
	int n;
	int len;
	struct sockaddr_in6 sock_addr;
    
	struct hip_common *msg = NULL;
	socklen_t alen;

	/* Allocate message. */
	msg = hip_msg_alloc();
	if (!msg) {
		err = -1;
		return err;
	}
		
	HIP_IFEL(initialise_firewall_socket(),-1, "Firewall socket creation failed\n");
	firewall_init_raw_sockets();

    	if( !g_thread_supported() )
  		{
     		g_thread_init(NULL);
     		HIP_DEBUG("control_thread_init: initialized thread system\n");
  		}
  		else
  		{
     		HIP_DEBUG("control_thread_init: thread system already initialized\n");
  		}
    	control_thread_started = 1;
    	control_thread = g_thread_create(run_control_thread, 
					   (gpointer)msg, 
					   FALSE,
					   NULL);   
		if (!control_thread)
		HIP_DEBUG("Could not initialize control_thread\n");			   

	return 0;

out_err:
	if (hip_firewall_sock) close(hip_firewall_sock);
	if (msg != NULL) HIP_FREE(msg);

	return err;			   
}
