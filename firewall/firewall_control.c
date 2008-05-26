/*
 * Firewall control
 * 
 */
 
#include "firewall_control.h"


int firewall_raw_sock_tcp_v4 = 0;
int firewall_raw_sock_udp_v4 = 0;
int firewall_raw_sock_icmp_v4 = 0;
int firewall_raw_sock_tcp_v6 = 0;
int firewall_raw_sock_udp_v6 = 0;
int firewall_raw_sock_icmp_v6 = 0;
int firewall_raw_sock_icmp_outbound = 0;
int hip_fw_sock = 0;
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
		FD_SET(hip_fw_sock, &read_fdset);
		max_fd = hip_fw_sock;
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
		else if (FD_ISSET(hip_fw_sock, &read_fdset))
		{
		}
		else {
			HIP_INFO("Unknown socket activity.\n");
		}
	}
out_err:
	/* Send quit message to daemon. */
	hip_build_user_hdr(msg, SO_HIP_FIREWALL_QUIT, 0);
	n = sendto_hipd(msg, sizeof(struct hip_common));
	if (n < 0) HIP_ERROR("Could not send quit message to daemon.\n");
	
	if (hip_fw_sock)
		close(hip_fw_sock);
	if (msg != NULL)
		HIP_FREE(msg);

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
	
	HIP_DEBUG("Handling message from hipd\n");
	
	type = hip_get_msg_type(msg);
	
	//for(param = hip_get_next_) {
	//	switch (type = hip_get_param_type(param))) 
	//      PARAM_XX:
	//      break;
	//}
	
	switch(type) {
	case SO_HIP_FIREWALL_BEX_DONE: {
		
		struct in6_addr *saddr = NULL, *daddr = NULL;
		struct in6_addr *src_hit = NULL, *dst_hit = NULL;
		uint32_t *spi_ipsec = NULL;
		int ealg;
		struct hip_crypto_key *enckey = NULL, *authkey = NULL;
		int already_acquired, direction, update, sport, dport;
		hip_tlv_type_t *param;
		
		HIP_DEBUG("Received base exchange done from hipd\n\n");
		
		/* now param: src addr */
		
		
		param = (hip_tlv_type_t *) hip_get_param(msg, HIP_PARAM_IPV6_ADDR);
		saddr = (struct in6_addr *) hip_get_param_contents_direct(param); 
		HIP_DEBUG_IN6ADDR("Received in6_addr: ", saddr);
		
                /* now param: dst addr */
		
		param = hip_get_next_param(msg, param);
		daddr = (struct in6_addr *) hip_get_param_contents_direct(param);
		HIP_DEBUG_IN6ADDR("Received in6_addr: ", daddr);
		param =  (hip_tlv_type_t *) hip_get_param(msg, HIP_PARAM_HIT);
		
		/* now param: src_hit */
		src_hit = (struct in6_addr *)hip_get_param_contents_direct(param);
		
		HIP_DEBUG_HIT("Received src_hit: ", src_hit);
		
		/* now param: dst_hit */
		
		param =  hip_get_next_param(msg, param);
		dst_hit = (struct in6_addr *)hip_get_param_contents_direct(param);
		
		HIP_DEBUG_HIT("Received dst_hit: ", dst_hit);
		
		
		param =  (hip_tlv_type_t *) hip_get_param(msg, HIP_PARAM_UINT);
		
		/* now param: spi */
		spi_ipsec = (uint32_t *) hip_get_param_contents_direct(param);
		
		HIP_DEBUG("the spi value is %x \n", *spi_ipsec);
		
		
		
		param =  hip_get_next_param(msg, param);
		sport = *((unsigned int *) hip_get_param_contents_direct(param));
		HIP_DEBUG("the source port vaule is %d \n", sport);
		
		param =  hip_get_next_param(msg, param);
		dport = *((unsigned int *) hip_get_param_contents_direct(param));
		HIP_DEBUG("the destination port value is %d \n", dport);
		
		
		
		
		param =  (hip_tlv_type_t *) hip_get_param(msg, HIP_PARAM_KEYS);
		
		
		/* now param: enckey */
		enckey = (struct hip_crypto_key *) hip_get_param_contents_direct(param);
		
		
		
		
		// HIP_DEBUG("crypto key is: \n");
		HIP_HEXDUMP("crypto key :", enckey, sizeof(struct hip_crypto_key));
		
		
		/* now param: anthkey */
		
		param =  hip_get_next_param(msg, param);
		authkey = (struct hip_crypto_key *)hip_get_param_contents_direct(param);
		// HIP_DEBUG("auth key key is: \n"); 
		
		
		HIP_HEXDUMP("authen key :", authkey, sizeof(struct hip_crypto_key));
		
		
		/* now param: ealg */
		param =  (hip_tlv_type_t *) hip_get_param(msg, HIP_PARAM_INT);
		
		ealg = *((int *) hip_get_param_contents_direct(param));
		
		HIP_DEBUG("ealg  value is %d \n", ealg);
		
		/* now param: already_acquired */
		param =  hip_get_next_param(msg, param);		
		already_acquired = *((int *) hip_get_param_contents_direct( param));
		HIP_DEBUG("already_acquired value is %d \n", already_acquired);
		
		/* now param: direction */
		param =  hip_get_next_param(msg, param);		
		direction = *((int *) hip_get_param_contents_direct(param));
		HIP_DEBUG("the direction value is %d \n", direction);
		
                /* now param: update */
		
		param =  hip_get_next_param(msg, param);
		update = *((int *) hip_get_param_contents_direct(param));
		HIP_DEBUG("the update value is %d \n", update);
		
		err =  hipl_userspace_ipsec_api_wrapper_sadb_add(saddr, daddr, 
								 src_hit, dst_hit, 
								 spi_ipsec, ealg, enckey, 
								 authkey, already_acquired, 
								 direction, update, 
								 sport, dport);
		
		
		HIP_IFEL(err, -1, "hip userspace sadb add went wrong\n");
		break;
	}
		
	case SO_HIP_ADD_ESCROW_DATA:
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
	case SO_HIP_DELETE_ESCROW_DATA:
	{
                struct in6_addr * addr = NULL;
                uint32_t * spi = NULL;
                
                HIP_DEBUG("Received delete message from hipd\n\n");
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
	}
	case SO_HIP_SET_ESCROW_ACTIVE:
		HIP_DEBUG("Received activate escrow message from hipd\n\n");
		set_escrow_active(1);
		break;
	case SO_HIP_SET_ESCROW_INACTIVE:
		HIP_DEBUG("Received deactivate escrow message from hipd\n\n");
		set_escrow_active(0);
		break;
	case SO_HIP_SET_HIPPROXY_ON:
	        HIP_DEBUG("Received HIP PROXY STATUS: ON message from hipd\n\n");
	        HIP_DEBUG("Firewall is working on Proxy Mode!\n\n");
	        hip_proxy_status = 1;
	        firewall_init_rules();
		break;
	case SO_HIP_SET_HIPPROXY_OFF:
		HIP_DEBUG("Received HIP PROXY STATUS: OFF message from hipd\n\n");
		HIP_DEBUG("Firewall is working on Firewall Mode!\n\n");
	        hip_proxy_status = 0;
	        firewall_init_rules();
		break;
	/*   else if(type == HIP_HIPPROXY_LOCAL_ADDRESS){
	     HIP_DEBUG("Received HIP PROXY LOCAL ADDRESS message from hipd\n\n");
	     if (hip_get_param_type(param) == HIP_PARAM_IPV6_ADDR)
		{
		_HIP_DEBUG("Handling HIP_PARAM_IPV6_ADDR\n");
		hit_s = hip_get_param_contents_direct(param);
		}
		}
	*/	
	default:
		HIP_ERROR("Unhandled message type %d\n", type);
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
	sock_addr.sin6_port = htons(HIP_DAEMON_LOCAL_PORT);
	sock_addr.sin6_addr = in6addr_loopback;
    
	alen = sizeof(sock_addr);
	n = sendto(hip_fw_sock, msg, len, 0,
		   (struct sockaddr *)&sock_addr, alen);

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
	hip_fw_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	HIP_IFEL((hip_fw_sock < 0), 1, "Could not create socket for firewall.\n");
	bzero(&sock_addr, sizeof(sock_addr));
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = HIP_FIREWALL_PORT;
	sock_addr.sin6_addr = in6addr_loopback;
	
	HIP_IFEL(bind(hip_fw_sock, (struct sockaddr *)& sock_addr,
		      sizeof(sock_addr)), -1, "Bind on firewall socket addr failed\n");
 out_err:
	return err;
}

inline u16 inchksum(const void *data, u32 length){
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
			HIP_DEBUG("icmp->type = %d\n",icmp->type);
			HIP_DEBUG("icmp->code = %d\n",icmp->code);
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


#ifdef CONFIG_HIP_HIPPROXY
int request_hipproxy_status(void)
{
        struct hip_common *msg;
        int err = 0;
        int n;
        socklen_t alen;
        HIP_DEBUG("Sending hipproxy msg to hipd.\n");                        
        HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
        hip_msg_init(msg);
        HIP_IFEL(hip_build_user_hdr(msg, 
                SO_HIP_HIPPROXY_STATUS_REQUEST, 0), 
                -1, "Build hdr failed\n");
                
        //n = hip_sendto(msg, &hip_firewall_addr);
        
        //n = sendto(hip_fw_sock, msg, hip_get_msg_total_len(msg),
        //		0,(struct sockaddr *)dst, sizeof(struct sockaddr_in6));
        
        n = sendto_hipd(msg, hip_get_msg_total_len(msg));
        if (n < 0) {
                HIP_ERROR("HIP_HIPPROXY_STATUS_REQUEST: Sendto HIPD failed.\n");
                err = -1;
                goto out_err;
        }
        else {
                HIP_DEBUG("HIP_HIPPROXY_STATUS_REQUEST: Sendto firewall OK.\n");
        }  
out_err:
        return err;
}
#endif /* CONFIG_HIP_HIPPROXY */
