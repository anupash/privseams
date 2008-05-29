#include "firewalldb.h"

int hip_firewall_sock = 0;
int firewall_raw_sock_tcp_v4 = 0;
int firewall_raw_sock_udp_v4 = 0;
int firewall_raw_sock_icmp_v4 = 0;
int firewall_raw_sock_tcp_v6 = 0;
int firewall_raw_sock_udp_v6 = 0;
int firewall_raw_sock_icmp_v6 = 0;
int firewall_raw_sock_icmp_outbound = 0;


/**
 * firewall_hit_lsi_db_match:
 * Search in the database the given lsi
 *
 * @param lsi_peer: entrance that we are searching in the db
 * @return NULL if not found and otherwise the firewall_hl_t structure
 */
firewall_hl_t *firewall_hit_lsi_db_match(hip_lsi_t *lsi_peer){
  //hip_firewall_hldb_dump();
  return (firewall_hl_t *)hip_ht_find(firewall_lsi_hit_db, (void *)lsi_peer);
  
}

firewall_hl_t *hip_create_hl_entry(void){
	firewall_hl_t *entry = NULL;
	int err = 0;
	HIP_IFEL(!(entry = (firewall_hl_t *) HIP_MALLOC(sizeof(firewall_hl_t),0)),
		 -ENOMEM, "No memory available for firewall database entry\n");
  	memset(entry, 0, sizeof(*entry));
out_err:
	return entry;
}


void hip_firewall_hldb_dump(void)
{
	int i;
	firewall_hl_t *this;
	hip_list_t *item, *tmp;
	HIP_DEBUG("/////////////////////////////\n");
	HIP_DEBUG("//////  Firewall db  ///////\n");
	HIP_DEBUG("/////////////////////////////\n")
	HIP_LOCK_HT(&firewall_lsi_hit_db);

	list_for_each_safe(item, tmp, firewall_lsi_hit_db, i)
	{
		this = list_entry(item);
		HIP_DEBUG_HIT("Dump >>> hit_our", &this->hit_our);
		HIP_DEBUG_HIT("Dump >>> hit_peer", &this->hit_peer);
		HIP_DEBUG_LSI("Dump >>> lsi", &this->lsi);
		HIP_DEBUG("Dump >>> bex_state %d \n", this->bex_state);
	}
	HIP_UNLOCK_HT(&firewall_lsi_hit_db);
	HIP_DEBUG("end hldbdb dump\n");
}

int firewall_add_hit_lsi(struct in6_addr *hit_our, struct in6_addr *hit_peer, hip_lsi_t *lsi, int state){
	int err = 0;
	firewall_hl_t *new_entry = NULL;

	HIP_ASSERT(hit_our != NULL && hit_peer != NULL && lsi != NULL);
	HIP_DEBUG("Start firewall_add_hit_lsi\n");
	
	new_entry = hip_create_hl_entry();
	ipv6_addr_copy(&new_entry->hit_our, hit_our);
	ipv6_addr_copy(&new_entry->hit_peer, hit_peer);
	ipv4_addr_copy(&new_entry->lsi, lsi);
	new_entry->bex_state = state;
	HIP_DEBUG_HIT("1. entry to add to firewall_db hit_our ", &new_entry->hit_our);
	HIP_DEBUG_HIT("1. entry to add to firewall_db hit_peer ", &new_entry->hit_peer);
	HIP_DEBUG_LSI("1. entry to add to firewall_db lsi ", &new_entry->lsi);
	hip_ht_add(firewall_lsi_hit_db, new_entry);

out_err:
	//	hip_firewall_hldb_dump();
	HIP_DEBUG("End firewall_add_hit_lsi\n");
	return err;
}


/**
 * hip_firewall_hash_lsi:
 * Generates the hash information that is used to index the table
 *
 * @param ptr: pointer to the lsi used to make the hash
 *
 * @return hash information
 */
unsigned long hip_firewall_hash_lsi(const void *ptr){
        hip_lsi_t *lsi = &((firewall_hl_t *)ptr)->lsi;
	uint8_t hash[HIP_AH_SHA_LEN];     
	     
	hip_build_digest(HIP_DIGEST_SHA1, lsi, sizeof(*lsi), hash);     
	return *((unsigned long *)hash);
}

/**
 * hip_firewall_match_lsi:
 * Compares two LSIs
 *
 * @param ptr1: pointer to lsi
 * @param ptr2: pointer to lsi
 *
 * @return 0 if hashes identical, otherwise 1
 */
int hip_firewall_match_lsi(const void *ptr1, const void *ptr2){
	return (hip_firewall_hash_lsi(ptr1) != hip_firewall_hash_lsi(ptr2));
}

void firewall_init_hldb(void){
	firewall_lsi_hit_db = hip_ht_init(hip_firewall_hash_lsi, hip_firewall_match_lsi);
	firewall_init_raw_sockets();
}

int firewall_set_bex_state(struct in6_addr *hit_s, struct in6_addr *hit_r, int state){
	int err = 0;
	hip_lsi_t *lsi_peer = NULL;
	firewall_hl_t *entry_update = NULL;

	lsi_peer = hip_get_lsi_peer_by_hits(hit_s, hit_r);

	if (lsi_peer){
	        entry_update = firewall_hit_lsi_db_match(lsi_peer);
		entry_update->bex_state = state;
		hip_ht_add(firewall_lsi_hit_db, entry_update);
	}
	else
		err = -1;
	return err;
}

void hip_firewall_delete_hldb(void){
	int i;
	firewall_hl_t *this;
	hip_list_t *item, *tmp;
	
	HIP_DEBUG("Start hldb delete\n");
	HIP_LOCK_HT(&firewall_lsi_hit_db);

	list_for_each_safe(item, tmp, firewall_lsi_hit_db, i)
	{
		this = list_entry(item);
		hip_ht_delete(firewall_lsi_hit_db, this);
	}
	HIP_UNLOCK_HT(&firewall_lsi_hit_db);
	HIP_DEBUG("End hldbdb delete\n");
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
  //HIP_IFEL(initialise_firewall_socket(),-1,"Firewall socket creation failed\n");
	firewall_init_raw_sock_tcp_v4(&firewall_raw_sock_tcp_v4);
	firewall_init_raw_sock_udp_v4(&firewall_raw_sock_udp_v4);
	firewall_init_raw_sock_icmp_v4(&firewall_raw_sock_icmp_v4);
	firewall_init_raw_sock_icmp_outbound(&firewall_raw_sock_icmp_outbound);
	firewall_init_raw_sock_tcp_v6(&firewall_raw_sock_tcp_v6);
	firewall_init_raw_sock_udp_v6(&firewall_raw_sock_udp_v6);
	firewall_init_raw_sock_icmp_v6(&firewall_raw_sock_icmp_v6); 
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

