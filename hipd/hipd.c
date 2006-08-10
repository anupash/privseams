
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "hipd.h" 

/* For receiving of HIP control messages */
int hip_raw_sock_v6 = 0;
int hip_raw_sock_v4 = 0;
int hip_nat_sock_udp = 0;	/* For NAT traversal of IPv4 packets for base exchange*/
int hip_nat_sock_udp_data = 0;  /* For NAT traversal of IPv4 packets for Data traffic */

int hip_nat_status = 0; /*Specifies the NAT status of the daemon. It is turned off by default*/


/* Communication interface to userspace apps (hipconf etc) */
int hip_user_sock = 0;
struct sockaddr_un hip_user_addr;

/* For receiving netlink IPsec events (acquire, expire, etc) */
struct rtnl_handle hip_nl_ipsec = { 0 };

/* For getting/setting routes and adding HITs (it was not possible to use
   nf_ipsec for this purpose). */
struct rtnl_handle hip_nl_route = { 0 };

int hip_agent_sock = 0, hip_agent_status = 0;
struct sockaddr_un hip_agent_addr;

#ifdef CONFIG_HIP_OPPORTUNISTIC
unsigned int opportunistic_mode = 1;
unsigned int oppdb_exist = 0;
extern   hip_opp_block_t *hip_oppdb_find_byhits(const hip_hit_t *hit_peer, 
						const hip_hit_t *hit_our);
#endif // CONFIG_HIP_OPPORTUNISTIC

/* We are caching the IP addresses of the host here. The reason is that during
   in hip_handle_acquire it is not possible to call getifaddrs (it creates
   a new netlink socket and seems like only one can be open per process).
   Feel free to experiment by porting the required functionality from
   iproute2/ip/ipaddrs.c:ipaddr_list_or_flush(). It would make these global
   variable and most of the functions referencing them unnecessary -miika */
int address_count;
struct list_head addresses;

int nat_keep_alive_counter = HIP_NAT_KEEP_ALIVE_TIME;
float retrans_counter = HIP_RETRANSMIT_INIT;
float precreate_counter = HIP_R1_PRECREATE_INIT;
float opendht_counter = OPENDHT_REFRESH_INIT;

time_t load_time;

void usage() {
	fprintf(stderr, "HIPL Daemon %.2f\n", HIPL_VERSION);
        fprintf(stderr, "Usage: hipd [options]\n\n");
	fprintf(stderr, "  -b run in foreground\n");
#ifdef CONFIG_HIP_HI3
	fprintf(stderr, "  -3 <i3 client configuration file>\n");
#endif
	fprintf(stderr, "\n");
}

int hip_handle_retransmission(hip_ha_t *entry, void *current_time)
{
	int err = 0;
	time_t *now = (time_t*) current_time;	

	if (!entry->hip_msg_retrans.buf)
		goto out_err;
	
	if (entry->state == HIP_STATE_FILTERING)
	{
		HIP_DEBUG("Waiting reply from agent...\n");
		goto out_err;
	}
	
	_HIP_DEBUG("Time to retrans: %d Retrans count: %d State: %d\n",
 		   entry->hip_msg_retrans.last_transmit + HIP_RETRANSMIT_WAIT - *now,
		   entry->hip_msg_retrans.count, entry->state);
	
	_HIP_DEBUG_HIT("hit_peer", &entry->hit_peer);
	_HIP_DEBUG_HIT("hit_our", &entry->hit_our);
	/* check if the last transmision was at least RETRANSMIT_WAIT seconds ago */
	if(*now - HIP_RETRANSMIT_WAIT > entry->hip_msg_retrans.last_transmit){
		if (entry->hip_msg_retrans.count > 0 &&
	    	entry->state != HIP_STATE_ESTABLISHED) {
			HIP_DEBUG("Retransmit packet\n");
			err = entry->hadb_xmit_func->hip_csum_send(&entry->hip_msg_retrans.saddr,
								   &entry->hip_msg_retrans.daddr,
									0,0, /*need to correct it*/
								   entry->hip_msg_retrans.buf,
								   entry, 0);
			/* Set entry state, if previous state was unassosiated and type is I1. */
			if (!err && hip_get_msg_type(entry->hip_msg_retrans.buf) == HIP_I1);
			{
				HIP_DEBUG("Send I1 succcesfully after acception.\n");
				entry->state = HIP_STATE_I1_SENT;
			}
			
			entry->hip_msg_retrans.count--;
			/* set the last transmission time to the current time value */
			time(&entry->hip_msg_retrans.last_transmit);
		} else {
		  	HIP_FREE(entry->hip_msg_retrans.buf);
			entry->hip_msg_retrans.buf = NULL;
			entry->hip_msg_retrans.count = 0;
		}
	}

 out_err:
	return err;
}

int hip_scan_retransmissions()
{
	int err = 0;
	time_t current_time;
	time(&current_time);
	HIP_IFEL(hip_for_each_ha(hip_handle_retransmission, &current_time), 0, 
		 "for_each_ha err.\n");
 out_err:
	return err;
}

int hip_agent_add_lhit(struct hip_host_id_entry *entry, void *msg)
{
	int err = 0;

	err = hip_build_param_contents(msg, (void *)&entry->lhi.hit, HIP_PARAM_HIT,
	                               sizeof(struct in6_addr));
	if (err)
	{
		HIP_ERROR("build param hit failed: %s\n", strerror(err));
		goto out_err;
	}

out_err:
	return (err);
}

int hip_agent_add_lhits(void)
{
	struct hip_common *msg;
	int err = 0, n;
	socklen_t alen;

#ifdef CONFIG_HIP_AGENT
/*	if (!hip_agent_is_alive())
	{
		return (-ENOENT);
	}*/

	msg = malloc(HIP_MAX_PACKET);
	if (!msg)
	{
		HIP_ERROR("malloc failed\n");
		goto out_err;
	}
	hip_msg_init(msg);

	HIP_IFEL(hip_for_each_hi(hip_agent_add_lhit, msg), 0,
	         "for_each_hi err.\n");

	err = hip_build_user_hdr(msg, SO_HIP_ADD_DB_HI, 0);
	if (err)
	{
		HIP_ERROR("build hdr failed: %s\n", strerror(err));
		goto out_err;
	}

	HIP_DEBUG("Sending local HITs to agent,"
	          " message body size is %d bytes...\n",
	          hip_get_msg_total_len(msg) - sizeof(struct hip_common));

	alen = sizeof(hip_agent_addr);                      
	n = sendto(hip_agent_sock, msg, hip_get_msg_total_len(msg),
	           0, (struct sockaddr *)&hip_agent_addr, alen);
	if (n < 0)
	{
		HIP_ERROR("Sendto() failed.\n");
		err = -1;
		goto out_err;
	}
	else HIP_DEBUG("Sendto() OK.\n");

#endif

out_err:
	return (err);
}

int hip_agent_is_alive()
{
#ifdef CONFIG_HIP_AGENT
	if (hip_agent_status) HIP_DEBUG("Agent is alive.\n");
	else HIP_DEBUG("Agent is not alive.\n");
	return hip_agent_status;
#else
	HIP_DEBUG("Agent is disabled.\n");
       return 0;
#endif /* CONFIG_HIP_AGENT */
}

int hip_agent_filter(struct hip_common *msg)
{
	int err = 0;
	int n, sendn;
	socklen_t alen;
	hip_ha_t *ha_entry;
	struct in6_addr hits;
	
	if (!hip_agent_is_alive())
	{
		return (-ENOENT);
	}
	
	HIP_DEBUG("Filtering hip control message trough agent,"
	          " message body size is %d bytes.\n",
	          hip_get_msg_total_len(msg) - sizeof(struct hip_common));
/*	HIP_HEXDUMP("contents start: ", msg, sizeof(struct hip_common));
	memcpy(&hits, &msg->hits, sizeof(hits));*/

	alen = sizeof(hip_agent_addr);                      
	n = sendto(hip_agent_sock, msg, hip_get_msg_total_len(msg),
	           0, (struct sockaddr *)&hip_agent_addr, alen);
	if (n < 0)
	{
		HIP_ERROR("Sendto() failed.\n");
		err = -1;
		goto out_err;
	}
	
	HIP_DEBUG("Sent %d bytes to agent for handling.\n", n);
	
	/*
		If message is type I1, then user action might be needed to filter the packet.
		Not receiving the packet directly from agent.
	*/
	HIP_IFE(hip_get_msg_type(msg) == HIP_I1, 1)
	
	alen = sizeof(hip_agent_addr);
	sendn = n;
	n = recvfrom(hip_agent_sock, msg, n, 0,
	             (struct sockaddr *)&hip_agent_addr, &alen);
	if (n < 0)
	{
		HIP_ERROR("Recvfrom() failed.\n");
		err = -1;
		goto out_err;
	}
	/* This happens, if agent rejected the packet. */
	else if (sendn != n)
	{
		err = 1;
	}

/*	if (hip_get_msg_type(msg) == HIP_I1 &&
	    memcmp(&msg->hits, &hits, sizeof(msg->hits)) != 0)
	{
		HIP_DEBUG("Updating selected local HIT state in hadb to I1_SENT...\n");
		ha_entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);
		if (ha_entry)
		{
			HIP_DEBUG("1. Changing state from %d to %d\n", ha_entry->state, HIP_STATE_I1_SENT);
			ha_entry->state = HIP_STATE_I1_SENT;
		}
		ha_entry = hip_hadb_find_byhits(&hits, &msg->hitr);
		if (ha_entry)
		{
			HIP_DEBUG("2. Changing state from %d to %d\n", ha_entry->state, HIP_STATE_UNASSOCIATED);
			ha_entry->state = HIP_STATE_UNASSOCIATED;
		}
		err = 1;
	}

	HIP_HEXDUMP("contents end: ", msg, sizeof(struct hip_common));*/

out_err:
       return (err);
}


int hip_init_host_ids() {
	int err = 0;
	struct stat status;
	struct hip_common *user_msg = NULL;

	/* We are first serializing a message with HIs and then
	   deserializing it. This building and parsing causes
	   a minor overhead, but as a result we can reuse the code
	   with hipconf. */

	HIP_IFE((!(user_msg = hip_msg_alloc())), -1);
		
	/* Create default keys if necessary. */

	if (stat(DEFAULT_CONFIG_DIR, &status) && errno == ENOENT) {
		hip_msg_init(user_msg);
		err = hip_serialize_host_id_action(user_msg,
						   ACTION_NEW, 0, 1,
						   NULL, NULL);
		if (err) {
			err = 1;
			HIP_ERROR("Failed to create keys to %s\n",
				  DEFAULT_CONFIG_DIR);
			goto out_err;
		}
	}
	
        /* Retrieve the keys to hipd */
	hip_msg_init(user_msg);
	err = hip_serialize_host_id_action(user_msg, ACTION_ADD, 0, 1,
					   NULL, NULL);
	if (err) {
		HIP_ERROR("Could not load default keys\n");
		goto out_err;
	}
	
	err = hip_handle_add_local_hi(user_msg);
	if (err) {
		HIP_ERROR("Adding of keys failed\n");
		goto out_err;
	}

 out_err:

	if (user_msg)
		HIP_FREE(user_msg);

	return err;
}

int hip_init_raw_sock_v6(int *hip_raw_sock_v6) {
	int on = 1, err = 0;

	HIP_IFEL(((*hip_raw_sock_v6 = socket(AF_INET6, SOCK_RAW,
					 IPPROTO_HIP)) <= 0), 1,
		 "Raw socket creation failed. Not root?\n");

	HIP_IFEL(setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6, IPV6_RECVERR, &on,
		   sizeof(on)), -1, "setsockopt recverr failed\n");
	HIP_IFEL(setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6,
			    IPV6_2292PKTINFO, &on,
		   sizeof(on)), -1, "setsockopt pktinfo failed\n");

	HIP_IFEL(setsockopt(*hip_raw_sock_v6, SOL_SOCKET, SO_REUSEADDR, &on,
			    sizeof(on)), -1,
		 "setsockopt v6 reuseaddr failed\n");

 out_err:
	return err;
}

int hip_init_raw_sock_v4(int *hip_raw_sock_v4) {
	int on = 1, err = 0;
	int off = 0;

	HIP_IFEL(((*hip_raw_sock_v4 = socket(AF_INET, SOCK_RAW,
					 IPPROTO_HIP)) <= 0), 1,
		 "Raw socket v4 creation failed. Not root?\n");
	HIP_IFEL(setsockopt(*hip_raw_sock_v4, IPPROTO_IP, IP_RECVERR, &on,
		   sizeof(on)), -1, "setsockopt v4 recverr failed\n");
	HIP_IFEL(setsockopt(*hip_raw_sock_v4, SOL_SOCKET, SO_BROADCAST, &on,
		   sizeof(on)), -1,
		 "setsockopt v4 failed to set broadcast \n");
	HIP_IFEL(setsockopt(*hip_raw_sock_v4, IPPROTO_IP, IP_PKTINFO, &on,
		   sizeof(on)), -1, "setsockopt v4 pktinfo failed\n");

	HIP_IFEL(setsockopt(*hip_raw_sock_v4, SOL_SOCKET, SO_REUSEADDR, &on,
			    sizeof(on)), -1,
		 "setsockopt v4 reuseaddr failed\n");

 out_err:
	return err;
}

int hip_init_nat_sock_udp(int *hip_nat_sock_udp)
{
	int on = 1, err = 0;
	int off = 0;
	int encap_on = UDP_ENCAP_ESPINUDP_NONIKE;
        struct sockaddr_in myaddr;

	HIP_DEBUG("----------Opening udp socket !--------------\n");
	if((*hip_nat_sock_udp = socket(AF_INET, SOCK_DGRAM, 0))<0)
        {
                HIP_ERROR("Can not open socket for UDP\n");
                return -1;
        }
	HIP_IFEL(setsockopt(*hip_nat_sock_udp, IPPROTO_IP, IP_PKTINFO, &on,
		   sizeof(on)), -1, "setsockopt udp pktinfo failed\n");
	HIP_IFEL(setsockopt(*hip_nat_sock_udp, IPPROTO_IP, IP_RECVERR, &on,
                   sizeof(on)), -1, "setsockopt udp recverr failed\n");
	HIP_IFEL(setsockopt(*hip_nat_sock_udp, SOL_UDP, UDP_ENCAP, &encap_on,
                   sizeof(encap_on)), -1, "setsockopt udp encap failed\n");
	HIP_IFEL(setsockopt(*hip_nat_sock_udp, SOL_SOCKET, SO_REUSEADDR, &on,
			    sizeof(encap_on)), -1,
		 "setsockopt udp reuseaddr failed\n");

        myaddr.sin_family=AF_INET;
        myaddr.sin_addr.s_addr = INADDR_ANY;	//FIXME: Change this inaddr_any -- Abi
        myaddr.sin_port=htons(HIP_NAT_UDP_PORT);

        //memcpy(nl_udp->local ,&myaddr, sizeof(myaddr));

        if( bind(*hip_nat_sock_udp, (struct sockaddr *)&myaddr, sizeof(myaddr))< 0 )
        {
                HIP_ERROR("Unable to bind udp socket to port\n");
                err = -1;
		goto out_err;
        }
	HIP_DEBUG("socket done\n");
        HIP_DEBUG_INADDR("Socket created and binded to port to addr :",&myaddr.sin_addr);
        return 0;


 out_err:
	return err;

}

int hip_init_nat_sock_udp_data(int *hip_nat_sock_udp_data)
{
	int on = UDP_ENCAP_ESPINUDP, err = 0;
	int off = 0;
	
	HIP_DEBUG("----------Opening udp socket !--------------\n");
	if((*hip_nat_sock_udp_data = socket(AF_INET, SOCK_DGRAM, 0))<0)
        {
                HIP_ERROR("Can not open socket for UDP\n");
                return -1;
        }
	HIP_IFEL(setsockopt(*hip_nat_sock_udp_data, SOL_UDP, UDP_ENCAP, &on,
		   sizeof(on)), -1, "setsockopt udp encap failed\n");


        struct sockaddr_in myaddr;


        myaddr.sin_family=AF_INET;
        myaddr.sin_addr.s_addr = INADDR_ANY;	//FIXME: Change this inaddr_any -- Abi
        myaddr.sin_port=htons(HIP_NAT_UDP_DATA_PORT);

        //memcpy(nl_udp->local ,&myaddr, sizeof(myaddr));

        if( bind(*hip_nat_sock_udp_data, (struct sockaddr *)&myaddr, sizeof(myaddr))< 0 )
        {
                HIP_ERROR("Unable to bind udp socket to port\n");
                err = -1;
		goto out_err;
        }
	HIP_DEBUG("socket done\n");
        HIP_DEBUG_INADDR("Socket created and binded to port to addr :",&myaddr.sin_addr);
        return 0;


 out_err:
	return err;

}


/*
 * Cleanup and signal handler to free userspace and kernel space
 * resource allocations.
 */
void hip_exit(int signal) {
	HIP_ERROR("Signal: %d\n", signal);

	//hip_delete_default_prefix_sp_pair();

	/* Close SAs with all peers */
	hip_send_close(NULL);

	hip_delete_all_sp();

	delete_all_addresses();

	set_up_device(HIP_HIT_DEV, 0);

#ifdef CONFIG_HIP_HI3
	cl_exit();
#endif
	//hip_uninit_workqueue();
#ifdef CONFIG_HIP_RVS
        hip_uninit_rvadb();
#endif

#ifdef CONFIG_HIP_ESCROW
	hip_uninit_keadb();
	hip_uninit_kea_endpoints();
	hip_uninit_services();
#endif

	// hip_uninit_host_id_dbs();
        // hip_uninit_hadb();
	// hip_uninit_beetdb();
	if (hip_raw_sock_v6)
		close(hip_raw_sock_v6);
	if (hip_raw_sock_v4)
		close(hip_raw_sock_v4);
	if(hip_nat_sock_udp)
		close(hip_nat_sock_udp);
	if(hip_nat_sock_udp_data)
		close(hip_nat_sock_udp_data);
	if (hip_user_sock)
		close(hip_user_sock);
	if (hip_nl_ipsec.fd)
		rtnl_close(&hip_nl_ipsec);
	if (hip_nl_route.fd)
		rtnl_close(&hip_nl_route);
	if (hip_agent_sock)
		close(hip_agent_sock);

	exit(signal);
}

int init_random_seed()
{
	struct timeval tv;
	struct timezone tz;
	int err = 0;

	err = gettimeofday(&tv, &tz);
	srandom(tv.tv_usec);

	return err;
}

/* insert mapping for local host IP addresses to HITs to DHT */
void register_to_dht ()
{
#ifdef CONFIG_HIP_OPENDHT

  struct netdev_address *n, *t;
  char hostname [HIP_HOST_ID_HOSTNAME_LEN_MAX];
  if (gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1)) 
    return;
  
  HIP_INFO("Using hostname: %s\n", hostname);
  
  list_for_each_entry_safe(n, t, &addresses, next) {
    //AG this should be replaced with a loop with hip_for_each_hi
    struct in6_addr tmp_hit;
    char *tmp_hit_str, *tmp_addr_str;
    if (ipv6_addr_is_hit(SA2IP(&n->addr)))
	continue;

    if (hip_get_any_localhost_hit(&tmp_hit, HIP_HI_DEFAULT_ALGO) < 0) {
      HIP_ERROR("No HIT found\n");
      return;
    }
	 
    tmp_hit_str =  hip_convert_hit_to_str(&tmp_hit, NULL);
    tmp_addr_str = hip_convert_hit_to_str(SA2IP(&n->addr), NULL);
    
    HIP_DEBUG("Inserting HIT=%s with IP=%s and hostname %s to DHT\n",
	      tmp_hit_str, tmp_addr_str, hostname);
    updateHIT(hostname, tmp_hit_str);
    updateHIT(tmp_hit_str, tmp_addr_str);
  } 	
#endif
}

int periodic_maintenance() {
	int err = 0;

	if (retrans_counter < 0) {
		HIP_IFEL(hip_scan_retransmissions(), -1,
			 "retransmission scan failed\n");
		retrans_counter = HIP_RETRANSMIT_INIT;
	} else {
		retrans_counter--;
	}

	if (precreate_counter < 0) {
		HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1,
			 "Failed to recreate puzzles\n");
		precreate_counter = HIP_R1_PRECREATE_INIT;
	} else {
		precreate_counter--;
	}

#ifdef CONFIG_HIP_OPENDHT
	if (precreate_counter < 0) {
		register_to_dht();
		opendht_counter = OPENDHT_REFRESH_INIT;
	} else {
                opendht_counter--;
        }
#endif

	if(nat_keep_alive_counter < 0){
		HIP_IFEL(hip_nat_keep_alive(), -1, 
			"Failed to send out keepalives\n");
		nat_keep_alive_counter = HIP_NAT_KEEP_ALIVE_TIME;
	} else {
		nat_keep_alive_counter--;
	}	
 out_err:
	
	return err;
}
#ifdef CONFIG_HIP_OPPORTUNISTIC
int hip_set_opportunistic_mode(const struct hip_common *msg)
{
  int err =  0;
  unsigned int *mode = NULL;
  
  mode = hip_get_param_contents(msg, HIP_PARAM_UINT);
  if (!mode) {
    err = -EINVAL;
    goto out_err;
  }
  
  if(*mode == 0 || *mode == 1){
    opportunistic_mode = *mode;
  } else {
    HIP_ERROR("Invalid value for opportunistic mode\n");
    err = -EINVAL;
    goto out_err;
  }
  
 out_err:
  return err;
}

int hip_get_peer_hit(struct hip_common *msg, const struct sockaddr_un *src)
{
  int n = 0;
  int err = 0;
  int alen = 0;
  struct in6_addr phit, dst_ip, hit_our;
  struct in6_addr *ptr = NULL;
  hip_opp_block_t *entry = NULL;
  hip_ha_t *ha = NULL;

  if(!opportunistic_mode)
    {
      hip_msg_init(msg);
      err = hip_build_user_hdr(msg, SO_HIP_SET_PEER_HIT, 0);
      if (err) {
	HIP_ERROR("build user header failed: %s\n", strerror(err));
	goto out_err;
      } 
      n = hip_sendto(msg, src);
      if(n < 0){
	HIP_ERROR("hip_sendto() failed.\n");
	err = -1;
      }
      goto out_err;
    }
  // hip_hadb_find_byhits(SRC_HIT, PHIT);
  // if (exists(hashtable(SRC_HIT, DST_PHIT)) { // two consecutive base exchanges
  //   msg = REAL_DST_HIT
  //   sendto(src, msg);
  // } else {
  //   add_to_hash_table(index=XOR(SRC_HIT, DST_PHIT), value=src);
  //   hip_send_i1(SRC_HIT, PHIT);
  // }
  memset(&hit_our, 0, sizeof(struct in6_addr));
  ptr = (struct in6_addr *) hip_get_param_contents(msg, HIP_PARAM_HIT);
  memcpy(&hit_our, ptr, sizeof(hit_our));
  HIP_DEBUG_HIT("hit_our=", &hit_our);
  
  ptr = (struct in6_addr *) hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR);
  memcpy(&dst_ip, ptr, sizeof(dst_ip));
  HIP_DEBUG_HIT("dst_ip=", &dst_ip);
  
  err = hip_opportunistic_ipv6_to_hit(&dst_ip, &phit, HIP_HIT_TYPE_HASH120);
  if(err){
    goto out_err;
  }
  HIP_ASSERT(hit_is_opportunistic_hashed_hit(&phit)); 
  
  err = hip_hadb_add_peer_info(&phit, &dst_ip);
  ha = hip_hadb_find_byhits(&hit_our, &phit);
  HIP_ASSERT(ha);

  if(!oppdb_exist){
    HIP_DEBUG("initializing oppdb\n");
    hip_init_opp_db();
    HIP_DEBUG("oppdb initialized\n");
    oppdb_exist = 1;

    err = hip_oppdb_add_entry(&phit, &hit_our, src);
    if(err){
      HIP_ERROR("failed to add entry to oppdb: %s\n", strerror(err));
      goto out_err;
    }
    hip_send_i1(&hit_our, &phit, ha);
    // first call, not consecutive base exchange. So we do not execute the following code
    goto out_err;
  }
  
  entry = hip_oppdb_find_byhits(&phit, &hit_our);
  
  if(entry){ // two consecutive base exchanges
    //DST_HIT = from database list;
    hip_msg_init(msg);
    err = hip_build_param_contents(msg, (void *)(&entry->peer_real_hit), HIP_PARAM_HIT,
				   sizeof(struct in6_addr));
    if (err) {
      HIP_ERROR("build param HIP_PARAM_HIT  failed: %s\n", strerror(err));
      goto out_err;
    }
    err = hip_build_user_hdr(msg, SO_HIP_SET_PEER_HIT, 0);
    if (err) {
      HIP_ERROR("build user header failed: %s\n", strerror(err));
      goto out_err;
    } 
    
    n = hip_sendto(msg, src);
    if(n < 0){
      HIP_ERROR("hip_sendto() failed.\n");
      err = -1;
    }
    
    goto out_err;
  } else {
    err = hip_oppdb_add_entry(&phit, hit_our, src);
    if(err){
      HIP_ERROR("failed to add entry to oppdb: %s\n", strerror(err));
      goto out_err;
    }
    hip_send_i1(&hit_our, &phit, ha);
  }
 out_err:
   return err;
}

int hip_get_pseudo_hit(struct hip_common *msg)
{
  int err = 0;
  int alen = 0;
  
  struct in6_addr hit, ip;
  struct in6_addr *ptr = NULL;

  memset(&hit, 0, sizeof(struct in6_addr));
  if(opportunistic_mode){
    ptr = (struct in6_addr *) hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR);
    memcpy(&ip, ptr, sizeof(ip));
    HIP_DEBUG_HIT("dst ip=", &ip);
    
    err = hip_opportunistic_ipv6_to_hit(&ip, &hit, HIP_HIT_TYPE_HASH120);
    if(err){
      goto out_err;
    }
    HIP_ASSERT(hit_is_opportunistic_hashed_hit(&hit)); 

    hip_msg_init(msg);
    err = hip_build_param_contents(msg, (void *) &hit, HIP_PSEUDO_HIT,
				   sizeof(struct in6_addr));
    if (err) {
      HIP_ERROR("build param hit failed: %s\n", strerror(err));
      goto out_err;
    }

    err = hip_build_user_hdr(msg, SO_HIP_SET_PSEUDO_HIT, 0);
    if (err) {
      HIP_ERROR("build user header failed: %s\n", strerror(err));
      goto out_err;
    } 
    err = hip_hadb_add_peer_info(&hit, &ip);

    if (err) {
      HIP_ERROR("add peer info failed: %s\n", strerror(err));
      goto out_err;
    }
  }

 out_err:
   return err;
}

int hip_query_opportunistic_mode(struct hip_common *msg)
{
  int err = 0;
  unsigned int opp_mode = opportunistic_mode;

  hip_msg_init(msg);
  
  err = hip_build_param_contents(msg, (void *) &opp_mode, HIP_PARAM_UINT,
				 sizeof(unsigned int));
  if (err) {
    HIP_ERROR("build param opp_mode failed: %s\n", strerror(err));
    goto out_err;
  }
  
  err = hip_build_user_hdr(msg, SO_HIP_ANSWER_OPPORTUNISTIC_MODE_QUERY, 0);
  if (err) {
    HIP_ERROR("build user header failed: %s\n", strerror(err));
    goto out_err;
  } 
 out_err:
  return err;
}



int hip_query_ip_hit_mapping(struct hip_common *msg)
{
  int err = 0;
  unsigned int mapping = 0;
  struct in6_addr *hit = NULL;
  hip_ha_t *entry = NULL;


  hit = (struct in6_addr *) hip_get_param_contents(msg, HIP_PSEUDO_HIT);
  HIP_ASSERT(hit_is_opportunistic_hashed_hit(hit));

  entry = hip_hadb_try_to_find_by_peer_hit(hit);
  if(entry)
    mapping = 1;
  else 
    mapping = 0;

  hip_msg_init(msg);
  err = hip_build_param_contents(msg, (void *) &mapping, HIP_PARAM_UINT,
				 sizeof(unsigned int));
  if (err) {
    HIP_ERROR("build param mapping failed: %s\n", strerror(err));
    goto out_err;
  }
  
  err = hip_build_user_hdr(msg, SO_HIP_ANSWER_IP_HIT_MAPPING_QUERY, 0);
  if (err) {
    HIP_ERROR("build user header failed: %s\n", strerror(err));
    goto out_err;
  } 
 out_err:
  return err;
}
#endif // CONFIG_HIP_OPPORTUNISTIC

int hip_sendto(const struct hip_common *msg, const struct sockaddr_un *dst){
  int n = 0;

  HIP_DEBUG("hip_sendto sending phit...\n");

  n = sendto(hip_user_sock, msg, hip_get_msg_total_len(msg),
	     0,(struct sockaddr *)dst, sizeof(struct sockaddr_un));
  return n;
}

void hip_probe_kernel_modules() {
	int count;
	char cmd[40];
        /* update also this if you add more modules */
	const int mod_total = 10;
	char *mod_name[] = {"xfrm6_tunnel", "xfrm4_tunnel",
			    "xfrm_user", "dummy", "esp6", "esp4",
			    "ipv6", "aes", "crypto_null", "des"};

	HIP_DEBUG("Probing for modules. When the modules are built-in, the errors can be ignored\n");
	for (count = 0; count < mod_total; count++) {
		snprintf(cmd, sizeof(cmd), "%s %s", "modprobe",
			 mod_name[count]);
		HIP_DEBUG("%s\n", cmd);
		system(cmd);
	}
	HIP_DEBUG("Probing completed\n");
}

int main(int argc, char *argv[]) {
	int ch;
	char buff[HIP_MAX_NETLINK_PACKET];
#ifdef CONFIG_HIP_HI3
	char *i3_config = NULL;
#endif
	fd_set read_fdset;
	int foreground = 1, highest_descriptor = 0, s_net, err = 0;
	struct timeval timeout;
	struct hip_work_order ping;

	struct hip_common *hip_msg = NULL;
	struct msghdr sock_msg;
	struct sockaddr_un daemon_addr;
        /* The flushing is enabled by default. The reason for this is that
	   people are doing some very experimental features on some branches
	   that may crash the daemon and leave the SAs floating around to
	   disturb further base exchanges. Use -N flag to disable this. */
	int flush_ipsec = 1;

	/* Parse command-line options */
	while ((ch = getopt(argc, argv, "b")) != -1) {		
		switch (ch) {
		case 'b':
			foreground = 0;
			break;
#ifdef CONFIG_HIP_HI3
		case '3':
			i3_config = strdup(optarg);
			break;
#endif
		case 'N':
			flush_ipsec = 0;
			break;
		case '?':
		case 'h':
		default:
			usage();
			return err;
		}
	}

	hip_probe_kernel_modules();

#ifdef CONFIG_HIP_HI3
	/* Note that for now the Hi3 host identities are not loaded in. */
	
	HIP_IFEL(!i3_config, 1,
		 "Please do pass a valid i3 configuration file.\n");
#endif

	hip_set_logfmt(LOGFMT_LONG);

	/* Configuration is valid! Fork a daemon, if so configured */
	if (foreground) {
		printf("foreground\n");
		hip_set_logtype(LOGTYPE_STDERR);
	} else {
		if (fork() > 0) /* check ret val */
			return(0);
		hip_set_logtype(LOGTYPE_SYSLOG);
	}

	HIP_INFO("hipd pid=%d starting\n", getpid());
	time(&load_time);

	/* Register signal handlers */
	signal(SIGINT, hip_exit);
	signal(SIGTERM, hip_exit);

        HIP_IFEL((hip_init_cipher() < 0), 1, "Unable to init ciphers.\n");

	HIP_IFE(init_random_seed(), -1);

        hip_init_hadb();

	hip_init_puzzle_defaults();

#ifdef CONFIG_HIP_RVS
        hip_init_rvadb();
#endif	

#ifdef CONFIG_HIP_ESCROW
	hip_init_keadb();
	hip_init_kea_endpoints();
	
	hip_init_services();
	
#endif

	/* Workqueue relies on an open netlink connection */
	hip_init_workqueue();

#ifdef CONFIG_HIP_HI3
	cl_init(i3_config);
#endif

	/* Resolve our current addresses, afterwards the events from kernel
	   will maintain the list This needs to be done before opening
	   NETLINK_ROUTE! See the comment about address_count global var. */
	HIP_DEBUG("Initializing the netdev_init_addresses\n");
	hip_netdev_init_addresses(&hip_nl_ipsec);

	/* Allocate user message. */
	HIP_IFE(!(hip_msg = hip_msg_alloc()), 1);

	if (rtnl_open_byproto(&hip_nl_route,
			      RTMGRP_LINK | RTMGRP_IPV6_IFADDR | IPPROTO_IPV6
				| RTMGRP_IPV4_IFADDR | IPPROTO_IP,
			      NETLINK_ROUTE) < 0) {
		err = 1;
		HIP_ERROR("Routing socket error: %s\n", strerror(errno));
		goto out_err;
	}

	/* Open the netlink socket for address and IF events */
	if (rtnl_open_byproto(&hip_nl_ipsec, XFRMGRP_ACQUIRE, NETLINK_XFRM) < 0) {
		HIP_ERROR("Netlink address and IF events socket error: %s\n", strerror(errno));
		err = 1;
		goto out_err;
	}

#if 0
	{
		const int ipsec_buf_size = 200000;
		socklen_t ipsec_buf_sizeof = sizeof(int);
		setsockopt(hip_nl_ipsec.fd, SOL_SOCKET, SO_RCVBUF,
			   &ipsec_buf_size, ipsec_buf_sizeof);
		setsockopt(hip_nl_ipsec.fd, SOL_SOCKET, SO_SNDBUF,
			   &ipsec_buf_size, ipsec_buf_sizeof);
	}
#endif

	HIP_IFEL(hip_init_raw_sock_v6(&hip_raw_sock_v6), -1, "raw sock v6\n");
	HIP_IFEL(hip_init_raw_sock_v4(&hip_raw_sock_v4), -1, "raw sock v4\n");
	HIP_IFEL(hip_init_nat_sock_udp(&hip_nat_sock_udp), -1, "raw sock udp\n");
	//HIP_IFEL(hip_init_nat_sock_udp_data(&hip_nat_sock_udp_data), -1, "raw sock udp for data\n");

	HIP_DEBUG("hip_raw_sock = %d highest_descriptor = %d\n",
		  hip_raw_sock_v6, highest_descriptor);
	HIP_DEBUG("hip_raw_sock_v4 = %d highest_descriptor = %d\n",
		  hip_raw_sock_v4, highest_descriptor);
	HIP_DEBUG("hip_nat_sock_udp = %d highest_descriptor = %d\n",
		  hip_nat_sock_udp, highest_descriptor);

	if (flush_ipsec) {
		hip_flush_all_sa();
		hip_flush_all_policy();
	}

	HIP_DEBUG("Setting SP\n");
	/*
	hip_delete_default_prefix_sp_pair();
	HIP_IFE(hip_setup_default_sp_prefix_pair(), 1);
	*/

	HIP_DEBUG("Setting iface %s\n", HIP_HIT_DEV);
	set_up_device(HIP_HIT_DEV, 0);
	HIP_IFE(set_up_device(HIP_HIT_DEV, 1), 1);

	HIP_IFE(hip_init_host_ids(), 1);

	hip_user_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	HIP_IFEL((hip_user_sock < 0), 1,
		 "Could not create socket for user communication.\n");
	bzero(&daemon_addr, sizeof(daemon_addr));
	daemon_addr.sun_family = AF_UNIX;
	strcpy(daemon_addr.sun_path, HIP_DAEMONADDR_PATH);
	unlink(HIP_DAEMONADDR_PATH);
	HIP_IFEL(bind(hip_user_sock, (struct sockaddr *)&daemon_addr,
		      /*sizeof(daemon_addr)*/
		      strlen(daemon_addr.sun_path) +
		      sizeof(daemon_addr.sun_family)),
		 1, "Bind on daemon addr failed.");
	HIP_IFEL(chmod(daemon_addr.sun_path, S_IRWXO),
		1, "Changing permissions of daemon addr failed.")

	hip_agent_sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	HIP_IFEL((hip_agent_sock < 0), 1,
		 "Could not create socket for agent communication.\n");
	unlink(HIP_AGENTADDR_PATH);
	bzero(&hip_agent_addr, sizeof(hip_agent_addr));
	hip_agent_addr.sun_family = AF_LOCAL;
	strcpy(hip_agent_addr.sun_path, HIP_AGENTADDR_PATH);
	HIP_IFEL(bind(hip_agent_sock, (struct sockaddr *)&hip_agent_addr,
	              sizeof(hip_agent_addr)), -1, "Bind on agent addr failed.");
	chmod(HIP_AGENTADDR_PATH, 0777);
	highest_descriptor = maxof(7, hip_nl_route.fd, hip_raw_sock_v6,
				   hip_user_sock, hip_nl_ipsec.fd,
				   hip_agent_sock, hip_raw_sock_v4,
				   hip_nat_sock_udp);
	
	register_to_dht();

	HIP_DEBUG("Daemon running. Entering select loop.\n");
	/* Enter to the select-loop */
	HIP_DEBUG_GL(HIP_DEBUG_GROUP_INIT, 
		     HIP_DEBUG_LEVEL_INFORMATIVE,
		     "Hipd daemon running.\n"
		     "Starting select loop.\n");
	for (;;) {
		struct hip_work_order *hwo;
		
		/* prepare file descriptor sets */
		FD_ZERO(&read_fdset);
		FD_SET(hip_nl_route.fd, &read_fdset);
		FD_SET(hip_raw_sock_v6, &read_fdset);
		FD_SET(hip_raw_sock_v4, &read_fdset);
		FD_SET(hip_nat_sock_udp, &read_fdset);
		FD_SET(hip_user_sock, &read_fdset);
		FD_SET(hip_nl_ipsec.fd, &read_fdset);
		FD_SET(hip_agent_sock, &read_fdset);
		timeout.tv_sec = HIP_SELECT_TIMEOUT;
		timeout.tv_usec = 0;
		
		_HIP_DEBUG("select loop\n");
		/* wait for socket activity */
		if ((err = HIPD_SELECT((highest_descriptor + 1), &read_fdset, 
				       NULL, NULL, &timeout)) < 0) {
			HIP_ERROR("select() error: %s.\n", strerror(errno));
		} else if (err == 0) {
			/* idle cycle - select() timeout */
			_HIP_DEBUG("Idle\n");
		} else if (FD_ISSET(hip_raw_sock_v6, &read_fdset)) {
			struct in6_addr saddr, daddr;
			struct hip_stateless_info pkt_info;

			hip_msg_init(hip_msg);
		
			if (hip_read_control_msg_v6(hip_raw_sock_v6, hip_msg,
						    1, &saddr, &daddr,
						    &pkt_info, 0))
				HIP_ERROR("Reading network msg failed\n");
			else
				err = hip_receive_control_packet(hip_msg,
								 &saddr,
								 &daddr,
								 &pkt_info);
		} else if (FD_ISSET(hip_raw_sock_v4, &read_fdset)) {
			struct in6_addr saddr, daddr;
			struct hip_stateless_info pkt_info;
			//int src_port = 0;

			hip_msg_init(hip_msg);
			HIP_DEBUG("Getting a msg on v4\n");
			/* Assuming that IPv4 header does not include any
			   options */
			if (hip_read_control_msg_v4(hip_raw_sock_v4, hip_msg,
						    1, &saddr, &daddr,
						    &pkt_info, IPV4_HDR_SIZE))
				HIP_ERROR("Reading network msg failed\n");
			else
			{
			  /* For some reason, the IPv4 header is always
			     included. Let's remove it here. */
			  memmove(hip_msg, ((char *)hip_msg) + IPV4_HDR_SIZE,
				  HIP_MAX_PACKET - IPV4_HDR_SIZE);

			  pkt_info.src_port = 0;
	
			  err = hip_receive_control_packet(hip_msg, &saddr,
							   &daddr, &pkt_info);
			}
		} else if(FD_ISSET(hip_nat_sock_udp, &read_fdset)){
			/* do NAT recieving here !! --Abi */
			
			struct in6_addr saddr, daddr;
			struct hip_stateless_info pkt_info;
			//int src_port = 0;

			hip_msg_init(hip_msg);
			HIP_DEBUG("Getting a msg on udp\n");	

		//	if (hip_read_control_msg_udp(hip_nat_sock_udp, hip_msg, 1,
                  //                                 &saddr, &daddr))
        		if (hip_read_control_msg_v4(hip_nat_sock_udp, hip_msg,
						    1, &saddr, &daddr,
						    &pkt_info, 0))
                                HIP_ERROR("Reading network msg failed\n");
                        else
                        {
				err =  hip_receive_control_packet_udp(hip_msg,
                                                                 &saddr,
                                                                 &daddr,
								 &pkt_info);

                                //err = hip_receive_control_packet(hip_msg,
                                                                 //&saddr,
                                                                 //&daddr);
                        }

			
		} else if (FD_ISSET(hip_user_sock, &read_fdset)) {
		  	//struct sockaddr_un app_src, app_dst;
		  //  	struct sockaddr_storage app_src;
			struct sockaddr_un app_src;
			HIP_DEBUG("Receiving user message.\n");
			hip_msg_init(hip_msg);

			if (hip_read_user_control_msg(hip_user_sock, hip_msg, &app_src))
				HIP_ERROR("Reading user msg failed\n");
			else
				err = hip_handle_user_msg(hip_msg, &app_src);
		} else if (FD_ISSET(hip_agent_sock, &read_fdset)) {
			int n;
			socklen_t alen;
			err = 0;
			hip_hdr_type_t msg_type;
			
			HIP_DEBUG("Receiving message from agent(?).\n");
			
			bzero(&hip_agent_addr, sizeof(hip_agent_addr));
			alen = sizeof(hip_agent_addr);
			n = recvfrom(hip_agent_sock, hip_msg, sizeof(struct hip_common), 0,
			             (struct sockaddr *) &hip_agent_addr, &alen);
			if (n < 0)
			{
				HIP_ERROR("Recvfrom() failed.\n");
				err = -1;
				continue;
			}
			
			msg_type = hip_get_msg_type(hip_msg);
			
			if (msg_type == SO_HIP_AGENT_PING)
			{
				memset(hip_msg, 0, sizeof(struct hip_common));
				hip_build_user_hdr(hip_msg, SO_HIP_AGENT_PING_REPLY, 0);
				alen = sizeof(hip_agent_addr);                    
				n = sendto(hip_agent_sock, hip_msg, sizeof(struct hip_common),
				           0, (struct sockaddr *) &hip_agent_addr, alen);
				if (n < 0)
				{
					HIP_ERROR("Sendto() failed.\n");
					err = -1;
					continue;
				}

				if (err == 0)
				{
					HIP_DEBUG("HIP agent ok.\n");
					if (hip_agent_status == 0)
					{
						hip_agent_add_lhits();
					}
					hip_agent_status = 1;
				}
			}
			else if (msg_type == SO_HIP_AGENT_QUIT)
			{
				HIP_DEBUG("Agent quit.\n");
				hip_agent_status = 0;
			}
			else if (msg_type == HIP_I1)
			{
				hip_ha_t *ha;
 				ha = hip_hadb_find_byhits(&hip_msg->hits, &hip_msg->hitr);
				if (ha)
				{
					ha->state = HIP_STATE_UNASSOCIATED;
					HIP_HEXDUMP("HA: ", ha, 4);
					HIP_DEBUG("Agent accepted I1.\n");
				}
			}
			else if (msg_type == SO_HIP_I1_REJECT)
			{
				hip_ha_t *ha;
				ha = hip_hadb_find_byhits(&hip_msg->hits, &hip_msg->hitr);
				if (ha)
				{
					ha->state = HIP_STATE_UNASSOCIATED;
					ha->hip_msg_retrans.count = 0;
					HIP_DEBUG("Agent rejected I1.\n");
				}
			}
		} else if (FD_ISSET(hip_nl_ipsec.fd, &read_fdset)) {
			/* Something on IF and address event netlink socket,
			   fetch it. */
			HIP_DEBUG("netlink receive\n");
			if (hip_netlink_receive(&hip_nl_ipsec,
						hip_netdev_event, NULL))
				HIP_ERROR("Netlink receiving failed\n");
		} else if (FD_ISSET(hip_nl_route.fd, &read_fdset)) {
			/* Something on IF and address event netlink socket,
			   fetch it. */
			HIP_DEBUG("netlink route receive\n");
			if (hip_netlink_receive(&hip_nl_route,
						hip_netdev_event, NULL))
				HIP_ERROR("Netlink receiving failed\n");
		} else {
			HIP_INFO("Unknown socket activity.");
		}

		err = periodic_maintenance();
		if (err) {
			HIP_ERROR("Error (%d) ignoring. %s\n", err,
				  ((errno) ? strerror(errno) : ""));
			err = 0;
		}
	}

 out_err:

	HIP_INFO("hipd pid=%d exiting, retval=%d\n", getpid(), err);

	/* free allocated resources */
	hip_exit(err);

	return err;
}

