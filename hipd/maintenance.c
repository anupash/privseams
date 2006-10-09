
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

#include "maintenance.h"


float retrans_counter = HIP_RETRANSMIT_INIT;
float opp_fallback_counter = HIP_OPP_FALLBACK_INIT;
float precreate_counter = HIP_R1_PRECREATE_INIT;
int nat_keep_alive_counter = HIP_NAT_KEEP_ALIVE_INTERVAL;
float opendht_counter = OPENDHT_REFRESH_INIT;
int force_exit_counter = FORCE_EXIT_COUNTER_START;

int hip_firewall_status = 0;

/**
 * Handle packet retransmissions.
 */
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
			
			entry->hadb_xmit_func->
				hip_send_pkt(&entry->hip_msg_retrans.saddr,
					     &entry->hip_msg_retrans.daddr,
					     HIP_NAT_UDP_PORT,
					     entry->peer_udp_port,
					     entry->hip_msg_retrans.buf,
					     entry, 0);
			
			/* Set entry state, if previous state was unassosiated
			   and type is I1. */
			if (!err && hip_get_msg_type(entry->hip_msg_retrans.buf)
			    == HIP_I1) {
				HIP_DEBUG("Sent I1 succcesfully after acception.\n");
				entry->state = HIP_STATE_I1_SENT;
			}
			
			entry->hip_msg_retrans.count--;
			/* set the last transmission time to the current time value */
			time(&entry->hip_msg_retrans.last_transmit);
		}
		else {
		  	HIP_FREE(entry->hip_msg_retrans.buf);
			entry->hip_msg_retrans.buf = NULL;
			entry->hip_msg_retrans.count = 0;
		}
	}

 out_err:
	return err;
}

#ifdef CONFIG_HIP_OPPORTUNISTIC
int hip_scan_opp_fallback()
{
	int err = 0;
	time_t current_time;
	time(&current_time);

	HIP_IFEL(hip_for_each_opp(hip_handle_opp_fallback, &current_time), 0, 
		 "for_each_ha err.\n");
 out_err:
	return err;
}
#endif

/**
 * Find packets, that should be retransmitted.
 */
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

/**
 * Send one local HIT to agent, enumerative function.
 */
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

/**
 * Send local HITs to agent.
 */
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

	err = hip_build_user_hdr(msg, HIP_ADD_DB_HI, 0);
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


/**
 * Send one used remote HIT to agent, enumerative function.
 */
int hip_agent_send_rhit(hip_ha_t *entry, void *msg)
{
	int err = 0;

	if (entry->state != HIP_STATE_ESTABLISHED) return (err);
	
	err = hip_build_param_contents(msg, (void *)&entry->hit_peer, HIP_PARAM_HIT,
	                               sizeof(struct in6_addr));
/*	err = hip_build_param_contents(msg, (void *)&entry->hit_our, HIP_PARAM_HIT,
	                               sizeof(struct in6_addr));*/
	if (err)
	{
		HIP_ERROR("build param hit failed: %s\n", strerror(err));
		goto out_err;
	}

out_err:
	return (err);
}


/**
 * Send remote HITs in use (hadb entrys) to agent.
 */
int hip_agent_send_remote_hits(void)
{
	struct hip_common *msg;
	int err = 0, n;
	socklen_t alen;

#ifdef CONFIG_HIP_AGENT
	msg = malloc(HIP_MAX_PACKET);
	if (!msg)
	{
		HIP_ERROR("malloc failed\n");
		goto out_err;
	}
	hip_msg_init(msg);

	HIP_IFEL(hip_for_each_ha(hip_agent_send_rhit, msg), 0,
	         "for_each_ha err.\n");

	err = hip_build_user_hdr(msg, HIP_UPDATE_HIU, 0);
	if (err)
	{
		HIP_ERROR("build hdr failed: %s\n", strerror(err));
		goto out_err;
	}

	alen = sizeof(hip_agent_addr);                      
	n = sendto(hip_agent_sock, msg, hip_get_msg_total_len(msg),
	           0, (struct sockaddr *)&hip_agent_addr, alen);
	if (n < 0)
	{
		HIP_ERROR("Sendto() failed.\n");
		err = -1;
		goto out_err;
	}
//	else HIP_DEBUG("Sendto() OK.\n");

#endif

out_err:
	return (err);
}


/**
 * Filter packet trough agent.
 */
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


/**
 * Insert mapping for local host IP addresses to HITs to DHT.
 */
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

    if (hip_get_any_localhost_hit(&tmp_hit, HIP_HI_DEFAULT_ALGO, 0) < 0) {
      HIP_ERROR("No HIT found\n");
      return;
    }
	 
    tmp_hit_str =  hip_convert_hit_to_str(&tmp_hit, NULL);
    tmp_addr_str = hip_convert_hit_to_str(SA2IP(&n->addr), NULL);
    
    // HIP_DEBUG("Inserting HIT=%s with IP=%s and hostname %s to DHT\n", tmp_hit_str, tmp_addr_str, hostname);
    updateMAPS(hostname, tmp_hit_str, tmp_addr_str);
  } 	
#endif
}

/**
 * Periodic maintenance.
 * 
 * @return ...
 */
int periodic_maintenance()
{
	int err = 0;
	
	if (hipd_get_state() == HIPD_STATE_CLOSING) {
		if (force_exit_counter > 0) {
			err = hip_count_open_connections();
			if (err < 1) hipd_set_state(HIPD_STATE_CLOSED);
		} else {
			hip_exit(SIGINT);
			exit(SIGINT);
		}
		force_exit_counter--;
	}
	
#ifdef CONFIG_HIP_AGENT
	if (hip_agent_is_alive())
	{
		hip_agent_send_remote_hits();
	}
#endif
	
	if (retrans_counter < 0) {
		HIP_IFEL(hip_scan_retransmissions(), -1,
			 "retransmission scan failed\n");
		retrans_counter = HIP_RETRANSMIT_INIT;
	} else {
		retrans_counter--;
	}

#ifdef CONFIG_HIP_OPPORTUNISTIC
	if (opp_fallback_counter < 0) {
		HIP_IFEL(hip_scan_opp_fallback(), -1,
			 "retransmission scan failed\n");
		opp_fallback_counter = HIP_OPP_FALLBACK_INIT;
	} else {
		opp_fallback_counter--;
	}
#endif

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
	/* Sending of NAT Keep-Alives. */
	if(hip_nat_status && nat_keep_alive_counter < 0){
		HIP_IFEL(hip_nat_refresh_port(),
			 -ECOMM, "Failed to refresh NAT port state.\n");
		nat_keep_alive_counter = HIP_NAT_KEEP_ALIVE_INTERVAL;
	} else {
		nat_keep_alive_counter--;
	}	
 out_err:
	
	return err;
}

int hip_firewall_is_alive()
{
#ifdef CONFIG_HIP_FIREWALL
	if (hip_firewall_status) {
		HIP_DEBUG("Firewall is alive.\n");
	}
	else {
		HIP_DEBUG("Firewall is not alive.\n");
	}
	return hip_firewall_status;
#else
	HIP_DEBUG("Firewall is disabled.\n");
	return 0;
#endif // CONFIG_HIP_FIREWALL
}


int hip_firewall_add_escrow_data(hip_ha_t *entry, struct hip_keys *keys)
{
		struct hip_common *msg;
		int err = 0;
		int n;
		socklen_t alen;
		struct in6_addr * hit_s;
		struct in6_addr * hit_r;
				
		msg = malloc(HIP_MAX_PACKET);
		if (!msg)
		{
			HIP_ERROR("malloc failed\n");
			goto out_err;
		}
		hip_msg_init(msg);

		err = hip_build_user_hdr(msg, HIP_ADD_ESCROW_DATA, 0);
		if (err)
		{
			HIP_ERROR("build hdr failed: %s\n", strerror(err));
			goto out_err;
		}
		
		if (hip_match_hit(&keys->hit, &entry->hit_our)) {
			hit_s = &entry->hit_peer;
			hit_r = &entry->hit_our;
		}
		else {
			hit_r = &entry->hit_peer;
			hit_s = &entry->hit_our;
		}
		
		err = hip_build_param_contents(msg, (void *)hit_s, HIP_PARAM_HIT,
	                               sizeof(struct in6_addr));
		if (err)
		{
			HIP_ERROR("build param hit with hit_our failed: %s\n", strerror(err));
			goto out_err;
		}
		err = hip_build_param_contents(msg, (void *)hit_r, HIP_PARAM_HIT,
	                               sizeof(struct in6_addr));
		if (err)
		{
			HIP_ERROR("build param hit with hit_peer failed: %s\n", strerror(err));
			goto out_err;
		}
		
		err = hip_build_param(msg, (struct hip_tlv_common *)keys);
		if (err)
		{
			HIP_ERROR("build param failed: %s\n", strerror(err));
			goto out_err;
		}
	
		HIP_DEBUG("Sending test msg to firewall\n");

		n = hip_sendto(msg, &hip_firewall_addr);                   
		if (n < 0)
		{
			HIP_ERROR("Sendto firewall failed.\n");
			err = -1;
			goto out_err;
		}
		else HIP_DEBUG("Sendto firewall OK.\n");

out_err:
	return err;

}



