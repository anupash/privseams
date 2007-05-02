
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

	if (entry->hip_msg_retrans.buf == NULL)
		goto out_err;
	
	_HIP_DEBUG("Time to retrans: %d Retrans count: %d State: %s\n",
		   entry->hip_msg_retrans.last_transmit + HIP_RETRANSMIT_WAIT - *now,
		   entry->hip_msg_retrans.count, hip_state_str(entry->state));
	
	_HIP_DEBUG_HIT("hit_peer", &entry->hit_peer);
	_HIP_DEBUG_HIT("hit_our", &entry->hit_our);
	
	/* check if the last transmision was at least RETRANSMIT_WAIT seconds ago */
	if(*now - HIP_RETRANSMIT_WAIT > entry->hip_msg_retrans.last_transmit){
		if (entry->hip_msg_retrans.count > 0 &&
		    entry->state != HIP_STATE_ESTABLISHED &&
		    entry->retrans_state == entry->state) {
			
			err = entry->hadb_xmit_func->
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
	entry->retrans_state = entry->state;
		
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
int hip_agent_filter(struct hip_common *msg,
                     struct in6_addr *src_addr,
                     struct in6_addr *dst_addr,
	                 hip_portpair_t *msg_info)
{
	/* Variables. */
	struct hip_common *user_msg = NULL;
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

	/* Create packet for agent. */	
	HIP_IFE(!(user_msg = hip_msg_alloc()), -1);
	HIP_IFE(hip_build_user_hdr(user_msg, hip_get_msg_type(msg), 0), -1);
	HIP_IFE(hip_build_param_contents(user_msg, msg, HIP_PARAM_ENCAPS_MSG,
	                                 hip_get_msg_total_len(msg)), -1);
	HIP_IFE(hip_build_param_contents(user_msg, src_addr, HIP_PARAM_SRC_ADDR,
	                                 sizeof(*src_addr)), -1);
	HIP_IFE(hip_build_param_contents(user_msg, dst_addr, HIP_PARAM_DST_ADDR,
	                                 sizeof(*dst_addr)), -1);
	HIP_IFE(hip_build_param_contents(user_msg, msg_info, HIP_PARAM_PORTPAIR,
	                                 sizeof(*msg_info)), -1);

	alen = sizeof(hip_agent_addr);
	n = sendto(hip_agent_sock, user_msg, hip_get_msg_total_len(user_msg),
	           0, (struct sockaddr *)&hip_agent_addr, alen);
	if (n < 0)
	{
		HIP_ERROR("Sendto() failed.\n");
		err = -1;
		goto out_err;
	}

	HIP_DEBUG("Sent %d bytes to agent for handling.\n", n);
	
out_err:
	return (err);
}


/**
 * Insert mapping for local host IP addresses to HITs to DHT.
 */
void register_to_dht ()
{
#ifdef CONFIG_HIP_OPENDHT  
  char hostname [HIP_HOST_ID_HOSTNAME_LEN_MAX];
  hip_list_t *item, *tmp;
  int i;
  struct netdev_address *opendht_n;
  int pub_addr_ret = 0;

  if (gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1)) 
    return;

  list_for_each_safe(item, tmp, addresses, i)
    {
      opendht_n = list_entry(item);
      struct in6_addr tmp_hit;
      char *tmp_hit_str, *tmp_addr_str;
      double time_diff = 0;
 
      if (ipv6_addr_is_hit(hip_cast_sa_addr(&opendht_n->addr))) continue;
      
      time_diff = difftime(opendht_n->timestamp, time(0));
      if (time_diff < 10)
        {
          if (hip_get_any_localhost_hit(&tmp_hit, HIP_HI_DEFAULT_ALGO, 0) < 0) 
            {
              HIP_ERROR("No HIT found\n");
              return;
            } 
          
          tmp_hit_str =  hip_convert_hit_to_str(&tmp_hit, NULL);
          tmp_addr_str = hip_convert_hit_to_str(hip_cast_sa_addr(&opendht_n->addr), NULL);
         
           /*
             HIP_HEXDUMP("TESTLINE: secret: ", n->secret, 40);
           
             HIP_DEBUG("TESTLINE: addr=%s timestamp = %s (local time)\n",
                       tmp_addr_str, ctime(&opendht_n->timestamp));
           */
          /* send the fqdn->hit mapping */
          publish_hit(&hostname, tmp_hit_str, tmp_addr_str);
           
          /* send the hit->ip mapping */
          pub_addr_ret = publish_addr(tmp_hit_str, tmp_addr_str);
          if (pub_addr_ret == 1)
            opendht_n->timestamp = time(0) + 240;
          else if (pub_addr_ret == -1)
            opendht_n->timestamp = time(0) + 30;
        }
    }
 out_err:
  return;
#endif
}

/**
 * publish_hit
 *
 * @param *hostname
 * @param *hit_str
 *
 * @return void
 */
void publish_hit(char *hostname, char *tmp_hit_str, char *tmp_addr_str)
{
#ifdef CONFIG_HIP_OPENDHT
  extern int hip_opendht_sock_fqdn;  
  extern int hip_opendht_fqdn_sent;
  extern int opendht_error;
  extern struct addrinfo opendht_serving_gateway; 
  extern int opendht_serving_gateway_port;
  extern int opendht_serving_gateway_ttl;

  if (hip_opendht_fqdn_sent == STATE_OPENDHT_IDLE) 
    {
      HIP_DEBUG("Sending mapping FQDN (%s) -> HIT (%s) to the openDHT\n", 
                hostname, tmp_hit_str);
      if (hip_opendht_sock_fqdn < 1)
        hip_opendht_sock_fqdn = init_dht_gateway_socket(hip_opendht_sock_fqdn);
      opendht_error = 0;
      opendht_error = connect_dht_gateway(hip_opendht_sock_fqdn, 
                                          &opendht_serving_gateway, 0);
      if (opendht_error > -1 && opendht_error != EINPROGRESS) 
        { 
          opendht_error = opendht_put(hip_opendht_sock_fqdn,
                                      (unsigned char *)hostname,
                                      (unsigned char *)tmp_hit_str, 
                                      (unsigned char *)tmp_addr_str,
                                      opendht_serving_gateway_port,
                                      opendht_serving_gateway_ttl);
          if (opendht_error < 0)
            HIP_DEBUG("Error sending FQDN->HIT mapping to the openDHT.\n");
          else hip_opendht_fqdn_sent = STATE_OPENDHT_WAITING_ANSWER; 
        } 
      if (opendht_error == EINPROGRESS)
        {
          hip_opendht_fqdn_sent = STATE_OPENDHT_WAITING_CONNECT; /* connect not ready */
          HIP_DEBUG("OpenDHT connect unfinished (fqdn publish)\n");
        }
    }
  else if (hip_opendht_fqdn_sent == STATE_OPENDHT_START_SEND)
    { /* connect finished send the data */
      opendht_error = opendht_put(hip_opendht_sock_fqdn, 
                                  (unsigned char *)hostname,
                                  (unsigned char *)tmp_hit_str, 
                                  (unsigned char *)tmp_addr_str,
                                  opendht_serving_gateway_port,
                                  opendht_serving_gateway_ttl);
      if (opendht_error < 0)
        HIP_DEBUG("Error sending FQDN->HIT mapping to the openDHT.\n");
      else hip_opendht_fqdn_sent = STATE_OPENDHT_WAITING_ANSWER; 
    }
 out_err:
  return;
#endif
}

/**
 * publish address
 * 
 * @param *hit_str
 * @param *addr_str
 * @param *netdev_address
 *
 * @return int 0 connect unfinished, -1 error, 1 success
 */
int publish_addr(char *tmp_hit_str, char *tmp_addr_str)
{
#ifdef CONFIG_HIP_OPENDHT
  extern int hip_opendht_sock_hit;
  extern int hip_opendht_hit_sent;
  extern int opendht_error;
  extern struct addrinfo opendht_serving_gateway;
  extern int opendht_serving_gateway_port;
  extern int opendht_serving_gateway_ttl;

  if (hip_opendht_hit_sent == STATE_OPENDHT_IDLE) 
    {
      HIP_DEBUG("Sending mapping HIT (%s) -> IP (%s) to the openDHT\n",
                tmp_hit_str, tmp_addr_str);
      if (hip_opendht_sock_hit < 1)
        hip_opendht_sock_hit = init_dht_gateway_socket(hip_opendht_sock_hit);
      opendht_error = 0;
      opendht_error = connect_dht_gateway(hip_opendht_sock_hit, 
                                          &opendht_serving_gateway, 0);
      if (opendht_error > -1 && opendht_error != EINPROGRESS)
        {
          opendht_error = opendht_put(hip_opendht_sock_hit, 
                                      (unsigned char *)tmp_hit_str,
                                      (unsigned char *)tmp_addr_str, 
                                      (unsigned char *)tmp_addr_str,
                                      opendht_serving_gateway_port,
                                      opendht_serving_gateway_ttl);
          if (opendht_error < 0)
            {
              HIP_DEBUG("Error sending HIT->IP mapping to the openDHT.\n");
              return -1;
            }
          else 
            {
              hip_opendht_hit_sent = STATE_OPENDHT_WAITING_ANSWER;
              return 1;
            }
        }
      else if (opendht_error == EINPROGRESS)
        {
          hip_opendht_hit_sent = STATE_OPENDHT_WAITING_CONNECT;
          HIP_DEBUG("OpenDHT connect unfinished (hit publish)\n");
          goto out_err;
        }
      else
        { /* connect error */
          return -1;
        }
    }
  else if (hip_opendht_hit_sent == STATE_OPENDHT_START_SEND)
    { /* connect finished send the data */
      opendht_error = opendht_put(hip_opendht_sock_hit, 
                                  (unsigned char *)tmp_hit_str,
                                  (unsigned char *)tmp_addr_str, 
                                  (unsigned char *)tmp_addr_str,
                                  opendht_serving_gateway_port,
                                  opendht_serving_gateway_ttl);
      if (opendht_error < 0)
        {
          HIP_DEBUG("Error sending HIT->IP mapping to the openDHT.\n");
          return -1;
        }
      else
        {
          hip_opendht_hit_sent = STATE_OPENDHT_WAITING_ANSWER;
          return 1;
        }
    }
 out_err:
  return 0;
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
	if (opendht_counter < 0) {
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


int hip_firewall_add_escrow_data(hip_ha_t *entry, struct in6_addr * hit_s, 
        struct in6_addr * hit_r, struct hip_keys *keys)
{
		struct hip_common *msg;
		int err = 0;
		int n;
		socklen_t alen;
		//struct in6_addr * hit_s;
		//struct in6_addr * hit_r;
				
		HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
		hip_msg_init(msg);
		HIP_IFEL(hip_build_user_hdr(msg, HIP_ADD_ESCROW_DATA, 0), -1, 
                        "Build hdr failed\n");
		
		/*if (hip_match_hit(&keys->hit, &entry->hit_our)) {
			hit_s = &entry->hit_peer;
			hit_r = &entry->hit_our;
		}
		else {
			hit_r = &entry->hit_peer;
			hit_s = &entry->hit_our;
		}*/
                
                HIP_IFEL(hip_build_param_contents(msg, (void *)hit_s, HIP_PARAM_HIT,
                        sizeof(struct in6_addr)), -1, "build param contents failed\n");
		HIP_IFEL(hip_build_param_contents(msg, (void *)hit_r, HIP_PARAM_HIT,
                        sizeof(struct in6_addr)), -1, "build param contents failed\n");
                
		HIP_IFEL(hip_build_param(msg, (struct hip_tlv_common *)keys), -1, 
                        "hip build param failed\n");

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

int hip_firewall_remove_escrow_data(struct in6_addr *addr, uint32_t spi)
{
        struct hip_common *msg;
        int err = 0;
        int n;
        socklen_t alen;
        struct in6_addr * hit_s;
        struct in6_addr * hit_r;                        
                                
        HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
        hip_msg_init(msg);
        HIP_IFEL(hip_build_user_hdr(msg, HIP_DELETE_ESCROW_DATA, 0), -1, 
                "Build hdr failed\n");
                
        HIP_IFEL(hip_build_param_contents(msg, (void *)addr, HIP_PARAM_HIT,
                sizeof(struct in6_addr)), -1, "build param contents failed\n");
        HIP_IFEL(hip_build_param_contents(msg, (void *)&spi, HIP_PARAM_UINT,
                sizeof(unsigned int)), -1, "build param contents failed\n");
                
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


int hip_firewall_set_escrow_active(int activate)
{
        struct hip_common *msg;
        int err = 0;
        int n;
        socklen_t alen;
        HIP_DEBUG("Sending activate msg to firewall (value=%d)\n", activate);                        
        HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
        hip_msg_init(msg);
        HIP_IFEL(hip_build_user_hdr(msg, 
                (activate ? HIP_SET_ESCROW_ACTIVE : HIP_SET_ESCROW_INACTIVE), 0), 
                -1, "Build hdr failed\n");
                
        n = hip_sendto(msg, &hip_firewall_addr);                   
        if (n < 0) {
                HIP_ERROR("Sendto firewall failed.\n");
                err = -1;
                goto out_err;
        }
        else {
                HIP_DEBUG("Sendto firewall OK.\n");
        }  
out_err:
        return err;        
}

