
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

#include "accessor.h"


int hipd_state = HIPD_STATE_CLOSED;
#ifdef CONFIG_HIP_OPPORTUNISTIC
unsigned int opportunistic_mode = 1;
unsigned int oppdb_exist = 0;
extern   hip_opp_block_t *hip_oppdb_find_byhits(const hip_hit_t *hit_peer, 
						const hip_hit_t *hit_our);
#endif // CONFIG_HIP_OPPORTUNISTIC


/**
 * Set global daemon state.
 * @param state @see daemon_states
 */
void hipd_set_state(int state)
{
	hipd_state = state;
}


/**
 * Get global daemon state.
 * @return @see daemon_states
 */
int hipd_get_state(void)
{
	return (hipd_state);
}


/**
 * Determines whether agent is alive, or not.
 *
 * @return non-zero, if agent is alive.
 */
int hip_agent_is_alive()
{
#ifdef CONFIG_HIP_AGENT
//	if (hip_agent_status) HIP_DEBUG("Agent is alive.\n");
//	else HIP_DEBUG("Agent is not alive.\n");
	return hip_agent_status;
#else
//	HIP_DEBUG("Agent is disabled.\n");
       return 0;
#endif /* CONFIG_HIP_AGENT */
}


#ifdef CONFIG_HIP_OPPORTUNISTIC
/**
 * No description.
 */
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

/**
 * No description.
 */
int hip_opp_get_peer_hit(struct hip_common *msg, const struct sockaddr_un *src)
{
	int n = 0;
	int err = 0;
	int alen = 0;
	struct in6_addr phit, dst_ip, hit_our;
	struct in6_addr *ptr = NULL;
	hip_opp_block_t *entry = NULL;
	hip_ha_t *ha = NULL;
	
	hip_msg_init(msg);

	/* If opportunistic mode is turned off, we don't support opp. mode */
	if(!opportunistic_mode) {
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_SET_PEER_HIT, 0), -1, 
			 "Building of user header failed\n");
		n = hip_sendto(msg, src);
		if(n < 0){
			HIP_ERROR("hip_sendto() failed.\n");
			err = -1;
		}
		goto out_err;
	}

	/* Create an opportunistic HIT from the peer's IP  */
	
	memset(&hit_our, 0, sizeof(struct in6_addr));
	ptr = (struct in6_addr *) hip_get_param_contents(msg, HIP_PARAM_HIT);
	HIP_IFEL(!ptr, -1, "No hit in msg\n");
	memcpy(&hit_our, ptr, sizeof(hit_our));
	HIP_DEBUG_HIT("hit_our=", &hit_our);
	
	ptr = (struct in6_addr *)
		hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR);
	HIP_IFEL(!ptr, -1, "No ip in msg\n");
	memcpy(&dst_ip, ptr, sizeof(dst_ip));
	HIP_DEBUG_HIT("dst_ip=", &dst_ip);
	
	HIP_IFEL(hip_opportunistic_ipv6_to_hit(&dst_ip, &phit,
					       HIP_HIT_TYPE_HASH100),
		 -1, "Opp HIT conversion failed\n");
	HIP_ASSERT(hit_is_opportunistic_hashed_hit(&phit)); 
	HIP_DEBUG_HIT("phit", &phit);
	
	err = hip_hadb_add_peer_info(&phit, &dst_ip);
	ha = hip_hadb_find_byhits(&hit_our, &phit);
	HIP_ASSERT(ha);

	/* Override the receiving function */
	ha->hadb_rcv_func->hip_receive_r1 = hip_receive_opp_r1;
	
	if(!oppdb_exist){
		HIP_DEBUG("initializing oppdb\n");
		hip_init_opp_db();
		HIP_DEBUG("oppdb initialized\n");
		oppdb_exist = 1;
	}
	
	entry = hip_oppdb_find_byhits(&phit, &hit_our);
	if(!entry) {
		HIP_IFEL(hip_oppdb_add_entry(&phit, &hit_our, &dst_ip, NULL,
					     src), -1,
			 "Add db failed\n");
	} else if (ipv6_addr_any(&entry->peer_real_hit)) {
		/* Two simultaneously connecting applications */
		HIP_DEBUG("Peer HIT still undefined, doing nothing\n");
		goto out_err;
	} else {
		/* Two applications connecting consequtively: let's just return
		   the real HIT instead of sending I1 */
		HIP_IFEL(hip_build_param_contents(msg,
					       (void *)(&entry->peer_real_hit),
					       HIP_PARAM_HIT,
					       sizeof(struct in6_addr)), -1,
			 "build param HIP_PARAM_HIT  failed: %s\n");
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_SET_PEER_HIT, 0), -1,
			 "Building of msg header failed\n");
		n = hip_sendto(msg, src);
		if(n < 0){
			HIP_ERROR("hip_sendto() failed.\n");
			err = -1;
		}
		goto out_err;
	}
	
 send_i1:
	HIP_IFEL(hip_send_i1(&hit_our, &phit, ha), -1,
		 "sending of I1 failed\n");
	
 out_err:
	return err;
}

/**
 * No description.
 */
int hip_query_opportunistic_mode(struct hip_common *msg)
{
	int err = 0;
	unsigned int opp_mode = opportunistic_mode;
	
	hip_msg_init(msg);
	
	HIP_IFEL(hip_build_param_contents(msg, (void *) &opp_mode,
					  HIP_PARAM_UINT,
					  sizeof(unsigned int)), -1,
		 "build param opp_mode failed\n");
	
	HIP_IFEL(hip_build_user_hdr(msg,
				    SO_HIP_ANSWER_OPPORTUNISTIC_MODE_QUERY, 0),
		 -1, "build user header failed\n");
	
 out_err:
  return err;
}

/**
 * No description.
 */
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
	HIP_IFEL(hip_build_param_contents(msg, (void *) &mapping,
					  HIP_PARAM_UINT,
					  sizeof(unsigned int)), -1,
		 "build param mapping failed\n");
	
	HIP_IFEL(hip_build_user_hdr(msg,
				    SO_HIP_ANSWER_IP_HIT_MAPPING_QUERY, 0),
		 -1, "build user header failed\n");

 out_err:
	return err;
}
#endif // CONFIG_HIP_OPPORTUNISTIC

