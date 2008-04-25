
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


unsigned int hipd_state = HIPD_STATE_CLOSED;
#ifdef CONFIG_HIP_OPPORTUNISTIC
unsigned int opportunistic_mode = 1;
#endif // CONFIG_HIP_OPPORTUNISTIC


/**
 * Set global daemon state.
 * @param state @see daemon_states
 */
void hipd_set_state(unsigned int state)
{
	hipd_state = (state & HIPD_STATE_MASK) | (hipd_state & ~HIPD_STATE_MASK);
}


/**
 * Get global daemon flag status.
 * @param state @see daemon_states
 * @return 1 if flag is on, 0 if not.
 */
int hipd_get_flag(unsigned int flag)
{
	return (hipd_state & flag) ? 1 : 0;
}


/**
 * Set global daemon flag.
 * @param state @see daemon_states
 */
void hipd_set_flag(unsigned int flag)
{
	hipd_state = hipd_state | flag;
}


/**
 * Clear global daemon flag.
 * @param state @see daemon_states
 */
void hipd_clear_flag(unsigned int flag)
{
	hipd_state = hipd_state & ~flag;
}


/**
 * Get global daemon state.
 * @return @see daemon_states
 */
unsigned int hipd_get_state(void)
{
	return (hipd_state & HIPD_STATE_MASK);
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
	
	
	hit = (struct in6_addr *) hip_get_param_contents(msg, HIP_PARAM_PSEUDO_HIT);
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

