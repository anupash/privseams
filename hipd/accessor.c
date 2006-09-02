
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
unsigned int opportunistic_mode = 0;
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
	if (hip_agent_status) HIP_DEBUG("Agent is alive.\n");
	else HIP_DEBUG("Agent is not alive.\n");
	return hip_agent_status;
#else
	HIP_DEBUG("Agent is disabled.\n");
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
  
  err = hip_opportunistic_ipv6_to_hit(&dst_ip, &phit, HIP_HIT_TYPE_HASH100);
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
    err = hip_oppdb_add_entry(&phit, &hit_our, src);
    if(err){
      HIP_ERROR("failed to add entry to oppdb: %s\n", strerror(err));
      goto out_err;
    }
    hip_send_i1(&hit_our, &phit, ha);
  }
 out_err:
   return err;
}

/**
 * No description.
 */
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
    
    err = hip_opportunistic_ipv6_to_hit(&ip, &hit, HIP_HIT_TYPE_HASH100);
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

/**
 * No description.
 */
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

