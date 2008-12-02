
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
  
	HIP_DEBUG("mode=%d\n", *mode);

	if(*mode == 0 || *mode == 1 || *mode == 2){
		opportunistic_mode = *mode;
	} else {
		HIP_ERROR("Invalid value for opportunistic mode\n");
		err = -EINVAL;
		goto out_err;
	}

	memset(msg, 0, HIP_MAX_PACKET);
	HIP_IFE(hip_build_user_hdr(msg, (opportunistic_mode == 2 ? SO_HIP_SET_OPPTCP_ON : SO_HIP_SET_OPPTCP_OFF),
				   0), -1);
	hip_set_opportunistic_tcp_status(msg);
	
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

int hip_get_hip_proxy_status(void)
{
	return hipproxy;
}

int hip_set_hip_proxy_on(void)
{
	int err = 0;
	hipproxy = 1;
	HIP_DEBUG("hip_set_hip_proxy_on() invoked.\n");
 out_err:
	return err;
}

int hip_set_hip_proxy_off(void)
{
	int err = 0;
	hipproxy = 0;
	HIP_DEBUG("hip_set_hip_proxy_off() invoked.\n");
 out_err:
	return err;
}

int hip_get_sava_client_status(void) {
  return hipsava_client;
}
int hip_get_sava_server_status(void) {
  return hipsava_server;
}
void hip_set_sava_client_on(void) {
  HIP_DEBUG("SAVA client on invoked.\n");
  hipsava_client = 1;
}

void hip_set_sava_server_on(void) {
  HIP_DEBUG("SAVA server on invoked.\n");
  hipsava_server = 1;
}

void hip_set_sava_client_off(void) {
  HIP_DEBUG("SAVA client off invoked.\n");
  hipsava_client = 0;
}

void hip_set_sava_server_off(void) {
  HIP_DEBUG("SAVA server off invoked.\n");
  hipsava_server = 0;
}

void hip_set_bex_start_timestamp(hip_ha_t *entry) {
  HIP_ASSERT(entry != NULL);
  if (entry->bex_timestamp == NULL) {
    entry->bex_timestamp = (struct timeval *)malloc(sizeof(struct timeval));
    memset(entry->bex_timestamp, 0, sizeof(struct timeval));
  }
  gettimeofday(entry->bex_timestamp, NULL);
}


void hip_set_bex_end_timestamp(hip_ha_t * entry) {
  struct timeval *init = NULL;
  unsigned long duration = 0;
  HIP_ASSERT(entry != NULL || entry->bex_timestamp);
  init = entry->bex_timestamp;
  gettimeofday(entry->bex_timestamp, NULL);
  duration = (entry->bex_timestamp->tv_sec - init->tv_sec)*1000000 +
    (entry->bex_timestamp->tv_usec - init->tv_usec);

  entry->bex_timestamp->tv_sec = duration / 1000000;
  entry->bex_timestamp->tv_usec = duration % 1000000;
}



static IMPLEMENT_LHASH_HASH_FN(hip_bex_timestamp_hash, const hip_bex_timestamp_t *)
static IMPLEMENT_LHASH_COMP_FN(hip_bex_timestamp_compare, const hip_bex_timestamp_t *)

unsigned long hip_bex_timestamp_hash(const hip_bex_timestamp_t * entry) {
  unsigned char hash[INDEX_HASH_LENGTH];

  int err = 0;
  
  // values have to be present
  HIP_ASSERT(entry != NULL && entry->addr != NULL);
  
  memset(hash, 0, INDEX_HASH_LENGTH);

  HIP_IFEL(hip_build_digest(INDEX_HASH_FN, (void *)entry->addr, 
			    sizeof(struct in6_addr), hash),
	   -1, "failed to hash addresses\n");
  
 out_err:
  if (err) {
    *hash = 0;
  }

  return *((unsigned long *)hash);
}

int hip_bex_timestamp_compare(const hip_bex_timestamp_t * entry1,
			      const hip_bex_timestamp_t * entry2) {
  int err = 0;
  unsigned long hash1 = 0;
  unsigned long hash2 = 0;

  // values have to be present
  HIP_ASSERT(entry1 != NULL && entry1->addr);
  HIP_ASSERT(entry2 != NULL && entry2->addr);

  HIP_IFEL(!(hash1 = hip_bex_timestamp_hash(entry1)), 
	   -1, "failed to hash sa entry\n");

  HIP_IFEL(!(hash2 = hip_bex_timestamp_hash(entry2)), 
	   -1, "failed to hash sa entry\n");

  err = (hash1 != hash2);

  out_err:
    return err;
  return 0;
}

int hip_bex_timestamp_db_init() {
  int err = 0;
  HIP_IFEL(!(bex_timestamp_db = hip_ht_init(LHASH_HASH_FN(hip_bex_timestamp_hash),
	     LHASH_COMP_FN(hip_bex_timestamp_compare))), -1,
	     "failed to initialize bex_timestamp_db \n");
  HIP_DEBUG("bex timestamp db initialized\n");
 out_err:
  return err;
}

int hip_bex_timestamp_db_uninit() {
  return 0;
}

hip_bex_timestamp_t * hip_bex_timestamp_find(struct in6_addr * addr) {
  hip_bex_timestamp_t *search_link = NULL, *stored_link = NULL;
  int err = 0;

  HIP_IFEL(!(search_link = 
	     (hip_bex_timestamp_t *) malloc(sizeof(hip_bex_timestamp_t))),
	     -1, "failed to allocate memory\n");
  memset(search_link, 0, sizeof(hip_bex_timestamp_t));

  // search the linkdb for the link to the corresponding entry
  search_link->addr = addr;

  HIP_DEBUG("looking up link entry with following index attributes:\n");
  HIP_DEBUG_HIT("Peer IP Address", search_link->addr);


  HIP_IFEL(!(stored_link = hip_ht_find(bex_timestamp_db, search_link)), -1,
				"failed to retrieve link entry\n");

 out_err:
  if (err)
    stored_link = NULL;
  
  if (search_link)
    free(search_link);

  return stored_link;
}

int hip_bex_timestamp_db_add(const struct in6_addr * addr, const struct timeval * time) {
  
  hip_bex_timestamp_t *  entry = malloc(sizeof(hip_bex_timestamp_t));
  
  HIP_DEBUG_HIT("Adding bex timestamp for peer ", addr);

  HIP_ASSERT(addr != NULL && time != NULL);
  
  memset(entry, 0, sizeof(hip_bex_timestamp_t));
  
  entry->addr = 
    (struct in6_addr *) malloc(sizeof(struct in6_addr));

  entry->timestamp = 
    (struct timeval *) malloc(sizeof(struct timeval));
  
  memcpy((char *)entry->addr, (char *)addr,
  	 sizeof(struct in6_addr));

  memcpy((char *)entry->timestamp, (char *)time,
  	 sizeof(struct timeval));

  hip_ht_add(bex_timestamp_db, entry);

  return 0;
}

int hip_bex_timestamp_db_delete(const struct in6_addr * addr) {
  hip_bex_timestamp_t *stored_link = NULL;
  int err = 0;
  
  // find link entry and free members
  HIP_IFEL(!(stored_link = hip_bex_timestamp_find(addr)), -1,
	   "failed to retrieve sava enc ip entry\n");

  hip_ht_delete(bex_timestamp_db, stored_link);
  // we still have to free the link itself
  free(stored_link);

 out_err:
  return err;
}

/*initializes the timestamp at startup of base exchange*/
int bex_add_initial_timestamp(const struct in6_addr * addr) {

  int err = 0;

  struct timeval time;

  memset(&time, 0, sizeof(struct timeval));

  gettimeofday(&time, NULL);

  return hip_bex_timestamp_db_add(addr, &time);
}

/*Return base exchange for given host*/
unsigned long bex_get_duration_timestamp(const struct in6_addr * addr) {

  int err = 0;

  long duration = 0;

  hip_bex_timestamp_t *stored_link = NULL;

  struct timeval time;

  memset(&time, 0, sizeof(struct timeval));

  gettimeofday(&time, NULL);

  HIP_IFEL(!(stored_link = hip_bex_timestamp_find(addr)), -1,
	   "Cannot find record for given address");

  duration = (time.tv_sec - stored_link->timestamp->tv_sec)*1000000
    + (time.tv_usec - stored_link->timestamp->tv_usec);
  
  hip_bex_timestamp_db_delete(addr);
  
 out_err:
  return duration;  
}
