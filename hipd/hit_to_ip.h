/**
 * @file ./hipd/hit_to_ip.h
 *
 *  <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * @brief look for locators in hit-to-ip domain
 * @brief usually invoked by hip_map_id_to_addr
 *
 * @author Oleg Ponomarev <oleg.ponomarev@hiit.fi>
 **/

#ifndef HIT_TO_IP_H
#define HIT_TO_IP_H

int hip_hit_to_ip(hip_hit_t *hit, struct in6_addr *retval);

void hip_set_hit_to_ip_status(const int status);
int hip_get_hit_to_ip_status(void);
void hip_hit_to_ip_set(const char *zone);

#endif /* HIT_TO_IP_H */
