/**
 * @file ./hipd/hit_to_ip.h
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @brief look for locators in hit-to-ip domain
 * @brief usually invoked by hip_map_id_to_addr
 *
 * @author Oleg Ponomarev <oleg.ponomarev@hiit.fi>
 */

#ifndef HIP_HIPD_HIT_TO_IP_H
#define HIP_HIPD_HIT_TO_IP_H

#include <netinet/in.h>
#include <sys/types.h>
#include "lib/core/protodefs.h"

int hip_hit_to_ip(hip_hit_t *hit, struct in6_addr *retval);

void hip_set_hit_to_ip_status(const int status);
int hip_get_hit_to_ip_status(void);
void hip_hit_to_ip_set(const char *zone);

#endif /* HIP_HIPD_HIT_TO_IP_H */
