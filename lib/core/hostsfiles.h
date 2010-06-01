/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_LIB_CORE_HOSTSFILES_H
#define HIP_LIB_CORE_HOSTSFILES_H

#include "conf.h"
#include "prefix.h"

int hip_map_lsi_to_hit_from_hosts_files(hip_lsi_t *lsi, hip_hit_t *hit);
int hip_map_hit_to_lsi_from_hosts_files(const hip_hit_t *hit, hip_lsi_t *lsi);
int hip_map_id_to_ip_from_hosts_files(hip_hit_t *hit,
                                      hip_lsi_t *lsi,
                                      struct in6_addr *ip);
int hip_map_lsi_to_hostname_from_hosts(hip_lsi_t *lsi, char *hostname);
int hip_host_file_info_exists_lsi(hip_lsi_t *lsi);

#endif /* HIP_LIB_CORE_HOSTSFILES_H */
