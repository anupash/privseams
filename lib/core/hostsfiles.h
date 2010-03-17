#ifndef HIP_LIB_CORE_HOSTSFILES_H
#define HIP_LIB_CORE_HOSTSFILES_H

#include "prefix.h"
#include "lib/conf/hipconf.h"

#ifndef HOST_NAME_MAX
#  define HOST_NAME_MAX 64
#endif /* HOST_NAME_MAX */

int hip_map_first_id_to_hostname_from_hosts(const struct hosts_file_line *entry,
                                            const void *arg,
                                            void *result);
int hip_map_first_hostname_to_hit_from_hosts(const struct hosts_file_line *entry,
                                             const void *arg,
                                             void *result);
int hip_map_first_hostname_to_lsi_from_hosts(const struct hosts_file_line *entry,
                                             const void *arg,
                                             void *result);
int hip_map_first_hostname_to_ip_from_hosts(const struct hosts_file_line *entry,
                                            const void *arg,
                                            void *result);
int hip_for_each_hosts_file_line(const char *hosts_file,
                                 int(*func)(const struct hosts_file_line *line,
                                            const void *arg,
                                            void *result),
                                 void *arg,
                                 void *result);
int hip_map_lsi_to_hit_from_hosts_files(hip_lsi_t *lsi, hip_hit_t *hit);
int hip_map_hit_to_lsi_from_hosts_files(const hip_hit_t *hit, hip_lsi_t *lsi);
int hip_map_id_to_ip_from_hosts_files(hip_hit_t *hit,
                                      hip_lsi_t *lsi,
                                      struct in6_addr *ip);
int hip_map_lsi_to_hostname_from_hosts(hip_lsi_t *lsi, char *hostname);
int hip_get_random_hostname_id_from_hosts(char *filename,
                                          char *hostname,
                                          char *id_str);
int hip_host_file_info_exists_lsi(hip_lsi_t *lsi);

#endif /* HIP_LIB_CORE_HOSTSFILES_H */
