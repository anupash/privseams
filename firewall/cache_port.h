#ifndef HIP_FIREWALL_CACHE_PORT_H
#define HIP_FIREWALL_CACHE_PORT_H

#include "lib/core/icomm.h"

void hip_firewall_port_cache_init_hldb(void);
firewall_port_cache_hl_t *hip_firewall_port_cache_db_match(in_port_t port,
                                                           int proto);
void hip_firewall_port_cache_uninit_hldb(void);

#endif /* HIP_CACHE_H */
