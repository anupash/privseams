#ifndef HIP_CACHE_PORT_H
#define HIP_CACHE_PORT_H

#include "libhipcore/icomm.h"

void firewall_port_cache_init_hldb(void);
firewall_port_cache_hl_t *firewall_port_cache_db_match(in_port_t port, 
                                                       int proto);

#endif /* HIP_CACHE_H */

