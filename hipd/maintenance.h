/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_HIPD_MAINTENANCE_H
#define HIP_HIPD_MAINTENANCE_H

#include <stdlib.h>
#include <fcntl.h>
#include "hidb.h"
#include "hipd.h"
#include "oppdb.h"
#include "lib/core/statistics.h"
#include "nat.h"

int hip_register_maint_function(int (*maint_function)(void),
                                const uint16_t priority);
int hip_unregister_maint_function(int (*maint_function)(void));
void hip_uninit_maint_functions(void);
int hip_periodic_maintenance(void);
void hip_set_firewall_status(void);
int hip_get_firewall_status(void);

/*Communication with firewall daemon*/
int hip_firewall_set_bex_data(int action, hip_ha_t *entry, struct in6_addr *hit_s,
                              struct in6_addr *hit_r);
int hip_firewall_set_esp_relay(int action);

#endif /* HIP_HIPD_MAINTENANCE_H */
