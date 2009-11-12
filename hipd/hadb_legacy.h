#ifndef HADB_LEGACY_H
#define HADB_LEGACY_H

#include "hadb.h"

int hip_hadb_get_peer_addr_info_old(hip_ha_t *entry, struct in6_addr *addr,
				uint32_t *lifetime, struct timeval *modified_time);
void hip_update_handle_ack_old(hip_ha_t *entry, struct hip_ack *ack, int have_esp_info);
void hip_hadb_dump_spis_in_old(hip_ha_t *entry);
void hip_hadb_dump_spis_out_old(hip_ha_t *entry);
//add by santtu
int hip_hadb_add_udp_addr_old(hip_ha_t *entry, struct in6_addr *addr,
			     int is_bex_address, uint32_t lifetime,
			     int is_preferred_addr,
			     uint16_t port,
			     uint32_t priority,
			     uint8_t kind);




#endif /* HADB_LEGACY_H */
