#ifndef HIP_HIPD_HADB_LEGACY_H
#define HIP_HIPD_HADB_LEGACY_H

#include "hadb.h"

int hip_hadb_get_peer_addr_info_old(hip_ha_t *entry,
                                    const struct in6_addr *addr,
                                    uint32_t *lifetime,
                                    struct timeval *modified_time);
void hip_update_handle_ack_old(hip_ha_t *entry,
                               struct hip_ack *ack,
                               int have_esp_info);
//add by santtu
int hip_hadb_add_udp_addr_old(hip_ha_t *entry,
                              struct in6_addr *addr,
                              int is_bex_address,
                              uint32_t lifetime,
                              int is_preferred_addr,
                              uint16_t port,
                              uint32_t priority,
                              uint8_t kind);

void hip_hadb_delete_peer_addrlist_one_old(hip_ha_t *ha, struct in6_addr *addr);

#endif /* HIP_HIPD_HADB_LEGACY_H */
