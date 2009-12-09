#ifndef HIP_FIREWALLDB_H
#define HIP_FIREWALLDB_H

#include <netinet/ip_icmp.h>
#include "libhipcore/icomm.h"
#include "libhipcore/kerncompat.h"

void firewall_init_hldb(void);
firewall_hl_t *firewall_ip_db_match(const struct in6_addr *ip_peer);
int firewall_set_bex_state(struct in6_addr *hit_s, 
                           struct in6_addr *hit_r, 
                           int state);
void hip_firewall_delete_hldb(void);
int firewall_add_default_entry(const struct in6_addr *ip);
int firewall_update_entry(const struct in6_addr *hit_our, 
                          const struct in6_addr *hit_peer, 
                          const hip_lsi_t *lsi, 
                          const struct in6_addr *ip, 
                          int state);
int firewall_send_outgoing_pkt(const struct in6_addr *src_hit, 
                               const struct in6_addr *dst_hit, 
                               u8 *msg, u16 len, 
                               int proto);
int firewall_send_incoming_pkt(const struct in6_addr *src_hit, 
                               const struct in6_addr *dst_hit, 
                               u8 *msg, u16 len, int proto, int ttl);

#endif /* HIP_FIREWALLDB_H */
