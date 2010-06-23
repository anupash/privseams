/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_FIREWALL_FIREWALLDB_H
#define HIP_FIREWALL_FIREWALLDB_H

#include <stdint.h>
#include <netinet/in.h>

#include "lib/core/icomm.h"
#include "lib/core/protodefs.h"

//definition of firewall db records
typedef struct firewall_hl {
    struct in6_addr ip_peer;
    hip_lsi_t       lsi;
    hip_hit_t       hit_our;
    hip_hit_t       hit_peer;
    int             bex_state;
} firewall_hl_t;

void hip_firewall_init_hldb(void);
firewall_hl_t *hip_firewall_ip_db_match(const struct in6_addr *ip_peer);
int hip_firewall_set_bex_state(struct in6_addr *hit_s,
                              struct in6_addr *hit_r,
                              int state);
void hip_firewall_delete_hldb(void);
int hip_firewall_add_default_entry(const struct in6_addr *ip);
int hip_firewall_update_entry(const struct in6_addr *hit_our,
                              const struct in6_addr *hit_peer,
                              const hip_lsi_t *lsi,
                              const struct in6_addr *ip,
                              int state);

#endif /* HIP_FIREWALL_FIREWALLDB_H */
