#ifndef HIP_HIPD_BOS_H
#define HIP_HIPD_BOS_H

#include <sys/types.h>
#include <netdb.h>

#include "lib/tool/nlink.h"
#include "lib/core/debug.h"
#include "hidb.h"
#include "hadb.h"
#include "lib/core/list.h"
#include "netdev.h"
#include "lib/core/state.h"

int hip_send_bos(const struct hip_common *msg);
int hip_verify_packet_signature(struct hip_common *bos,
                                struct hip_host_id *peer_host_id);

int hip_handle_bos(struct hip_common *bos,
                   struct in6_addr *bos_saddr,
                   struct in6_addr *bos_daddr,
                   hip_ha_t *entry, hip_portpair_t *);


#endif /* HIP_HIPD_BOS_H */
