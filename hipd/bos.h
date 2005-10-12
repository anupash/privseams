#ifndef HIP_BOS_NEW_H
#define HIP_BOS_NEW_H

#include "hip.h"
#include "debug.h"
//#include "socket.h"
#include "beet.h"
#include "hidb.h"
#include "hadb.h"
#include "netlink.h"

#  include <sys/types.h>
#  include <netdb.h>
#  include "netdev.h"
#  include "list.h"

//extern struct my_addrinfo;


int hip_send_bos(const struct hip_common *msg);
int hip_create_bos_signature(struct hip_host_id *priv, int algo, struct hip_common *bos);
int hip_verify_packet_signature(struct hip_common *bos, struct hip_host_id *peer_host_id);

int hip_handle_bos(struct hip_common *bos,
		   struct in6_addr *bos_saddr,
		   struct in6_addr *bos_daddr,
		   hip_ha_t *entry);


#endif /* HIP_BOS_NEW_H */
