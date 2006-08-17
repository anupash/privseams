#ifndef _HIPD_ACCESSOR
#define _HIPD_ACCESSOR

#include "hipd.h"

int hip_agent_is_alive();
int hip_set_opportunistic_mode(const struct hip_common *msg);
int hip_get_peer_hit(struct hip_common *msg, const struct sockaddr_un *src);
int hip_get_pseudo_hit(struct hip_common *msg);
int hip_query_opportunistic_mode(struct hip_common *msg);
int hip_query_ip_hit_mapping(struct hip_common *msg);


#endif /* _HIPD_ACCESSOR */

