#ifndef HIP_UPDATE_H
#define HIP_UPDATE_H

#include <net/hip.h>

int hip_handle_update_initial(struct hip_common *msg, int state);
int hip_handle_update_reply(struct hip_common *msg, int state);
int hip_receive_update(struct sk_buff *skb);
int hip_send_update(struct hip_hadb_state *entry);
void hip_send_update_all(void);

#endif /* HIP_UPDATE_H */
