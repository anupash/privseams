#ifndef HIP_UPDATE_H
#define HIP_UPDATE_H

#ifdef __KERNEL__
#  include <net/ipv6.h>
#  include <linux/xfrm.h>
#  include <net/xfrm.h>
#endif /* __KERNEL__ */

#include <net/hip.h>
#include "hip.h"
#include "dh.h"
#include "input.h"
#include "hadb.h"
#include "db.h"
#include "keymat.h"
#include "builder.h"
#include "misc.h"
#include "output.h"

/* int hip_update_spi_waitlist_ispending(uint32_t spi); */
/* void hip_update_spi_waitlist_delete_all(void); */
int hip_receive_update(struct sk_buff *skb);
int hip_send_update(struct hip_hadb_state *entry, struct hip_rea_info_addr_item *addr_list,
		    int addr_count, int ifindex, int flags);
void hip_send_update_all(struct hip_rea_info_addr_item *addr_list, int addr_count, int ifindex, int flags);

#endif /* HIP_UPDATE_H */
