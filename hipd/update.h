#ifndef HIP_UPDATE_H
#define HIP_UPDATE_H

#include "hip.h"
#include "builder.h"
#include "hadb.h"

/* FIXME: where to include these from in userspace? */
#  define IPV6_ADDR_ANY           0x0000U
#  define IPV6_ADDR_UNICAST       0x0001U 
#  define IPV6_ADDR_LOOPBACK      0x0010U
#  define IPV6_ADDR_LINKLOCAL     0x0020U
#  define IPV6_ADDR_SITELOCAL     0x0040U

int hip_receive_update(struct 	hip_common *msg,
		       struct 	in6_addr *update_saddr,
		       struct 	in6_addr *update_daddr,
		       hip_ha_t *entry);
		       
int hip_send_update(struct hip_hadb_state *entry,
		    struct hip_locator_info_addr_item *addr_list,
		    int addr_count, int ifindex, int flags);
		    
void hip_send_update_all(struct hip_locator_info_addr_item *addr_list,
			 int addr_count,
			 int ifindex, 
			 int flags);
			 
int hip_handle_update_plain_locator(hip_ha_t *entry, 
				struct hip_common *msg,
				struct in6_addr *src_ip,
				struct in6_addr *dst_ip,
				struct hip_esp_info *esp_info);
				
int hip_handle_update_addr_verify(hip_ha_t *entry,
					struct hip_common *msg,
					struct in6_addr *src_ip,
					struct in6_addr *dst_ip);
					
void hip_update_handle_ack(hip_ha_t *entry,
				struct hip_ack *ack,
				int have_nes,
				struct hip_echo_response *echo_esp);
				
int hip_handle_update_established(hip_ha_t *entry,
					struct hip_common *msg,
					struct in6_addr *src_ip,
					struct in6_addr *dst_ip);
					
int hip_handle_update_rekeying(hip_ha_t *entry,
				struct hip_common *msg,
				struct in6_addr *src_ip); 
				
int hip_update_send_addr_verify(hip_ha_t *entry, struct hip_common *msg,
				struct in6_addr *src_ip, uint32_t spi);

#endif /* HIP_UPDATE_H */
