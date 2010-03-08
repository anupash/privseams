#ifndef HIP_LIB_CORE_HIP_UDP_H
#define HIP_LIB_CORE_HIP_UDP_H

#include <netinet/in.h>

#define HIP_NAT_UDP_PORT 10500
#define HIP_NAT_TURN_PORT 10500

/**
 * Get HIP local NAT UDP port.
 */
in_port_t hip_get_local_nat_udp_port(void);

/**
 * Get HIP peer NAT UDP port.
 */
in_port_t hip_get_peer_nat_udp_port(void);

/**
 * Set HIP local NAT UDP port.
 */
int hip_set_local_nat_udp_port(in_port_t port);

/**
 * Set HIP peer NAT UDP port.
 */
int hip_set_peer_nat_udp_port(in_port_t port);

#endif /* HIP_LIB_CORE_HIP_UDP_H */
