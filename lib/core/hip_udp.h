/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */
#ifndef HIP_LIB_CORE_HIP_UDP_H
#define HIP_LIB_CORE_HIP_UDP_H

#include <netinet/in.h>

#define HIP_NAT_UDP_PORT 10500
//#define HIP_NAT_TURN_PORT 10500

/** For setting socket to listen for beet-udp packets. */
#define HIP_UDP_ENCAP 100
/** UDP encapsulation type. */
#define HIP_UDP_ENCAP_ESPINUDP 2
/** UDP encapsulation type. */
#define HIP_UDP_ENCAP_ESPINUDP_NONIKE 1

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
