/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef HIP_LIB_CORE_HIP_UDP_H
#define HIP_LIB_CORE_HIP_UDP_H

#include <netinet/in.h>

#define HIP_NAT_UDP_PORT 10500

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
