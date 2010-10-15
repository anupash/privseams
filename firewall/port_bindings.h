/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
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

/**
 * @file
 * The port binding says whether a port is locally bound to an IPv6
 * application or not.
 * This allows the firewall to determine whether an incoming HIT-based packet
 * is meant to go to a local IPv6 port or not.
 * If not, the packet needs to be converted to IPv4 and sent to an LSI.
 * More details can be found in <a
 * href="http://hipl.hiit.fi/hipl/thesis_teresa_finez.pdf">T. Finez,
 * Backwards Compatibility Experimentation with Host Identity Protocol
 * and Legacy Software and Networks , final project, December 2008</a>.
 *
 * @author Miika Komu <miika@iki.fi>, Stefan Goetz <stefan.goetz@cs.rwth-aachen.de>
 */

#ifndef HIP_FIREWALL_PORT_INFO_H
#define HIP_FIREWALL_PORT_INFO_H

#include <stdbool.h>    // bool
#include <netinet/in.h> // in_port_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The binding state of a particular TCP or UDP port under IPv6 on the local
 * host.
 */
enum hip_port_binding {
    /**
     * It is not known which network protocol the port is bound under.
     */
    HIP_PORT_INFO_UNKNOWN = 0,
    /**
     * The port is not bound to an IPv6 address (but potentially to an
     * IPv4 address).
     */
    HIP_PORT_INFO_IPV6UNBOUND,
    /**
     * The port is bound to an IPv6 address (and potentially to an IPv4
     * address)
     */
    HIP_PORT_INFO_IPV6BOUND,
};

int hip_port_bindings_init(const bool enable_cache);
void hip_port_bindings_uninit(void);
enum hip_port_binding hip_port_bindings_get(const uint8_t proto,
                  				            const in_port_t port);

#ifdef __cplusplus
}
#endif

#endif /* HIP_CACHE_H */
