/**
 * @file
 *
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

#ifndef HIP_FIREWALL_CACHE_PORT_H
#define HIP_FIREWALL_CACHE_PORT_H

#include <netinet/in.h> // in_port_t

enum hip_firewall_port_info {
    HIP_FIREWALL_PORT_UNKNOWN = 0,  // only used internally
    HIP_FIREWALL_PORT_UNBOUND,      // no application is bound to a certain
                                    // port under IPv4 or IPv6
    HIP_FIREWALL_PORT_IPV6,         // the port is bound to an IPv6 address (and
                                    // potentially an IPv4 address)
    HIP_FIREWALL_PORT_IPV4,         // the port is bound to a non-LSI IPv4
                                    // address (but not to an IPv6 address)
    HIP_FIREWALL_PORT_LSI           // the port is bound to an LSI IPv4 address
};

void hip_firewall_port_cache_init(void);

enum hip_firewall_port_info
hip_firewall_port_cache_lookup_binding(const uint8_t proto,
                                       const in_port_t port);
void hip_firewall_port_cache_uninit(void);

#endif /* HIP_CACHE_H */
