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
 * @brief UDP-related functions
 */

#include <netinet/in.h>

#include "hip_udp.h"
#include "debug.h"

/** Port numbers for NAT traversal of hip control packets. */
static in_port_t hip_local_nat_udp_port = HIP_NAT_UDP_PORT;
static in_port_t hip_peer_nat_udp_port  = HIP_NAT_UDP_PORT;


/**
 * Retrieve the default local UDP port
 *
 * @return the default local UDP port
 */
in_port_t hip_get_local_nat_udp_port(void)
{
    return hip_local_nat_udp_port;
}

/**
 * Retrieve the default remote UDP port
 *
 * @return the default remote UDP port
 */
in_port_t hip_get_peer_nat_udp_port(void)
{
    return hip_peer_nat_udp_port;
}

/**
 * set the default local UDP port
 *
 * @param port the port to set as the default local UDP port
 * @return zero
 */
int hip_set_local_nat_udp_port(in_port_t port)
{
    int err = 0;
    HIP_DEBUG("set local nat udp port %d\n", port);
    hip_local_nat_udp_port = port;

    return err;
}

/**
 * set the default remote UDP port
 *
 * @param port the port to set as the default remote UDP port
 * @return zero
 */
int hip_set_peer_nat_udp_port(in_port_t port)
{
    int err = 0;

    HIP_DEBUG("set peer nat udp port %d\n", port);
    hip_peer_nat_udp_port = port;
    return err;
}
