/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @brief UDP-related functions
 *
 * @author Miika Komu <miika@iki.fi>
 */

#include "hip_udp.h"
#include "debug.h"

/** Port numbers for NAT traversal of hip control packets. */
in_port_t hip_local_nat_udp_port = HIP_NAT_UDP_PORT;
in_port_t hip_peer_nat_udp_port  = HIP_NAT_UDP_PORT;


/**
 * Retrieve the default local UDP port
 *
 * @return the default local UDP port
 */
in_port_t hip_get_local_nat_udp_port()
{
    return hip_local_nat_udp_port;
}

/**
 * Retrieve the default remote UDP port
 *
 * @return the default remote UDP port
 */
in_port_t hip_get_peer_nat_udp_port()
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
