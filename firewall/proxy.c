/** @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * HIP client-side proxy. Documented in detail in Weiwei's thesis when
 * it's finished.
 *
 * @author Weiwei Hu
 */

#define _BSD_SOURCE

#include <netinet/icmp6.h>

#include "firewall/proxy.h"
#include "firewall/proxyconndb.h"
#include "firewall/firewall_defines.h"
#include "lib/tool/checksum.h"

int hip_proxy_raw_sock_tcp_v4          = 0;
int hip_proxy_raw_sock_tcp_v6          = 0;
int hip_proxy_raw_sock_udp_v4          = 0;
int hip_proxy_raw_sock_udp_v6          = 0;
int hip_proxy_raw_sock_icmp_v4         = 0;
int hip_proxy_raw_sock_icmp_v6         = 0;
int hip_proxy_raw_sock_icmp_inbound    = 0;
const char hip_proxy_supported_proto[] = { IPPROTO_TCP,
        IPPROTO_ICMP, IPPROTO_UDP };


#ifdef CONFIG_HIP_HIPPROXY
/**
 * Request the status of the HIP proxy
 *
 * @return zero on success, non-zero on error
 */
int request_hipproxy_status(void)
{
    struct hip_common *msg = NULL;
    int err                = 0;
    HIP_DEBUG("Sending hipproxy msg to hipd.\n");
    HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg,
                                HIP_MSG_HIPPROXY_STATUS_REQUEST, 0),
             -1, "Build hdr failed\n");

    //n = hip_sendto(msg, &hip_firewall_addr);

    //n = sendto(hip_fw_sock, msg, hip_get_msg_total_len(msg),
    //      0,(struct sockaddr *)dst, sizeof(struct sockaddr_in6));

    HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_sock), -1,
             "HIP_HIPPROXY_STATUS_REQUEST: Sendto HIPD failed.\n");
    HIP_DEBUG("HIP_HIPPROXY_STATUS_REQUEST: Sendto hipd ok.\n");

out_err:
    if (msg) {
        free(msg);
    }
    return err;
}

#endif /* CONFIG_HIP_HIPPROXY */


/**
 * Request the peer HIT from HIP Daemon
 *
 * @param peer_ip the address of the peer host (HIP Server)
 * @param local_hit the HIT of the local HIP proxy
 * @return zero on success, non-zero on error
 */
int hip_proxy_request_peer_hit_from_hipd(const struct in6_addr *peer_ip,
                                         const struct in6_addr *local_hit)
{
    struct hip_common *msg = NULL;
    int err                = 0;

    HIP_IFE(!(msg = hip_msg_alloc()), -1);

    /* build the message header */
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_GET_PEER_HIT, 0), -1,
             "build hdr failed\n");

    HIP_IFEL(hip_build_param_contents(msg, (void *) (local_hit),
                                      HIP_PARAM_HIT_LOCAL,
                                      sizeof(struct in6_addr)), -1,
             "build param HIP_PARAM_HIT  failed\n");
    HIP_IFEL(hip_build_param_contents(msg, (void *) (peer_ip),
                                      HIP_PARAM_IPV6_ADDR_PEER,
                                      sizeof(struct in6_addr)), -1,
             "build param HIP_PARAM_IPV6_ADDR failed\n");

    /* @todo: we should call trigger_bex instead ! */

    /* Send to hipd without waiting for an response; blocking
     * prevent receiving of R1 message. This message has to be delivered
     * with the async socket because opportunistic mode responds asynchronously */
    HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_async_sock), -1, "sending msg failed\n");
    _HIP_DEBUG("send_recv msg succeed\n");

out_err:

    if (msg) {
        free(msg);
    }

    return err;
}

/**
 * Get the local HIT from HIP Daemon
 *
 * @param hit the pointer used to store the local HIT
 * @return zero on success, non-zero on error
 */
int hip_get_local_hit_wrapper(hip_hit_t *hit)
{
    int err                = 0;
    char *param            = 0;
    struct hip_common *msg = NULL;
    //struct gaih_addrtuple *at = NULL;

    HIP_IFEL(!(msg = hip_msg_alloc()), -1, "malloc failed\n");
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_DEFAULT_HIT, 0),
             -1, "Fail to get hits");
    HIP_IFEL(hip_send_recv_daemon_info(msg, 0, hip_fw_sock), -1, "send/recv\n");
    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_HIT)), -1,
             "No HIT received\n");
    ipv6_addr_copy(hit, hip_get_param_contents_direct(param));
    _HIP_DEBUG_HIT("hit", hit);

out_err:
    if (msg) {
        free(msg);
    }
    return err;
}

/**
 * Set the peer HIT into the HIP Proxy Database
 *
 * @param msg the received message for the HIT request of the peer host
 * @return zero on success, non-zero on error
 */
int hip_fw_proxy_set_peer_hit(hip_common_t *msg)
{
    int fallback               = 1, reject = 0, addr_found = 0, err = 0;
    hip_hit_t local_hit, peer_hit;
    struct in6_addr local_addr, peer_addr;
    hip_hit_t *ptr             = NULL;
    struct in6_addr *proxy_hit = NULL;

    HIP_IFEL( !(proxy_hit = hip_fw_get_default_hit()), 0,
              "Error while getting the default HIT!\n");

    ptr = (hip_hit_t *) hip_get_param_contents(msg, HIP_PARAM_HIT_PEER);
    if (ptr) {
        memcpy(&peer_hit, ptr, sizeof(hip_hit_t));
        HIP_DEBUG_HIT("peer_hit", &peer_hit);
        fallback = 0;
    }

    ptr = (hip_hit_t *) hip_get_param_contents(msg, HIP_PARAM_HIT_LOCAL);
    if (ptr) {
        memcpy(&local_hit, ptr, sizeof(hip_hit_t));
        HIP_DEBUG_HIT("local_hit", &local_hit);
    }

    ptr = (hip_hit_t *) hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR_PEER);
    if (ptr) {
        memcpy(&peer_addr, ptr, sizeof(struct in6_addr));
        HIP_DEBUG_IN6ADDR("peer_addr", &peer_addr);
        addr_found++;
    }

    ptr = (hip_hit_t *) hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR_LOCAL);
    if (ptr) {
        memcpy(&local_addr, ptr, sizeof(hip_hit_t));
        HIP_DEBUG_IN6ADDR("local_addr", &local_addr);
        addr_found++;
    }

    if (addr_found != 2) {
        HIP_ERROR("Internal error: two addr not found\n");
        err = -1;
    }

    ptr = hip_get_param(msg, HIP_PARAM_AGENT_REJECT);
    if (ptr) {
        HIP_DEBUG("Connection is to be rejected\n");
        reject = 1;
    }

    if (reject) {
        HIP_DEBUG("Connection should be rejected\n");
        err = -1;
        goto out_err;
    }

    if (fallback) {
        HIP_DEBUG("Peer does not support HIP, fallback\n");
        //update the state of the ip pair
        if (hip_proxy_update_state(NULL, &peer_addr, NULL, NULL, NULL,
                                   HIP_PROXY_PASSTHROUGH)) {
            HIP_ERROR("Proxy update Failed!\n");
        }

        //let the packet pass
        err = -1;
    } else {
        if (hip_proxy_update_state(NULL, &peer_addr, &local_addr, proxy_hit,
                                   &peer_hit, HIP_PROXY_TRANSLATE)) {
            HIP_ERROR("Proxy update Failed!\n");
        }

#if 0
        if (hip_proxy_conn_add_entry(&local_addr,
                                     &peer_addr,
                                     proxy_hit,
                                     &peer_hit,
                                     protocol,
                                     port_client,
                                     port_peer,
                                     HIP_PROXY_TRANSLATE)) {
            HIP_ERROR("ConnDB add entry Failed!\n");
        }
#endif

        /* Drop packet. Firewall translates further retransmissions correctly */
        err = 0;
    }

out_err:

    return err;
}

/**
 * Initialize the IPv6 socket for TCP connection
 *
 * @param hip_raw_sock_v6 the socket pointer used for TCP connection in IPv6
 * @return zero on success, non-zero on error
 */
int hip_init_proxy_raw_sock_tcp_v6(int *hip_raw_sock_v6)
{
    int on = 1, off = 0, err = 0;

    *hip_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    HIP_IFEL(*hip_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    err = setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    err = setsockopt(*hip_raw_sock_v6, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize the IPv4 socket for TCP connection
 *
 * @param hip_raw_sock_v4 the socket pointer used for TCP connection in IPv4
 * @return zero on success, non-zero on error
 */
int hip_init_proxy_raw_sock_tcp_v4(int *hip_raw_sock_v4)
{
    int on  = 1, err = 0;
    int off = 0;

    *hip_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    HIP_IFEL(*hip_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*hip_raw_sock_v4, IPPROTO_IP,
                     IP_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
    err = setsockopt(*hip_raw_sock_v4, SOL_SOCKET,
                     SO_BROADCAST, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
    err = setsockopt(*hip_raw_sock_v4, IPPROTO_IP,
                     IP_PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
    err = setsockopt(*hip_raw_sock_v4, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize the IPv6 socket for UDP connection
 *
 * @param hip_raw_sock_v6 the socket pointer used for UDP connection in IPv6
 * @return zero on success, non-zero on error
 */
int hip_init_proxy_raw_sock_udp_v6(int *hip_raw_sock_v6)
{
    int on = 1, off = 0, err = 0;

    *hip_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
    HIP_IFEL(*hip_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    err = setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    err = setsockopt(*hip_raw_sock_v6, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize the IPv4 socket for UDP connection
 *
 * @param hip_raw_sock_v4 the socket pointer used for UDP connection in IPv4
 * @return zero on success, non-zero on error
 */
int hip_init_proxy_raw_sock_udp_v4(int *hip_raw_sock_v4)
{
    int on  = 1, err = 0;
    int off = 0;

    *hip_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    HIP_IFEL(*hip_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*hip_raw_sock_v4, IPPROTO_IP,
                     IP_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
    err = setsockopt(*hip_raw_sock_v4, SOL_SOCKET,
                     SO_BROADCAST, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
    err = setsockopt(*hip_raw_sock_v4, IPPROTO_IP,
                     IP_PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
    err = setsockopt(*hip_raw_sock_v4, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize the ICMPv6 socket
 *
 * @param hip_raw_sock_v6 the socket pointer used for ICMPv6 connection
 * @return zero on success, non-zero on error
 */
int hip_init_proxy_raw_sock_icmp_v6(int *hip_raw_sock_v6)
{
    int on = 1, off = 0, err = 0;

    *hip_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    HIP_IFEL(*hip_raw_sock_v6 <= 0, 1,
             "Raw socket creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    err = setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    err = setsockopt(*hip_raw_sock_v6, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize the ICMP socket
 *
 * @param hip_raw_sock_v4 the socket pointer used for ICMP
 * @return zero on success, non-zero on error
 */
int hip_init_proxy_raw_sock_icmp_v4(int *hip_raw_sock_v4)
{
    int on  = 1, err = 0;
    int off = 0;

    *hip_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    HIP_IFEL(*hip_raw_sock_v4 <= 0, 1,
             "Raw socket v4 creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*hip_raw_sock_v4, IPPROTO_IP,
                     IP_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
    err = setsockopt(*hip_raw_sock_v4, SOL_SOCKET,
                     SO_BROADCAST, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
    err = setsockopt(*hip_raw_sock_v4, IPPROTO_IP,
                     IP_PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
    err = setsockopt(*hip_raw_sock_v4, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize the ICMPV6 socket for Inbound connection
 *
 * @param hip_raw_sock_v6 the socket pointer used for ICMPv6 connection in IPv6
 * @return zero on success, non-zero on error
 */
int hip_init_proxy_raw_sock_icmp_inbound(int *hip_raw_sock_v6)
{
    int on = 1, off = 0, err = 0;

    *hip_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMP);
    HIP_IFEL(*hip_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    err = setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    err = setsockopt(*hip_raw_sock_v6, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize all the sockets
 *
 * @return zero on success, non-zero on error
 */
int hip_proxy_init_raw_sockets(void)
{
    hip_init_proxy_raw_sock_tcp_v6(&hip_proxy_raw_sock_tcp_v6);
    hip_init_proxy_raw_sock_tcp_v4(&hip_proxy_raw_sock_tcp_v4);
    hip_init_proxy_raw_sock_udp_v6(&hip_proxy_raw_sock_udp_v6);
    hip_init_proxy_raw_sock_udp_v4(&hip_proxy_raw_sock_udp_v4);
    hip_init_proxy_raw_sock_icmp_v6(&hip_proxy_raw_sock_icmp_v6);
    hip_init_proxy_raw_sock_icmp_v4(&hip_proxy_raw_sock_icmp_v4);
    hip_init_proxy_raw_sock_icmp_inbound(&hip_proxy_raw_sock_icmp_inbound);

    return 0;
}

/**
 * Initialize the HIP proxy
 *
 * @return zero on success, non-zero on error
 */
int init_proxy(void)
{
    int err = 0;

    hip_init_proxy_db();
    hip_proxy_init_raw_sockets();
    hip_proxy_init_conn_db();

    return err;
}

/**
 * Uninitialize the HIP proxy
 *
 * @return zero on success, non-zero on error
 */
int uninit_proxy(void)
{
    int err = 0;

    hip_uninit_proxy_db();
    //hip_proxy_uninit_raw_sockets(); // FIXME not implemented yet
    hip_proxy_uninit_conn_db();

    return err;
}

/**
 * Send packets to the HIP server
 * @param local_addr the HIT of the sender
 * @param peer_addr the HIT of the receiver
 * @param msg the payload of the packet
 * @param len the len of the packet
 * @param protocol the protocol of the connection
 * @return zero on success, non-zero on error
 */
static int hip_proxy_send_pkt(struct in6_addr *local_addr,
                              struct in6_addr *peer_addr,
                              uint8_t *msg, uint16_t len, int protocol)
{
    int err = 0, sa_size, sent;
    struct sockaddr_storage src, dst;
    int src_is_ipv4, dst_is_ipv4;
    struct sockaddr_in6 *src6, *dst6;
    struct sockaddr_in *src4, *dst4;
    struct in6_addr my_addr;
    /* Points either to v4 or v6 raw sock */
    int hip_raw_sock = 0;


    _HIP_DEBUG("hip_send_raw() invoked.\n");

    /* Verify the existence of obligatory parameters. */
    HIP_ASSERT(peer_addr != NULL && msg != NULL);

    HIP_DEBUG_IN6ADDR("hip_send_raw(): local_addr", local_addr);
    HIP_DEBUG_IN6ADDR("hip_send_raw(): peer_addr", peer_addr);

    dst_is_ipv4 = IN6_IS_ADDR_V4MAPPED(peer_addr);

    /* Some convinient short-hands to avoid too much casting (could be
     * an union as well) */
    src6        = (struct sockaddr_in6 *) &src;
    dst6        = (struct sockaddr_in6 *) &dst;
    src4        = (struct sockaddr_in *)  &src;
    dst4        = (struct sockaddr_in *)  &dst;

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    if (dst_is_ipv4) {
        HIP_DEBUG("Using IPv4 raw socket\n");
        if (protocol == IPPROTO_TCP) {
            hip_raw_sock = hip_proxy_raw_sock_tcp_v4;
        }
        if (protocol == IPPROTO_UDP) {
            hip_raw_sock = hip_proxy_raw_sock_udp_v4;
        }
        if (protocol == IPPROTO_ICMP) {
            hip_raw_sock = hip_proxy_raw_sock_icmp_v4;
        }
        sa_size = sizeof(struct sockaddr_in);
    } else {
        HIP_DEBUG("Using IPv6 raw socket\n");
        if (protocol == IPPROTO_TCP) {
            hip_raw_sock = hip_proxy_raw_sock_tcp_v6;
        }
        if (protocol == IPPROTO_UDP) {
            hip_raw_sock = hip_proxy_raw_sock_udp_v6;
        }
        if (protocol == IPPROTO_ICMPV6) {
            hip_raw_sock = hip_proxy_raw_sock_icmp_v6;
        }
        sa_size = sizeof(struct sockaddr_in6);
    }

    if (local_addr) {
        HIP_DEBUG("local address given\n");
        memcpy(&my_addr, local_addr, sizeof(struct in6_addr));
    } else {
        HIP_DEBUG("no local address, selecting one\n");
    }

    src_is_ipv4 = IN6_IS_ADDR_V4MAPPED(&my_addr);

    if (src_is_ipv4) {
        IPV6_TO_IPV4_MAP(&my_addr, &src4->sin_addr);
        src4->sin_family = AF_INET;
        HIP_DEBUG_INADDR("src4", &src4->sin_addr);
    } else {
        memcpy(&src6->sin6_addr, &my_addr,  sizeof(struct in6_addr));
        src6->sin6_family = AF_INET6;
        HIP_DEBUG_IN6ADDR("src6", &src6->sin6_addr);
    }

    if (dst_is_ipv4) {
        IPV6_TO_IPV4_MAP(peer_addr, &dst4->sin_addr);
        dst4->sin_family = AF_INET;
        HIP_DEBUG_INADDR("dst4", &dst4->sin_addr);
    } else {
        memcpy(&dst6->sin6_addr, peer_addr, sizeof(struct in6_addr));
        dst6->sin6_family = AF_INET6;
        HIP_DEBUG_IN6ADDR("dst6", &dst6->sin6_addr);
    }

    if (src6->sin6_family != dst6->sin6_family) {
        /* @todo: Check if this may cause any trouble.
         * It happens every time we send update packet that contains few locators in msg, one is
         * the IPv4 address of the source, another is IPv6 address of the source. But even if one of
         * them is ok to send raw IPvX to IPvX raw packet, another one cause the trouble, and all
         * updates are dropped.  by Andrey "laser".
         *
         */
        err = -1;
        HIP_ERROR("Source and destination address families differ\n");
        goto out_err;
    }


    //re-construct packet from here
    if (protocol == IPPROTO_TCP) {
        HIP_DEBUG("Previous checksum: %X\n", ((struct tcphdr *) msg)->check);
        ((struct tcphdr *) msg)->check = htons(0);

        if (src_is_ipv4 && dst_is_ipv4) {
            HIP_DEBUG("src_addr and dst_aadr are ipv4!\n");
            HIP_DEBUG("TCP packet\n");
            ((struct tcphdr *) msg)->check = ipv4_checksum(
                    IPPROTO_TCP,
                    (uint8_t *) (&(src4->sin_addr)),
                    (uint8_t *) (&(dst4->sin_addr)),
                    msg, len);       //checksum is ok for ipv4
        } else {
            HIP_DEBUG("src_addr and dst_aadr are ipv6!\n");
            HIP_DEBUG("TCP packet\n");
            ((struct tcphdr *) msg)->check = ipv6_checksum(
                    IPPROTO_TCP, &src6->sin6_addr, &dst6->sin6_addr, msg, len);
        }

        HIP_DEBUG("Current checksum: %X\n", ((struct tcphdr *) msg)->check);
    }

    if (protocol == IPPROTO_UDP) {
        //TODO calculate the udp checksum
        ((struct udphdr *) msg)->check = htons(0);

        if (src_is_ipv4 && dst_is_ipv4) {
            HIP_DEBUG("src_addr and dst_aadr are ipv4!\n");
            HIP_DEBUG("UDP packet\n");
            ((struct udphdr *) msg)->check = ipv4_checksum(
                    IPPROTO_UDP, (uint8_t *) (&(src4->sin_addr)),
                    (uint8_t *) (&(dst4->sin_addr)),
                    msg, len);       //checksum is ok for ipv4
        } else {
            HIP_DEBUG("src_addr and dst_aadr are ipv6!\n");
            HIP_DEBUG("UDP packet\n");
            ((struct udphdr *) msg)->check = ipv6_checksum(
                    IPPROTO_UDP, &src6->sin6_addr, &dst6->sin6_addr, msg, len);
        }
    }

    if (protocol == IPPROTO_ICMP) {
        //TODO IPv4 only checksum the buff
        HIP_DEBUG("ICMP packet\n");
        ((struct icmphdr *) msg)->checksum = htons(0);
        ((struct icmphdr *) msg)->checksum = inchksum(msg, len); //checksum is ok for ipv4
    }

    if (protocol == IPPROTO_ICMPV6) {
        //TODO
        HIP_DEBUG("ICMPV6 packet\n");
        ((struct icmp6_hdr *) msg)->icmp6_cksum = htons(0);
        ((struct icmp6_hdr *) msg)->icmp6_cksum = ipv6_checksum(
                IPPROTO_ICMPV6, &src6->sin6_addr, &dst6->sin6_addr, msg, len);
    }

    /* Handover may cause e.g. on-link duplicate address detection
     * which may cause bind to fail. */

    HIP_IFEL(bind(hip_raw_sock, (struct sockaddr *) &src, sa_size),
             -1, "Binding to raw sock failed\n");

    HIP_DEBUG("Binding OK!\n");
    /* For some reason, neither sendmsg or send (with bind+connect)
     * do not seem to work properly. Thus, we use just sendto() */

    sent = sendto(hip_raw_sock, msg, len, 0,
                  (struct sockaddr *) &dst, sa_size);
    if (sent != len) {
        HIP_ERROR("Could not send the all requested"            \
                  " data (%d/%d)\n", sent, len);
        HIP_ERROR("strerror: %s\n", strerror(errno));
    } else {
        HIP_DEBUG("sent=%d/%d ipv4=%d\n",
                  sent, len, dst_is_ipv4);
        HIP_DEBUG("Packet sent ok\n");
    }

out_err:

    /* Reset the interface to wildcard or otherwise receiving
     * broadcast messages fails from the raw sockets */
    if (dst_is_ipv4) {
        src4->sin_addr.s_addr = INADDR_ANY;
        src4->sin_family      = AF_INET;
        sa_size               = sizeof(struct sockaddr_in);
    } else {
        struct in6_addr any = IN6ADDR_ANY_INIT;
        src6->sin6_family = AF_INET6;
        ipv6_addr_copy(&src6->sin6_addr, &any);
        sa_size           = sizeof(struct sockaddr_in6);
    }
    bind(hip_raw_sock, (struct sockaddr *) &src, sa_size);

    if (err) {
        HIP_ERROR("strerror: %s\n", strerror(errno));
    }

    return err;
}

/**
 * Send packets to the legacy client
 * @param local_addr the address of the sender
 * @param peer_addr the address of the receiver
 * @param buff the payload of the packet
 * @param len the len of the packet
 * @return zero on success, non-zero on error
 */
static int hip_proxy_send_to_client_pkt(struct in6_addr *local_addr,
                                        struct in6_addr *peer_addr,
                                        uint8_t *buff, uint16_t len)
{
    int on = 1, off = 0, protocol, err = 0, sa_size = 0, sent;
    struct sockaddr_storage src, dst;
    int src_is_ipv4, dst_is_ipv4;
    struct sockaddr_in6 *src6   = NULL;
    struct sockaddr_in6 *dst6   = NULL;
    struct sockaddr_in *src4    = NULL;
    struct sockaddr_in *dst4    = NULL;
    struct in6_addr my_addr;
    struct ip6_hdr *incomingip6 = NULL;
    struct ip6_hdr *ip6_hdr     = NULL;
    struct ip *iphdr            = NULL;
    struct tcphdr *tcp          = NULL;
    struct udphdr *udp          = NULL;
    struct icmphdr *icmp        = NULL;
    struct icmp6_hdr *icmpv6     = NULL;
    uint8_t *msg                     = NULL;
    /* Points either to v4 or v6 raw sock */
    int hip_raw_sock            = 0;


    _HIP_DEBUG("hip_send_raw() invoked.\n");
    HIP_HEXDUMP("ip msg dump: ", buff, len);

    /* Verify the existence of obligatory parameters. */
    HIP_ASSERT(peer_addr != NULL && buff != NULL);

    HIP_DEBUG_IN6ADDR("hip_send_raw(): local_addr", local_addr);
    HIP_DEBUG_IN6ADDR("hip_send_raw(): peer_addr", peer_addr);

    dst_is_ipv4 = IN6_IS_ADDR_V4MAPPED(peer_addr);

    /* Some convinient short-hands to avoid too much casting (could be
     * an union as well) */
    src6        = (struct sockaddr_in6 *) &src;
    dst6        = (struct sockaddr_in6 *) &dst;
    src4        = (struct sockaddr_in *)  &src;
    dst4        = (struct sockaddr_in *)  &dst;
    incomingip6 = (struct ip6_hdr *) buff;
    protocol    = incomingip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    tcp         = (struct tcphdr *) (buff + 40); //sizeof ip6_hdr is 40
    udp         = (struct udphdr *) (buff + 40); //sizeof ip6_hdr is 40
    icmp        = (struct icmphdr *) (buff + 40); //sizeof ip6_hdr is 40
    icmpv6      = (struct icmp6_hdr *) (buff + 40); //sizeof ip6_hdr is 40

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));


    if (local_addr) {
        HIP_DEBUG("local address given\n");
        memcpy(&my_addr, local_addr, sizeof(struct in6_addr));
    } else {
        HIP_DEBUG("no local address, selecting one\n");
    }

    src_is_ipv4 = IN6_IS_ADDR_V4MAPPED(&my_addr);

    if (src_is_ipv4) {
        IPV6_TO_IPV4_MAP(&my_addr, &src4->sin_addr);
        src4->sin_family = AF_INET;
        HIP_DEBUG_INADDR("src4", &src4->sin_addr);
    } else {
        memcpy(&src6->sin6_addr, &my_addr,  sizeof(struct in6_addr));
        src6->sin6_family = AF_INET6;
        HIP_DEBUG_IN6ADDR("src6", &src6->sin6_addr);
    }

    if (dst_is_ipv4) {
        IPV6_TO_IPV4_MAP(peer_addr, &dst4->sin_addr);
        dst4->sin_family = AF_INET;

        HIP_DEBUG_INADDR("dst4", &dst4->sin_addr);
    } else {
        memcpy(&dst6->sin6_addr, peer_addr, sizeof(struct in6_addr));
        dst6->sin6_family = AF_INET6;
        HIP_DEBUG_IN6ADDR("dst6", &dst6->sin6_addr);
    }

    if (dst_is_ipv4) {
        HIP_DEBUG("Using IPv4 raw socket\n");
        HIP_DEBUG("IP packet length: %d\n", len);
        HIP_DEBUG("IP packet real length: %d\n", (len - sizeof(struct ip6_hdr) + sizeof(struct ip)));
        HIP_DEBUG("PACKET PROTOCOL: %d\n", protocol);

        if (protocol == IPPROTO_TCP) {
            hip_raw_sock = hip_proxy_raw_sock_tcp_v4;
            sa_size      = sizeof(struct sockaddr_in);
            msg          = (uint8_t *) HIP_MALLOC((len - sizeof(struct ip6_hdr) + sizeof(struct ip)), 0);
            memset(msg, 0, (len - sizeof(struct ip6_hdr) + sizeof(struct ip)));

            HIP_DEBUG_INADDR("ipv4 src address  inbound: ", &src4->sin_addr);
            HIP_DEBUG_INADDR("ipv4 src address  inbound: ", &dst4->sin_addr);
            tcp->check =  htons(0);
            tcp->check = ipv4_checksum(IPPROTO_TCP, (uint8_t *) (&(src4->sin_addr)), (uint8_t *) (&(dst4->sin_addr)), (uint8_t *) tcp, (len - sizeof(struct ip6_hdr)));       //checksum is ok for ipv4
            HIP_HEXDUMP("tcp dump: ", tcp, (len - sizeof(struct ip6_hdr)));
            memcpy((msg + sizeof(struct ip)), (uint8_t *) tcp, (len - sizeof(struct ip6_hdr)));
            HIP_HEXDUMP("tcp msg dump: ", msg, (len - sizeof(struct ip6_hdr) + sizeof(struct ip)));
        }

        if (protocol == IPPROTO_UDP) {
            hip_raw_sock = hip_proxy_raw_sock_udp_v4;
            sa_size      = sizeof(struct sockaddr_in);
            msg          = (uint8_t *) HIP_MALLOC((len - sizeof(struct ip6_hdr) + sizeof(struct ip)), 0);
            memset(msg, 0, (len - sizeof(struct ip6_hdr) + sizeof(struct ip)));

            HIP_DEBUG_INADDR("ipv4 src address  inbound: ", &src4->sin_addr);
            HIP_DEBUG_INADDR("ipv4 src address  inbound: ", &dst4->sin_addr);
            udp->check =  htons(0);
            udp->check = ipv4_checksum(IPPROTO_UDP, (uint8_t *) (&(src4->sin_addr)), (uint8_t *) (&(dst4->sin_addr)), (uint8_t *) udp, (len - sizeof(struct ip6_hdr)));       //checksum is ok for ipv4
            HIP_HEXDUMP("udp dump: ", udp, (len - sizeof(struct ip6_hdr)));
            memcpy((msg + sizeof(struct ip)), (uint8_t *) udp, (len - sizeof(struct ip6_hdr)));
            HIP_HEXDUMP("udp msg dump: ", msg, (len - sizeof(struct ip6_hdr) + sizeof(struct ip)));
        }

        if (protocol == IPPROTO_ICMP) {
            hip_raw_sock = hip_proxy_raw_sock_icmp_v4;
            sa_size      = sizeof(struct sockaddr_in);
            msg          = (uint8_t *) HIP_MALLOC((len - sizeof(struct ip6_hdr) + sizeof(struct ip)), 0);
            memset(msg, 0, (len - sizeof(struct ip6_hdr) + sizeof(struct ip)));

            HIP_DEBUG_INADDR("ipv4 src address  inbound: ", &src4->sin_addr);
            HIP_DEBUG_INADDR("ipv4 src address  inbound: ", &dst4->sin_addr);
            icmp->checksum =  htons(0);
            //icmp->checksum = ipv4_checksum(IPPROTO_ICMP, &(src4->sin_addr), &(dst4->sin_addr), icmp, (len - sizeof(struct ip6_hdr))); //checksum is ok for ipv4
            icmp->checksum = inchksum(icmp, (len - sizeof(struct ip6_hdr)));             //checksum is ok for ipv4
            HIP_HEXDUMP("icmp dump: ", icmp, (len - sizeof(struct ip6_hdr)));
            memcpy((msg + sizeof(struct ip)), (uint8_t *) icmp, (len - sizeof(struct ip6_hdr)));
            HIP_HEXDUMP("icmp msg dump: ", msg, (len - sizeof(struct ip6_hdr) + sizeof(struct ip)));
        }
    } else {
        if (protocol == IPPROTO_TCP) {
            HIP_DEBUG("Using IPv6 raw socket (TCP)\n");
            hip_raw_sock = hip_proxy_raw_sock_tcp_v6;
            sa_size      = sizeof(struct sockaddr_in6);
            msg          = (uint8_t *) HIP_MALLOC(len, 0);
            //memset(msg, 0, len);
            tcp->check   =  htons(0);
            tcp->check   = ipv6_checksum(IPPROTO_TCP, &(src6->sin6_addr), &(dst6->sin6_addr), tcp, (len - sizeof(struct ip6_hdr)));           //checksum is ok for ipv6
            memcpy((msg + sizeof(struct ip6_hdr)), (uint8_t *) tcp, (len - sizeof(struct ip6_hdr)));
        }

        if (protocol == IPPROTO_UDP) {
            HIP_DEBUG("Using IPv6 raw socket (UDP)\n");
            hip_raw_sock = hip_proxy_raw_sock_udp_v6;
            sa_size      = sizeof(struct sockaddr_in6);
            msg          = (uint8_t *) HIP_MALLOC(len, 0);
            //memset(msg, 0, len);
            udp->check   =  htons(0);
            udp->check   = ipv6_checksum(IPPROTO_UDP, &(src6->sin6_addr), &(dst6->sin6_addr), udp, (len - sizeof(struct ip6_hdr)));           //checksum is ok for ipv6
            memcpy((msg + sizeof(struct ip6_hdr)), (uint8_t *) udp, (len - sizeof(struct ip6_hdr)));
        }

        if (protocol == IPPROTO_ICMPV6) {
            HIP_DEBUG("Using IPv6 raw socket (ICMPV6)\n");
            hip_raw_sock        = hip_proxy_raw_sock_icmp_v6;
            sa_size             = sizeof(struct sockaddr_in6);
            msg                 = (uint8_t *) HIP_MALLOC(len, 0);
            //memset(msg, 0, len);
            icmpv6->icmp6_cksum =  htons(0);
            icmpv6->icmp6_cksum = ipv6_checksum(IPPROTO_ICMPV6, &(src6->sin6_addr), &(dst6->sin6_addr), icmpv6, (len - sizeof(struct ip6_hdr)));             //checksum is ok for ipv6
            memcpy((msg + sizeof(struct ip6_hdr)), (uint8_t *) icmpv6, (len - sizeof(struct ip6_hdr)));
        }
    }

    iphdr   = (struct ip *) msg;
    ip6_hdr = (struct ip6_hdr *) msg;

    //set the IP_HDRINCL flag
    if (dst_is_ipv4) {
        if (setsockopt(hip_raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
            HIP_DEBUG("setsockopt IP_HDRINCL ERROR!\n");
        } else {
            HIP_DEBUG("setsockopt IP_HDRINCL for ipv4 OK!\n");
        }
    } else {
        if (setsockopt(hip_raw_sock, IPPROTO_IPV6, IP_HDRINCL, &on, sizeof(on)) < 0) {
            HIP_DEBUG("setsockopt IP_HDRINCL ERROR!\n");
        } else {
            HIP_DEBUG("setsockopt IP_HDRINCL for ipv6 OK!\n");
        }
    }

    if (src6->sin6_family != dst6->sin6_family) {
        /* @todo: Check if this may cause any trouble.
         * It happens every time we send update packet that contains few locators in msg, one is
         * the IPv4 address of the source, another is IPv6 address of the source. But even if one of
         * them is ok to send raw IPvX to IPvX raw packet, another one cause the trouble, and all
         * updates are dropped.  by Andrey "laser".
         *
         */
        err = -1;
        HIP_ERROR("Source and destination address families differ\n");
        goto out_err;
    }

    HIP_DEBUG("Previous checksum: %X\n", (tcp->check));
//tcp->check = htons(0);

    if (src_is_ipv4 && dst_is_ipv4) {
        //struct tcphdr * tcptemp;
        HIP_DEBUG("src_addr and dst_aadr are ipv4!\n");
        iphdr->ip_v   = 4;
        iphdr->ip_hl  = sizeof(struct ip) >> 2;
        iphdr->ip_tos = 0;
        iphdr->ip_len = len - sizeof(struct ip6_hdr) + sizeof(struct ip);
        iphdr->ip_id  = 0;
        iphdr->ip_off = 0;
        iphdr->ip_ttl = MAXTTL;
        iphdr->ip_p   = protocol;
        iphdr->ip_sum = 0;
        iphdr->ip_src = src4->sin_addr;
        iphdr->ip_dst = dst4->sin_addr;
    } else {
        ip6_hdr->ip6_src                        = src6->sin6_addr;
        ip6_hdr->ip6_dst                        = dst6->sin6_addr;
        ip6_hdr->ip6_ctlun.ip6_un2_vfc          = 0x60;
        ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt  = protocol;
        ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen = len - 40;
        ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim = 0xff;
        HIP_DEBUG("src_addr and dst_aadr are ipv6!\n");
    }


    HIP_DEBUG("Current packet length: %d\n", len);

    HIP_DEBUG("HEX DUMP OK!\n");

    HIP_HEXDUMP("hex", iphdr, (len - sizeof(struct ip6_hdr) + sizeof(struct ip)));

    HIP_DEBUG("HEX DUMP OK1!\n");

    /* For some reason, neither sendmsg or send (with bind+connect)
     * do not seem to work properly. Thus, we use just sendto() */
    if (dst_is_ipv4) {
        sent = sendto(hip_raw_sock, iphdr, (len - sizeof(struct ip6_hdr) + sizeof(struct ip)), 0,
                      (struct sockaddr *) &dst, sa_size);
        if (sent != (len - sizeof(struct ip6_hdr) + sizeof(struct ip))) {
            HIP_ERROR("Could not send the all requested"    \
                      " data (%d/%d)\n", sent, (len - sizeof(struct ip6_hdr) + sizeof(struct ip)));
            HIP_DEBUG("ERROR NUMBER: %d\n", errno);
        } else {
            HIP_DEBUG("sent=%d/%d ipv4=%d\n",
                      sent, (len + sizeof(struct ip)), dst_is_ipv4);
            HIP_DEBUG("Packet sent ok\n");
        }
    } else {
        sent = sendto(hip_raw_sock, ip6_hdr, len, 0,
                      (struct sockaddr *) &dst, sa_size);
        if (sent != len) {
            HIP_ERROR("Could not send the all requested"    \
                      " data (%d/%d)\n", sent, len);
        } else {
            HIP_DEBUG("sent=%d/%d ipv4=%d\n",
                      sent, len, dst_is_ipv4);
            HIP_DEBUG("Packet sent ok\n");
        }
    }

    if (dst_is_ipv4) {
        if (setsockopt(hip_raw_sock, IPPROTO_IP, IP_HDRINCL, &off, sizeof(off)) < 0) {
            HIP_DEBUG("setsockopt IP_HDRINCL ERROR!\n");
        }
    } else {
        if (setsockopt(hip_raw_sock, IPPROTO_IPV6, IP_HDRINCL, &off, sizeof(off)) < 0) {
            HIP_DEBUG("setsockopt IP_HDRINCL ERROR!\n");
        }
    }

out_err:

    /* Reset the interface to wildcard or otherwise receiving
     * broadcast messages fails from the raw sockets */
    if (dst_is_ipv4) {
        src4->sin_addr.s_addr = INADDR_ANY;
        src4->sin_family      = AF_INET;
        sa_size               = sizeof(struct sockaddr_in);
    } else {
        struct in6_addr any = IN6ADDR_ANY_INIT;
        src6->sin6_family = AF_INET6;
        ipv6_addr_copy(&src6->sin6_addr, &any);
        sa_size           = sizeof(struct sockaddr_in6);
    }
    bind(hip_raw_sock, (struct sockaddr *) &src, sa_size);

    if (err) {
        HIP_ERROR("strerror: %s\n", strerror(errno));
    }

    return err;
}

/**
 * Handle the proxy inbound traffic
 * @param m the ipq packet captured by the hipfw
 * @param src_addr the source address
 * @return zero on success, non-zero on error
 */
int handle_proxy_inbound_traffic(const ipq_packet_msg_t *m,
                                 const struct in6_addr *src_addr)
{
    in_port_t port_client        = 0, port_peer = 0;
    int protocol, err = 0;
    struct ip6_hdr *ipheader;
    hip_proxy_conn_t *conn_entry = NULL;
    struct in6_addr *proxy_hit   = NULL;
    ipheader = (struct ip6_hdr *) m->payload;
    protocol = ipheader->ip6_ctlun.ip6_un1.ip6_un1_nxt;

    HIP_DEBUG("HIP PROXY INBOUND PROCESS:\n");
    HIP_DEBUG("receiving ESP packets from firewall!\n");

    HIP_IFEL( !(proxy_hit = hip_fw_get_default_hit()), 0, "Error while getting the default HIT!\n");

    if (protocol == IPPROTO_TCP) {
        port_peer   = ((struct tcphdr *) (m->payload + 40))->source;
        port_client = ((struct tcphdr *) (m->payload + 40))->dest;
    } else if (protocol == IPPROTO_UDP) {
        port_peer   = ((struct udphdr *) (m->payload + 40))->source;
        port_client = ((struct udphdr *) (m->payload + 40))->dest;
    } else {
        /* allow packet */
        HIP_DEBUG("Unknown protocol %d, accepting\n", protocol);
        err = -1;
        goto out_err;
    }

    HIP_DEBUG("client_port=%d, peer port=%d, protocol=%d\n", port_client, port_peer, protocol);
    HIP_DEBUG_HIT("proxy_hit:", proxy_hit);
    HIP_DEBUG_IN6ADDR("src_addr:", src_addr);

    //hip_get_local_hit_wrapper(&proxy_hit);
    conn_entry = hip_proxy_conn_find_by_portinfo(proxy_hit, src_addr, protocol, port_client, port_peer);

    if (conn_entry) {
        if (conn_entry->state == HIP_PROXY_TRANSLATE) {
            HIP_DEBUG("We are translating esp packet!\n");
            HIP_DEBUG_IN6ADDR("inbound address 1:", &conn_entry->addr_peer);
            HIP_DEBUG_IN6ADDR("inbound address 2:", &conn_entry->addr_client);
            hip_proxy_send_to_client_pkt(&conn_entry->addr_peer, &conn_entry->addr_client, (uint8_t *) ipheader, m->data_len);
            /* drop packet */
            err = 0;
        }

        if (conn_entry->state == HIP_PROXY_PASSTHROUGH) {
            /* allow packet */
            err = -1;
        }
    } else {
        //allow esp packet
        HIP_DEBUG("Can't find entry in ConnDB!\n");
        err = -1;
    }

out_err:
    return err;
}

/**
 * Send the inbound ICMP packet
 * @param src_addr the ipq packet captured by the hipfw
 * @param dst_addr the source address inside the packet
 * @param buff the payload of the packet
 * @param len the length of the payload
 * @return zero on success, non-zero on error
 */
static int hip_proxy_send_inbound_icmp_pkt(struct in6_addr *src_addr, struct in6_addr *dst_addr, const unsigned char *buff, uint16_t len)
{
    struct sockaddr_in6 src6, dst6;
    struct ip *ip = NULL;
    struct ip6_hdr *ip6 = NULL;
    struct icmphdr *icmp = NULL;
    int sa_size, sent;
    int on = 1;
    unsigned char *msg = NULL;

    ip = (struct ip *) buff;

    if (setsockopt(hip_proxy_raw_sock_icmp_inbound, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        HIP_DEBUG("setsockopt IP_HDRINCL ERROR!\n");
    }

    memcpy(&src6.sin6_addr, src_addr,  sizeof(struct in6_addr));
    src6.sin6_family = AF_INET6;
    HIP_DEBUG_IN6ADDR("src6", &src6.sin6_addr);

    memcpy(&dst6.sin6_addr, dst_addr, sizeof(struct in6_addr));
    dst6.sin6_family = AF_INET6;
    HIP_DEBUG_IN6ADDR("dst6", &dst6.sin6_addr);

    sa_size = sizeof(struct sockaddr_in6);
    msg = HIP_MALLOC((len + sizeof(struct ip6_hdr) - ip->ip_hl), 0);
    memset(msg, 0, (len + sizeof(struct ip6_hdr) - ip->ip_hl));

    ip6 = (struct ip6_hdr *) msg;
    icmp = (struct icmphdr *) (msg + sizeof(struct ip6_hdr));

    ip6->ip6_src = src6.sin6_addr;
    ip6->ip6_dst = dst6.sin6_addr;


    memcpy((msg + sizeof(struct ip6_hdr)), (uint8_t *) icmp, (len - ip->ip_hl));

    icmp->checksum = htons(0);
    icmp->checksum = inchksum(icmp, (len - ip->ip_hl));     //checksum is ok for ipv4
    HIP_HEXDUMP("icmp dump: ", icmp, (len - sizeof(struct ip6_hdr)));

    sent = sendto(hip_proxy_raw_sock_icmp_inbound, ip6,
                  (len + sizeof(struct ip6_hdr) - ip->ip_hl), 0,
                  (struct sockaddr *) &dst6, sa_size);
    if (sent != (len + sizeof(struct ip6_hdr) - ip->ip_hl)) {
        HIP_ERROR("Could not send the all requested"            \
                  " data (%d/%d)\n", sent,
                  (len + sizeof(struct ip6_hdr) - ip->ip_hl));
    } else {
        HIP_DEBUG("sent=%d/%d ipv6=%d\n",
                  sent, (len + sizeof(struct ip6_hdr) -  ip->ip_hl), 0);
        HIP_DEBUG("Packet sent ok\n");
    }

    return 0;
}

/**
 * Handle the proxy outbound traffic
 * @param m the ipq packet captured by the hipfw
 * @param src_addr the source address
 * @param dst_addr the destination address
 * @param hdr_size the header size
 * @param ip_version the IP protocol version
 * @return zero on success, non-zero on error
 */
int handle_proxy_outbound_traffic(const ipq_packet_msg_t *m,
                                  const struct in6_addr *src_addr,
                                  const struct in6_addr *dst_addr,
                                  const int hdr_size,
                                  const int ip_version)
{
    //the destination ip address should be checked first to ensure it supports hip
    //if the destination ip does not support hip, drop the packet
    int err                    = 0;
    int protocol               = 0;
    in_port_t port_client      = 0, port_peer = 0;
    struct hip_proxy_t *entry  = NULL;
    struct in6_addr *proxy_hit = NULL;

    HIP_DEBUG("HIP PROXY OUTBOUND PROCESS:\n");

    HIP_IFEL( !(proxy_hit = hip_fw_get_default_hit()), 0,
              "Error while getting the default HIT!\n");

    if (ip_version == 4) {
        protocol = ((struct ip *) (m->payload))->ip_p;
    }

    if (ip_version == 6) {
        protocol = ((struct ip6_hdr *)
                (m->payload))->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    }

    if (protocol == IPPROTO_TCP) {
        port_client = ((struct tcphdr *) (m->payload + hdr_size))->source;
        port_peer   = ((struct tcphdr *) (m->payload + hdr_size))->dest;
    }

    if (protocol == IPPROTO_UDP) {
        port_client = ((struct udphdr *) (m->payload + hdr_size))->source;
        port_peer   = ((struct udphdr *) (m->payload + hdr_size))->dest;
    }

    HIP_DEBUG("client port %d peer port %d\n", port_client, port_peer);

    entry = hip_proxy_find_by_addr(src_addr, dst_addr);
    //hip_get_local_hit_wrapper(&proxy_hit);

    if (entry == NULL) {
        hip_proxy_add_entry(src_addr, dst_addr);

        entry = hip_proxy_find_by_addr(src_addr, dst_addr);
        HIP_ASSERT(entry)

        ipv6_addr_copy(&entry->hit_proxy, proxy_hit);
        HIP_DEBUG_IN6ADDR("outbound address 1:", src_addr);
        HIP_DEBUG_IN6ADDR("outbound address 2:", dst_addr);

        /* Request a HIT of the peer from hipd. This will possibly
         * launch an I1 with NULL HIT. The call does not block because
         * otherwise single threaded firewall blocks too and does not
         * allow HIP/ESP through. See hip_fw_handle_set_peer_hit() how the
         * the firewall continues from this state when receiving R1 or
         * timeout from hipd.
         */

        HIP_DEBUG("requesting hit from hipd\n");
        HIP_DEBUG_IN6ADDR("ip addr", dst_addr);
        HIP_IFEL(hip_proxy_request_peer_hit_from_hipd(dst_addr,
                                                      proxy_hit),
                 -1, "Request from hipd failed\n");
        entry->state = HIP_PROXY_I1_SENT;
        err          = 0;
    } else {
        //check if the entry state is PASSTHROUGH
        if (entry->state == HIP_PROXY_PASSTHROUGH) {
            HIP_DEBUG("PASSTHROUGH!\n");
            err = -1;
        } else if (entry->state == HIP_PROXY_I1_SENT) {
            HIP_DEBUG("Waiting for I1 or timeout. Drop packet.\n");
            err = 0;
        } else if (entry->state == HIP_PROXY_TRANSLATE) {
            int packet_length = 0;
            uint8_t *msg;

            //TODO: check the connection with same ip but different port, should be added into conndb

            if (hip_proxy_conn_find_by_portinfo(&entry->hit_proxy,
                                                &entry->hit_peer,
                                                protocol,
                                                port_client,
                                                port_peer)) {
                HIP_DEBUG("find same connection  in connDB\n");
            } else {
#if 0
                /* add outbound entry */
                if (hip_proxy_conn_add_entry(&entry->addr_client, &entry->addr_peer, &entry->hit_proxy, &entry->hit_peer, protocol, port_client, port_peer, HIP_PROXY_TRANSLATE)) {
                    HIP_DEBUG("ConnDB add entry Failed!\n");
                } else {
                    HIP_DEBUG("ConnDB add entry Successful!\n");
                }
#endif
                /* add inbound entry */
                HIP_DEBUG_HIT("proxy_hit:",  &entry->hit_proxy);
                HIP_DEBUG_IN6ADDR("src_addr:",  &entry->addr_peer);

                if (hip_proxy_conn_add_entry(&entry->addr_client, &entry->addr_peer, &entry->hit_proxy, &entry->hit_peer, protocol, port_client, port_peer, HIP_PROXY_TRANSLATE)) {
                    HIP_DEBUG("ConnDB add entry Failed!\n");
                } else {
                    HIP_DEBUG("ConnDB add entry Successful!\n");
                }
            }

            if ((protocol == IPPROTO_ICMP) || (protocol == IPPROTO_ICMPV6)) {
                hip_proxy_send_inbound_icmp_pkt(proxy_hit, &entry->hit_peer, m->payload, m->data_len);
                /* drop packet */
                err = 0;
            } else {
                packet_length = m->data_len - hdr_size;
                msg           = (uint8_t *) HIP_MALLOC(packet_length, 0);
                memcpy(msg, (m->payload) + hdr_size,
                       packet_length);

                HIP_DEBUG("Packet Length: %d\n", packet_length);
                HIP_HEXDUMP("ipv6 msg dump: ", msg, packet_length);
                hip_proxy_send_pkt(proxy_hit, &entry->hit_peer, msg, packet_length, protocol);
                /* drop packet */
                err = 0;
            }
        }
    }

out_err:
    return err;
}
