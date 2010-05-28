/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
 * Heartbeat code detects problems with the ESP tunnel. It is based on
 * sending ICMPv6 requests inside the tunnel. Each received ICMPv6
 * message indicates that the tunnel is in good "health". Correspondingly,
 * when there are no ICMPv6 messages received it may be a good time
 * to trigger an UPDATE packet to recover from the disconnectivity.
 *
 * The heartbeat code keeps also track of the time stamps for the
 * ICMPv6 messages. It could be used to implement handovers to switch
 * to faster paths or even as an utility for load balancing. At the
 * moment, the heartbeat algorithm is rather simple and used just for
 * fault tolerance.  It should also noticed that the heartbeat code is
 * required only at one side of the communications as long as the
 * other party supports replying to ICMPv6 echo requests.
 *
 * @see "Varjonen et al, Secure and Efficient IPv4/IPv6 Handovers Using
 * Host-Based Identifier-Locator Split, Journal of Communications
 * Software and Systems, 2010".
 *
 * @note Implementation of the heartbeat concept in tiny branch:
 *
 *       - Send periodic ICMP messages to all associated peers (HEARTBEATs).
 *       - Increment the heartbeat counter in hadb.
 *       - When a HEARTBEAT response is received, calculate roundtrip time and
 *         maintain statistics. Reset heartbeat counter to 0.
 *
 * @author Samu Varjonen
 * @author Miika Komu
 * @author Rene Hummen
 * @author Tim Just
 */

#define _BSD_SOURCE

#include <netinet/icmp6.h>

#include "heartbeat.h"
#include "hipd/hadb.h"
#include "hipd/init.h"
#include "hipd/hip_socket.h"
#include "hipd/pkt_handling.h"
#include "lib/core/statistics.h"

#define HIP_HEARTBEAT_INTERVAL 20

int hip_icmp_sock;
static int heartbeat_counter = HIP_HEARTBEAT_INTERVAL;

/**
 * This function sends ICMPv6 echo with timestamp to dsthit
 *
 * @param socket to send with
 * @param srchit HIT to send from
 * @param dsthit HIT to send to
 *
 * @return 0 on success negative on error
 */
static int hip_send_icmp(int sockfd, hip_ha_t *entry)
{
    int err                = 0, i = 0, identifier = 0;
    struct icmp6_hdr *icmph = NULL;
    struct sockaddr_in6 dst6;
    u_char cmsgbuf[CMSG_SPACE(sizeof(struct inet6_pktinfo))];
    u_char *icmp_pkt       = NULL;
    struct msghdr mhdr;
    struct iovec iov[1];
    struct cmsghdr *chdr = NULL;
    struct inet6_pktinfo *pkti = NULL;
    struct timeval tval;

    HIP_IFEL(!entry, 0, "No entry\n");

    HIP_IFEL((entry->outbound_sa_count == 0), 0,
             "No outbound sa, ignoring keepalive\n")

    /* memset and malloc everything you need */
    memset(&mhdr, 0, sizeof(struct msghdr));
    memset(&tval, 0, sizeof(struct timeval));
    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    memset(iov, 0, sizeof(struct iovec));
    memset(&dst6, 0, sizeof(dst6));

    icmp_pkt         = malloc(HIP_MAX_ICMP_PACKET);
    HIP_IFEL((!icmp_pkt), -1, "Malloc for icmp_pkt failed\n");
    memset(icmp_pkt, 0, sizeof(HIP_MAX_ICMP_PACKET));

    chdr             = (struct cmsghdr *) (void *) cmsgbuf;
    pkti             = (struct inet6_pktinfo *) (void *) (CMSG_DATA(chdr));

    identifier       = getpid() & 0xFFFF;

    /* Build ancillary data */
    chdr->cmsg_len   = CMSG_LEN(sizeof(struct inet6_pktinfo));
    chdr->cmsg_level = IPPROTO_IPV6;
    chdr->cmsg_type  = IPV6_PKTINFO;
    memcpy(&pkti->ipi6_addr, &entry->hit_our, sizeof(struct in6_addr));

    /* get the destination */
    memcpy(&dst6.sin6_addr, &entry->hit_peer, sizeof(struct in6_addr));
    dst6.sin6_family        = AF_INET6;
    dst6.sin6_flowinfo      = 0;

    /* build icmp header */
    icmph                   = (struct icmp6_hdr *) (void *) icmp_pkt;
    icmph->icmp6_type       = ICMP6_ECHO_REQUEST;
    icmph->icmp6_code       = 0;
    entry->heartbeats_sent++;

    icmph->icmp6_seq        = htons(entry->heartbeats_sent);
    icmph->icmp6_id         = identifier;

    gettimeofday(&tval, NULL);

    memset(&icmp_pkt[8], 0xa5, HIP_MAX_ICMP_PACKET - 8);
    /* put timeval into the packet */
    memcpy(&icmp_pkt[8], &tval, sizeof(struct timeval));

    /* put the icmp packet to the io vector struct for the msghdr */
    iov[0].iov_base     = icmp_pkt;
    iov[0].iov_len      = sizeof(struct icmp6_hdr) + sizeof(struct timeval);

    /* build the msghdr for the sendmsg, put ancillary data also*/
    mhdr.msg_name       = &dst6;
    mhdr.msg_namelen    = sizeof(struct sockaddr_in6);
    mhdr.msg_iov        = iov;
    mhdr.msg_iovlen     = 1;
    mhdr.msg_control    = &cmsgbuf;
    mhdr.msg_controllen = sizeof(cmsgbuf);

    i                   = sendmsg(sockfd, &mhdr, 0);
    if (i <= 0) {
        HIP_PERROR("SENDMSG ");
        /* Set return error, even if 0 bytes sent. */
        err = (0 > i) ? i : -1;
    }

    HIP_IFEL((i < 0), -1, "Failed to send ICMP into ESP tunnel\n");
    HIP_DEBUG_HIT("Sent heartbeat to", &entry->hit_peer);

out_err:
    if (icmp_pkt) {
        free(icmp_pkt);
    }
    return err;
}

/**
 * This function calculates RTT and then stores them to correct entry
 *
 * @param src HIT
 * @param dst HIT
 * @param time when sent
 * @param time when received
 *
 * @return zero on success or negative on failure
 */
static int hip_icmp_statistics(struct in6_addr *src,
                               struct in6_addr *dst,
                               struct timeval *stval,
                               struct timeval *rtval)
{
    int err                  = 0;
    uint32_t rcvd_heartbeats = 0;
    uint64_t rtt             = 0;
    double avg               = 0.0, std_dev = 0.0;
    char hit[INET6_ADDRSTRLEN];
    hip_ha_t *entry          = NULL;
    uint8_t *heartbeat_counter = NULL;

    hip_in6_ntop(src, hit);

    /* Find the correct entry */
    entry = hip_hadb_find_byhits(src, dst);
    HIP_IFEL((!entry), -1, "Entry not found\n");

    /* Calculate the RTT from given timevals */
    rtt   = calc_timeval_diff(stval, rtval);

    /* add the heartbeat item to the statistics */
    add_statistics_item(&entry->heartbeats_statistics, rtt);

    /* calculate the statistics for immediate output */
    calc_statistics(&entry->heartbeats_statistics, &rcvd_heartbeats, NULL, NULL, &avg,
                    &std_dev, STATS_IN_MSECS);

    heartbeat_counter = lmod_get_state_item(entry->hip_modular_state,
                                            "heartbeat_update");

    *heartbeat_counter = 0;
    HIP_DEBUG("heartbeat_counter: %d\n", *heartbeat_counter);

    HIP_DEBUG("\nHeartbeat from %s, RTT %.6f ms,\n%.6f ms mean, "
              "%.6f ms std dev, packets sent %d recv %d lost %d\n",
              hit, ((float) rtt / STATS_IN_MSECS), avg, std_dev, entry->heartbeats_sent,
              rcvd_heartbeats, (entry->heartbeats_sent - rcvd_heartbeats));

out_err:
    return err;
}

/**
 * This function receives ICMPv6 msgs (heartbeats)
 *
 * @param sockfd to recv from
 *
 * @return 0 on success otherwise negative
 *
 * @note see RFC2292
 */
static int hip_icmp_recvmsg(int sockfd)
{
    int err = 0, ret = 0, identifier = 0;
    struct msghdr mhdr;
    struct cmsghdr *chdr;
    struct iovec iov[1];
    unsigned char cmsgbuf[CMSG_SPACE(sizeof(struct inet6_pktinfo))];
    unsigned char iovbuf[HIP_MAX_ICMP_PACKET];
    struct icmp6_hdr *icmph = NULL;
    struct inet6_pktinfo *pktinfo;
    struct sockaddr_in6 src_sin6;
    struct in6_addr *src   = NULL, *dst = NULL;
    struct timeval *stval  = NULL, *rtval = NULL, *ptr = NULL;

    /* malloc what you need */
    stval   = malloc(sizeof(struct timeval));
    HIP_IFEL((!stval), -1, "Malloc for stval failed\n");
    rtval   = malloc(sizeof(struct timeval));
    HIP_IFEL((!rtval), -1, "Malloc for rtval failed\n");
    src     = malloc(sizeof(struct in6_addr));
    HIP_IFEL((!src), -1, "Malloc for dst6 failed\n");
    dst     = malloc(sizeof(struct in6_addr));
    HIP_IFEL((!dst), -1, "Malloc for dst failed\n");

    /* cast */
    chdr    = (struct cmsghdr *) (void *) cmsgbuf;
    pktinfo = (struct inet6_pktinfo *) (void *) (CMSG_DATA(chdr));

    /* clear memory */
    memset(stval, 0, sizeof(struct timeval));
    memset(rtval, 0, sizeof(struct timeval));
    memset(src, 0, sizeof(struct in6_addr));
    memset(dst, 0, sizeof(struct in6_addr));
    memset(&src_sin6, 0, sizeof(struct sockaddr_in6));
    memset(&iov, 0, sizeof(&iov));
    memset(&iovbuf, 0, sizeof(iovbuf));
    memset(&mhdr, 0, sizeof(mhdr));

    /* receive control msg */
    chdr->cmsg_level    = IPPROTO_IPV6;
    chdr->cmsg_type     = IPV6_2292PKTINFO;
    chdr->cmsg_len      = CMSG_LEN(sizeof(struct inet6_pktinfo));

    /* Input output buffer */
    iov[0].iov_base     = &iovbuf;
    iov[0].iov_len      = sizeof(iovbuf);

    /* receive msg hdr */
    mhdr.msg_iov        = &(iov[0]);
    mhdr.msg_iovlen     = 1;
    mhdr.msg_name       = (caddr_t) &src_sin6;
    mhdr.msg_namelen    = sizeof(struct sockaddr_in6);
    mhdr.msg_control    = (caddr_t) cmsgbuf;
    mhdr.msg_controllen = sizeof(cmsgbuf);

    ret                 = recvmsg(sockfd, &mhdr, MSG_DONTWAIT);
    if (errno == EAGAIN) {
        err = 0;
        goto out_err;
    }
    if (ret < 0) {
        HIP_DEBUG("Recvmsg on ICMPv6 failed\n");
        err = -1;
        goto out_err;
    }

    /* Get the current time as the return time */
    gettimeofday(rtval, (struct timezone *) NULL);

    /* Check if the process identifier is ours and that this really is echo response */
    icmph = (struct icmp6_hdr *) (void *) iovbuf;
    if (icmph->icmp6_type != ICMP6_ECHO_REPLY) {
        err = 0;
        goto out_err;
    }
    identifier = getpid() & 0xFFFF;
    if (identifier != icmph->icmp6_id) {
        err = 0;
        goto out_err;
    }

    /* Get the timestamp as the sent time*/
    ptr = (struct timeval *) (icmph + 1);
    memcpy(stval, ptr, sizeof(struct timeval));

    /* gather addresses */
    memcpy(src, &src_sin6.sin6_addr, sizeof(struct in6_addr));
    memcpy(dst, &pktinfo->ipi6_addr, sizeof(struct in6_addr));

    if (!ipv6_addr_is_hit(src) && !ipv6_addr_is_hit(dst)) {
        HIP_DEBUG("Addresses are NOT HITs, this msg is not for us\n");
    }

    /* Calculate and store everything into the correct entry */
    HIP_IFEL(hip_icmp_statistics(src, dst, stval, rtval), -1,
             "Failed to calculate the statistics and store the values\n");

out_err:

    if (stval) {
        free(stval);
    }
    if (rtval) {
        free(rtval);
    }
    if (src) {
        free(src);
    }
    if (dst) {
        free(dst);
    }

    return err;
}

static int hip_heartbeat_handle_icmp_sock(struct hip_packet_context *ctx)
{
    int err = 0;

    HIP_IFEL(hip_icmp_recvmsg(hip_icmp_sock), -1,
             "Failed to recvmsg from ICMPv6\n");

out_err:
    return err;
}

/**
 * This function goes through the HA database and sends an icmp echo to all of them
 *
 * @param socket to send with
 *
 * @return 0 on success negative on error
 */
static int hip_send_heartbeat(hip_ha_t *hadb_entry, void *opaq)
{
    int err                    = 0;
    int *sockfd                = (int *) opaq;
    uint8_t *heartbeat_counter = NULL;

    if ((hadb_entry->state == HIP_STATE_ESTABLISHED) &&
        (hadb_entry->outbound_sa_count > 0)) {

        HIP_IFEL(hip_send_icmp(*sockfd, hadb_entry), 0,
                     "Error sending heartbeat, ignore\n");
        heartbeat_counter = lmod_get_state_item(hadb_entry->hip_modular_state,
                                                "heartbeat_update");

        *heartbeat_counter = *heartbeat_counter + 1;
        HIP_DEBUG("heartbeat_counter: %d\n", *heartbeat_counter);
    }

out_err:
    return err;
}

static int hip_heartbeat_maintenance(void)
{
    /* Check if the heartbeats should be sent */
    if (heartbeat_counter < 1) {
        hip_for_each_ha(hip_send_heartbeat, &hip_icmp_sock);
        heartbeat_counter = HIP_HEARTBEAT_INTERVAL;
    } else {
        heartbeat_counter--;
    }

    return 0;
}

static int hip_heartbeat_handle_usr_msg(hip_common_t *msg,
                                        struct sockaddr_in6 *src)
{
    int err = 0;

#if 0
    heartbeat         = hip_get_param(msg, HIP_PARAM_HEARTBEAT);
    hip_icmp_interval = heartbeat->heartbeat;
    heartbeat_counter = hip_icmp_interval;
    HIP_DEBUG("Received heartbeat interval (%d seconds)\n", hip_icmp_interval);
#endif

    return err;
}

static int hip_heartbeat_init_state(struct modular_state *state)
{
    int err = 0;
    uint8_t *heartbeat_counter = NULL;

    HIP_IFEL(!(heartbeat_counter = malloc(sizeof(uint8_t))),
                -1,
                "Error on allocating memory for heartbeat_counter.\n");

    err = lmod_add_state_item(state, heartbeat_counter, "heartbeat_update");

out_err:
    return err;
}

/**
 * Initialize icmpv6 socket.
 */
int hip_heartbeat_init(void)
{
    int err = 0, on = 1;
    struct icmp6_filter filter;
    int *icmpsockfd = &hip_icmp_sock;

    *icmpsockfd       = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    set_cloexec_flag(*icmpsockfd, 1);
    HIP_IFEL(*icmpsockfd <= 0, 1, "ICMPv6 socket creation failed\n");

    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
    err = setsockopt(*icmpsockfd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
                     sizeof(struct icmp6_filter));
    HIP_IFEL(err, -1, "setsockopt icmp ICMP6_FILTER failed\n");


    err = setsockopt(*icmpsockfd, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt icmp IPV6_RECVPKTINFO failed\n");

    HIP_IFEL(hip_register_socket(hip_icmp_sock,
                                 &hip_heartbeat_handle_icmp_sock,
                                 30000),
             -1,
             "Error on registration of hip_icmp_sock for HEARTBEAT module.\n");

    if (hip_unregister_maint_function(&hip_nat_refresh_port)) {
        HIP_DEBUG("Unregister 'hip_nat_refresh_port() failed.\n");
    }

    HIP_IFEL(hip_register_maint_function(&hip_heartbeat_maintenance, 10000),
             -1,
             "Error on registration of hip_heartbeat_maintenance().\n");

    HIP_IFEL(lmod_register_state_init_function(&hip_heartbeat_init_state),
             -1,
             "Error on registration of hip_heartbeat_init_state().\n");

    HIP_IFEL(hip_user_register_handle(HIP_MSG_HEARTBEAT,
                                      &hip_heartbeat_handle_usr_msg,
                                      20000),
             -1,
             "Error on registering HEARTBEAT user message handle function.\n");

out_err:
    return err;
}