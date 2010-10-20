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
 * This file contains functions to read and writing of HIP-related
 * messages. HIP message format is overloaded (see builder.c) so that
 * interprocess and network communications share roughly the same message
 * format. Thus, the functions in this file support also sending and receiving
 * of interprocess and network related messages. The interprocess communications
 * occurs between hipd, hipfw, hipconf and the resolver. Network communications
 * occurs between different HIP daemon processes located on different hosts.
 *
 * The messaging interface supports both "synchronous" and
 * "asynchronous" messaging. Synchronous "request" message blocks
 * until a "response" message is received. Asynchronous message means
 * that the message is just sent and the no response is expected,
 * hence the message does not block.
 *
 * Use the synchronous message interface only when you expect the
 * request message to be completed immediately. For example, "hipconf
 * get ha all" was safe to be implemented with synchronous messaging
 * because hipd can process the request immediately.
 *
 * Use the asynchronous message interface when you don't want any
 * response or you just want to avoid blocking.  Reading of the hipd
 * configuration file is a good example of (a). It was implemented
 * using the hipconf interface itself to maximize code reuse. When
 * hipd reads its configuration file, it is actually calling hipconf
 * messaging API which sends messages to hipd. So, effectively hipd is
 * sending messages to itself through the loopback interface.  This
 * had to be implemented through the asynchronous messaging interface
 * or otherwise the single-threaded hipd was blocking itself in
 * reading the configuration file and waiting for a response message
 * for the first hipconf message. The hipd did not reach the select
 * loop that processes incoming hipconf messaging because it was still
 * initializing itself. So, the use of asynchronous messages avoided
 * the chicken-egg-problem here.
 *
 * It should be also noticed the there is an optional timeout period
 * to wait for responses of synchronous messages. When the timeout is
 * exceeded, the called function will return an error and unblocks the
 * caller. Use this wisely; timeouts optimized for LAN can be short but
 * they are not applicable with the long delays introduced by WAN.
 *
 * @brief HIP messaging interface that allows the resolver, hipd, hipfw and hipconf
 *        to communicate with each other. Includes also functions to read messages
 *        from the network.
 *
 * @author  Miika Komu <miika_iki.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @see     The building and parsing functions are located in @c builder.c.
 */

#define _BSD_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "lib/tool/nlink.h"
#include "builder.h"
#include "common.h"
#include "debug.h"
#include "hip_udp.h"
#include "icomm.h"
#include "ife.h"
#include "prefix.h"
#include "protodefs.h"
#include "message.h"


/**
 * Finds out how much data is coming from a socket
 *
 * @param  sockfd         the socked file descriptor.
 * @param  encap_hdr_size udp etc header size
 * @param  timeout        -1 for blocking sockets, 0 or positive nonblocking
 * @return Number of bytes received on success or a negative error value on
 *         error.
 * @todo This function had some portability issues on symbian. It should be ok
 *       to read HIP_MAX_PACKET because the socket call returns the number of
 *       actual bytes read. If you decide to reimplement this functionality,
 *       remember to preserve the timeout property.
 */
static int hip_peek_recv_total_len(int sockfd,
                                   int encap_hdr_size,
                                   long timeout)
{
    int bytes                  = 0, err = 0, flags = MSG_PEEK;
    unsigned long timeout_left = timeout;
    int hdr_size               = encap_hdr_size + sizeof(struct hip_common);
    char *msg                  = NULL;
    hip_common_t *hip_hdr      = NULL;
    struct timespec ts;

    ts.tv_sec  = 0;
    ts.tv_nsec =  100000000;

    /* We're using system call here add thus reseting errno. */
    errno      = 0;

    msg        = malloc(hdr_size);
    HIP_IFEL(!msg, -ENOMEM, "Error allocating memory.\n");

    /* If a positive timeout value is given, make sure that the
     * retrieving the message from the hipd does not block */
    if (timeout >= 0) {
        flags |= MSG_DONTWAIT;
    }

    do {
        errno         = 0;
        nanosleep(&ts, NULL);
        bytes         = recv(sockfd, msg, hdr_size, flags);
        timeout_left -= ts.tv_nsec;
    } while (timeout_left > 0 && errno == EAGAIN && bytes < 0);

    if (bytes < 0) {
        HIP_ERROR("recv() peek error (is hipd running?)\n");
        err = -EAGAIN;
        goto out_err;
    } else if (bytes < hdr_size) {
        HIP_ERROR("Packet payload is smaller than HIP header. Dropping.\n");
        /* Read and discard the datagram */
        recv(sockfd, msg, 0, 0);
        err = -bytes;
        goto out_err;
    }

    hip_hdr = (struct hip_common *) (msg + encap_hdr_size);
    bytes   = hip_get_msg_total_len(hip_hdr);

    if (bytes == 0) {
        HIP_ERROR("HIP message is of zero length. Dropping.\n");
        recv(sockfd, msg, 0, 0);
        err   = -EBADMSG;
        errno = EBADMSG;
        goto out_err;
    }

    bytes += encap_hdr_size;

out_err:
    if (msg != NULL) {
        free(msg);
    }

    if (err) {
        return err;
    }

    return bytes;
}

/**
 * Connect a socket to the loop back address of hipd
 *
 * @param hip_user_sock The socket to connect. Currently the only SOCK_DGRAM
 *                      and AF_INET6 are supported.
 * @return zero on success and negative on failure
 * @note currently the only SOCK_DGRAM and AF_INET6 are supported
 */
int hip_daemon_connect(int hip_user_sock)
{
    int err = 0;
    struct sockaddr_in6 daemon_addr;
    // We're using system call here add thus reseting errno.
    errno                   = 0;

    memset(&daemon_addr, 0, sizeof(daemon_addr));
    daemon_addr.sin6_family = AF_INET6;
    daemon_addr.sin6_port   = htons(HIP_DAEMON_LOCAL_PORT);
    daemon_addr.sin6_addr   = in6addr_loopback;

    HIP_IFEL(connect(hip_user_sock, (struct sockaddr *) &daemon_addr,
             sizeof(daemon_addr)), -1, "connection to daemon failed\n");

out_err:

    return err;
}

/**
 * Bind a socket to a specific socket address structure to communicate
 * with hipd. This function has also a access control feature when the
 * port number in the socket is zero. This function first tries to
 * obtain a port number below 1024. In UNIX/Linux this means that the
 * process has superuser privileges. Hipd uses the port number to
 * verify if the caller has sufficient privileges to execute
 * e.g. "hipconf rst all". The function falls back to non-privileged
 * ports if it fails to obtain a privileged port and then hipd allows
 * only certain operations for the calling process.
 *
 * @param sockfd the socket to bind to
 * @param sa     An IPv6-based socket address structure. The sin6_port
 *               field may be filled in in the case of e.g. sockets
 *               remaining open for long time periods. Alternetively,
 *               the sin6_port can be zero to allow the function to
 *               determine a suitable port number (see the description
 *               of the function).
 * @return zero on success and negative on failure
 */
static int hip_daemon_bind_socket(int sockfd, struct sockaddr *sa)
{
    int err                   = 0, port = 0, on = 1;
    struct sockaddr_in6 *addr = (struct sockaddr_in6 *) sa;

    HIP_ASSERT(addr->sin6_family == AF_INET6);

    errno = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
        HIP_DEBUG("Failed to set socket option SO_REUSEADDR %s \n",
                  strerror(errno));
    }

    if (addr->sin6_port) {
        HIP_DEBUG("Bind to fixed port %d\n", addr->sin6_port);
        err = bind(sockfd, (struct sockaddr *) addr,
                   sizeof(struct sockaddr_in6));
        err = -errno;
        goto out_err;
    }

    /* try to bind first to a priviledged port and then to ephemeral */
    port = 1000;
    while (port++ < 61000) {
        addr->sin6_port = htons(port);
        err             = bind(sockfd, (struct sockaddr *) addr,
                               hip_sockaddr_len(addr));
        if (err == -1) {
            if (errno == EACCES) {
                /* Ephemeral ports:
                 * /proc/sys/net/ipv4/ip_local_port_range */
                port  = 32768;
                errno = 0;
                err   = 0;
            } else if (errno == EADDRINUSE) {
                errno = 0;
                err   = 0;
            } else {
                HIP_ERROR("Error %d bind() wasn't succesful\n",
                          errno);
                err = -1;
                goto out_err;
            }
        } else {
            goto out_err;
        }
    }

    if (port == 61000) {
        HIP_ERROR("All privileged ports were occupied\n");
        err = -1;
    }

out_err:
    return err;
}

/**
 * Send one-way data to hipd. Do not call this function directly, use
 * hip_send_recv_daemon_info instead!
 *
 * @param sockfd    the socket to use for sending
 * @param msg       the message to send to hipd
 * @param len       the length of the message in bytes
 * @return          zero on success and negative on failure
 * @note currently the only SOCK_DGRAM and AF_INET6 are supported
 */
static int hip_sendto_hipd(int sockfd, struct hip_common *msg, int len)
{
    /* Variables. */
    struct sockaddr_in6 sock_addr;
    int n = -1, alen;

    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin6_family = AF_INET6;
    sock_addr.sin6_port   = htons(HIP_DAEMON_LOCAL_PORT);
    sock_addr.sin6_addr   = in6addr_loopback;

    alen                  = sizeof(sock_addr);

    HIP_DEBUG("Sending user message %d to HIPD on socket %d\n",
              hip_get_msg_type(msg), sockfd);

    n = sendto(sockfd, msg, len, MSG_NOSIGNAL,
               (struct sockaddr *) &sock_addr, alen);
    HIP_DEBUG("Sent %d bytes\n", n);

    return n;
}

/**
 * Send and receive data with hipd. Do not call this function directly, use
 * hip_send_recv_daemon_info instead!
 *
 * @param msg the message to send to hipd
 * @param opt_socket Optional socket to use for the message exchange. When
 *                   set to zero, the function creates a temporary socket
 *                   and closes it after the transaction is completed.
 * @return zero on success and negative on failure
 * @note currently the only SOCK_DGRAM and AF_INET6 are supported
 */
static int hip_send_recv_daemon_info_internal(struct hip_common *msg, int opt_socket)
{
    int hip_user_sock = 0, err = 0, n = 0, len = 0;
    struct sockaddr_in6 addr;
    uint8_t msg_type_old, msg_type_new;

    msg_type_old = hip_get_msg_type(msg);

    // We're using system call here and thus reseting errno.
    errno        = 0;

    if (opt_socket) {
        hip_user_sock = opt_socket;
    } else {
        HIP_IFE(((hip_user_sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0), EHIP);

        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_addr   = in6addr_loopback;

        HIP_IFEL(hip_daemon_bind_socket(hip_user_sock,
                                        (struct sockaddr *) &addr), -1,
                 "bind failed\n");
        /* Connect to hipd. Otherwise e.g. "hipconf get ha all"
         * blocks when hipd is not running. */
        HIP_IFEL(hip_daemon_connect(hip_user_sock), -1,
                 "connect failed\n");
    }

    if ((len = hip_get_msg_total_len(msg)) < 0) {
        err = -EBADMSG;
        goto out_err;
    }

    /* Require a response from hipd */
    hip_set_msg_response(msg, 1);

    n = hip_sendto_hipd(hip_user_sock, msg, len);
    if (n < len) {
        HIP_ERROR("Could not send message to daemon.\n");
        err = -ECOMM;
        goto out_err;
    }

    HIP_DEBUG("Waiting to receive daemon info.\n");

    if ((len = hip_peek_recv_total_len(hip_user_sock, 0, HIP_DEFAULT_MSG_TIMEOUT)) < 0) {
        err = len;
        goto out_err;
    }

    n = recv(hip_user_sock, msg, len, 0);

    /* You have a message synchronization problem if you see this error. */
    msg_type_new = hip_get_msg_type(msg);
    HIP_IFEL((msg_type_new != msg_type_old), -1,
             "Message sync problem. Expected %d, got %d\n",
             msg_type_old, msg_type_new);

    HIP_DEBUG("%d bytes received from HIP daemon\n", n);

    if (n == 0) {
        HIP_INFO("The HIP daemon has performed an " \
                 "orderly shutdown.\n");
        // Note. This is not an error condition, thus we return zero.
        goto out_err;
    } else if (n < (int)sizeof(struct hip_common)) {
        HIP_ERROR("Could not receive message from daemon.\n");
        goto out_err;
    }

    if (hip_get_msg_err(msg)) {
        HIP_ERROR("HIP message contained an error.\n");
        err = -EHIP;
    }

out_err:

    if (!opt_socket && hip_user_sock) {
        close(hip_user_sock);
    }

    return err;
}

/**
 * A generic function to send messages to hipd. Optionally, a response
 * message can be required from hipd. This will block the process
 * until the hipd sends the response or a predefined timeout is
 * exceeded.
 *
 * @param msg An input/output parameter. As input, contains the
 *            message to be sent to hipd. As output, hipd response
 *            will be written here when @c send_only is zero.
 * @param send_only Zero when the caller requires a response
 *                  from hipd. One when the caller does not
 *                  want to wait for any response.
 * @param opt_socket Optional precreated socket to use for
 *                   communications with hipd. A value of zero
 *                   means that a temporary socket will be created
 *                   during the transaction.
 * @return zero on success and negative on failure.
 * @note currently the only SOCK_DGRAM and AF_INET6 are supported
 */
int hip_send_recv_daemon_info(struct hip_common *msg,
                              int send_only,
                              int opt_socket)
{
    int hip_user_sock = 0, err = 0, n, len;
    struct sockaddr_in6 addr;

    if (!send_only) {
        return hip_send_recv_daemon_info_internal(msg, opt_socket);
    }

    if (opt_socket) {
        hip_user_sock = opt_socket;
    } else {
        HIP_IFE(((hip_user_sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0), -1);
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_addr   = in6addr_loopback;

        HIP_IFEL(hip_daemon_bind_socket(hip_user_sock,
                                        (struct sockaddr *) &addr), -1,
                 "bind failed\n");
        HIP_IFEL(hip_daemon_connect(hip_user_sock), -1,
                 "connect failed\n");
    }

    len = hip_get_msg_total_len(msg);
    n   = send(hip_user_sock, msg, len, 0);

    if (n < len) {
        HIP_ERROR("Could not send message to daemon.\n");
        err = -1;
        goto out_err;
    }

out_err:
    if (!opt_socket && hip_user_sock) {
        close(hip_user_sock);
    }

    return err;
}

/**
 * Read an interprocess (user) message
 *
 * @param  sockfd   a socket from where to read
 * @param  hip_msg  the message will be written here
 * @param  saddr    the sender information is stored here
 * @return          zero on success and negative on error
 * @note currently the only SOCK_DGRAM and AF_INET6 are supported
 */
int hip_read_user_control_msg(int sockfd, struct hip_common *hip_msg,
                              struct sockaddr_in6 *saddr)
{
    int err = 0, bytes = 0, total;
    socklen_t len;

    HIP_DEBUG("Receiving user message.\n");

    hip_msg_init(hip_msg);
    memset(saddr, 0, sizeof(*saddr));

    len = sizeof(*saddr);

    HIP_IFEL(((total = hip_peek_recv_total_len(sockfd, 0, HIP_DEFAULT_MSG_TIMEOUT)) <= 0),
             -1,
             "recv peek failed\n");

    /** @todo Compiler warning;
     *  warning: pointer targets in passing argument 6 of 'recvfrom'
     *  differ in signedness. */
    HIP_IFEL(((bytes = recvfrom(sockfd, hip_msg, total, 0,
                                (struct sockaddr *) saddr,
                                &len)) != total),
               -1, "recv\n");

    HIP_DEBUG("received user message from local port %d\n",
              ntohs(saddr->sin6_port));
out_err:
    if (bytes < 0 || err) {
        HIP_PERROR("perror: ");
    }

    return err;
}

/**
 * Prepare a @c hip_common struct, allocate memory for buffers and nested
 * structs. Receive a message from socket and fill the @c hip_common struct
 * with the values from this message. Do not call this function directly,
 * use hip_read_control_msg_v4() and hip_read_control_msg_v6() wrappers
 * instead!
 *
 * @param sockfd         a socket to read from.
 * @param ctx            a pointer to the packet context
 * @param encap_hdr_size size of encapsulated header in bytes.
 * @param is_ipv4        a boolean value to indicate whether message is received
 *                       on IPv4.
 * @return               -1 in case of an error, 0 otherwise.
 */
static int hip_read_control_msg_all(int sockfd,
                                    struct hip_packet_context *ctx,
                                    int encap_hdr_size,
                                    int is_ipv4)
{
    struct sockaddr_storage addr_from, addr_to;
    struct sockaddr_in *addr_from4  = ((struct sockaddr_in *) &addr_from);
    struct sockaddr_in6 *addr_from6 = ((struct sockaddr_in6 *) &addr_from);
    struct cmsghdr *cmsg = NULL;
    struct msghdr msg;
    union {
        struct in_pktinfo *   pktinfo_in4;
        struct inet6_pktinfo *pktinfo_in6;
    } pktinfo;
    struct iovec iov;
    char cbuff[CMSG_SPACE(256)];
    int err = 0, len;
    int cmsg_level, cmsg_type;

    hip_msg_init(ctx->input_msg);

    HIP_DEBUG("hip_read_control_msg_all() invoked.\n");

//    memset(msg_info, 0, sizeof(hip_portpair_t));
    memset(&msg, 0, sizeof(msg));
    memset(cbuff, 0, sizeof(cbuff));
    memset(&addr_to, 0, sizeof(addr_to));

    /* setup message header with control and receive buffers */
    msg.msg_name        = &addr_from;
    msg.msg_namelen     = sizeof(struct sockaddr_storage);
    msg.msg_iov         = &iov;
    msg.msg_iovlen      = 1;

    memset(cbuff, 0, sizeof(cbuff));
    msg.msg_control     = cbuff;
    msg.msg_controllen  = sizeof(cbuff);
    msg.msg_flags       = 0;

    iov.iov_len         = HIP_MAX_NETWORK_PACKET;
    iov.iov_base        = ctx->input_msg;

    pktinfo.pktinfo_in4 = NULL;

    len                 = recvmsg(sockfd, &msg, 0);

    HIP_IFEL((len < 0), -1, "ICMP%s error: errno=%d, %s\n",
             (is_ipv4 ? "v4" : "v6"), errno, strerror(errno));

    cmsg_level = (is_ipv4) ? IPPROTO_IP : IPPROTO_IPV6;
    cmsg_type  = (is_ipv4) ? IP_PKTINFO : IPV6_2292PKTINFO;

    /* destination address comes from ancillary data passed
     * with msg due to IPV6_PKTINFO socket option */
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if ((cmsg->cmsg_level == cmsg_level) &&
            (cmsg->cmsg_type == cmsg_type)) {
            /* The structure is a union, so this fills also the
             * pktinfo_in6 pointer */
            pktinfo.pktinfo_in4 =
                (struct in_pktinfo *) CMSG_DATA(cmsg);
            break;
        }
    }

    /* If this fails, change IPV6_2292PKTINFO to IPV6_PKTINFO in
     * hip_init_raw_sock_v6 */
    HIP_IFEL(!pktinfo.pktinfo_in4, -1,
             "Could not determine dst addr, dropping\n");

    /* UDP port numbers */
    if (is_ipv4 && encap_hdr_size == HIP_UDP_ZERO_BYTES_LEN) {
        HIP_DEBUG("source port = %d\n", ntohs(addr_from4->sin_port));
        ctx->msg_ports.src_port = ntohs(addr_from4->sin_port);
        /* Destination port is known from the bound socket. */
        ctx->msg_ports.dst_port = hip_get_local_nat_udp_port();
    } else {
        ctx->msg_ports.src_port = 0;
        ctx->msg_ports.dst_port = 0;
   }

    /* IPv4 addresses */
    if (is_ipv4) {
        struct sockaddr_in *addr_to4 = (struct sockaddr_in *) &addr_to;
        IPV4_TO_IPV6_MAP(&addr_from4->sin_addr, &ctx->src_addr);
        IPV4_TO_IPV6_MAP(&pktinfo.pktinfo_in4->ipi_addr, &ctx->dst_addr);
        addr_to4->sin_family = AF_INET;
        addr_to4->sin_addr   = pktinfo.pktinfo_in4->ipi_addr;
        addr_to4->sin_port   = ctx->msg_ports.dst_port;
    } else {   /* IPv6 addresses */
        struct sockaddr_in6 *addr_to6 =
            (struct sockaddr_in6 *) &addr_to;
        memcpy(&ctx->src_addr, &addr_from6->sin6_addr,
               sizeof(struct in6_addr));
        memcpy(&ctx->dst_addr, &pktinfo.pktinfo_in6->ipi6_addr,
               sizeof(struct in6_addr));
        addr_to6->sin6_family = AF_INET6;
        ipv6_addr_copy(&addr_to6->sin6_addr, &ctx->dst_addr);
    }

    if (is_ipv4 && (encap_hdr_size == IPV4_HDR_SIZE)) {    /* raw IPv4, !UDP */
        /* For some reason, the IPv4 header is always included.
         * Let's remove it here. */
        memmove(ctx->input_msg,
                ((char *) ctx->input_msg) + IPV4_HDR_SIZE,
                HIP_MAX_PACKET - IPV4_HDR_SIZE);
    } else if (is_ipv4 && encap_hdr_size == HIP_UDP_ZERO_BYTES_LEN) {
        /* remove 32-bits of zeroes between UDP and HIP headers */
        memmove(ctx->input_msg,
                ((char *) ctx->input_msg) + HIP_UDP_ZERO_BYTES_LEN,
                HIP_MAX_PACKET - HIP_UDP_ZERO_BYTES_LEN);
    }

    HIP_IFEL(hip_verify_network_header(ctx->input_msg,
                                       (struct sockaddr *) &addr_from,
                                       (struct sockaddr *) &addr_to,
                                       len - encap_hdr_size), -1,
             "verifying network header failed\n");



    HIP_DEBUG_IN6ADDR("src", &ctx->src_addr);
    HIP_DEBUG_IN6ADDR("dst", &ctx->dst_addr);

out_err:
    return err;
}

/**
 * Read an IPv6 control message
 *
 * @param  sockfd         a socket file descriptor.
 * @param  ctx            .
 * @param  encap_hdr_size .
 * @return                .
 */
int hip_read_control_msg_v6(int sockfd,
                            struct hip_packet_context *ctx,
                            int encap_hdr_size)
{
    HIP_DEBUG("Receiving a message on raw HIP from IPv6/HIP socket "\
              " (file descriptor: %d).\n", sockfd);
    return hip_read_control_msg_all(sockfd, ctx, encap_hdr_size, 0);
}

/**
 * Read an IPv4 control message
 *
 * @param  sockfd         a socket file descriptor.
 * @param  ctx            .
 * @param  encap_hdr_size .
 * @return                .
 */
int hip_read_control_msg_v4(int sockfd,
                            struct hip_packet_context *ctx,
                            int encap_hdr_size)
{
    HIP_DEBUG("Receiving a message on raw HIP from IPv4/HIP socket "\
              " (file descriptor: %d).\n", socket);
    return hip_read_control_msg_all(sockfd, ctx, encap_hdr_size, 1);
}
