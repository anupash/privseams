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
 * This file defines handling functions for network sockets for the Host
 * Identity Protocol (HIP).
 *
 * @author  Tim Just
 */

#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "lib/core/builder.h"
#include "lib/core/common.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/linkedlist.h"
#include "lib/core/message.h"
#include "lib/tool/nlink.h"
#include "hipd.h"
#include "input.h"
#include "netdev.h"
#include "pkt_handling.h"
#include "user.h"
#include "hip_socket.h"


struct socketfd {
    uint16_t priority;
    int      fd;
    int      (*func_ptr)(struct hip_packet_context *ctx);
};

/**
 * List for storage of used sockets
 */
static struct hip_ll *hip_sockets;

static int hip_handle_raw_input_v6(struct hip_packet_context *ctx)
{
    int err = 0;

    HIP_DEBUG("received on: hip_raw_sock_input_v6\n");

    if (hip_read_control_msg_v6(hip_raw_sock_input_v6,
                                ctx,
                                0)) {
        HIP_ERROR("Reading network msg failed\n");
    } else {
        err = hip_receive_control_packet(ctx);
        if (err) {
            HIP_ERROR("hip_receive_control_packet()!\n");
        }
    }

    return err;
}

static int hip_handle_raw_input_v4(struct hip_packet_context *ctx)
{
    int err = 0;

    HIP_DEBUG("received on: hip_raw_sock_input_v4\n");

    if (hip_read_control_msg_v4(hip_raw_sock_input_v4,
                                ctx,
                                IPV4_HDR_SIZE)) {
        HIP_ERROR("Reading network msg failed\n");
    } else {
        err = hip_receive_control_packet(ctx);
        if (err) {
            HIP_ERROR("hip_receive_control_packet()!\n");
        }
    }

    return err;
}

static int hip_handle_nat_input(struct hip_packet_context *ctx)
{
    int err = 0;

    HIP_DEBUG("received on: hip_nat_sock_input_udp\n");

    err = hip_read_control_msg_v4(hip_nat_sock_input_udp,
                                  ctx,
                                  HIP_UDP_ZERO_BYTES_LEN);
    if (err) {
        HIP_ERROR("Reading network msg failed\n");
    } else {
        err = hip_receive_udp_control_packet(ctx);
    }

    return err;
}

static int hip_handle_user_sock(struct hip_packet_context *ctx)
{
    int                 err      = 0, send_response = 0, n = 0, len = 0;
    uint8_t             msg_type = 0;
    struct sockaddr_in6 app_src;

    HIP_DEBUG("received on: hip_user_sock\n");

    HIP_IFEL(hip_read_user_control_msg(hip_user_sock,
                                       ctx->input_msg,
                                       &app_src),
             -1,
             "Reading user msg failed\n");

    msg_type      = hip_get_msg_type(ctx->input_msg);
    send_response = hip_get_msg_response(ctx->input_msg);

    if (hip_user_run_handles(msg_type, ctx->input_msg, &app_src)) {
        err = hip_handle_user_msg(ctx->input_msg, &app_src);
    }

    if (send_response) {
        HIP_DEBUG("Send response\n");
        if (err) {
            hip_set_msg_err(ctx->input_msg, 1);
        }
        len = hip_get_msg_total_len(ctx->input_msg);
        HIP_DEBUG("Sending message (type=%d) response to port %d \n",
                  hip_get_msg_type(ctx->input_msg), ntohs(app_src.sin6_port));
        HIP_DEBUG_HIT("To address", &app_src.sin6_addr);
        n = hip_sendto_user(ctx->input_msg, (struct sockaddr *)  &app_src);
        if (n != len) {
            err = -1;
        } else {
            HIP_DEBUG("Response sent ok\n");
        }
    } else {
        HIP_DEBUG("No response sent\n");
    }
out_err:
    return err;
}

static int hip_handle_nl_ipsec_sock(UNUSED struct hip_packet_context *ctx)
{
    HIP_DEBUG("received on: hip_nl_ipsec\n");

    if (hip_netlink_receive(&hip_nl_ipsec,
                            hip_netdev_event, NULL)) {
        HIP_ERROR("Netlink receiving failed\n");
        return -1;
    }

    return 0;
}

static int hip_handle_nl_route_sock(UNUSED struct hip_packet_context *ctx)
{
    HIP_DEBUG("received on: hip_nl_route\n");

    if (hip_netlink_receive(&hip_nl_route,
                            hip_netdev_event, NULL)) {
        HIP_ERROR("Netlink receiving failed\n");
        return -1;
    }

    return 0;
}

/**
 * Register the hip sockets with their associated handler functions.
 */
void hip_register_sockets(void)
{
    hip_register_socket(hip_raw_sock_input_v6,  &hip_handle_raw_input_v6,  10000);
    hip_register_socket(hip_raw_sock_input_v4,  &hip_handle_raw_input_v4,  10100);
    hip_register_socket(hip_nat_sock_input_udp, &hip_handle_nat_input,     10200);
    hip_register_socket(hip_nl_ipsec.fd,        &hip_handle_nl_ipsec_sock, 10300);
    hip_register_socket(hip_user_sock,          &hip_handle_user_sock,     10400);
    hip_register_socket(hip_nl_route.fd,        &hip_handle_nl_route_sock, 10500);
}

/**
 * Free memory used for storage of the socket list.
 */
void hip_unregister_sockets(void)
{
    hip_ll_uninit(hip_sockets, free);
    free(hip_sockets);
}

/**
 * Register a socket with a handler function and priority.
 *
 * @note Free allocated memory from all registered sockets with
 *       hip_unregister_sockets().
 *
 * @param socketfd The socket descriptor.
 * @param func_ptr The associated handler function.
 * @param priority Execution priority for the handler function.
 * @return Success =  0
 *         Error   = -1
 */
int hip_register_socket(int socketfd,
                        int (*func_ptr)(struct hip_packet_context *ctx),
                        const uint16_t priority)
{
    int              err        = 0;
    struct socketfd *new_socket = NULL;

    HIP_IFEL(!(new_socket = malloc(sizeof(struct socketfd))),
             -1,
             "Error on allocating memory for a socket entry.\n");

    new_socket->priority = priority;
    new_socket->fd       = socketfd;
    new_socket->func_ptr = func_ptr;

    HIP_IFEL(!(hip_sockets = lmod_register_function(hip_sockets, new_socket, priority)),
             -1,
             "Error on registering a maintenance function.\n");

    return 0;

out_err:
    free(new_socket);
    return err;
}

int hip_get_highest_descriptor(void)
{
    int                       highest_descriptor = 0;
    const struct hip_ll_node *iter               = NULL;

    if (hip_sockets) {
        while ((iter = hip_ll_iterate(hip_sockets, iter))) {
            if (((struct socketfd *) iter->ptr)->fd >= highest_descriptor) {
                highest_descriptor = ((struct socketfd *) iter->ptr)->fd;
            }
        }
    } else {
        HIP_DEBUG("No sockets registered.\n");
    }

    return highest_descriptor;
}

void hip_prepare_fd_set(fd_set *read_fdset)
{
    const struct hip_ll_node *iter = NULL;

    FD_ZERO(read_fdset);

    if (hip_sockets) {
        while ((iter = hip_ll_iterate(hip_sockets, iter))) {
            FD_SET(((struct socketfd *) iter->ptr)->fd, read_fdset);
        }
    } else {
        HIP_DEBUG("No sockets registered.\n");
    }
}

/**
 * Run callbacks for any global socket that's flagged in the fd_set.
 * Invoked from hipd_main's main loop.
 *
 * @param read_fdset fd_set loaded with global socket handles, after
 *                   select() call.
 * @param ctx        Initialized packet context. Will be prepared for next
 *                   iteration upon return.
 * @todo             select() should probably be called here rather than in
 *                   hipd_main (passing read_fdset is superfluous)
 * @see              hipd_main
 */
void hip_run_socket_handles(fd_set *read_fdset, struct hip_packet_context *ctx)
{
    const struct hip_ll_node *iter = NULL;
    int                       socketfd;

    if (hip_sockets) {
        while ((iter = hip_ll_iterate(hip_sockets, iter))) {
            socketfd = ((struct socketfd *) iter->ptr)->fd;

            if (FD_ISSET(socketfd, read_fdset)) {
                ((struct socketfd *) iter->ptr)->func_ptr(ctx);
                HIP_DEBUG("result: %d\n", ctx->error);

                /* Reset for next iteration.
                 * msg_ports has no reset-state. */
                ctx->hadb_entry = NULL;
                ctx->error      = 0;
            }
        }
    } else {
        HIP_DEBUG("No sockets registered.\n");
    }
}
