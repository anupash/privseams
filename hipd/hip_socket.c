/** @file
 * This file defines handling functions for network sockets for the Host
 * Identity Protocol (HIP).
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
 * @author  Tim Just
 */

#include <malloc.h>

#include "hip_socket.h"
#include "hipd.h"
#include "input.h"
#include "pkt_handling.h"

struct socketfd {
    uint16_t priority;
    int      fd;
    int    (*func_ptr)(struct hip_packet_context *ctx);
};

/**
 * List for storage of used sockets
 */
static hip_ll_t *hip_sockets;

static int hip_handle_raw_input_v6(struct hip_packet_context *ctx)
{
    int err = 0;

    if (hip_read_control_msg_v6(hip_raw_sock_input_v6,
                                ctx,
                                0)) {
        HIP_ERROR("Reading network msg failed\n");
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

    HIP_DEBUG("Receiving a message on UDP from NAT " \
              "socket (file descriptor: %d).\n",
              hip_nat_sock_input_udp);

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
    int err = 0, send_response = 0, n = 0, len = 0;
    uint8_t msg_type = 0;
    struct sockaddr_in6 app_src;


    HIP_IFEL(hip_read_user_control_msg(hip_user_sock,
                                       ctx->input_msg,
                                       &app_src),
             -1,
             "Reading user msg failed\n");

    msg_type      = hip_get_msg_type(ctx->input_msg);
    send_response = hip_get_msg_response(ctx->input_msg);

    if (hip_user_run_handles(msg_type, ctx->input_msg, &app_src)) {
        err = hip_handle_user_msg(ctx->input_msg, &app_src, &send_response);
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
        n   = hip_sendto_user(ctx->input_msg, (struct sockaddr *)  &app_src);
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

static int hip_handle_nl_ipsec_sock(struct hip_packet_context *ctx)
{
    HIP_DEBUG("netlink receive\n");
    if (hip_netlink_receive(&hip_nl_ipsec,
                            hip_netdev_event, NULL)) {
        HIP_ERROR("Netlink receiving failed\n");
        return -1;
    }

    return 0;
}

static int hip_handle_nl_route_sock(struct hip_packet_context *ctx)
{
    HIP_DEBUG("netlink route receive\n");
    if (hip_netlink_receive(&hip_nl_route,
                            hip_netdev_event, NULL)) {
        HIP_ERROR("Netlink receiving failed\n");
        return -1;
    }

    return 0;
}

void hip_init_sockets(void)
{
    hip_register_socket(hip_raw_sock_input_v6,  &hip_handle_raw_input_v6,  10000);
    hip_register_socket(hip_raw_sock_input_v4,  &hip_handle_raw_input_v4,  10100);
    hip_register_socket(hip_nat_sock_input_udp, &hip_handle_nat_input,     10200);
    hip_register_socket(hip_nl_ipsec.fd,        &hip_handle_nl_ipsec_sock, 10300);
    hip_register_socket(hip_user_sock,          &hip_handle_user_sock,     10400);
    hip_register_socket(hip_nl_route.fd,        &hip_handle_nl_route_sock, 10500);
}

/**
 * hip_register_socket
 *
 */
int hip_register_socket(int socketfd,
                        int (*func_ptr)(struct hip_packet_context *ctx),
                        const uint16_t priority)
{
    int err = 0;
    struct socketfd *new_socket = NULL;

    HIP_IFEL(!(new_socket = malloc(sizeof(struct socketfd))),
             -1,
             "Error on allocating memory for a socket entry.\n");

    new_socket->priority = priority;
    new_socket->fd       = socketfd;
    new_socket->func_ptr = func_ptr;

    hip_sockets = lmod_register_function(hip_sockets,
                                         new_socket,
                                         priority);
    if (!hip_sockets) {
        HIP_ERROR("Error on registering a maintenance function.\n");
        err = -1;
    }

out_err:
    return err;
}

/**
 * hip_get_highest_descriptor
 *
 */
int hip_get_highest_descriptor(void)
{
    int highest_descriptor = 0;
    hip_ll_node_t *iter    = NULL;

    if (hip_sockets) {
        while ((iter = hip_ll_iterate(hip_sockets, iter))) {
            if (((struct socketfd*) iter->ptr)->fd >= highest_descriptor) {
                highest_descriptor = ((struct socketfd*) iter->ptr)->fd;
            }
        }
    } else {
        HIP_DEBUG("No sockets registered.\n");
    }

    return highest_descriptor;
}

/**
 * hip_prepare_fd_set
 *
 */
void hip_prepare_fd_set(fd_set *read_fdset)
{
    hip_ll_node_t *iter = NULL;

    FD_ZERO(read_fdset);

    if (hip_sockets) {
        while ((iter = hip_ll_iterate(hip_sockets, iter))) {
            FD_SET(((struct socketfd*) iter->ptr)->fd, read_fdset);
        }
    } else {
        HIP_DEBUG("No sockets registered.\n");
    }
}

/**
 * hip_run_socket_handles
 *
 */
void hip_run_socket_handles(fd_set *read_fdset, struct hip_packet_context *ctx)
{
    hip_ll_node_t *iter = NULL;
    int socketfd;

    if (hip_sockets) {
        while ((iter = hip_ll_iterate(hip_sockets, iter))) {
            socketfd = ((struct socketfd*) iter->ptr)->fd;

            if (FD_ISSET(socketfd, read_fdset)) {
                ((struct socketfd*) iter->ptr)->func_ptr(ctx);
            }
        }
    } else {
        HIP_DEBUG("No sockets registered.\n");
    }
}
