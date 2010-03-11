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
#include "modularization.h"

struct socketfd {
    uint16_t priority;
    int      fd;
    int    (*func_ptr)(struct hip_packet_context *ctx);
};

/**
 * List for storage of used sockets
 */
static hip_ll_t *hip_sockets;

static int hip_handle_raw_input_v6(struct hip_packet_context *packet_ctx)
{
    int err = 0;

    if (hip_read_control_msg_v6(hip_raw_sock_input_v6,
                                packet_ctx,
                                0)) {
        HIP_ERROR("Reading network msg failed\n");
        err = hip_receive_control_packet(packet_ctx);
        if (err) {
            HIP_ERROR("hip_receive_control_packet()!\n");
        }
    }

    return err;
}

static int hip_handle_raw_input_v4(struct hip_packet_context *packet_ctx)
{
    int err = 0;

    if (hip_read_control_msg_v4(hip_raw_sock_input_v4,
                                packet_ctx,
                                IPV4_HDR_SIZE)) {
        HIP_ERROR("Reading network msg failed\n");
    } else {
        err = hip_receive_control_packet(packet_ctx);
        if (err) {
            HIP_ERROR("hip_receive_control_packet()!\n");
        }
    }

    return err;
}

static int hip_handle_nat_input(struct hip_packet_context *packet_ctx)
{
    int err = 0;

    HIP_DEBUG("Receiving a message on UDP from NAT " \
              "socket (file descriptor: %d).\n",
              hip_nat_sock_input_udp);

    err = hip_read_control_msg_v4(hip_nat_sock_input_udp,
                                  packet_ctx,
                                  HIP_UDP_ZERO_BYTES_LEN);
    if (err) {
        HIP_ERROR("Reading network msg failed\n");
    } else {
        err = hip_receive_udp_control_packet(packet_ctx);
    }

    return err;
}

static int hip_handle_user_sock(struct hip_packet_context *packet_ctx)
{
    int err = 0;
    struct sockaddr_in6 app_src;

    if (hip_read_user_control_msg(hip_user_sock,
                                  packet_ctx->input_msg,
                                  &app_src)) {
        HIP_ERROR("Reading user msg failed\n");
    } else {
        err = hip_handle_user_msg(packet_ctx->input_msg, &app_src);
    }

    return err;
}

static int hip_handle_nl_ipsec_sock(struct hip_packet_context *packet_ctx)
{
    HIP_DEBUG("netlink receive\n");
    if (hip_netlink_receive(&hip_nl_ipsec)) {
        HIP_ERROR("Netlink receiving failed\n");
        return -1;
    }

    return 0;
}

static int hip_handle_nl_route_sock(struct hip_packet_context *packet_ctx)
{
    HIP_DEBUG("netlink route receive\n");
    if (hip_netlink_receive(&hip_nl_route)) {
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

/**
 * hip_uninit_sockets
 *
 * Free the memory used for storage of socket fd's.
 *
 */
void hip_uninit_sockets(void)
{
    if (hip_sockets) {
        hip_ll_uninit(hip_sockets, free);
        free(hip_sockets);
    }
}
