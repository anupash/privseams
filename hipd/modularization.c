/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
 * @brief HIP daemon related specializations for libmodularization (lmod).
 *
 * @author Tim Just <tim.just@rwth-aachen.de>
 *
 */
#include "lib/core/protodefs.h"
#include "lib/core/state.h"
#include "lib/modularization/modularization.h"

struct handle_function {
    uint16_t priority;
    int    (*func_ptr)(const uint8_t packet_type,
                       const uint32_t ha_state,
                       struct hip_packet_context *ctx);
};

struct maint_function {
    uint16_t priority;
    int    (*func_ptr)(void);
};

struct socketfd {
    uint16_t priority;
    int      fd;
    int    (*func_ptr)(int socketfd,
                       struct hip_packet_context *ctx);
};

/**
 * @todo add description
 */
static hip_ll_t *hip_handle_functions[HIP_MAX_PACKET_TYPE][HIP_MAX_HA_STATE];

/**
 * @todo add description
 */
static hip_ll_t *hip_maintenance_functions;

/**
 * @todo add description
 */
static hip_ll_t *hip_sockets;

/**
 * hip_register_handle_function
 *
 * Register a function for handling of the specified combination from packet
 * type and host association state.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *handle_function Pointer to the function which should be called
 *                         when the combination of packet type and host
 *                         association state is reached.
 * @param priority Execution priority for the handle function.
 *
 * @return Success =  0
 *         Error   = -1
 */
int hip_register_handle_function(const uint8_t packet_type,
                                 const uint32_t ha_state,
                                 int (*handle_function)(const uint8_t packet_type,
                                                        const uint32_t ha_state,
                                                        struct hip_packet_context *ctx),
                                 const uint16_t priority)
{
    int err = 0;
    struct handle_function *new_entry = NULL;

    HIP_IFEL(packet_type > HIP_MAX_PACKET_TYPE,
             -1,
             "Maximum packet type exceeded.\n");
    HIP_IFEL(ha_state    > HIP_MAX_HA_STATE,
             -1,
             "Maximum host association state exceeded.\n");

    HIP_IFEL(!(new_entry = malloc(sizeof(struct handle_function))),
             -1,
             "Error on allocating memory for a handle function entry.\n");

    new_entry->priority    = priority;
    new_entry->func_ptr    = handle_function;

    hip_handle_functions[packet_type][ha_state] =
            lmod_register_function(hip_handle_functions[packet_type][ha_state],
                                   new_entry,
                                   priority);
    if (!hip_handle_functions[packet_type][ha_state]) {
        HIP_ERROR("Error on registering a handle function.\n");
        err = -1;
    }
out_err:
    return err;
}

/**
 * hip_unregister_handle_function
 *
 * Unregister a function for handling of the specified combination from packet
 * type and host association state.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *handle_function Pointer to the function which should be unregistered.
 *
 * @return Success =  0
 *         Error   = -1
 */
int hip_unregister_handle_function(const uint8_t packet_type,
                                   const uint32_t ha_state,
                                   const void *handle_function)
{
    int err = 0;

    HIP_IFEL(packet_type > HIP_MAX_PACKET_TYPE,
             -1,
             "Maximum packet type exceeded.\n");
    HIP_IFEL(ha_state    > HIP_MAX_HA_STATE,
             -1,
             "Maximum host association state exceeded.\n");

    err = lmod_unregister_function(hip_handle_functions[packet_type][ha_state],
                                   handle_function);

out_err:
    return err;
}

/**
 * hip_run_handle_functions
 *
 * Run all handle functions for specified combination from packet type and host
 * association state.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *ctx The packet context containing the received message, source and
 *             destination address, the ports and the corresponding entry from
 *             the host association database.
 *
 * @return Success =  0
 *         Error   = -1
 */
int hip_run_handle_functions(const uint8_t packet_type,
                             const uint32_t ha_state,
                             struct hip_packet_context *ctx)
{
    int            err  = 0;
    hip_ll_node_t *iter = NULL;

    HIP_IFEL(packet_type > HIP_MAX_PACKET_TYPE,
             -1,
             "Maximum packet type exceeded.\n");
    HIP_IFEL(ha_state    > HIP_MAX_HA_STATE,
             -1,
             "Maximum host association state exceeded.\n");

    HIP_IFEL(!hip_handle_functions[packet_type][ha_state],
             -1,
             "Error on running handle functions.\nPacket type: %d, HA state: %d\n",
             packet_type,
             ha_state);

    while ((iter = hip_ll_iterate(hip_handle_functions[packet_type][ha_state],
                                  iter))
           && !ctx->drop_packet) {

        ((struct handle_function *) iter->ptr)->func_ptr(packet_type,
                                                         ha_state,
                                                         ctx);
    }

out_err:
    return err;
}

/**
 * hip_uninit_handle_functions
 *
 * Free the memory used for storage of handle functions.
 *
 */
void hip_uninit_handle_functions(void)
{
    int i, j;

    for (i = 0; i < HIP_MAX_PACKET_TYPE; i++) {
        for (j = 0; j < HIP_MAX_HA_STATE; j++) {
            if (hip_handle_functions[i][j]) {
                hip_ll_uninit(hip_handle_functions[i][j], free);
                free(hip_handle_functions[i][j]);
            }
        }
    }
}

/**
 * hip_register_maint_function
 *
 */
int hip_register_maint_function(int (*maint_function)(void),
                                const uint16_t priority)
{
    int err = 0;
    struct maint_function *new_entry = NULL;

    HIP_IFEL(!(new_entry = malloc(sizeof(struct maint_function))),
             -1,
             "Error on allocating memory for a maintenance function entry.\n");

    new_entry->priority    = priority;
    new_entry->func_ptr    = maint_function;

    hip_maintenance_functions = lmod_register_function(hip_maintenance_functions,
                                                       new_entry,
                                                       priority);
    if (!hip_maintenance_functions) {
        HIP_ERROR("Error on registering a maintenance function.\n");
        err = -1;
    }

out_err:
    return err;
}

/**
 * hip_run_maint_functions
 *
 * Run all maintenance functions.
 *
 * @return Success =  0
 *         Error   = -1
 */
int hip_run_maint_functions(void)
{
    int            err  = 0;
    hip_ll_node_t *iter = NULL;

    if (hip_maintenance_functions) {
        while ((iter = hip_ll_iterate(hip_maintenance_functions, iter))) {
            ((struct maint_function*) iter->ptr)->func_ptr();
        }
    } else {
        HIP_DEBUG("No maintenance function registered.\n");
    }

    return err;
}

/**
 * hip_uninit_maint_functions
 *
 * Free the memory used for storage of maintenance functions.
 *
 */
void hip_uninit_maint_functions(void)
{
    if (hip_maintenance_functions) {
        hip_ll_uninit(hip_maintenance_functions, free);
        free(hip_maintenance_functions);
    }
}

/**
 * hip_register_socket
 *
 */
int hip_register_socket(int socketfd,
                        int (*func_ptr)(int socketfd,
                                        struct hip_packet_context *ctx),
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
//                ((struct socketfd*) iter->ptr)->func_ptr(socketfd, ctx);
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

