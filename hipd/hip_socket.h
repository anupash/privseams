/**
 * @file
 * The header file for hipd/hip_socket.c
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
 * @author Tim Just
 *
 */
#ifndef HIP_HIPD_SOCKET_H
#define HIP_HIPD_SOCKET_H

#include <stdint.h>
#include <sys/select.h>
#include "lib/core/protodefs.h"

void hip_init_sockets(void);

int hip_register_socket(int socketfd,
                        int (*func_ptr)(struct hip_packet_context *ctx),
                        const uint16_t priority);

int hip_get_highest_descriptor(void);

void hip_prepare_fd_set(fd_set *read_fdset);

void hip_run_socket_handles(fd_set *read_fdset, struct hip_packet_context *ctx);

void hip_uninit_sockets(void);

#endif /* HIP_HIPD_SOCKET_H */
