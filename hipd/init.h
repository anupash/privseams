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

#ifndef HIP_HIPD_INIT_H
#define HIP_HIPD_INIT_H

#include <stdint.h>
#include <netinet/in.h>


/* startup flags options to be configured via the command line */
#define HIPD_START_FOREGROUND               (1 << 0)
#define HIPD_START_CREATE_CONFIG_AND_EXIT   (1 << 1)
#define HIPD_START_FLUSH_IPSEC              (1 << 2)
#define HIPD_START_KILL_OLD                 (1 << 3)
#define HIPD_START_FIX_ALIGNMENT            (1 << 4)
#define HIPD_START_LOWCAP                   (1 << 5)
#define HIPD_START_LOAD_KMOD                (1 << 6)

/*
 * HIP daemon initialization functions.
 */
int set_cloexec_flag(int desc, int value);

int hipd_init(const uint64_t flags);
/**
 * Creates a UDP socket for NAT traversal.
 *
 * @param  hip_nat_sock_udp a pointer to the UDP socket.
 * @param addr the address that will be used to create the
 *                 socket. If NULL is passed, INADDR_ANY is used.
 * @param is_output 1 if the socket is for output, otherwise 0
 *
 * @return zero on success, negative error value on error.
 */
int hip_create_nat_sock_udp(int *hip_nat_sock_udp,
                            struct sockaddr_in *addr,
                            int is_output);
void hip_exit(void);

#endif /* HIP_HIPD_INIT_H */
