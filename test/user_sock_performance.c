/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
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
 *
 *
 */

#include  <stdio.h>
#include  <string.h>
#include  <unistd.h>
#include  <sys/types.h>
#include  <sys/socket.h>
#include  <sys/select.h>
#include  <sys/time.h>

#include "lib/core/ife.h"
#include "lib/core/protodefs.h"
#include "lib/core/common.h"
#include "lib/core/builder.h"
#include "lib/tool/lutil.h"
#include "lib/core/prefix.h"

#include "modules/signaling/lib/signaling_prot_common.h"
#include "modules/signaling/lib/signaling_common_builder.h"


#define   MAX_COUNT  200
#define   BUF_SIZE   100
#define   HIP_MSG_SIGNALING_PERF_TEST 140

int sender_sock = 0;

int receiver_port = 4444;
int sender_port = 4445;

/*
static void print_timeres(void);
static int signaling_hipd_send_to_fw(int sockfd, const struct hip_common *msg, const struct sockaddr *dst);
static int test_send_conn_ctx_to_firewall(UNUSED struct signaling_connection_context *conn_ctx);
static int test_send_param_app_to_firewall(struct signaling_connection_context *conn_ctx);
static void do_tests(int runs);
static void sender(int receiver_port, int sender_port);
static void receiver(int receiver_port, int sender_port);
*/

static void print_timeres(void)
{
    struct timeval tv1, tv2;
    int i;
    printf( "-------------------------------\n"
            "Determine gettimeofday resolution:\n");


    for (i = 0; i < 10; i++) {
        gettimeofday(&tv1, NULL);
        do {
            gettimeofday(&tv2, NULL);
        } while (tv1.tv_usec == tv2.tv_usec);

        printf("Resolution: %ld us\n", tv2.tv_usec - tv1.tv_usec +
               1000000 * (tv2.tv_sec - tv1.tv_sec));
    }

    printf( "-------------------------------\n\n");
}


static int signaling_hipd_send_to_fw(const struct hip_common *msg, UNUSED int block)
{
    struct sockaddr_in6 receiver_addr;
    struct in6_addr loopback = in6addr_loopback;
    int err                  = 0;

    //HIP_DEBUG("[SENDER] Sending msg type %d\n", hip_get_msg_type(msg));

    HIP_ASSERT(msg != NULL);

    // destination is receiver socket
    receiver_addr.sin6_family = AF_INET6;
    receiver_addr.sin6_port   = htons(receiver_port);
    ipv6_addr_copy(&receiver_addr.sin6_addr, &loopback);

    err = sendto(sender_sock, msg, hip_get_msg_total_len(msg), 0,
                 (struct sockaddr *) &receiver_addr,
                 hip_sockaddr_len((struct sockaddr *) &receiver_addr));
    if (err < 0) {
        HIP_ERROR("Sending message to firewall failed\n");
        err = -1;
        goto out_err;
    } else {
        err = 0;
    }

out_err:
    return err;
}

static int test_send_conn_ctx_to_firewall(struct signaling_connection_context *conn_ctx) {
    struct hip_common *loc_msg = NULL;
    int err                = 0;

    HIP_IFEL(!(loc_msg = malloc(HIP_MAX_PACKET)),
            -1, "memor alloc fail\n");
    hip_msg_init(loc_msg);
    HIP_IFEL(hip_build_user_hdr(loc_msg, HIP_MSG_SIGNALING_PERF_TEST, 0), -1,
              "build hdr failed\n");
    hip_build_param_contents(loc_msg, conn_ctx, HIP_PARAM_SIGNALING_APPINFO, sizeof(struct signaling_connection_context));
    HIP_DEBUG("Sending message of size %d \n", hip_get_msg_total_len(loc_msg));
    HIP_IFEL(signaling_hipd_send_to_fw(loc_msg, 0), -1, "failed to send add scdb-msg to fw\n");

out_err:
    free(loc_msg);
    return err;
}

static int test_send_param_app_to_firewall(struct signaling_connection_context *conn_ctx) {
    struct hip_common *msg = NULL;
    int err                = 0;

    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)),
            -1, "memor alloc fail\n");
    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_SIGNALING_PERF_TEST, 0), -1,
              "build hdr failed\n");
    if(signaling_build_param_connection_identifier(msg, conn_ctx)) {
        HIP_DEBUG("Building of connection identifier parameter failed\n");
    }
    HIP_IFEL(signaling_build_param_application_context(msg, conn_ctx),
            -1, "Building of param appinfo for I2 failed.\n");
    HIP_DEBUG("Sending message of size %d \n", hip_get_msg_total_len(msg));
    HIP_IFEL(signaling_hipd_send_to_fw(msg, 0), -1, "failed to send add scdb-msg to fw\n");

out_err:
    free(msg);
    return err;
}

static void do_tests(int runs) {
    struct timeval start_time;
    struct timeval stop_time;
    uint64_t timediff       = 0;
    uint64_t cum_timediff   = 0;
    uint64_t cum_timediff_2 = 0;
    uint64_t cum_timediff_3 = 0;
    uint64_t cum_timediff_4 = 0;
    int i = 0;
    char fill[128] = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456";
    int sleeptime = 0;
    struct signaling_connection_context *conn_ctx;

    conn_ctx = malloc(sizeof(struct signaling_connection_context));
    signaling_init_connection_context(conn_ctx);

    printf("--------------------------------------------\n"
           "Socket performance on internal struct\n"
           "--------------------------------------------\n");

    for (i = 0; i < runs; i++) {
        gettimeofday(&start_time, NULL);

        test_send_conn_ctx_to_firewall(conn_ctx);

        gettimeofday(&stop_time, NULL);

        timediff = calc_timeval_diff(&start_time, &stop_time);
        cum_timediff += timediff;
        usleep(sleeptime);
        //printf("%i. fw-send-wire: %.3f ms / %.3f ms \n", i + 1, timediff / 1000.0, cum_timediff / 1000.0);
    }


    printf("--------------------------------------------\n"
           "Socket performance on empty wire struct\n"
           "--------------------------------------------\n");

    signaling_connection_context_print(conn_ctx, "");


    for (i = 0; i < runs; i++) {
        gettimeofday(&start_time, NULL);

        test_send_param_app_to_firewall(conn_ctx);

        gettimeofday(&stop_time, NULL);

        timediff = calc_timeval_diff(&start_time, &stop_time);
        cum_timediff_2 += timediff;
        //printf("%i. fw-send-wire: %.3f ms / %.3f ms \n", i + 1, timediff / 1000.0, cum_timediff_2 / 1000.0);
        usleep(sleeptime);
    }

    printf("--------------------------------------------\n"
           "Socket performance on medium full wire struct\n"
           "--------------------------------------------\n");
    //strcpy(conn_ctx->user_ctx.subject_name, "Jan Henrik Ziegeldorf");
    strcpy(conn_ctx->app_ctx.application_dn, "Mozilla Firefox 3.2.1");
    strcpy(conn_ctx->app_ctx.issuer_dn, "Versign Inc.");
    strcpy(conn_ctx->app_ctx.groups, "Browser");
    strcpy(conn_ctx->app_ctx.requirements, "tcp, in/out");

    signaling_connection_context_print(conn_ctx, "");

    for (i = 0; i < runs; i++) {
        gettimeofday(&start_time, NULL);

        test_send_param_app_to_firewall(conn_ctx);

        gettimeofday(&stop_time, NULL);

        timediff = calc_timeval_diff(&start_time, &stop_time);
        cum_timediff_3 += timediff;
        //printf("%i. fw-send-wire: %.3f ms / %.3f ms \n", i + 1, timediff / 1000.0, cum_timediff_2 / 1000.0);
        usleep(sleeptime);
    }

    printf("--------------------------------------------\n"
           "Socket performance on maximum full wire struct\n"
           "--------------------------------------------\n");

    //strncpy(conn_ctx->user_ctx.subject_name, fill, 127);
    strncpy(conn_ctx->app_ctx.application_dn, fill, 127);
    strncpy(conn_ctx->app_ctx.issuer_dn, fill, 127);
    strncpy(conn_ctx->app_ctx.groups, fill, 63);
    strncpy(conn_ctx->app_ctx.requirements, fill, 63);

    signaling_connection_context_print(conn_ctx, "");


    for (i = 0; i < runs; i++) {
        gettimeofday(&start_time, NULL);

        test_send_param_app_to_firewall(conn_ctx);

        gettimeofday(&stop_time, NULL);

        timediff = calc_timeval_diff(&start_time, &stop_time);
        cum_timediff_4 += timediff;
        //printf("%i. fw-send-wire: %.3f ms / %.3f ms \n", i + 1, timediff / 1000.0, cum_timediff_4 / 1000.0);
        usleep(sleeptime);
    }

    printf("-----------------------------------------------\n"
           "Summary. Time for %d internal-runs: total %.4f ms, per msg %.4f\n",
           runs, cum_timediff / 1000.0, cum_timediff / 1000.0 / runs);
    printf("Summary. Time for %d empty-wire-runs: %.4f ms, per msg %.4f\n",
           runs, cum_timediff_2 / 1000.0, cum_timediff_2 / 1000.0 / runs);
    printf("Summary. Time for %d medium-wire-runs: %.4f ms, per msg %.4f\n",
           runs, cum_timediff_3 / 1000.0, cum_timediff_3 / 1000.0 / runs);
    printf("Summary. Time for %d full-wire-runs: total %.4f ms, per msg %.4f\n"
           "------------------------------------------------\n",
           runs, cum_timediff_4 / 1000.0, cum_timediff_4 / 1000.0 / runs);

}

UNUSED static int sender(void) {
    int sockfd;
    struct sockaddr_in6 sender_addr;
    int err;

    sleep(2);

    sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    HIP_IFEL((sockfd < 0), 1,
             "Could not create socket for user communication.\n");
    memset(&sender_addr, 0, sizeof(sender_addr));
    sender_addr.sin6_family = AF_INET6;
    sender_addr.sin6_port   = htons(sender_port);
    sender_addr.sin6_addr   = in6addr_loopback;

    HIP_IFEL(bind(sockfd, (struct sockaddr *) &sender_addr,
                  sizeof(sender_addr)), -1,
             "Bind on sender addr failed\n");

    print_timeres();

    sender_sock = sockfd;

    do_tests(10000);

out_err:
    return err;
}

UNUSED static int receiver(void) {
    int sockfd = 0;
    fd_set read_fdset;
    struct sockaddr_in6 sock_addr;
    struct sockaddr_in6 sender_addr;
    int highest_descriptor;
    socklen_t alen;
    int err = 0;
    int n;
    int len;
    struct timeval timeout;
    struct hip_common *msg = NULL;
    int count = 0;

    msg = hip_msg_alloc();
    if (!msg) {
        err = -1;
        return err;
    }

    /* Create, bind and connect the socket */
    sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    HIP_IFEL((sockfd < 0), 1, "Could not create receiver socket.\n");
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin6_family = AF_INET6;
    sock_addr.sin6_port = htons(receiver_port);
    sock_addr.sin6_addr = in6addr_loopback;
    HIP_IFEL(bind(sockfd, (struct sockaddr *)& sock_addr,
              sizeof(sock_addr)), -1, "Bind on receiver socket addr failed. Choose other port?\n");

    memset(&sender_addr, 0, sizeof(sender_addr));
    sender_addr.sin6_family = AF_INET6;
    sender_addr.sin6_port   = htons(sender_port);
    sender_addr.sin6_addr   = in6addr_loopback;

    HIP_IFEL(connect(sockfd, (struct sockaddr *) &sender_addr, sizeof(sender_addr)),
             -1, "connection to sender failed\n");

    highest_descriptor = maxof(1, sockfd);

    while (1) {
        // set up file descriptors for select
        FD_ZERO(&read_fdset);
        FD_SET(sockfd, &read_fdset);

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        // get handle with queued packet and process
        /* @todo: using HIPD_SELECT blocks hipfw with R1 */
        if ((err = select((highest_descriptor + 1), &read_fdset, NULL, NULL, &timeout)) < 0) {
            HIP_PERROR("select error, ignoring\n");
            continue;
        }

        if (FD_ISSET(sockfd, &read_fdset)) {
            memset(&sock_addr, 0, sizeof(sock_addr));
            alen = sizeof(sock_addr);
            n    = recvfrom(sockfd, msg, sizeof(struct hip_common),
                            MSG_PEEK, (struct sockaddr *) &sock_addr, &alen);
            if (n < 0) {
                HIP_ERROR("Error receiving message header from sender.\n");
                err = -1;
                continue;
            }

            alen = sizeof(sock_addr);
            len  = hip_get_msg_total_len(msg);

            HIP_DEBUG("Received message number %d of type %d and size %d\n",
                      ++count, hip_get_msg_type(msg), len);
            n    = recvfrom(sockfd, msg, len, 0,
                            (struct sockaddr *) &sock_addr, &alen);

            if (n < 0) {
                HIP_ERROR("Error receiving message parameters from daemon.\n");
                err = -1;
                continue;
            }
        }
    }
out_err:
    return err;
}

int main(void)
{
     pid_t pid;

     pid = fork();
     if(pid == 0) {
         HIP_DEBUG("SENDER\n");
         sender();
     } else {
         HIP_DEBUG("RECEIVER\n");
         receiver();
     }

     return 0;
}
