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
 * Periodically handled "maintenance" actions are processed here by
 * default roughly once in a second. These actions include
 * retransmissions of lost HIP control packets, keepalives for NATs,
 * heartbeats to detect connectivity problems, purging of opportunistic
 * mode state, delaying of UPDATE triggering until addresses have stabilized.
 *
 * @brief Hipd maintenance loop
 *
 * @note When adding new functionality, make sure that the socket
 *       calls do not block because hipd is single threaded.
 */

#define _BSD_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/hip_udp.h"
#include "lib/core/ife.h"
#include "lib/core/linkedlist.h"
#include "lib/core/protodefs.h"
#include "lib/core/modularization.h"
#include "config.h"
#include "accessor.h"
#include "close.h"
#include "cookie.h"
#include "hadb.h"
#include "hidb.h"
#include "hipd.h"
#include "init.h"
#include "output.h"
#include "maintenance.h"

#define FORCE_EXIT_COUNTER_START                5

struct maint_function {
    uint16_t priority;
    int      (*func_ptr)(void);
};

int hip_firewall_sock_lsi_fd = -1;

float retrans_counter      = HIP_RETRANSMIT_INIT;
float precreate_counter    = HIP_R1_PRECREATE_INIT;
float queue_counter        = QUEUE_CHECK_INIT;
int   force_exit_counter   = FORCE_EXIT_COUNTER_START;
int   cert_publish_counter = CERTIFICATE_PUBLISH_INTERVAL;
int   hip_firewall_status  = -1;
int   fall, retr;

/**
 * List containing all maintenance functions.
 */
static struct hip_ll *hip_maintenance_functions;

/**
 * an iterator to handle packet retransmission for a given host association
 *
 * @param entry the host association which to handle
 * @param current_time current time
 * @return zero on success or negative on failure
 */
static int hip_handle_retransmission(struct hip_hadb_state *entry,
                                     void *current_time)
{
    int     err = 0;
    time_t *now = (time_t *) current_time;

    if (entry->hip_msg_retrans.buf == NULL ||
        entry->hip_msg_retrans.count == 0) {
        goto out_err;
    }

    /* check if the last transmision was at least RETRANSMIT_WAIT seconds ago */
    if (*now - HIP_RETRANSMIT_WAIT > entry->hip_msg_retrans.last_transmit) {
        if ((entry->hip_msg_retrans.count > 0) && entry->hip_msg_retrans.buf &&
            ((entry->state != HIP_STATE_ESTABLISHED && entry->retrans_state != entry->state) ||
             (entry->update_state != 0 && entry->retrans_state != entry->update_state) ||
             entry->light_update_retrans == 1)) {
            HIP_DEBUG("state=%d, retrans_state=%d, update_state=%d\n",
                      entry->state, entry->retrans_state, entry->update_state, entry->retrans_state);

            /* @todo: verify that this works over slow ADSL line */
            err = hip_send_pkt(&entry->hip_msg_retrans.saddr,
                               &entry->hip_msg_retrans.daddr,
                               (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
                               entry->peer_udp_port,
                               entry->hip_msg_retrans.buf,
                               entry, 0);

            /* Set entry state, if previous state was unassosiated
             * and type is I1. */
            if (!err && hip_get_msg_type(entry->hip_msg_retrans.buf)
                == HIP_I1 && entry->state == HIP_STATE_UNASSOCIATED) {
                HIP_DEBUG("Resent I1 succcesfully\n");
                entry->state = HIP_STATE_I1_SENT;
            }

            entry->hip_msg_retrans.count--;
            /* set the last transmission time to the current time value */
            time(&entry->hip_msg_retrans.last_transmit);
        } else {
            if (entry->hip_msg_retrans.buf) {
                entry->hip_msg_retrans.count = 0;
                memset(entry->hip_msg_retrans.buf, 0, HIP_MAX_NETWORK_PACKET);
            }

            if (entry->state == HIP_STATE_ESTABLISHED) {
                entry->retrans_state = entry->update_state;
            } else {
                entry->retrans_state = entry->state;
            }
        }
    }

out_err:

    return err;
}

/**
 * deliver pending retransmissions for all host associations
 *
 * @return zero on success or negative on failure
 */
static int hip_scan_retransmissions(void)
{
    time_t current_time;
    time(&current_time);

    if (hip_for_each_ha(hip_handle_retransmission, &current_time)) {
        return -1;
    }
    return 0;
}

/**
 * Register a maintenance function. All maintenance functions are called during
 * the periodic maintenance cycle.
 *
 * @param maint_function Pointer to the maintenance function.
 * @param priority Priority of the maintenance function.
 *
 * @return Success =  0
 *         Error   = -1
 *
 */
int hip_register_maint_function(int (*maint_function)(void),
                                const uint16_t priority)
{
    int                    err       = 0;
    struct maint_function *new_entry = NULL;

    HIP_IFEL(!(new_entry = malloc(sizeof(struct maint_function))),
             -1,
             "Error on allocating memory for a maintenance function entry.\n");

    new_entry->priority = priority;
    new_entry->func_ptr = maint_function;

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
 * Remove a maintenance function from the list.
 *
 * @param maint_function Pointer to the function which should be unregistered.
 *
 * @return Success =  0
 *         Error   = -1
 */
int hip_unregister_maint_function(int (*maint_function)(void))
{
    return lmod_unregister_function(hip_maintenance_functions,
                                    maint_function);
}

/**
 * Run all maintenance functions.
 *
 * @return Success =  0
 *         Error   = -1
 */
static int hip_run_maint_functions(void)
{
    int                 err  = 0;
    struct hip_ll_node *iter = NULL;

    if (hip_maintenance_functions) {
        while ((iter = hip_ll_iterate(hip_maintenance_functions, iter))) {
            ((struct maint_function *) iter->ptr)->func_ptr();
        }
    } else {
        HIP_DEBUG("No maintenance function registered.\n");
    }

    return err;
}

/**
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
 * Periodic maintenance.
 *
 * @return zero on success or negative on failure
 */
int hip_periodic_maintenance(void)
{
    int err = 0;

    if (hipd_get_state() == HIPD_STATE_CLOSING) {
        if (force_exit_counter > 0) {
            err = hip_count_open_connections();
            if (err < 1) {
                hipd_set_state(HIPD_STATE_CLOSED);
            }
        } else {
            hip_exit();
            exit(EXIT_SUCCESS);
        }
        force_exit_counter--;
    }

    /* If some HAs are still remaining after certain grace period
     * in closing or closed state, delete them */
    hip_for_each_ha(hip_purge_closing_ha, NULL);

    if (retrans_counter < 0) {
        HIP_IFEL(hip_scan_retransmissions(), -1,
                 "retransmission scan failed\n");
        retrans_counter = HIP_RETRANSMIT_INIT;
    } else {
        retrans_counter--;
    }

    if (precreate_counter < 0) {
        HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1,
                 "Failed to recreate puzzles\n");
        precreate_counter = HIP_R1_PRECREATE_INIT;
    } else {
        precreate_counter--;
    }

    hip_run_maint_functions();

out_err:

    return err;
}

/**
 * get the current running status of firewall
 *
 * @return one if firewall is running or zero otherwise
 * @todo this is redundant with hip_firewall_is_alive()
 */
int hip_get_firewall_status(void)
{
    return hip_firewall_status;
}

/**
 *
 * get the current running status of firewall
 *
 * @return one if firewall is running or zero otherwise
 */
int hip_firewall_is_alive(void)
{
#ifdef CONFIG_HIP_FIREWALL
    if (hip_firewall_status) {
        HIP_DEBUG("Firewall is alive.\n");
    } else {
        HIP_DEBUG("Firewall is not alive.\n");
    }
    return hip_firewall_status;
#else
    HIP_DEBUG("Firewall is disabled.\n");
    return 0;
#endif // CONFIG_HIP_FIREWALL
}

/**
 * Update firewall on host association state. Currently used by the
 * LSI mode in the firewall.
 *
 * @param action HIP_MSG_FW_UPDATE_DB or HIP_MSG_FW_BEX_DONE
 * @param hit_s optional source HIT
 * @param hit_r optional destination HIT
 *
 * @return zero on success or negative on failure
 */
int hip_firewall_set_bex_data(int action, struct in6_addr *hit_s, struct in6_addr *hit_r)
{
    struct hip_common  *msg = NULL;
    struct sockaddr_in6 hip_fw_addr;
    int                 err  = 0, n = 0, r_is_our;
    socklen_t           alen = sizeof(hip_fw_addr);

    if (!hip_get_firewall_status()) {
        goto out_err;
    }

    /* Makes sure that the hits are sent always in the same order */
    r_is_our = hip_hidb_hit_is_our(hit_r);

    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, "alloc\n");
    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg, action, 0), -1,
             "Build hdr failed\n");

    HIP_IFEL(hip_build_param_contents(msg,
                                      r_is_our ? hit_s : hit_r, HIP_PARAM_HIT,
                                      sizeof(struct in6_addr)), -1, "build param contents failed\n");
    HIP_IFEL(hip_build_param_contents(msg,
                                      r_is_our ? hit_r : hit_s, HIP_PARAM_HIT,
                                      sizeof(struct in6_addr)), -1, "build param contents failed\n");

    bzero(&hip_fw_addr, alen);
    hip_fw_addr.sin6_family = AF_INET6;
    hip_fw_addr.sin6_port   = htons(HIP_FIREWALL_PORT);
    hip_fw_addr.sin6_addr   = in6addr_loopback;

    n = sendto(hip_firewall_sock_lsi_fd,
               (char *) msg,
               hip_get_msg_total_len(msg),
               0,
               (struct sockaddr *) &hip_firewall_addr,
               alen);

    HIP_IFEL(n < 0, -1, "Send to firewall failed. str errno %s\n", strerror(errno));

    HIP_DEBUG("BEX DATA Send to firewall OK.\n");

out_err:
    free(msg);
    return err;
}

/**
 * tell firewall to turn on or off the ESP relay mode
 *
 * @param action HIP_MSG_OFFER_FULLRELAY or HIP_MSG_CANCEL_FULLRELAY
 *
 * @return zero on success or negative on failure
 */
int hip_firewall_set_esp_relay(int action)
{
    struct hip_common *msg = NULL;
    int                err = 0;
    int                sent;

    HIP_DEBUG("Setting ESP relay to %d\n", action);
    HIP_IFE(!(msg = hip_msg_alloc()), -ENOMEM);
    HIP_IFEL(hip_build_user_hdr(msg,
                                action ? HIP_MSG_OFFER_FULLRELAY : HIP_MSG_CANCEL_FULLRELAY, 0),
             -1, "Build header failed\n");

    sent = hip_sendto_firewall(msg);
    if (sent < 0) {
        HIP_PERROR("Send to firewall failed: ");
        err = -1;
        goto out_err;
    }
    HIP_DEBUG("Sent %d bytes to firewall.\n", sent);

out_err:
    free(msg);
    return err;
}
