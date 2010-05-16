/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
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

#include <stdlib.h>

#include "config.h"
#include "maintenance.h"
#include "update.h"
#include "heartbeat.h"
#include "hipd.h"
#include "lib/core/hip_udp.h"

#define FORCE_EXIT_COUNTER_START                5

int hip_firewall_sock_lsi_fd = -1;

float retrans_counter        = HIP_RETRANSMIT_INIT;
float opp_fallback_counter   = HIP_OPP_FALLBACK_INIT;
float precreate_counter      = HIP_R1_PRECREATE_INIT;
int nat_keep_alive_counter   = HIP_NAT_KEEP_ALIVE_INTERVAL;
float queue_counter          = QUEUE_CHECK_INIT;
int force_exit_counter       = FORCE_EXIT_COUNTER_START;
int cert_publish_counter     = CERTIFICATE_PUBLISH_INTERVAL;
int heartbeat_counter        = 0;
int hip_firewall_status      = -1;
int fall, retr;



static int hip_handle_retransmission(hip_ha_t *entry, void *current_time);
static int hip_scan_retransmissions(void);

/**
 * an iterator to handle packet retransmission for a given host association
 *
 * @param entry the host association which to handle
 * @param current_time current time
 * @return zero on success or negative on failure
 */
static int hip_handle_retransmission(hip_ha_t *entry, void *current_time)
{
    int err     = 0;
    time_t *now = (time_t *) current_time;

    if (entry->hip_msg_retrans.buf == NULL ||
        entry->hip_msg_retrans.count == 0) {
        goto out_err;
    }

    _HIP_DEBUG("Time to retrans: %d Retrans count: %d State: %s\n",
               entry->hip_msg_retrans.last_transmit + HIP_RETRANSMIT_WAIT - *now,
               entry->hip_msg_retrans.count, hip_state_str(entry->state));

    _HIP_DEBUG_HIT("hit_peer", &entry->hit_peer);
    _HIP_DEBUG_HIT("hit_our", &entry->hit_our);

    /* check if the last transmision was at least RETRANSMIT_WAIT seconds ago */
    if (*now - HIP_RETRANSMIT_WAIT > entry->hip_msg_retrans.last_transmit) {
        _HIP_DEBUG("%d %d %d\n", entry->hip_msg_retrans.count,
                   entry->state, entry->retrans_state);
        if ((entry->hip_msg_retrans.count > 0) && entry->hip_msg_retrans.buf &&
            ((entry->state != HIP_STATE_ESTABLISHED && entry->retrans_state != entry->state) ||
             (entry->update_state != 0 && entry->retrans_state != entry->update_state) ||
             entry->light_update_retrans == 1)) {
            HIP_DEBUG("state=%d, retrans_state=%d, update_state=%d\n",
                      entry->state, entry->retrans_state, entry->update_state, entry->retrans_state);

            /* @todo: verify that this works over slow ADSL line */
            err = entry->hadb_xmit_func->
                  hip_send_pkt(&entry->hip_msg_retrans.saddr,
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

#ifdef CONFIG_HIP_OPPORTUNISTIC
/**
 * scan for opportunistic connections that should time out
 * and give up (fall back to normal TCP/IP)
 *
 * @return zero on success or negative on failure
 */
static int hip_scan_opp_fallback(void)
{
    int err = 0;
    time_t current_time;
    time(&current_time);

    HIP_IFEL(hip_for_each_opp(hip_handle_opp_fallback, &current_time), 0,
             "for_each_ha err.\n");
out_err:
    return err;
}
#endif

/**
 * deliver pending retransmissions for all host associations
 *
 * @return zero on success or negative on failure
 */
static int hip_scan_retransmissions(void)
{
    int err = 0;
    time_t current_time;
    time(&current_time);
    HIP_IFEL(hip_for_each_ha(hip_handle_retransmission, &current_time), 0,
             "for_each_ha err.\n");
out_err:
    return err;
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
            hip_exit(SIGINT);
            exit(SIGINT);
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

#ifdef CONFIG_HIP_OPPORTUNISTIC

    if (opp_fallback_counter < 0) {
        HIP_IFEL(hip_scan_opp_fallback(), -1,
                 "retransmission scan failed\n");
        opp_fallback_counter = HIP_OPP_FALLBACK_INIT;
    } else {
        opp_fallback_counter--;
    }
#endif

    if (precreate_counter < 0) {
        HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1,
                 "Failed to recreate puzzles\n");
        precreate_counter = HIP_R1_PRECREATE_INIT;
    } else {
        precreate_counter--;
    }

    /* is heartbeat support on */
    if (hip_icmp_interval > 0) {
        /* Check if the heartbeats should be sent */
        if (heartbeat_counter < 1) {
            hip_for_each_ha(hip_send_heartbeat, &hip_icmp_sock);
            heartbeat_counter = hip_icmp_interval;
        } else {
            heartbeat_counter--;
        }
    } else if (hip_nat_status) {
        /* Send NOTIFY keepalives for NATs only when ICMPv6
         * keepalives are disabled */
        if (nat_keep_alive_counter < 0) {
            HIP_IFEL(hip_nat_refresh_port(),
                     -ECOMM,
                     "Failed to refresh NAT port state.\n");
            nat_keep_alive_counter = HIP_NAT_KEEP_ALIVE_INTERVAL;
        } else {
            nat_keep_alive_counter--;
        }
    }

    if (hip_trigger_update_on_heart_beat_failure &&
        hip_icmp_interval > 0) {
        hip_for_each_ha(hip_handle_update_heartbeat_trigger, NULL);
    }

    if (hip_wait_addr_changes_to_stabilize &&
        address_change_time_counter != -1) {
        if (address_change_time_counter == 0) {
            address_change_time_counter = -1;
            HIP_DEBUG("Triggering UPDATE\n");
            err                         = hip_send_locators_to_all_peers();
            if (err) {
                HIP_ERROR("Error sending UPDATE\n");
            }
        } else {
            HIP_DEBUG("Delay mobility triggering (count %d)\n",
                      address_change_time_counter - 1);
            address_change_time_counter--;
        }
    }

    /* Clear the expired records from the relay hashtable. */
    hip_relht_maintenance();

    /* Clear the expired pending service requests. This is by no means time
     * critical operation and is not needed to be done on every maintenance
     * cycle. Once every 10 minutes or so should be enough. Just for the
     * record, if periodic_maintenance() is ever to be optimized. */
    hip_registration_maintenance();

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
 * LSI and system-based opportunistic mode in the firewall.
 *
 * @param action HIP_MSG_FW_UPDATE_DB or HIP_MSG_FW_BEX_DONE
 * @param entry the host association
 * @param hit_s optional source HIT
 * @param hit_r optional destination HIT
 *
 * @return zero on success or negative on failure
 */
int hip_firewall_set_bex_data(int action, hip_ha_t *entry, struct in6_addr *hit_s, struct in6_addr *hit_r)
{
    struct hip_common *msg = NULL;
    struct sockaddr_in6 hip_firewall_addr;
    int err                = 0, n = 0, r_is_our;
    socklen_t alen         = sizeof(hip_firewall_addr);

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
                                      (void *) (r_is_our ? hit_s : hit_r), HIP_PARAM_HIT,
                                      sizeof(struct in6_addr)), -1, "build param contents failed\n");
    HIP_IFEL(hip_build_param_contents(msg,
                                      (void *) (r_is_our ? hit_r : hit_s), HIP_PARAM_HIT,
                                      sizeof(struct in6_addr)), -1, "build param contents failed\n");

    bzero(&hip_firewall_addr, alen);
    hip_firewall_addr.sin6_family = AF_INET6;
    hip_firewall_addr.sin6_port   = htons(HIP_FIREWALL_PORT);
    hip_firewall_addr.sin6_addr   = in6addr_loopback;

    n = sendto(hip_firewall_sock_lsi_fd,
               (char *) msg,
               hip_get_msg_total_len(msg),
               0,
               (struct sockaddr *) &hip_firewall_addr,
               alen);

    HIP_IFEL( n < 0, -1, "Send to firewall failed. str errno %s\n", strerror(errno));

    HIP_DEBUG("BEX DATA Send to firewall OK.\n");

out_err:
    if (msg) {
        free(msg);
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
int hip_icmp_statistics(struct in6_addr *src, struct in6_addr *dst,
                        struct timeval *stval, struct timeval *rtval)
{
    int err                  = 0;
    uint32_t rcvd_heartbeats = 0;
    uint64_t rtt             = 0;
    double avg               = 0.0, std_dev = 0.0;
    char hit[INET6_ADDRSTRLEN];
    hip_ha_t *entry          = NULL;

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

    _HIP_DEBUG("Reset heartbeat timer to trigger UPDATE\n");
    entry->update_trigger_on_heartbeat_counter = 0;

    HIP_DEBUG("\nHeartbeat from %s, RTT %.6f ms,\n%.6f ms mean, "
              "%.6f ms std dev, packets sent %d recv %d lost %d\n",
              hit, ((float) rtt / STATS_IN_MSECS), avg, std_dev, entry->heartbeats_sent,
              rcvd_heartbeats, (entry->heartbeats_sent - rcvd_heartbeats));

out_err:
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
    int err                = 0;
    int sent;

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
    if (msg) {
        free(msg);
    }
    return err;
}
