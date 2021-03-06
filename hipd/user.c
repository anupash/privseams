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
 * This file defines a user message (i.e. message from hipconf or hipfw) processing.
 * The interface sends a response message back if the sender requested one. See
 * lib/core/message.c for the details.
 *
 * No queue has been implemented for the user message. The interface relies on
 * the user socket internal buffers to have enough space for caching.
 *
 * The user socket listens on an UDP port bound to IPv6 loopback.
 * Processing of user messages includes an access control mechanism based on the
 * port number. If the sender's port number is below 1024, it is running on
 * root privileges and has full access. Ports above 1024 have limited access
 * to functionality.
 *
 * @todo split the gigantic hip_handle_user_msg() into an array of handler functions
 */

#define _BSD_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/hip_udp.h"
#include "lib/core/hostid.h"
#include "lib/core/icomm.h"
#include "lib/core/ife.h"
#include "lib/core/linkedlist.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "lib/core/modularization.h"
#include "lib/tool/nlink.h"
#include "config.h"
#include "accessor.h"
#include "cert.h"
#include "close.h"
#include "cookie.h"
#include "esp_prot_anchordb.h"
#include "esp_prot_hipd_msg.h"
#include "hadb.h"
#include "hidb.h"
#include "hipd.h"
#include "hiprelay.h"
#include "hit_to_ip.h"
#include "init.h"
#include "maintenance.h"
#include "nat.h"
#include "netdev.h"
#include "nsupdate.h"
#include "output.h"
#include "registration.h"
#include "user.h"
#include "user_ipsec_hipd_msg.h"


struct usr_msg_handle {
    uint16_t priority;
    int      (*func_ptr)(struct hip_common *msg, struct sockaddr_in6 *src);
};

static struct hip_ll *hip_user_msg_handles[HIP_MSG_ROOT_MAX];

/**
 * Convert a local host id into LSI/HIT information and write the
 * result into a HIP message as a HIP_PARAM_HIT_INFO parameter.
 * Interprocess communications only.
 *
 * @param entry an local_host_id structure
 * @param msg a HIP user message where the HIP_PARAM_HIT_INFO
 *            parameter will be written
 * @return zero on success and negative on error
 */
static int host_id_entry_to_hit_info(struct local_host_id *entry, void *msg)
{
    struct hip_hit_info data;
    int                 err = 0;

    data.lhi = (struct hip_host_id_local) { entry->hit, entry->anonymous, hip_get_host_id_algo(&entry->host_id) };
    memcpy(&data.lsi, &entry->lsi, sizeof(hip_lsi_t));

    HIP_IFEL(hip_build_param_contents(msg,
                                      &data,
                                      HIP_PARAM_HIT_INFO,
                                      sizeof(data)),
             -1,
             "Error building parameter\n");

out_err:
    return err;
}

/**
 * Register a function for handling of the specified combination from packet
 * type and host association state.
 *
 * @param msg_type The packet type of the control message (RFC 5201, 5.3.)
 * @param handle_func Pointer to the function which should be called when
 *                    the combination of packet type and host association
 *                    state is reached.
 * @param priority Execution priority for the handle function.
 *
 * @return Success =  0
 *         Error   = -1
 */
int hip_user_register_handle(const uint8_t msg_type,
                             int (*handle_func)(struct hip_common *msg,
                                                struct sockaddr_in6 *src),
                             const uint16_t priority)
{
    int                    err       = 0;
    struct usr_msg_handle *new_entry = NULL;

    HIP_IFEL(!(new_entry = malloc(sizeof(struct usr_msg_handle))),
             -1,
             "Error on allocating memory for a handle function entry.\n");

    new_entry->priority = priority;
    new_entry->func_ptr = handle_func;

    hip_user_msg_handles[msg_type] =
        lmod_register_function(hip_user_msg_handles[msg_type],
                               new_entry,
                               priority);
    if (!hip_user_msg_handles[msg_type]) {
        HIP_ERROR("Error on registering a handle function.\n");
        err = -1;
    }
out_err:
    return err;
}

/**
 * Run all handle functions for specified combination from packet type and host
 * association state.
 *
 * @param msg_type The packet type of the control message (RFC 5201, 5.3.)
 * @param msg The message
 * @param src The source address
 *
 * @return Success =  0
 *         Error   = -1
 */
int hip_user_run_handles(const uint8_t msg_type,
                         struct hip_common *msg,
                         struct sockaddr_in6 *src)
{
    const struct hip_ll_node *iter = NULL;

    if (!hip_user_msg_handles[msg_type] ||
        !hip_ll_get_size(hip_user_msg_handles[msg_type])) {
        HIP_DEBUG("No user handles for message (type: %d) and not handled statically.\n", msg_type);
        return -1;
    }

    while ((iter = hip_ll_iterate(hip_user_msg_handles[msg_type],
                                  iter))) {
        ((struct usr_msg_handle *) iter->ptr)->func_ptr(msg, src);
    }

    return 0;
}

/**
 * Free the memory used for storage of handle functions.
 *
 */
void hip_user_uninit_handles(void)
{
    int i;

    for (i = 0; i < HIP_MSG_ROOT_MAX; i++) {
        if (hip_user_msg_handles[i]) {
            hip_ll_uninit(hip_user_msg_handles[i], free);
            free(hip_user_msg_handles[i]);
        }
    }
}

/**
 * send a response message back to the origin
 *
 * @param msg the message to send
 * @param dst the destination of the message
 * @return number of bytes sent on success, -1 on error
 */
int hip_sendto_user(const struct hip_common *msg, const struct sockaddr *dst)
{
    HIP_DEBUG("Sending msg type %d\n", hip_get_msg_type(msg));
    return sendto(hip_user_sock, msg, hip_get_msg_total_len(msg),
                  0, dst, hip_sockaddr_len(dst));
}

/** generic send function used to send messages to hipfw
 *
 * @param msg   the message to be sent
 * @return      0, if correct, else -1
 */
int hip_send_to_hipfw(const struct hip_common *msg)
{
    struct sockaddr_in6 hip_fw_addr;
    const struct in6_addr loopback = in6addr_loopback;

    HIP_ASSERT(msg != NULL);

    // destination is firewall
    hip_fw_addr.sin6_family = AF_INET6;
    hip_fw_addr.sin6_port   = htons(HIP_FIREWALL_PORT);
    ipv6_addr_copy(&hip_fw_addr.sin6_addr, &loopback);

    if (hip_sendto_user(msg, (struct sockaddr *) &hip_fw_addr) < 0) {
        HIP_ERROR("sending of message to firewall failed\n");
        return -1;
    }

    HIP_DEBUG("sending of message to firewall successful\n");

    return 0;
}

/**
 * Handles a user message.
 *
 * @note If you added a HIP_MSG_NEWMODE in lib/core/icomm.h, you also need to
 *       add a case block for your HIP_MSG_NEWMODE constant in the
 *       switch(msg_type) block in this function.
 * @param  msg  a pointer to the received user message HIP packet.
 * @param  src the origin of the sender
 * @return zero on success, or negative error value on error.
 */
int hip_handle_user_msg(struct hip_common *msg,
                        struct sockaddr_in6 *src)
{
    const hip_hit_t                       *src_hit   = NULL, *dst_hit = NULL;
    struct hip_hadb_state                 *entry     = NULL;
    int                                    err       = 0, msg_type = 0, reti = 0;
    int                                    access_ok = 0, is_root = 0, name_len;
    const struct hip_tlv_common           *param     = NULL;
    const struct hip_transformation_order *transorder;
    struct hip_hit_to_ip_set              *name_info;

    HIP_ASSERT(src->sin6_family == AF_INET6);
    HIP_DEBUG("User message from port %d\n", htons(src->sin6_port));

    err = hip_check_userspace_msg(msg);

    if (err) {
        HIP_ERROR("HIP socket option was invalid.\n");
        goto out_err;
    }

    msg_type = hip_get_msg_type(msg);

    is_root = ntohs(src->sin6_port) < 1024;
    if (is_root) {
        access_ok = 1;
    } else if (!is_root &&
               msg_type >= HIP_MSG_ANY_MIN && msg_type <= HIP_MSG_ANY_MAX) {
        access_ok = 1;
    }

    if (!access_ok) {
        HIP_ERROR("The user does not have privilege for this "
                  "operation. The operation is cancelled.\n");
        err = -1;
        goto out_err;
    }

    /* This prints numerical addresses until we have separate
     * print function for icomm.h and protodefs.h -miika */
    HIP_DEBUG("HIP user message type is: %d\n", msg_type);

    switch (msg_type) {
    case HIP_MSG_ADD_LOCAL_HI:
        err = hip_handle_add_local_hi(msg);
        break;
    case HIP_MSG_DEL_LOCAL_HI:
        err = hip_handle_del_local_hi(msg);
        break;
    case HIP_MSG_ADD_PEER_MAP_HIT_IP:
        HIP_DEBUG("Handling HIP_MSG_ADD_PEER_MAP_HIT_IP.\n");
        err = hip_add_peer_map(msg);
        if (err) {
            HIP_ERROR("add peer mapping failed.\n");
            goto out_err;
        }
        break;
    case HIP_MSG_RST:
        err = hip_send_close(msg, 1);
        break;
    case HIP_MSG_SET_NAT_NONE:
    case HIP_MSG_SET_NAT_PLAIN_UDP:
        HIP_IFEL(hip_user_nat_mode(msg_type),
                 -1,
                 "Error when setting daemon NAT status to \"on\"\n");

        HIP_DEBUG("Recreate all R1s\n");
        hip_recreate_all_precreated_r1_packets();
        break;
    case HIP_MSG_SET_LOCATOR_ON:
        HIP_DEBUG("Setting LOCATOR ON\n");
        hip_locator_status = HIP_MSG_SET_LOCATOR_ON;
        HIP_DEBUG("hip_locator status =  %d (should be %d)\n",
                  hip_locator_status, HIP_MSG_SET_LOCATOR_ON);
        HIP_DEBUG("Recreate all R1s\n");
        hip_recreate_all_precreated_r1_packets();
        break;
    case HIP_MSG_SET_LOCATOR_OFF:
        HIP_DEBUG("Setting LOCATOR OFF\n");
        hip_locator_status = HIP_MSG_SET_LOCATOR_OFF;
        HIP_DEBUG("hip_locator status =  %d (should be %d)\n",
                  hip_locator_status, HIP_MSG_SET_LOCATOR_OFF);
        hip_recreate_all_precreated_r1_packets();
        break;
    case HIP_MSG_SET_DEBUG_ALL:
        /* Displays all debugging messages. */
        HIP_IFEL(hip_set_logdebug(LOGDEBUG_ALL), -1,
                 "Error when setting daemon DEBUG status to ALL\n");
        break;
    case HIP_MSG_SET_DEBUG_MEDIUM:
        /* Removes debugging messages. */
        HIP_DEBUG("Handling DEBUG MEDIUM user message.\n");
        HIP_IFEL(hip_set_logdebug(LOGDEBUG_MEDIUM), -1,
                 "Error when setting daemon DEBUG status to MEDIUM\n");
        break;
    case HIP_MSG_SET_DEBUG_NONE:
        /* Removes debugging messages. */
        HIP_DEBUG("Handling DEBUG NONE user message.\n");
        HIP_IFEL(hip_set_logdebug(LOGDEBUG_NONE), -1,
                 "Error when setting daemon DEBUG status to NONE\n");
        break;
    case HIP_MSG_CONF_PUZZLE_NEW:
        err = hip_recreate_all_precreated_r1_packets();
        break;
    case HIP_MSG_CONF_PUZZLE_GET:
        err = hip_get_puzzle_difficulty_msg(msg);
        break;
    case HIP_MSG_CONF_PUZZLE_SET:
        err = hip_set_puzzle_difficulty_msg(msg);
        break;
    case HIP_MSG_CONF_PUZZLE_INC:
        dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT);
        hip_inc_cookie_difficulty();
        break;
    case HIP_MSG_CONF_PUZZLE_DEC:
        dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT);
        hip_dec_cookie_difficulty();
        break;
    case HIP_MSG_CERT_SPKI_VERIFY:
    {
        HIP_DEBUG("Got an request to verify SPKI cert\n");
        reti = hip_cert_spki_verify(msg);
        HIP_IFEL(reti, -1, "Verifying SPKI cert returned an error\n");
        HIP_DEBUG("SPKI cert verified sending it back to requester\n");
    }
    break;
    case HIP_MSG_CERT_SPKI_SIGN:
    {
        HIP_DEBUG("Got an request to sign SPKI cert sequence\n");
        reti = hip_cert_spki_sign(msg);
        HIP_IFEL(reti, -1, "Signing SPKI cert returned an error\n");
        HIP_DEBUG("SPKI cert signed sending it back to requester\n");
    }
    break;
    case HIP_MSG_CERT_X509V3_SIGN:
    {
        HIP_DEBUG("Got an request to sign X509v3 cert\n");
        reti = hip_cert_x509v3_handle_request_to_sign(msg);
        HIP_IFEL(reti, -1, "Signing of x509v3 cert returned an error\n");
        HIP_DEBUG("X509v3 cert signed sending it back to requester\n");
    }
    break;
    case HIP_MSG_CERT_X509V3_VERIFY:
    {
        HIP_DEBUG("Got an request to verify X509v3 cert\n");
        reti = hip_cert_x509v3_handle_request_to_verify(msg);
        HIP_IFEL(reti, -1, "Verification of x509v3 cert "
                           "returned an error\n");
        HIP_DEBUG("X509v3 verification ended "
                  "sending it back to requester\n");
    }
    break;
    case HIP_MSG_TRANSFORM_ORDER:
    {
        err = 0;
        HIP_IFEL(!(transorder = hip_get_param(msg, HIP_PARAM_TRANSFORM_ORDER)), -1,
                 "no transform order struct found (should contain transform order)\n");
        HIP_DEBUG("Transform order received from hipconf: %d\n", transorder->transorder);
        hip_transform_order = transorder->transorder;
        hip_recreate_all_precreated_r1_packets();
    }
    break;
#ifdef CONFIG_HIP_RVS
    case HIP_MSG_ADD_DEL_SERVER:
        err = hip_handle_req_user_msg(msg);
        break;
    case HIP_MSG_OFFER_RVS:
        /* draft-ietf-hip-registration-02 RVS registration. Rendezvous
         * server handles this message. Message indicates that the
         * current machine is willing to offer rendezvous service. This
         * message is received from hipconf. */
        HIP_DEBUG("Handling OFFER RENDEZVOUS user message.\n");

        hip_set_srv_status(HIP_SERVICE_RENDEZVOUS, HIP_SERVICE_ON);
        hip_relay_set_status(HIP_RELAY_ON);

        err = hip_recreate_all_precreated_r1_packets();
        break;
    case HIP_MSG_OFFER_FULLRELAY:
        HIP_IFEL(hip_firewall_set_esp_relay(1), -1,
                 "Failed to enable ESP relay in firewall\n");

        hip_set_srv_status(HIP_SERVICE_FULLRELAY, HIP_SERVICE_ON);
        hip_set_srv_status(HIP_SERVICE_RELAY, HIP_SERVICE_ON);
        hip_relay_set_status(HIP_RELAY_FULL);
        HIP_DEBUG("Handling OFFER FULLRELAY user message\n");
        err = hip_recreate_all_precreated_r1_packets();
        break;
    case HIP_MSG_OFFER_HIPRELAY:
        /* draft-ietf-hip-registration-02 HIPRELAY registration. Relay
         * server handles this message. Message indicates that the
         * current machine is willing to offer relay service. This
         * message is received from hipconf. */
        HIP_DEBUG("Handling OFFER HIPRELAY user message.\n");

        hip_set_srv_status(HIP_SERVICE_RELAY, HIP_SERVICE_ON);
        hip_relay_set_status(HIP_RELAY_ON);

        err = hip_recreate_all_precreated_r1_packets();
        break;
    case HIP_MSG_REINIT_RVS:
    case HIP_MSG_REINIT_RELAY:
        HIP_DEBUG("Handling REINIT RELAY or REINIT RVS user message.\n");
        HIP_IFEL(hip_relay_reinit(), -1,
                 "Unable to reinitialize the HIP relay / RVS service.\n");
        break;
    case HIP_MSG_CANCEL_RVS:
        HIP_DEBUG("Handling CANCEL RVS user message.\n");

        hip_set_srv_status(HIP_SERVICE_RENDEZVOUS, HIP_SERVICE_OFF);

        hip_relht_free_all_of_type(HIP_RVSRELAY);
        /* If all off the relay records were freed we can set the relay
         * status "off". */
        if (hip_relht_size() == 0) {
            hip_relay_set_status(HIP_RELAY_OFF);
        }

        /* We have to recreate the R1 packets so that they do not
         * advertise the RVS service anymore. I.e. we're removing
         * the REG_INFO parameters here. */
        err = hip_recreate_all_precreated_r1_packets();
        break;

    case HIP_MSG_CANCEL_HIPRELAY:
        HIP_DEBUG("Handling CANCEL RELAY user message.\n");

        hip_set_srv_status(HIP_SERVICE_RELAY, HIP_SERVICE_OFF);
        hip_relht_free_all_of_type(HIP_RELAY);
        break;
    case HIP_MSG_CANCEL_FULLRELAY:
        hip_set_srv_status(HIP_SERVICE_FULLRELAY, HIP_SERVICE_OFF);
        hip_relht_free_all_of_type(HIP_FULLRELAY);
        if (hip_firewall_is_alive()) {
            hip_firewall_set_esp_relay(0);
        }

        /* If all off the relay records were freed we can set the relay
         * status "off". */
        if (hip_relht_size() == 0) {
            hip_relay_set_status(HIP_RELAY_OFF);
        } else {
            hip_relay_set_status(HIP_RELAY_ON);
        }

        /* We have to recreate the R1 packets so that they do not
         * advertise the relay service anymore. I.e. we're removing
         * the REG_INFO parameters here. */
        err = hip_recreate_all_precreated_r1_packets();
        break;
#endif /* CONFIG_HIP_RVS */
    case HIP_MSG_GET_LOCAL_HITS:
        hip_msg_init(msg);
        hip_build_user_hdr(msg, HIP_MSG_GET_LOCAL_HITS, 0);
        err = hip_for_each_hi(host_id_entry_to_hit_info, msg);
        break;
    case HIP_MSG_GET_HA_INFO:
        hip_msg_init(msg);
        hip_build_user_hdr(msg, HIP_MSG_GET_HA_INFO, 0);
        err = hip_for_each_ha(hip_handle_get_ha_info, msg);
        break;
    case HIP_MSG_GET_DEFAULT_HIT:
        err = hip_get_default_hit_msg(msg);
        break;
    case HIP_MSG_USERSPACE_IPSEC:
        HIP_DUMP_MSG(msg);
        err = hip_userspace_ipsec_activate(msg);
        break;
    case HIP_MSG_RESTART_DUMMY_INTERFACE:
        set_up_device(HIP_HIT_DEV, 0);
        err = set_up_device(HIP_HIT_DEV, 1);
        break;
    case HIP_MSG_ESP_PROT_TFM:
        HIP_DUMP_MSG(msg);
        err = esp_prot_set_preferred_transforms(msg);
        break;
    case HIP_MSG_BEX_STORE_UPDATE:
        HIP_DUMP_MSG(msg);
        err = anchor_db_update(msg);
        break;
    case HIP_MSG_TRIGGER_UPDATE:
        HIP_DUMP_MSG(msg);
        err = esp_prot_handle_trigger_update_msg(msg);
        break;
    case HIP_MSG_ANCHOR_CHANGE:
        HIP_DUMP_MSG(msg);
        err = esp_prot_handle_anchor_change_msg(msg);
        break;
    case HIP_MSG_GET_LSI_PEER:
        while ((param = hip_get_next_param(msg, param))) {
            if (hip_get_param_type(param) == HIP_PARAM_HIT) {
                if (!dst_hit) {
                    dst_hit = hip_get_param_contents_direct(param);
                    HIP_DEBUG_HIT("dst_hit", dst_hit);
                } else {
                    src_hit = hip_get_param_contents_direct(param);
                    HIP_DEBUG_HIT("src_hit", src_hit);
                }
            }
        }
        if (src_hit && dst_hit) {
            entry = hip_hadb_find_byhits(src_hit, dst_hit);
        } else if (dst_hit) {
            entry = hip_hadb_try_to_find_by_peer_hit(dst_hit);
        }
        if (entry && IS_LSI32(entry->lsi_peer.s_addr)) {
            HIP_IFE(hip_build_param_contents(msg, &entry->lsi_peer,
                                             HIP_PARAM_LSI, sizeof(hip_lsi_t)), -1);
            HIP_IFE(hip_build_param_contents(msg, &entry->lsi_our,
                                             HIP_PARAM_LSI, sizeof(hip_lsi_t)), -1);
        } else if (dst_hit) {         /* Assign a new LSI */
            struct hip_common msg_tmp = { 0 };
            hip_lsi_t         lsi;

            hip_generate_peer_lsi(&lsi);
            HIP_IFE(hip_build_param_contents(&msg_tmp, dst_hit,
                                             HIP_PARAM_HIT, sizeof(hip_hit_t)), -1);
            HIP_IFE(hip_build_param_contents(&msg_tmp, &lsi,
                                             HIP_PARAM_LSI, sizeof(hip_lsi_t)), -1);
            hip_add_peer_map(&msg_tmp);
            HIP_IFE(hip_build_param_contents(msg, &lsi,
                                             HIP_PARAM_LSI, sizeof(hip_lsi_t)), -1);
        }
        break;
    case HIP_MSG_SET_NAT_PORT:
    {
        const struct hip_port_info *nat_port;

        nat_port = hip_get_param(msg, HIP_PARAM_LOCAL_NAT_PORT);
        if (nat_port) {
            HIP_DEBUG("Setting local NAT port\n");
            hip_set_local_nat_udp_port(nat_port->port);
            /* We need to recreate only the input socket to bind to the new
             * port. Output port must be left intact as it is a raw socket */
            close(hip_nat_sock_input_udp);
            hip_nat_sock_input_udp = 0;
            hip_create_nat_sock_udp(&hip_nat_sock_input_udp, 0, 0);
        } else {
            HIP_DEBUG("Setting peer NAT port\n");
            HIP_IFEL(!(nat_port = hip_get_param(msg, HIP_PARAM_PEER_NAT_PORT)),
                     -1, "No nat port param found\n");
            hip_set_peer_nat_udp_port(nat_port->port);
        }
        break;
    }
    case HIP_MSG_NSUPDATE_OFF:
    case HIP_MSG_NSUPDATE_ON:
        hip_set_nsupdate_status((msg_type == HIP_MSG_NSUPDATE_OFF) ? 0 : 1);
        if (msg_type == HIP_MSG_NSUPDATE_ON) {
            nsupdate(1);
        }
        break;

    case HIP_MSG_HIT_TO_IP_OFF:
    case HIP_MSG_HIT_TO_IP_ON:
        hip_set_hit_to_ip_status((msg_type == HIP_MSG_NSUPDATE_OFF) ? 0 : 1);
        break;

    case HIP_MSG_HIT_TO_IP_SET:
    {
        err = 0;
        HIP_IFEL(!(name_info = hip_get_param_readwrite(msg,
                                                       HIP_PARAM_HIT_TO_IP_SET)),
                 -1, "no name struct found\n");
        HIP_DEBUG("Name in name_info %s\n", name_info->name);
        name_len = strlen(name_info->name);
        if (name_len >= 1) {
            if (name_info->name[name_len - 1] != '.') {
                HIP_DEBUG("final dot is missing");
                if (name_len < HIT_TO_IP_ZONE_MAX_LEN - 2) {
                    HIP_DEBUG("adding final dot");
                    name_info->name[name_len]     = '.';
                    name_info->name[name_len + 1] = 0;
                    HIP_DEBUG("new name %s\n", name_info->name);
                }
            }
        }
        hip_hit_to_ip_set(name_info->name);
    }
    break;
    case HIP_MSG_SHOTGUN_ON:
        HIP_DEBUG("Setting SHOTGUN ON\n");
        hip_shotgun_status = HIP_MSG_SHOTGUN_ON;
        HIP_DEBUG("hip_shotgun_status =  %d (should be %d)\n",
                  hip_shotgun_status, HIP_MSG_SHOTGUN_ON);
        break;

    case HIP_MSG_SHOTGUN_OFF:
        HIP_DEBUG("Setting SHOTGUN OFF\n");
        hip_shotgun_status = HIP_MSG_SHOTGUN_OFF;
        HIP_DEBUG("hip_shotgun_status =  %d (should be %d)\n",
                  hip_shotgun_status, HIP_MSG_SHOTGUN_OFF);
        break;
    case HIP_MSG_MAP_ID_TO_ADDR:
    {
        const struct in6_addr *id  = NULL;
        const hip_hit_t       *hit = NULL;
        hip_lsi_t              lsi;
        struct in6_addr        addr;

        HIP_IFE(!(param = hip_get_param(msg, HIP_PARAM_IPV6_ADDR)), -1);
        HIP_IFE(!(id = hip_get_param_contents_direct(param)), -1);

        if (IN6_IS_ADDR_V4MAPPED(id)) {
            IPV6_TO_IPV4_MAP(id, &lsi);
        } else {
            hit = id;
        }

        HIP_IFEL(hip_map_id_to_addr(hit, &lsi, &addr), -1,
                 "Couldn't determine address\n");
        hip_msg_init(msg);
        HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_MAP_ID_TO_ADDR, 0), -1,
                 "Build header failed\n");
        HIP_IFEL(hip_build_param_contents(msg, &addr,
                                          HIP_PARAM_IPV6_ADDR, sizeof(addr)),
                 -1, "Build param failed\n");
        break;
    }
    case HIP_MSG_FIREWALL_START:
        hip_firewall_status = 1;
        break;
    case HIP_MSG_FIREWALL_QUIT:
        hip_firewall_status = 0;
        if (hip_relay_get_status() == HIP_RELAY_FULL) {
            hip_relay_set_status(HIP_RELAY_ON);
            hip_set_srv_status(HIP_SERVICE_FULLRELAY, HIP_SERVICE_OFF);
            hip_relht_free_all_of_type(HIP_FULLRELAY);
            err = hip_recreate_all_precreated_r1_packets();
        }
        break;
    case HIP_MSG_LSI_TO_HIT:
    {
        const hip_lsi_t       *lsi;
        struct hip_hadb_state *ha;

        HIP_IFE(!(param = hip_get_param(msg, HIP_PARAM_LSI)), -1);
        HIP_IFE(!(lsi = hip_get_param_contents_direct(param)), -1);
        if (!(ha = hip_hadb_try_to_find_by_peer_lsi(lsi))) {
            HIP_DEBUG("No HA found\n");
            goto out_err;
        }
        hip_msg_init(msg);
        HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_LSI_TO_HIT, 0), -1,
                 "Build header failed\n");
        HIP_IFEL(hip_build_param_contents(msg, &ha->hit_peer,
                                          HIP_PARAM_IPV6_ADDR, sizeof(struct in6_addr)),
                 -1, "Build param failed\n");
        break;
    }
    case HIP_MSG_BROADCAST_ON:
        HIP_DEBUG("Setting BROADCAST ON\n");
        hip_broadcast_status = HIP_MSG_BROADCAST_ON;
        HIP_DEBUG("hip_broadcast_status =  %d (should be %d)\n",
                  hip_broadcast_status, HIP_MSG_BROADCAST_ON);
        break;

    case HIP_MSG_BROADCAST_OFF:
        HIP_DEBUG("Setting BROADCAST OFF\n");
        hip_broadcast_status = HIP_MSG_BROADCAST_OFF;
        HIP_DEBUG("hip_broadcast_status =  %d (should be %d)\n",
                  hip_broadcast_status, HIP_MSG_BROADCAST_OFF);
        break;
    default:
        if (hip_user_run_handles(msg_type, msg, src) < 0) {
            HIP_ERROR("Unknown socket option (%d)\n", msg_type);
            err = -ESOCKTNOSUPPORT;
        }
    }

out_err:
    return err;
}
