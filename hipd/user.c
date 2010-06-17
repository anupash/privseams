/** @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
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
 * @author  Miika Komu <miika_iki.fi>
 * @author  Kristian Slavov <kslavov_hiit.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @author  Tao Wan  <twan_cc.hut.fi>
 * @author  Rene Hummen
 * @author  Tim Just
 * @todo split the gigantic hip_handle_user_msg() into an array of handler functions
 */

#define _BSD_SOURCE

#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

#include "config.h"
#include "accessor.h"
#include "user.h"
#include "esp_prot_anchordb.h"
#include "lib/core/hostid.h"
#include "lib/core/hip_udp.h"
#include "hipd.h"
#include "lib/modularization/lmod.h"

struct usr_msg_handle {
    uint16_t priority;
    int    (*func_ptr)(hip_common_t *msg, struct sockaddr_in6 *src);
};

static hip_ll_t *hip_user_msg_handles[HIP_MSG_ROOT_MAX];

/**
 * Register a function for handling of the specified combination from packet
 * type and host association state.
 *
 * @param msg_type The packet type of the control message (RFC 5201, 5.3.)
 * @param *handle_func Pointer to the function which should be called
 *                         when the combination of packet type and host
 *                         association state is reached.
 * @param priority Execution priority for the handle function.
 *
 * @return Success =  0
 *         Error   = -1
 */
int hip_user_register_handle(const uint8_t msg_type,
                             int (*handle_func)(hip_common_t *msg,
                                                struct sockaddr_in6 *src),
                             const uint16_t priority)
{
    int err = 0;
    struct usr_msg_handle *new_entry = NULL;

    HIP_IFEL(!(new_entry = malloc(sizeof(struct usr_msg_handle))),
             -1,
             "Error on allocating memory for a handle function entry.\n");

    new_entry->priority    = priority;
    new_entry->func_ptr    = handle_func;

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
                         hip_common_t *msg,
                         struct sockaddr_in6 *src)
{
    hip_ll_node_t *iter = NULL;

    if (!hip_user_msg_handles[msg_type] ||
        !hip_ll_get_size(hip_user_msg_handles[msg_type])) {
        HIP_DEBUG("User message (type: %d) not dynamically handled -> " \
                  "trigger static handling.\n", msg_type);
        return 1;
    }

    while ((iter = hip_ll_iterate(hip_user_msg_handles[msg_type],
                                  iter))) {

        ((struct usr_msg_handle *) iter->ptr)->func_ptr(msg, src);
    }

    return 0;
}

/**
 * hip_uninit_handle_functions
 *
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
 * @return zero on success, or negative error value on error.
 */
int hip_sendto_user(const struct hip_common *msg, const struct sockaddr *dst)
{
    HIP_DEBUG("Sending msg type %d\n", hip_get_msg_type(msg));
    return sendto(hip_user_sock, msg, hip_get_msg_total_len(msg),
                  0, dst, hip_sockaddr_len(dst));
}

/**
 * Handles a user message.
 *
 * @note If you added a HIP_MSG_NEWMODE in lib/core/icomm.h, you also need to
 *       add a case block for your HIP_MSG_NEWMODE constant in the
 *       switch(msg_type) block in this function.
 * @param  msg  a pointer to the received user message HIP packet.
 * @param  src the origin of the sender
 * @param  send_response response
 * @return zero on success, or negative error value on error.
 */
int hip_handle_user_msg(hip_common_t *msg,
                        struct sockaddr_in6 *src,
                        int *send_response)
{
    hip_hit_t *src_hit           = NULL, *dst_hit = NULL;
    hip_ha_t *entry              = NULL;
    int err                      = 0, msg_type = 0, n = 0, reti = 0;
    int access_ok                = 0, is_root = 0;
    struct hip_tlv_common *param = NULL;

    HIP_ASSERT(src->sin6_family == AF_INET6);
    HIP_DEBUG("User message from port %d\n", htons(src->sin6_port));

    err = hip_check_userspace_msg(msg);

    if (err) {
        HIP_ERROR("HIP socket option was invalid.\n");
        goto out_err;
    }

    msg_type      = hip_get_msg_type(msg);

    is_root       = (ntohs(src->sin6_port) < 1024);
    if (is_root) {
        access_ok = 1;
    } else if (!is_root &&
               (msg_type >= HIP_MSG_ANY_MIN && msg_type <= HIP_MSG_ANY_MAX)) {
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
    case HIP_MSG_NULL_OP:
        HIP_DEBUG("Null op\n");
        break;
    case HIP_MSG_PING:
        break;
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
        err                = hip_send_close(msg, 1);
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
        err     = hip_recreate_all_precreated_r1_packets();
        break;
    case HIP_MSG_CONF_PUZZLE_GET:
        err     = hip_get_puzzle_difficulty_msg(msg);
        break;
    case HIP_MSG_CONF_PUZZLE_SET:
        err     = hip_set_puzzle_difficulty_msg(msg);
        break;
    case HIP_MSG_CONF_PUZZLE_INC:
        dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT);
        hip_inc_cookie_difficulty();
        break;
    case HIP_MSG_CONF_PUZZLE_DEC:
        dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT);
        hip_dec_cookie_difficulty();
        break;
#ifdef CONFIG_HIP_OPPORTUNISTIC
    case HIP_MSG_GET_PEER_HIT:
        err = hip_opp_get_peer_hit(msg, src);
        break;
#endif
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
        struct hip_transformation_order *transorder;
        HIP_IFEL(!(transorder = hip_get_param(msg, HIP_PARAM_TRANSFORM_ORDER)), -1,
                 "no transform order struct found (should contain transform order)\n");
        HIP_DEBUG("Transform order received from hipconf: %d\n", transorder->transorder);
        hip_transform_order = transorder->transorder;
        hip_recreate_all_precreated_r1_packets();
    }
    break;
#ifdef CONFIG_HIP_RVS
    case HIP_MSG_ADD_DEL_SERVER:
    {
        /* RFC 5203 service registration. The requester, i.e. the client
         * of the server handles this message. Message indicates that
         * the hip daemon wants either to register to a server for
         * additional services or it wants to cancel a registration.
         * Cancellation is identified with a zero lifetime. */
        struct hip_reg_request *reg_req    = NULL;
        hip_pending_request_t *pending_req = NULL;
        uint8_t *reg_types                 = NULL;
        in6_addr_t *dst_ip                 = NULL;
        int i                              = 0, type_count = 0;
        int opp_mode                       = 0;
        int add_to_global                  = 0;
        struct sockaddr_in6 sock_addr6;
        struct sockaddr_in sock_addr;
        struct in6_addr server_addr, hitr;
#ifdef CONFIG_HIP_OPPORTUNISTIC
        struct in6_addr *hit_local;
#endif

        /* Get RVS IP address, HIT and requested lifetime given as
         * commandline parameters to hipconf. */

        dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT);
        dst_ip  = hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR);
        reg_req = hip_get_param(msg, HIP_PARAM_REG_REQUEST);

        /* Register to an LSI, no IP address */
        if (dst_ip && !dst_hit && !ipv6_addr_is_hit(dst_ip)) {
            struct in_addr lsi;

            IPV6_TO_IPV4_MAP(dst_ip, &lsi);
            memset(&hitr, 0, sizeof(hitr));
            memset(&server_addr, 0, sizeof(server_addr));

            if (IS_LSI32(lsi.s_addr) &&
                !hip_map_id_to_addr(&hitr, &lsi, &server_addr)) {
                dst_ip = &server_addr;
                /* Note: next map_id below fills the HIT */
            }
        }

        /* Register to a HIT without IP address */
        if (dst_ip && !dst_hit && ipv6_addr_is_hit(dst_ip)) {
            struct in_addr bcast = { INADDR_BROADCAST };
            if (hip_map_id_to_addr(dst_ip, NULL,
                                   &server_addr)) {
                IPV4_TO_IPV6_MAP(&bcast, &server_addr);
            }
            dst_hit = dst_ip;
            dst_ip  = &server_addr;
        }

        if (dst_hit == NULL) {
            HIP_DEBUG("No HIT parameter found from the user " \
                      "message. Trying opportunistic mode \n");
            opp_mode = 1;
        } else if (dst_ip == NULL)   {
            HIP_ERROR("No IPV6 parameter found from the user " \
                      "message.\n");
            err = -1;
            goto out_err;
        } else if (reg_req == NULL)   {
            HIP_ERROR("No REG_REQUEST parameter found from the " \
                      "user message.\n");
            err = -1;
            goto out_err;
        }

        if (!opp_mode) {
            HIP_IFEL(hip_hadb_add_peer_info(dst_hit, dst_ip,
                                            NULL, NULL),
                     -1, "Error on adding server "  \
                         "HIT to IP address mapping to the hadb.\n");

            /* Fetch the hadb entry just created. */
            entry = hip_hadb_try_to_find_by_peer_hit(dst_hit);

            if (entry == NULL) {
                HIP_ERROR("Error on fetching server HIT to IP address " \
                          "mapping from the haDB.\n");
                err = -1;
                goto out_err;
            }
        }
#ifdef CONFIG_HIP_OPPORTUNISTIC
        else {
            hit_local = malloc(sizeof(struct in6_addr));
            HIP_IFEL(hip_get_default_hit(hit_local), -1,
                     "Error retrieving default HIT \n");
            entry     = hip_opp_add_map(dst_ip, hit_local, src);
        }
#endif
        reg_types  = reg_req->reg_type;
        type_count = hip_get_param_contents_len(reg_req) -
                     sizeof(reg_req->lifetime);

        for (; i < type_count; i++) {
            pending_req = malloc(sizeof(hip_pending_request_t));
            if (pending_req == NULL) {
                HIP_ERROR("Error on allocating memory for a " \
                          "pending registration request.\n");
                err = -1;
                goto out_err;
            }

            pending_req->entry    = entry;
            pending_req->reg_type = reg_types[i];
            pending_req->lifetime = reg_req->lifetime;
            pending_req->created  = time(NULL);

            HIP_DEBUG("Adding pending service request for service %u.\n",
                      reg_types[i]);
            hip_add_pending_request(pending_req);

            /* Set the request flag. */
            switch (reg_types[i]) {
            case HIP_SERVICE_RENDEZVOUS:
                hip_hadb_set_local_controls(
                    entry, HIP_HA_CTRL_LOCAL_REQ_RVS);
                add_to_global = 1;
                break;
            case HIP_SERVICE_RELAY:
                hip_hadb_set_local_controls(
                    entry, HIP_HA_CTRL_LOCAL_REQ_RELAY);
                /* Don't ask for ICE from relay */
                entry->nat_mode = 1;
                add_to_global   = 1;
                break;
            case HIP_SERVICE_FULLRELAY:
                hip_hadb_set_local_controls(
                    entry, HIP_HA_CTRL_LOCAL_REQ_FULLRELAY);
                entry->nat_mode = 1;
                add_to_global   = 1;
                break;
            default:
                HIP_INFO("Undefined service type (%u) " \
                         "requested in the service " \
                         "request.\n", reg_types[i]);
                /* For testing purposes we allow the user to
                 * request services that HIPL does not support.
                 */
                hip_hadb_set_local_controls(
                    entry, HIP_HA_CTRL_LOCAL_REQ_UNSUP);
                /*
                 * HIP_DEBUG("Deleting pending service request "\
                 * "for service %u.\n", reg_types[i]);
                 * hip_del_pending_request_by_type(entry,
                 * reg_types[i]);
                 */
                break;
            }
        }

        if (add_to_global) {
            if (IN6_IS_ADDR_V4MAPPED(dst_ip)) {
                memset(&sock_addr, 0, sizeof(sock_addr));
                IPV6_TO_IPV4_MAP(dst_ip, &sock_addr.sin_addr);
                sock_addr.sin_family = AF_INET;
                /* The server address is added with 0 interface index */
                hip_add_address_to_list((struct sockaddr *) &sock_addr,
                                    0,
                                    HIP_FLAG_CONTROL_TRAFFIC_ONLY);

            } else {
                memset(&sock_addr6, 0, sizeof(sock_addr6));
                sock_addr6.sin6_family = AF_INET6;
                sock_addr6.sin6_addr   = *dst_ip;
                /* The server address is added with 0 interface index */
                hip_add_address_to_list((struct sockaddr *) &sock_addr6,
                                    0,
                                    HIP_FLAG_CONTROL_TRAFFIC_ONLY);
            }
        }

        /* Workaround for bug id 880 until bug id 589 is implemented.
         * -miika  */
        if (entry->state != HIP_STATE_NONE || HIP_STATE_UNASSOCIATED) {
            hip_common_t *msg2 = calloc(HIP_MAX_PACKET, 1);
            HIP_IFE((msg2 == 0), -1);
            HIP_IFE(hip_build_user_hdr(msg2, HIP_MSG_RST, 0), -1);
            HIP_IFE(hip_build_param_contents(msg2,
                                             &entry->hit_peer,
                                             HIP_PARAM_HIT,
                                             sizeof(hip_hit_t)),
                    -1);
            hip_send_close(msg2, 0);
            free(msg2);
        }

        /* Send a I1 packet to the server (registrar). */

        /** @todo When registering to a service or cancelling a service,
         *  we should first check the state of the host association that
         *  is registering. When it is ESTABLISHED or R2-SENT, we have
         *  already successfully carried out a base exchange and we
         *  must use an UPDATE packet to carry a REG_REQUEST parameter.
         *  When the state is not ESTABLISHED or R2-SENT, we launch a
         *  base exchange using an I1 packet. */
        HIP_IFEL(hip_send_i1(&entry->hit_our, dst_hit, entry), -1,
                 "Error on sending I1 packet to the server.\n");
        break;
    }
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
        HIP_IFEL(hip_relay_reinit(), -1, "Unable to reinitialize " \
                                         "the HIP relay / RVS service.\n");
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
    case HIP_MSG_GET_HITS:
        hip_msg_init(msg);
        hip_build_user_hdr(msg, HIP_MSG_GET_HITS, 0);
        err = hip_for_each_hi(hip_host_id_entry_to_hit_info, msg);
        break;
    case HIP_MSG_GET_HA_INFO:
        hip_msg_init(msg);
        hip_build_user_hdr(msg, HIP_MSG_GET_HA_INFO, 0);
        err              = hip_for_each_ha(hip_handle_get_ha_info, msg);
        break;
    case HIP_MSG_DEFAULT_HIT:
        err              =  hip_get_default_hit_msg(msg);
        break;
    case HIP_MSG_MHADDR_ACTIVE:
        is_active_mhaddr = 1;
        break;
    case HIP_MSG_MHADDR_LAZY:
        is_active_mhaddr = 0;
        break;
    case HIP_MSG_HANDOVER_HARD:
        is_hard_handover = 1;
        break;
    case HIP_MSG_HANDOVER_SOFT:
        is_hard_handover = 0;
        break;
    case HIP_MSG_RESTART:
        HIP_DEBUG("Restart message received, restarting HIP daemon now!!!\n");
        hipd_set_flag(HIPD_FLAG_RESTART);
        /* invoking the signal handler directly is not a sane thing to do */
        kill(getpid(), SIGINT);
        break;
    case HIP_MSG_SET_DATAPACKET_MODE_ON:
    {
        struct sockaddr_in6 sock_addr;
        HIP_DEBUG("HIP_MSG_SET_DATAPACKET_MODE_ON\n");
        HIP_DUMP_MSG(msg);

        hip_use_userspace_data_packet_mode = 1;

        memset(&sock_addr, 0, sizeof(sock_addr));
        sock_addr.sin6_family              = AF_INET6;
        sock_addr.sin6_port                = htons(HIP_FIREWALL_PORT);
        sock_addr.sin6_addr                = in6addr_loopback;

        n  = hip_sendto_user(msg, (struct sockaddr *) &sock_addr);
        if (n <= 0) {
            HIP_ERROR("hipconf datapacket  failed \n");
        } else {
            HIP_DEBUG("hipconf datapacket ok (sent %d bytes)\n", n);
            break;
        }
        *send_response = 1;
        break;
    }

    case HIP_MSG_SET_DATAPACKET_MODE_OFF:
    {
        struct sockaddr_in6 sock_addr_1;
        HIP_DEBUG("HIP_MSG_SET_DATAPACKET_MODE_OFF\n");
        HIP_DUMP_MSG(msg);

        hip_use_userspace_data_packet_mode = 0;

        //firewall socket address
        memset(&sock_addr_1, 0, sizeof(sock_addr_1));
        sock_addr_1.sin6_family            = AF_INET6;
        sock_addr_1.sin6_port              = htons(HIP_FIREWALL_PORT);
        sock_addr_1.sin6_addr              = in6addr_loopback;

        n = hip_sendto_user(msg, (struct sockaddr *) &sock_addr_1);
        if (n <= 0) {
            HIP_ERROR("hipconf datapacket  failed \n");
        } else {
            HIP_DEBUG("hipconf datapacket ok (sent %d bytes)\n", n);
        }
        *send_response = 1;
        break;
    }

    case HIP_MSG_BUILD_HOST_ID_SIGNATURE_DATAPACKET:
    {
        int original_type;
        hip_hit_t data_hit;

        HIP_IFEL(hip_get_any_localhost_hit(&data_hit, HIP_HI_DEFAULT_ALGO, 0), -1,
                 "No HIT found\n");

        HIP_DEBUG("HIP_MSG_BUILD_HOST_ID_SIGNATURE_DATAPACKET");

        original_type = msg->type_hdr;

        /* We are about the sign the packet ..
         * So change the MSG type to HIP_DATA and then reset it to original */
        msg->type_hdr = HIP_DATA;
        err           = hip_build_host_id_and_signature(msg, &data_hit);
        msg->type_hdr = original_type;

        *send_response = 1;
        goto out_err;
    }
    break;

    case HIP_MSG_TRIGGER_BEX:
        HIP_DEBUG("HIP_MSG_TRIGGER_BEX\n");
        hip_firewall_status = 1;
        err                 = hip_netdev_trigger_bex_msg(msg);
        goto out_err;
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
                    dst_hit = (struct in6_addr *) hip_get_param_contents_direct(param);
                    HIP_DEBUG_HIT("dst_hit", dst_hit);
                } else {
                    src_hit = (struct in6_addr *) hip_get_param_contents_direct(param);
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
            struct hip_common msg_tmp;
            hip_lsi_t lsi;

            memset(&msg_tmp, 0, sizeof(msg_tmp));
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
        struct hip_port_info *nat_port;

        nat_port = hip_get_param(msg, HIP_PARAM_LOCAL_NAT_PORT);
        if (nat_port) {
            HIP_DEBUG("Setting local NAT port\n");
            hip_set_local_nat_udp_port(nat_port->port);
            /* We need to recreate only the input socket to bind to the new
               port. Output port must be left intact as it is a raw socket */
            close(hip_nat_sock_input_udp);
            hip_nat_sock_input_udp  = 0;
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
        struct hip_hit_to_ip_set *name_info;
        HIP_IFEL(!(name_info = hip_get_param(msg, HIP_PARAM_HIT_TO_IP_SET)), -1,
                 "no name struct found\n");
        HIP_DEBUG("Name in name_info %s\n", name_info->name);
        int name_len = strlen(name_info->name);
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
        struct in6_addr *id = NULL;
        hip_hit_t *hit      = NULL;
        hip_lsi_t lsi;
        struct in6_addr addr;

        HIP_IFE(!(param = hip_get_param(msg, HIP_PARAM_IPV6_ADDR)), -1);
        HIP_IFE(!(id = hip_get_param_contents_direct(param)), -1);

        if (IN6_IS_ADDR_V4MAPPED(id)) {
            IPV6_TO_IPV4_MAP(id, &lsi);
        } else {
            hit = id;
        }

        memset(&addr, 0, sizeof(addr));
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
        hip_lsi_t *lsi;
        hip_ha_t *ha;

        HIP_IFE(!(param = hip_get_param(msg, HIP_PARAM_LSI)), -1);
        HIP_IFE(!(lsi =  hip_get_param_contents_direct(param)), -1);
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
    default:
        HIP_ERROR("Unknown socket option (%d)\n", msg_type);
        err = -ESOCKTNOSUPPORT;
    }

out_err:
    return err;
}
