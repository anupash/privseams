/**
 * @file
 * This file defines various functions for sending, handling and receiving
 * UPDATE packets for the Host Identity Protocol (HIP). This file is under
 * heavy editing currently.
 *
 * TODO: Doxygen documentation is missing. Please fix this.
 *
 * @author  Baris Boyvat <baris#boyvat.com>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */

/* requiread for s6_addr32 */
#define _BSD_SOURCE

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "update.h"

#include "lib/core/builder.h"
#include "lib/core/protodefs.h"
#include "hipd/netdev.h"
#include "update_legacy.h"

#ifdef CONFIG_HIP_PERFORMANCE
#include "lib/performance/performance.h"
#endif

#ifdef CONFIG_HIP_MIDAUTH
#include "hipd/pisa.h"
#endif

int update_id_window_size = 50;

int hip_create_locators(hip_common_t *locator_msg,
                        struct hip_locator_info_addr_item **locators)
{
    int err = 0;
    struct hip_locator *loc;

    hip_msg_init(locator_msg);
    HIP_IFEL(hip_build_user_hdr(locator_msg,
                                SO_HIP_SET_LOCATOR_ON, 0), -1,
             "Failed to add user header\n");
    HIP_IFEL(hip_build_locators_old(locator_msg, 0), -1,
             "Failed to build locators\n");
    loc       = hip_get_param(locator_msg, HIP_PARAM_LOCATOR);
    hip_print_locator_addresses(locator_msg);
    *locators = hip_get_locator_first_addr_item(loc);

out_err:
    return err;
}

/// @todo : should we implement base draft update with ifindex 0 stuff ??
/// @todo :  Divide this function into more pieces, handle_spi, handle_seq, etc
/// @todo : Remove the uncommented lines?
static int hip_create_update_msg(hip_common_t *received_update_packet,
                                 struct hip_hadb_state *ha, hip_common_t *update_packet_to_send,
                                 struct hip_locator_info_addr_item *locators,
                                 int type)
{
    int err                               = 0;

    uint32_t update_id_out                = 0;
    uint32_t esp_info_old_spi             = 0, esp_info_new_spi = 0;
    uint16_t mask                         = 0;
    struct hip_seq *seq                   = NULL;
    struct hip_echo_request *echo_request = NULL;

    HIP_DEBUG("Creating the UPDATE packet\n");

    if (type != HIP_UPDATE_LOCATOR) {
        HIP_DEBUG("UPDATE without locators\n");
    }

    ha->hadb_misc_func->hip_build_network_hdr(update_packet_to_send, HIP_UPDATE,
                                              mask, &ha->hit_our,
                                              &ha->hit_peer);

    // Add ESP_INFO
    if (type == HIP_UPDATE_LOCATOR || type == HIP_UPDATE_ECHO_REQUEST) {
        // Handle SPI numbers
        esp_info_old_spi = ha->spi_inbound_current;
        esp_info_new_spi = ha->spi_inbound_current;

        HIP_DEBUG("esp_info_old_spi=0x%x esp_info_new_spi=0x%x\n",
                  esp_info_old_spi, esp_info_new_spi);

        HIP_IFEL(hip_build_param_esp_info(update_packet_to_send, ha->current_keymat_index,
                                          esp_info_old_spi, esp_info_new_spi),
                 -1, "Building of ESP_INFO param failed\n");
    }

    // Add LOCATOR
    if (type == HIP_UPDATE_LOCATOR) {
        HIP_DEBUG("locators = 0x%p locator_count = %d\n", locators, address_count);
        err = hip_build_param_locator(update_packet_to_send, locators, address_count);
    }

#ifdef CONFIG_HIP_MIDAUTH
    /* TODO: no caching is done for PUZZLE_M parameters. This may be
     * a DOS attack vector.
     */
    if (received_update_packet && type == HIP_UPDATE_ECHO_REQUEST) {
        HIP_IFEL(hip_solve_puzzle_m(update_packet_to_send, received_update_packet, ha), -1,
                 "Building of Challenge_Response failed\n");
    } else {
        HIP_DEBUG("msg is NULL, midauth parameters not included in reply\n");
    }

    /* TODO: no caching is done for PUZZLE_M parameters. This may be
     * a DOS attack vector.
     */
    if (type == HIP_UPDATE_ECHO_RESPONSE) {
        HIP_IFEL(hip_solve_puzzle_m(update_packet_to_send, received_update_packet, ha), -1,
                 "Building of Challenge_Response failed\n");
    }
#endif

    // Add SEQ
    if (type == HIP_UPDATE_LOCATOR || type == HIP_UPDATE_ECHO_REQUEST) {
        // TODO check the following function!
        /* hip_update_set_new_spi_in_old(ha, esp_info_old_spi,
         *  esp_info_new_spi, 0);*/

        ha->update_id_out++;
        update_id_out = ha->update_id_out;
        _HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
        /** @todo Handle this case. */
        HIP_IFEL(hip_build_param_seq(update_packet_to_send, update_id_out), -1,
                 "Building of SEQ param failed\n");

        /* remember the update id of this update */
        /* hip_update_set_status(ha, esp_info_old_spi,
         *  0x1 | 0x2 | 0x8, update_id_out, 0, NULL,
         *  ha->current_keymat_index); */

        /************************************************/
    }

    // Add ACK
    if (type == HIP_UPDATE_ECHO_REQUEST || type == HIP_UPDATE_ECHO_RESPONSE) {
        HIP_IFEL(!(seq = hip_get_param(received_update_packet,
                                       HIP_PARAM_SEQ)), -1, "SEQ not found\n");

        HIP_IFEL(hip_build_param_ack(update_packet_to_send,
                                     ntohl(seq->update_id)), -1, "Building of ACK failed\n");
    }

#ifdef CONFIG_HIP_MIDAUTH

    if (type == HIP_UPDATE_ECHO_RESPONSE) {
        HIP_IFEL(hip_build_param(update_packet_to_send, ha->our_pub), -1,
                 "Building of host id failed\n");
    }

    if (type == HIP_UPDATE_ECHO_REQUEST) {
        char *midauth_cert = hip_pisa_get_certificate();

        HIP_IFEL(hip_build_param(update_packet_to_send, ha->our_pub), -1,
                 "Building of host id failed\n");

        /* For now we just add some random data to see if it works */
        HIP_IFEL(hip_build_param_cert(update_packet_to_send,
                                      1,
                                      1,
                                      1,
                                      1,
                                      midauth_cert,
                                      strlen(midauth_cert)),
                 -1,
                 "Building of cert failed\n");
    }

#endif

    /* Add ECHO_REQUEST (signed)
     * Notice that ECHO_REQUEST is same for the identical UPDATE packets
     * sent between different address combinations.
     */
    if (type == HIP_UPDATE_ECHO_REQUEST) {
        HIP_HEXDUMP("ECHO_REQUEST in the host association",
                    ha->echo_data, sizeof(ha->echo_data));
        HIP_IFEBL2(hip_build_param_echo(update_packet_to_send, ha->echo_data,
                                        sizeof(ha->echo_data), 1, 1),
                   -1, return err, "Building of ECHO_REQUEST failed\n");
    }

    /* Add ECHO_RESPONSE (signed) */
    if (type == HIP_UPDATE_ECHO_RESPONSE) {
        echo_request = hip_get_param(received_update_packet,
                                     HIP_PARAM_ECHO_REQUEST_SIGN);
        HIP_IFEL(!echo_request, -1, "ECHO REQUEST not found!\n");

        HIP_DEBUG("echo opaque data len=%d\n",
                  hip_get_param_contents_len(echo_request));
        HIP_HEXDUMP("ECHO_REQUEST ",
                    (void *) echo_request +
                    sizeof(struct hip_tlv_common),
                    hip_get_param_contents_len(echo_request));
        HIP_IFEL(hip_build_param_echo(update_packet_to_send, (void *) echo_request +
                                      sizeof(struct hip_tlv_common),
                                      hip_get_param_contents_len(echo_request), 1, 0),
                 -1, "Building of ECHO_RESPONSE failed\n");
    }

    // Add HMAC
    HIP_IFEL(hip_build_param_hmac_contents(update_packet_to_send,
                                           &ha->hip_hmac_out), -1, "Building of HMAC failed\n");

    // Add SIGNATURE
    HIP_IFEL(ha->sign(ha->our_priv_key, update_packet_to_send), -EINVAL,
             "Could not sign UPDATE. Failing\n");


out_err:
    return err;
}

static int hip_send_update_pkt(hip_common_t *update_packet_to_send,
                               struct hip_hadb_state *ha, struct in6_addr *src_addr,
                               struct in6_addr *dst_addr)
{
    int err = 0;

    // TODO: set the local address unverified for that dst_hit();

    err = ha->hadb_xmit_func->
          hip_send_pkt(src_addr, dst_addr,
                       (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       ha->peer_udp_port, update_packet_to_send, ha, 1);

    return err;
}

static int hip_select_local_addr_for_first_update(const struct hip_hadb_state *ha,
                                                  const struct in6_addr *src_addr,
                                                  const struct in6_addr *dst_addr,
                                                  struct in6_addr *new_src_addr)
{
    int err = 0;
    struct sockaddr_storage ss;
    struct netdev_address *na;
    hip_list_t *n, *t;
    const struct in6_addr *in6;
    int c;

    memset(&ss, 0, sizeof(ss));
    memset(new_src_addr, 0, sizeof(*new_src_addr));

    if (IN6_IS_ADDR_V4MAPPED(&ha->our_addr)) {
        ss.ss_family = AF_INET;
        IPV6_TO_IPV4_MAP(&ha->our_addr, &(((struct sockaddr_in *) &ss)->sin_addr));
    } else {
        ss.ss_family = AF_INET6;
        ipv6_addr_copy(&((struct sockaddr_in6 *) &ss)->sin6_addr, &ha->our_addr);
    }

    /* Ask a route from the kernel first */
    if (hip_select_source_address(new_src_addr, dst_addr) == 0) {
        HIP_DEBUG("Using default route address\n");
        goto out_err;
    }

    /* Use previous hadb source address if it still exists */
    if (hip_exists_address_in_list((const struct sockaddr *) &ss, -1) &&
        are_addresses_compatible(&ha->our_addr, dst_addr)) {
        HIP_DEBUG("Reusing hadb old source address\n");
        ipv6_addr_copy(new_src_addr, &ha->our_addr);
        goto out_err;
    }

    /* Last resort: use any address from the local list */
    list_for_each_safe(n, t, addresses, c) {
        na  = (struct netdev_address *) list_entry(n);
        in6 = hip_cast_sa_addr((const struct sockaddr *) &na->addr);
        if (are_addresses_compatible(in6, dst_addr)) {
            HIP_DEBUG("Reusing a local address from the list\n");
            ipv6_addr_copy(new_src_addr, in6);
            goto out_err;
        }
    }

    HIP_ERROR("Failed to find source address\n");
    err = -1;

out_err:

    if (err == 0) {
        HIP_DEBUG_IN6ADDR("selected source address", src_addr);
    }

    return err;
}

// Locators should be sent to the whole verified addresses!!!
int hip_send_locators_to_one_peer(hip_common_t *received_update_packet,
                                  struct hip_hadb_state *ha,
                                  struct in6_addr *src_addr,
                                  struct in6_addr *dst_addr,
                                  struct hip_locator_info_addr_item *locators,
                                  int type)
{
    int err                             = 0, i = 0;
    hip_list_t *item                    = NULL, *tmp = NULL;
    hip_common_t *update_packet_to_send = NULL;
    struct in6_addr local_addr;

    HIP_IFEL(!(update_packet_to_send = hip_msg_alloc()), -ENOMEM,
             "Out of memory while allocation memory for the update packet\n");
    err = hip_create_update_msg(received_update_packet, ha, update_packet_to_send,
                                locators, type);
    if (err) {
        goto out_err;
    }

    if (hip_shotgun_status == SO_HIP_SHOTGUN_OFF) {
        switch (type) {
        case HIP_UPDATE_LOCATOR:
            HIP_IFEL(hip_select_local_addr_for_first_update(ha, src_addr, dst_addr, &local_addr), -1,
                     "No source address found for first update\n");
            HIP_DEBUG_IN6ADDR("Sending update from", &local_addr);
            HIP_DEBUG_IN6ADDR("to", dst_addr);

            hip_send_update_pkt(update_packet_to_send, ha, &local_addr,
                                dst_addr);

            break;
        case HIP_UPDATE_ECHO_RESPONSE:
            HIP_DEBUG_IN6ADDR("Sending update from", src_addr);
            HIP_DEBUG_IN6ADDR("to", dst_addr);

            hip_send_update_pkt(update_packet_to_send, ha, src_addr,
                                dst_addr);

            break;
        case HIP_UPDATE_ECHO_REQUEST:
            list_for_each_safe(item, tmp, ha->addresses_to_send_echo_request, i) {
                dst_addr = (struct in6_addr *) list_entry(item);

                _HIP_DEBUG_IN6ADDR("Sending echo requests from", src_addr);
                _HIP_DEBUG_IN6ADDR("to", dst_addr);

                if (!are_addresses_compatible(src_addr, dst_addr)) {
                    continue;
                }

                HIP_DEBUG_IN6ADDR("Sending echo requests from", src_addr);
                HIP_DEBUG_IN6ADDR("to", dst_addr);

                hip_send_update_pkt(update_packet_to_send, ha,
                                    src_addr, dst_addr);
            }

            break;
        case SEND_UPDATE_ESP_ANCHOR:
            // TODO re-implement sending of esp prot anchors

            hip_send_update_pkt(update_packet_to_send, ha, src_addr, dst_addr);
            break;
        }
    }
    // TODO
    /*else
     * {
     *  for go through all local addressses
     *  {
     *      for go through all peer addresses
     *      {
     *          if (check_if_address_peer_ok)
     *              send_update_pkt()
     *      }
     *  }
     * }*/

out_err:
    if (update_packet_to_send) {
        free(update_packet_to_send);
    }
    return err;
}

int hip_send_locators_to_all_peers()
{
    int err                   = 0;
    struct hip_locator_info_addr_item *locators;
    int i                     = 0;
    hip_ha_t *ha;
    hip_list_t *item, *tmp;
    hip_common_t *locator_msg = NULL;

    HIP_IFEL(!(locator_msg = hip_msg_alloc()), -ENOMEM,
             "Out of memory while allocation memory for the packet\n");
    HIP_IFE(hip_create_locators(locator_msg, &locators), -1);

    // Go through all the peers and send update packets
    list_for_each_safe(item, tmp, hadb_hit, i)
    {
        ha = (hip_ha_t *) list_entry(item);

        if (ha->hastate == HIP_HASTATE_HITOK &&
            ha->state == HIP_STATE_ESTABLISHED) {
            err = hip_send_locators_to_one_peer(NULL, ha, &ha->our_addr,
                                                &ha->peer_addr, locators, HIP_UPDATE_LOCATOR);
            if (err) {
                goto out_err;
            }
        }
    }

out_err:

    /* Update DNS data in hit-to-ip domain name. This is done after
     * sending UPDATE packets. See the discussion for the reasoning:
     * http://www.freelists.org/post/hipl-users/HIP-UPDATE-select-error-Interrupted-system-call,2 */
    if (hip_get_nsupdate_status()) {
        nsupdate(0);
    }

    if (hip_locator_status == SO_HIP_SET_LOCATOR_ON) {
        hip_recreate_all_precreated_r1_packets();
    }
    if (locator_msg) {
        free(locator_msg);
    }
    return err;
}

static int hip_check_hmac_and_signature(hip_common_t *msg, hip_ha_t *entry)
{
    int err = 0;

    /** @todo Check these references again because these checks are done
     * separately for ACKs and SEQs */

    /* RFC 5201 Section 6.12.1. Handling a SEQ Parameter in a Received
     *  UPDATE Message:
     * 3. The system MUST verify the HMAC in the UPDATE packet. If
     * the verification fails, the packet MUST be dropped. */
    HIP_IFEL(hip_verify_packet_hmac(msg, &entry->hip_hmac_in), -1,
             "HMAC validation on UPDATE failed.\n");

    /* RFC 5201 Section 6.12.1. Handling a SEQ Parameter in a Received
     *  UPDATE Message:
     * 4. The system MAY verify the SIGNATURE in the UPDATE packet.
     * If the verification fails, the packet SHOULD be dropped and an error
     * message logged. */
    HIP_IFEL(entry->verify(entry->peer_pub_key, msg), -1,
             "Verification of UPDATE signature failed.\n");

out_err:
    return err;
}

static int hip_handle_locator_parameter(hip_ha_t *ha, in6_addr_t *src_addr,
                                        const struct hip_locator *locator)
{
    int err                    = 0;
    int locator_addr_count     = 0;
    int i                      = 0;
    struct hip_locator_info_addr_item *locator_address_item;
    union hip_locator_info_addr *locator_info_addr;
    struct in6_addr *peer_addr = 0;
    int src_addr_included      = 0;

    HIP_IFEL(!locator, -1, "locator is NULL");

    locator_addr_count = hip_get_locator_addr_item_count(locator);
    HIP_IFEL((locator_addr_count < 0), -1, "Negative address count\n");

    HIP_DEBUG("LOCATOR has %d address(es), loc param len=%d\n",
              locator_addr_count, hip_get_param_total_len(locator));

    _HIP_DEBUG("The previous addresses to send update request:\n");
    // hip_print_addresses_to_send_update_request(ha);

    // Empty the addresses_to_send_echo_request list before adding the
    // new addresses
    hip_remove_addresses_to_send_echo_request(ha);

    locator_address_item =  hip_get_locator_first_addr_item(locator);
    for (i = 0; i < locator_addr_count; i++) {
        locator_info_addr = hip_get_locator_item(locator_address_item, i);

        peer_addr         = malloc(sizeof(in6_addr_t));
        if (!peer_addr) {
            HIP_ERROR("Couldn't allocate memory for peer_addr.\n");
            return -1;
        }
        ;

        ipv6_addr_copy(peer_addr, hip_get_locator_item_address(locator_info_addr));
        list_add(peer_addr, ha->addresses_to_send_echo_request);

        HIP_DEBUG_IN6ADDR("Comparing", src_addr);
        HIP_DEBUG_IN6ADDR("to ", peer_addr);

        if (ipv6_addr_cmp(src_addr, peer_addr) == 0) {
            src_addr_included = 1;
        }
    }

    if (!src_addr_included) {
        HIP_DEBUG("Preferred address was not in locator (NAT?)\n");

        peer_addr = malloc(sizeof(in6_addr_t));
        if (!peer_addr) {
            HIP_ERROR("Couldn't allocate memory for peer_addr.\n");
            return -1;
        }
        ;

        ipv6_addr_copy(peer_addr, src_addr);
        list_add(peer_addr, ha->addresses_to_send_echo_request);
    }

    hip_print_addresses_to_send_update_request(ha);

out_err:
    return err;
}

static int hip_handle_first_update_packet(hip_common_t *received_update_packet,
                                          hip_ha_t *ha, in6_addr_t *src_addr)
{
    int err = 0;
    struct hip_locator *locator;
    struct hip_esp_info *esp_info;

    locator              = hip_get_param(received_update_packet, HIP_PARAM_LOCATOR);
    err                  = hip_handle_locator_parameter(ha, src_addr, locator);
    if (err) {
        goto out_err;
    }

    esp_info             = hip_get_param(received_update_packet, HIP_PARAM_ESP_INFO);
    ha->spi_outbound_new = ntohl(esp_info->new_spi);

    // Randomize the echo response opaque data before sending ECHO_REQUESTS.
    // Notice that we're using the same opaque value for the identical
    // UPDATE packets sent between different address combinations.
    get_random_bytes(ha->echo_data, sizeof(ha->echo_data));

    err = hip_send_locators_to_one_peer(received_update_packet, ha, &ha->our_addr,
                                        &ha->peer_addr, NULL, HIP_UPDATE_ECHO_REQUEST);
    if (err) {
        goto out_err;
    }

out_err:
    return err;
}

static void hip_handle_second_update_packet(hip_common_t *received_update_packet,
                                            hip_ha_t *ha,
                                            in6_addr_t *src_addr,
                                            in6_addr_t *dst_addr)
{
    struct hip_esp_info *esp_info;

    hip_send_locators_to_one_peer(received_update_packet, ha, src_addr,
                                  dst_addr, NULL, HIP_UPDATE_ECHO_RESPONSE);

    esp_info             = hip_get_param(received_update_packet, HIP_PARAM_ESP_INFO);
    ha->spi_outbound_new = ntohl(esp_info->new_spi);

    hip_recreate_security_associations_and_sp(ha, src_addr, dst_addr);

    // Set active addresses
    ipv6_addr_copy(&ha->our_addr, src_addr);
    ipv6_addr_copy(&ha->peer_addr, dst_addr);
}

static void hip_handle_third_update_packet(hip_common_t *received_update_packet,
                                           hip_ha_t *ha,
                                           in6_addr_t *src_addr,
                                           in6_addr_t *dst_addr)
{
    (void) received_update_packet; /* avoid warning about unused parameter */

    hip_recreate_security_associations_and_sp(ha, src_addr, dst_addr);

    // Set active addresses
    ipv6_addr_copy(&ha->our_addr, src_addr);
    ipv6_addr_copy(&ha->peer_addr, dst_addr);
}

static void hip_empty_oppipdb_old(void)
{
#ifdef CONFIG_HIP_OPPORTUNISTIC
    hip_for_each_oppip(hip_oppipdb_del_entry_by_entry, NULL);
#endif
    if (hip_firewall_is_alive()) {
        int err;
        struct hip_common *msg;

        msg = hip_msg_alloc();
        HIP_IFEL(!msg, -1, "msg alloc failed\n");
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_FW_FLUSH_SYS_OPP_HIP, 0),
                 -1, "build hdr failed\n");

        err = hip_sendto_firewall(msg);
        err = err > 0 ? 0 : -1;

out_err:
        HIP_FREE(msg);
        if (err) {
            HIP_ERROR("Couldn't flush firewall chains\n");
        }
    }
}

int hip_receive_update(hip_common_t *received_update_packet, in6_addr_t *src_addr,
                       in6_addr_t *dst_addr, hip_ha_t *ha, hip_portpair_t *sinfo)
{
    int err                                 = 0;
    unsigned int ack_peer_update_id         = 0;
    unsigned int seq_update_id              = 0;
    unsigned int has_esp_info               = 0;
    struct hip_seq *seq                     = NULL;
    struct hip_ack *ack                     = NULL;
    struct hip_esp_info *esp_info           = NULL;
    struct hip_locator *locator             = NULL;
    struct hip_echo_request *echo_request   = NULL;
    struct hip_echo_response *echo_response = NULL;
    int same_seq                            = 0;

    /* RFC 5201 Section 5.4.4: If there is no corresponding HIP association,
     * the implementation MAY reply with an ICMP Parameter Problem. */
    HIP_IFEL(!ha, -1, "No host association database entry found.\n");

    /// @todo: Relay support

    /* RFC 5201 Section 4.4.2, Table 5: According to the state processes
     * listed, the state is moved from R2_SENT to ESTABLISHED if an
     * UPDATE packet is received */
    if (ha->state == HIP_STATE_R2_SENT) {
        ha->state = HIP_STATE_ESTABLISHED;
        HIP_DEBUG("Received UPDATE in state %s, moving to " \
                  "ESTABLISHED.\n", hip_state_str(ha->state));
    } else if (ha->state != HIP_STATE_ESTABLISHED) {
        HIP_ERROR("Received UPDATE in illegal state %s.\n",
                  hip_state_str(ha->state));
        err = -EPROTO;
        goto out_err;
    }

    /* RFC 5201 Section 6.12: Receiving UPDATE Packets */
    HIP_DEBUG("previous incoming update id=%u\n", ha->update_id_in);
    HIP_DEBUG("previous outgoing update id=%u\n", ha->update_id_out);

    /* RFC 5201 Section 6.12: 3th or 4th step:
     *
     * Summary: ACK is processed before SEQ if both are present.
     *
     * 4th step: If the association is in the ESTABLISHED state and there is
     * both an ACK and SEQ in the UPDATE, the ACK is first processed as
     * described in Section 6.12.2, and then the rest of the UPDATE is
     * processed as described in Section 6.12.1 */
    ack = hip_get_param(received_update_packet, HIP_PARAM_ACK);
    if (ack != NULL) {
        ack_peer_update_id = ntohl(ack->peer_update_id);
        HIP_DEBUG("ACK parameter found with peer Update ID %u.\n",
                  ack_peer_update_id);
        /*ha->hadb_update_func->hip_update_handle_ack(
         *      ha, ack, has_esp_info);*/
        if (ack_peer_update_id != ha->update_id_out) {
            // Simplified logic of RFC 5201 6.12.2, 1st step:
            // We drop the packet if the Update ID in the ACK
            // parameter does not equal to the last outgoing Update ID
            HIP_DEBUG("Update ID (%u) in the ACK parameter does not "
                      "equal to the last outgoing Update ID (%u). "
                      "Dropping the packet.\n",
                      ack_peer_update_id,
                      ha->update_id_out);
            err = -1;
            goto out_err;
        }
    }

    /* RFC 5201 Sections 6.12: 2nd or 4th step:
     *
     * 2nd case: If the association is in the ESTABLISHED state and the SEQ
     * (but not ACK) parameter is present, the UPDATE is processed and replied
     * to as described in Section 6.12.1. */
    seq = hip_get_param(received_update_packet, HIP_PARAM_SEQ);
    if (seq != NULL) {
        seq_update_id = ntohl(seq->update_id);
        HIP_DEBUG("SEQ parameter found with  Update ID %u.\n",
                  seq_update_id);

        /// @todo 15.9.2009: Handle retransmission case

        if (ha->update_id_in != 0 &&
            (seq_update_id < ha->update_id_in ||
             seq_update_id > ha->update_id_in + update_id_window_size)) {
            // RFC 5201 6.12.1 part 1:
            HIP_DEBUG("Update ID (%u) in the SEQ parameter is not "
                      "in the window of the previous Update ID (%u). "
                      "Dropping the packet.\n",
                      seq_update_id,
                      ha->update_id_in);

            err = -1;
            goto out_err;
        }

        /* Section 6.12.1 5th step:
         * If a new SEQ parameter is being processed, the parameters in the
         * UPDATE are then processed.  The system MUST record the Update ID
         * in the received SEQ parameter, for replay protection.
         */

        if (ha->update_id_in != 0 && ha->update_id_in == seq_update_id) {
            same_seq = 1;
        }

        ha->update_id_in = seq_update_id;
        _HIP_DEBUG("Stored peer's incoming UPDATE ID %u\n", ha->update_id_in);
    }

    /* RFC 5201 Section 6.12.1 3th and 4th steps or
     *          Section 6.12.2 2nd and 3th steps */
    HIP_IFE(hip_check_hmac_and_signature(received_update_packet, ha), -1);

    esp_info = hip_get_param(received_update_packet, HIP_PARAM_ESP_INFO);
    if (esp_info != NULL) {
        HIP_DEBUG("ESP INFO parameter found with new SPI %u.\n",
                  ntohl(esp_info->new_spi));
        has_esp_info = 1;

        if (esp_info->new_spi != esp_info->old_spi) {
            HIP_DEBUG("New SPI != Old SPI -> Please notice that "
                      "rekeying case is not implemented yet.");
        }
        /// @todo Further ESP_INFO handling
        // Done in hip_handle_esp_info() before
    }

    /* @todo: a workaround for bug id 944 */
    ha->peer_udp_port = sinfo->src_port;

    /* RFC 5206: End-Host Mobility and Multihoming. */
    // 3.2.1. Mobility with a Single SA Pair (No Rekeying)
    locator           = hip_get_param(received_update_packet, HIP_PARAM_LOCATOR);
    echo_request      = hip_get_param(received_update_packet, HIP_PARAM_ECHO_REQUEST_SIGN);
    echo_response     = hip_get_param(received_update_packet, HIP_PARAM_ECHO_RESPONSE_SIGN);

    if (locator != NULL) {
        hip_handle_first_update_packet(received_update_packet,
                                       ha, src_addr);

        goto out_err;
    } else if (echo_request != NULL)   {
        // Ignore the ECHO REQUESTS with the same SEQ after processing
        // the first one.
        if (same_seq) {
            goto out_err;
        }

        // We handle ECHO_REQUEST by sending an update packet
        // with reversed source and destination address.
        hip_handle_second_update_packet(received_update_packet,
                                        ha, dst_addr, src_addr);

        goto out_err;
    } else if (echo_response != NULL)   {
        hip_handle_third_update_packet(received_update_packet,
                                       ha, dst_addr, src_addr);

        goto out_err;
    }

out_err:
    if (err != 0) {
        HIP_ERROR("UPDATE handler failed, err=%d\n", err);
    }

    /** @todo Is this needed? */

    // Empty the oppipdb.
    hip_empty_oppipdb_old();

    return err;
}
