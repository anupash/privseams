/**
 * @file
 * This file defines various functions for sending, handling and receiving
 * UPDATE packets for the Host Identity Protocol (HIP). This file is under
 * heavy editing currently.
 *
 * @author  Baris Boyvat <baris#boyvat.com>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */

#include "update.h"
//#include "update_old.h"

#include "protodefs.h"

/** A transmission function set for NAT traversal. */
extern hip_xmit_func_set_t nat_xmit_func_set;
/** A transmission function set for sending raw HIP packets. */
extern hip_xmit_func_set_t default_xmit_func_set;

int update_id_window_size = 50;

int hip_create_locators(hip_common_t* locator_msg,
        struct hip_locator_info_addr_item **locators)
{
        int err = 0;
        struct hip_locator *loc;

        hip_msg_init(locator_msg);
        HIP_IFEL(hip_build_locators_old(locator_msg, 0, hip_get_nat_mode(NULL)), -1,
                 "Failed to build locators\n");
        /// @todo : 20.11.2011: Do we need to build the user header?
        HIP_IFEL(hip_build_user_hdr(locator_msg,
                                    SO_HIP_SET_LOCATOR_ON, 0), -1,
                 "Failed to add user header\n");
        loc = hip_get_param(locator_msg, HIP_PARAM_LOCATOR);
        hip_print_locator_addresses(locator_msg);
        *locators = hip_get_locator_first_addr_item(loc);

out_err:
        return err;
}

/// @todo : should we implement base draft update with ifindex 0 stuff ??
/// @todo :  Divide this function into more pieces, handle_spi, handle_seq, etc
/// @todo : Remove the uncommented lines?
int hip_create_update_msg(hip_common_t* received_update_packet,
        struct hip_hadb_state *ha, hip_common_t *update_packet_to_send,
        struct hip_locator_info_addr_item *locators,
        int type)
{
        int err = 0;

        uint32_t update_id_out = 0;
        uint32_t esp_info_old_spi = 0, esp_info_new_spi = 0;
        uint16_t mask = 0;
      	struct hip_seq *seq = NULL;
	struct hip_echo_request *echo_request = NULL;

        HIP_DEBUG("Creating the UPDATE packet\n");

        if (type != HIP_UPDATE_LOCATOR)
                HIP_DEBUG("UPDATE without locators\n");

        ha->hadb_misc_func->hip_build_network_hdr(update_packet_to_send, HIP_UPDATE,
                                                     mask, &ha->hit_our,
                                                         &ha->hit_peer);

        // Add ESP_INFO
        if (type == HIP_UPDATE_LOCATOR || type == HIP_UPDATE_ECHO_REQUEST) {
                // Handle SPI numbers
                esp_info_old_spi  = ha->spi_inbound_current;
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

        // Add SEQ
        if (type == HIP_UPDATE_LOCATOR || type == HIP_UPDATE_ECHO_REQUEST) {
                // TODO check the following function!
                /* hip_update_set_new_spi_in_old(ha, esp_info_old_spi,
                    esp_info_new_spi, 0);*/

                ha->update_id_out++;
                update_id_out = ha->update_id_out;
                _HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
                /** @todo Handle this case. */
                HIP_IFEL(hip_build_param_seq(update_packet_to_send, update_id_out), -1,
                  "Building of SEQ param failed\n");

                /* remember the update id of this update */
                /* hip_update_set_status(ha, esp_info_old_spi,
                    0x1 | 0x2 | 0x8, update_id_out, 0, NULL,
                    ha->current_keymat_index); */

                /************************************************/
        }

        // Add ACK
        if (type == HIP_UPDATE_ECHO_REQUEST || type == HIP_UPDATE_ECHO_RESPONSE) {
                HIP_IFEL(!(seq = hip_get_param(received_update_packet,
                    HIP_PARAM_SEQ)), -1, "SEQ not found\n");

                HIP_IFEL(hip_build_param_ack(update_packet_to_send,
                    ntohl(seq->update_id)), -1, "Building of ACK failed\n");
        }

       	/* Add ECHO_REQUEST (signed)
         * Notice that ECHO_REQUEST is same for the identical UPDATE packets
         * sent between different address combinations.
         */
        if (type == HIP_UPDATE_ECHO_REQUEST) {
                HIP_HEXDUMP("ECHO_REQUEST in the host association",
                        ha->echo_data, sizeof(ha->echo_data));
                HIP_IFEBL2(hip_build_param_echo(update_packet_to_send, ha->echo_data,
			sizeof(ha->echo_data), 1, 1),
                        -1, return , "Building of ECHO_REQUEST failed\n");
        }

        /* Add ECHO_RESPONSE (signed) */
        if (type == HIP_UPDATE_ECHO_RESPONSE) {
              	echo_request = hip_get_param(received_update_packet,
                        HIP_PARAM_ECHO_REQUEST_SIGN);
                HIP_IFEL(!echo_request, -1, "ECHO REQUEST not found!\n");

		HIP_DEBUG("echo opaque data len=%d\n",
			  hip_get_param_contents_len(echo_request));
		HIP_HEXDUMP("ECHO_REQUEST ",
			    (void *)echo_request +
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

void hip_send_update_pkt(hip_common_t* update_packet_to_send, 
        struct hip_hadb_state *ha, struct in6_addr *src_addr,
        struct in6_addr *dst_addr)
{
        int err = 0;

        // TODO: set the local address unverified for that dst_hit();

        err = ha->hadb_xmit_func->
            hip_send_pkt(src_addr, dst_addr,
                    (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                    ha->peer_udp_port, update_packet_to_send, ha, 1);

out_err:
        return;
}

int recreate_security_associations(struct hip_hadb_state *ha, in6_addr_t *src_addr,
        in6_addr_t *dst_addr)
{
        int err = 0;
        int prev_spi_out = ha->spi_outbound_current;
        int new_spi_out = ha->spi_outbound_new;
        
        int prev_spi_in = ha->spi_inbound_current;
        int new_spi_in = ha->spi_inbound_current;

        // Delete previous security policies
        ha->hadb_ipsec_func->hip_delete_hit_sp_pair(&ha->hit_our, &ha->hit_peer,
                IPPROTO_ESP, 1);
        ha->hadb_ipsec_func->hip_delete_hit_sp_pair(&ha->hit_peer, &ha->hit_our,
                IPPROTO_ESP, 1);

        // Delete the previous SAs
        HIP_DEBUG("Previous SPI out =0x%x\n", prev_spi_out);
        HIP_DEBUG("Previous SPI in =0x%x\n", prev_spi_in);

        HIP_DEBUG_IN6ADDR("Our current active addr", &ha->our_addr);
        HIP_DEBUG_IN6ADDR("Peer's current active addr", &ha->peer_addr);

        default_ipsec_func_set.hip_delete_sa(prev_spi_out, &ha->peer_addr,
					     &ha->our_addr, HIP_SPI_DIRECTION_OUT, ha);
	default_ipsec_func_set.hip_delete_sa(prev_spi_in, &ha->our_addr,
					     &ha->peer_addr, HIP_SPI_DIRECTION_IN, ha);

        // Create a new security policy
        HIP_IFEL(ha->hadb_ipsec_func->hip_setup_hit_sp_pair(&ha->hit_peer,
                &ha->hit_our, dst_addr, src_addr, IPPROTO_ESP, 1, 0),
	      -1, "Setting up SP pair failed\n");

        // Create a new inbound SA
        HIP_DEBUG("Creating a new inbound SA, SPI=0x%x\n", new_spi_in);

        HIP_IFEL(ha->hadb_ipsec_func->hip_add_sa(dst_addr, src_addr,
                &ha->hit_peer, &ha->hit_our, new_spi_in, ha->esp_transform,
                &ha->esp_in, &ha->auth_in, 1, HIP_SPI_DIRECTION_IN, 0,
                ha), -1,
	      "Error while changing inbound security association\n");

	HIP_DEBUG("New inbound SA created with SPI=0x%x\n", new_spi_in);

        /*HIP_IFEL(ha->hadb_ipsec_func->hip_setup_hit_sp_pair(&ha->hit_our,
                &ha->hit_peer, src_addr, dst_addr, IPPROTO_ESP, 1, 0), -1,
		 "Setting up SP pair failed\n");      */

        // Create a new outbound SA
        HIP_DEBUG("Creating a new outbound SA, SPI=0x%x\n", new_spi_out);
	ha->local_udp_port = ha->nat_mode ? hip_get_local_nat_udp_port() : 0;

      	HIP_IFEL(ha->hadb_ipsec_func->hip_add_sa(src_addr, dst_addr,
                &ha->hit_our, &ha->hit_peer, new_spi_out, ha->esp_transform,
                &ha->esp_out, &ha->auth_out, 1, HIP_SPI_DIRECTION_OUT, 0,
                ha), -1,
	      "Error while changing outbound security association\n");

	HIP_DEBUG("New outbound SA created with SPI=0x%x\n", new_spi_out);
        
out_err:
        return err;
};

// Locators should be sent to the whole verified addresses!!!
int hip_send_update_to_one_peer(hip_common_t* received_update_packet,
        struct hip_hadb_state *ha, struct in6_addr *src_addr,
        struct in6_addr *dst_addr, struct hip_locator_info_addr_item *locators,
        int type)
{
        int err = 0;
        hip_list_t *item = NULL, *tmp = NULL;
	int i = 0;
        hip_common_t* update_packet_to_send = NULL;

        HIP_IFEL(!(update_packet_to_send = hip_msg_alloc()), -ENOMEM,
                "Out of memory while allocation memory for the update packet\n");
        err = hip_create_update_msg(received_update_packet, ha, update_packet_to_send,
                locators, type);
        if (err)
            goto out_err;

        if (hip_shotgun_status == SO_HIP_SHOTGUN_OFF)
        {
                switch (type) {
                case HIP_UPDATE_LOCATOR:
                case HIP_UPDATE_ECHO_RESPONSE:
                        HIP_DEBUG_IN6ADDR("Sending update from", src_addr);
                        HIP_DEBUG_IN6ADDR("to", dst_addr);

                        hip_send_update_pkt(update_packet_to_send, ha, src_addr,
                                dst_addr);

                        break;
                case HIP_UPDATE_ECHO_REQUEST:
                        list_for_each_safe(item, tmp, ha->addresses_to_send_echo_request, i) {
                                dst_addr = list_entry(item);

                                _HIP_DEBUG_IN6ADDR("Sending echo requests from", src_addr);
                                _HIP_DEBUG_IN6ADDR("to", dst_addr);

                                if (!are_addresses_compatible(src_addr, dst_addr))
                                        continue;

                                HIP_DEBUG_IN6ADDR("Sending echo requests from", src_addr);
                                HIP_DEBUG_IN6ADDR("to", dst_addr);

                                hip_send_update_pkt(update_packet_to_send, ha,
                                        src_addr, dst_addr);
                        }

                        break;
                }
            }
        // TODO
        /*else
        {
            for go through all local addressses
            {
                for go through all peer addresses
                {
                    if (check_if_address_peer_ok)
                        send_update_pkt()
                }
            }
        }*/

out_err:
        if (update_packet_to_send)
                free(update_packet_to_send);
}

int hip_send_update_locator()
{
        int err = 0;
        struct hip_locator_info_addr_item *locators;
        int i = 0;
        hip_ha_t *ha;
        hip_list_t *item, *tmp;
        hip_common_t *locator_msg;

        HIP_IFEL(!(locator_msg = hip_msg_alloc()), -ENOMEM,
            "Out of memory while allocation memory for the packet\n");
        HIP_IFE(hip_create_locators(locator_msg, &locators), -1);

        // Go through all the peers and send update packets
        list_for_each_safe(item, tmp, hadb_hit, i)
        {
                ha = list_entry(item);

                if (ha->hastate == HIP_HASTATE_HITOK &&
                    ha->state == HIP_STATE_ESTABLISHED)
                {
                        err = hip_send_update_to_one_peer(NULL, ha, &ha->our_addr,
                                &ha->peer_addr, locators, HIP_UPDATE_LOCATOR);
                        if (err)
                            goto out_err;
                }
        }

out_err:
        if (hip_locator_status == SO_HIP_SET_LOCATOR_ON)
            hip_recreate_all_precreated_r1_packets();
        if (locator_msg)
            free(locator_msg);
}

int hip_check_hmac_and_signature(hip_common_t* msg, hip_ha_t *entry)
{
        int err = 0;

        /** @todo Check these references again because these checks are done
         * separately for ACKs and SEQs.

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

int hip_handle_locator_parameter(hip_ha_t *ha, in6_addr_t *src_addr,
        struct hip_locator *locator)
{
        int err = 0;
        int locator_addr_count = 0;
        int i = 0;
        u32 spi_in = 0;
        struct hip_peer_addr_list_item *locator_address_item;
        union hip_locator_info_addr *locator_info_addr;
        struct in6_addr *peer_addr = 0;
        int preferred_addr_not_in = 1;

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

        locator_address_item = hip_get_locator_first_addr_item(locator);
	for (i = 0; i < locator_addr_count; i++)
        {
                locator_info_addr = hip_get_locator_item(locator_address_item, i);
         
                peer_addr = malloc(sizeof(in6_addr_t));
                if (!peer_addr)
                {
                        HIP_ERROR("Couldn't allocate memory for peer_addr.\n");
                        return -1;
                };

                memcpy(peer_addr, hip_get_locator_item_address(locator_info_addr),
                    sizeof(in6_addr_t));
                list_add(peer_addr, ha->addresses_to_send_echo_request);

                HIP_DEBUG_IN6ADDR("Comparing", peer_addr);
                HIP_DEBUG_IN6ADDR("to ", &ha->peer_addr);

                if (!ipv6_addr_cmp(peer_addr, &ha->peer_addr))
                        preferred_addr_not_in = 0;
        }

        hip_print_addresses_to_send_update_request(ha);

	if (preferred_addr_not_in)
        {
                HIP_DEBUG("Preferred address was not in locator, Handle"
                        "specially this case if needed!");
        }

out_err:
        return err;
}

int hip_handle_first_update_packet(hip_common_t* received_update_packet,
        hip_ha_t *ha, in6_addr_t *src_addr)
{
        int err = 0;
        struct hip_locator *locator;
        struct hip_esp_info *esp_info;

        locator = hip_get_param(received_update_packet, HIP_PARAM_LOCATOR);
        err = hip_handle_locator_parameter(ha, src_addr, locator);
        if (err)
            goto out_err;

        esp_info = hip_get_param(received_update_packet, HIP_PARAM_ESP_INFO);
        ha->spi_outbound_new = ntohl(esp_info->new_spi);

        // Randomize the echo response opaque data before sending ECHO_REQUESTS.
        // Notice that we're using the same opaque value for the identical
        // UPDATE packets sent between different address combinations.
        get_random_bytes(ha->echo_data, sizeof(ha->echo_data));

        err = hip_send_update_to_one_peer(received_update_packet, ha, &ha->our_addr,
                &ha->peer_addr, NULL, HIP_UPDATE_ECHO_REQUEST);
        if (err)
            goto out_err;

out_err:
        return err;
}

void hip_handle_second_update_packet(hip_common_t* received_update_packet,
        hip_ha_t *ha, in6_addr_t *src_addr, in6_addr_t *dst_addr)
{
        struct hip_esp_info *esp_info;

        hip_send_update_to_one_peer(received_update_packet, ha, src_addr,
                dst_addr, NULL, HIP_UPDATE_ECHO_RESPONSE);

        esp_info = hip_get_param(received_update_packet, HIP_PARAM_ESP_INFO);
        ha->spi_outbound_new = ntohl(esp_info->new_spi);
        
        recreate_security_associations(ha, src_addr, dst_addr);

        // Set active addresses
        ipv6_addr_copy(&ha->our_addr, src_addr);
      	ipv6_addr_copy(&ha->peer_addr, dst_addr);
}

void hip_handle_third_update_packet(hip_common_t* received_update_packet, 
        hip_ha_t *ha, in6_addr_t *src_addr, in6_addr_t *dst_addr)
{
        recreate_security_associations(ha, src_addr, dst_addr);

        // Set active addresses
        ipv6_addr_copy(&ha->our_addr, src_addr);
      	ipv6_addr_copy(&ha->peer_addr, dst_addr);
}

void empty_oppipdb_old()
{
	hip_for_each_oppip(hip_oppipdb_del_entry_by_entry, NULL);
}

int hip_receive_update(hip_common_t* received_update_packet, in6_addr_t *src_addr,
        in6_addr_t *dst_addr, hip_ha_t *ha, hip_portpair_t *sinfo)
{
        int err = 0;
        int ack_peer_update_id = 0;
        int seq_update_id = 0;
        int has_esp_info = 0;
       	struct hip_seq *seq = NULL;
	struct hip_ack *ack = NULL;
        struct hip_esp_info *esp_info = NULL;
	struct hip_locator *locator = NULL;
	struct hip_echo_request *echo_request = NULL;
	struct hip_echo_response *echo_response = NULL;
        int same_seq = 0;

        /* RFC 5201 Section 5.4.4: If there is no corresponding HIP association,
         * the implementation MAY reply with an ICMP Parameter Problem. */
        HIP_IFEL(!ha, -1, "No host association database entry found.\n");

        /// @todo: Relay support

        /* RFC 5201 Section 4.4.2, Table 5: According to the state processes
         * listed, the state is moved from R2_SENT to ESTABLISHED if an
         * UPDATE packet is received */
        if (ha->state == HIP_STATE_R2_SENT) {
                ha->state == HIP_STATE_ESTABLISHED;
                HIP_DEBUG("Received UPDATE in state %s, moving to "\
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
                        ha, ack, has_esp_info);*/
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

                if (ha->update_id_in != 0 && ha->update_id_in == seq_update_id)
                        same_seq = 1;

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

                if (esp_info->new_spi != esp_info->old_spi)
                {
                    HIP_DEBUG("New SPI != Old SPI -> Please notice that "
                            "rekeying case is not implemented yet.");
                }
                /// @todo Further ESP_INFO handling
                // Done in hip_handle_esp_info() before
	}
        
        /* RFC 5206: End-Host Mobility and Multihoming. */
        // 3.2.1. Mobility with a Single SA Pair (No Rekeying)
        locator = hip_get_param(received_update_packet, HIP_PARAM_LOCATOR);
        echo_request = hip_get_param(received_update_packet, HIP_PARAM_ECHO_REQUEST_SIGN);
        echo_response = hip_get_param(received_update_packet, HIP_PARAM_ECHO_RESPONSE_SIGN);

        if (locator != NULL) {
                hip_handle_first_update_packet(received_update_packet,
                        ha, src_addr);
                
                goto out_err;
        }
        else if (echo_request != NULL) {
                // Ignore the ECHO REQUESTS with the same SEQ after processing
                // the first one.
                if (same_seq)
                        goto out_err;

                // We handle ECHO_REQUEST by sending an update packet
                // with reversed source and destination address.
                hip_handle_second_update_packet(received_update_packet,
                        ha, dst_addr, src_addr);

                goto out_err;
        } 
        else if (echo_response != NULL) {
                 hip_handle_third_update_packet(received_update_packet,
                         ha, dst_addr, src_addr);

                 goto out_err;
        }
	
out_err:
        if (err != 0)
                HIP_ERROR("UPDATE handler failed, err=%d\n", err);

        /** @todo Is this needed? */

        // Empty the oppipdb.
        empty_oppipdb_old();

        return err;
}

/**
 * Builds udp and raw locator items into locator list to msg
 * this is the extension of hip_build_locators in output.c
 * type2 locators are collected also
 *
 * @param msg          a pointer to hip_common to append the LOCATORS
 * @return             len of LOCATOR2 on success, or negative error value on error
 */
int hip_build_locators_old(struct hip_common *msg, uint32_t spi, hip_transform_suite_t ice)
{
    int err = 0, i = 0, count1 = 0, count2 = 0, UDP_relay_count = 0;
    int addr_max1, addr_max2;
    struct netdev_address *n;
    hip_list_t *item = NULL, *tmp = NULL;
    struct hip_locator_info_addr_item *locs1 = NULL;
    struct hip_locator_info_addr_item2 *locs2 = NULL;
    hip_ha_t *ha_n;

    //TODO count the number of UDP relay servers.
    // check the control state of every hatb_state.

    if (address_count == 0) {
	    HIP_DEBUG("Host has only one or no addresses no point "
		      "in building LOCATOR2 parameters\n");
	    goto out_err;
    }

    //TODO check out the count for UDP and hip raw.
    addr_max1 = address_count;
    // let's put 10 here for now. anyhow 10 additional type 2 addresses should be enough
    addr_max2 = HIP_REFLEXIVE_LOCATOR_ITEM_AMOUNT_MAX + 10;

    HIP_IFEL(!(locs1 = malloc(addr_max1 *
			      sizeof(struct hip_locator_info_addr_item))),
	     -1, "Malloc for LOCATORS type1 failed\n");
    HIP_IFEL(!(locs2 = malloc(addr_max2 *
			      sizeof(struct hip_locator_info_addr_item2))),
                 -1, "Malloc for LOCATORS type2 failed\n");


    memset(locs1,0,(addr_max1 *
		    sizeof(struct hip_locator_info_addr_item)));

    memset(locs2,0,(addr_max2 *
		    sizeof(struct hip_locator_info_addr_item2)));

    HIP_DEBUG("there are %d type 1 locator item\n" , addr_max1);

    if (ice == HIP_NAT_MODE_ICE_UDP)
	    goto build_ice_locs;

    list_for_each_safe(item, tmp, addresses, i) {
            n = list_entry(item);
 	    HIP_DEBUG_IN6ADDR("Add address:",hip_cast_sa_addr(&n->addr));
            HIP_ASSERT(!ipv6_addr_is_hit(hip_cast_sa_addr(&n->addr)));
	    memcpy(&locs1[count1].address, hip_cast_sa_addr(&n->addr),
		   sizeof(struct in6_addr));
	    if (n->flags & HIP_FLAG_CONTROL_TRAFFIC_ONLY)
		    locs1[count1].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_SIGNAL;
	    else
		    locs1[count1].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_DUAL;
	    locs1[count1].locator_type = HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI;
	    locs1[count1].locator_length = sizeof(struct in6_addr) / 4;
	    locs1[count1].reserved = 0;
	    count1++;
    }

    if (ice != HIP_NAT_MODE_ICE_UDP)
	    goto skip_ice;

build_ice_locs:

#if 0
    HIP_DEBUG("Looking for reflexive addresses from a HA of a relay\n");
    i = 0;

    list_for_each_safe(item, tmp, hadb_hit, i) {
            ha_n = list_entry(item);
            if (count2 >= addr_max2)
	    	    break;
            HIP_DEBUG_IN6ADDR("Looking for reflexive, preferred address: ",
			      &ha_n->peer_addr );
            HIP_DEBUG_IN6ADDR("Looking for reflexive, local address: ",
			      &ha_n->our_addr );
            HIP_DEBUG("Looking for reflexive port: %d \n",
		      ha_n->local_reflexive_udp_port);
            HIP_DEBUG("Looking for reflexive addr: ",
		      &ha_n->local_reflexive_address);
            /* Check if this entry has reflexive port */
            if(ha_n->local_reflexive_udp_port) {
		    memcpy(&locs2[count2].address, &ha_n->local_reflexive_address,
			   sizeof(struct in6_addr));
		    locs2[count2].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_DUAL;
		    locs2[count2].locator_type = HIP_LOCATOR_LOCATOR_TYPE_UDP;
		    locs2[count2].locator_length = 7;
		    locs2[count2].reserved = 0;
		    // for IPv4 we add UDP information
		    locs2[count2].port = htons(ha_n->local_reflexive_udp_port);
                    locs2[count2].transport_protocol = 0;
                    locs2[count2].kind = ICE_CAND_TYPE_SRFLX;  // 2 for peer reflexive
                    locs2[count2].spi = htonl(spi);
                    locs2[count2].priority = htonl(ice_calc_priority(HIP_LOCATOR_LOCATOR_TYPE_REFLEXIVE_PRIORITY,ICE_CAND_PRE_SRFLX,1) - ha_n->local_reflexive_udp_port);
		    HIP_DEBUG("build a locator at priority : %d\n", ntohl(locs2[count2].priority));
                    HIP_DEBUG_HIT("Created one reflexive locator item: ",
                                  &locs1[count2].address);
                    count2++;
                    if (count2 >= addr_max2)
                            break;
            }
    }

#endif

skip_ice:

    HIP_DEBUG("locator count %d\n", count1, count2);

    err = hip_build_param_locator2(msg, locs1, locs2, count1, count2);

 out_err:

    if (locs1)
	    free(locs1);
    if (locs2)
	    free(locs2);

    return err;
}

// Used in hip_handle_locator_parameter_old
int hip_update_for_each_peer_addr_old(
	int (*func)
	(hip_ha_t *entry, struct hip_peer_addr_list_item *list_item,
	 struct hip_spi_out_item *spi_out, void *opaq),
	hip_ha_t *entry, struct hip_spi_out_item *spi_out, void *opaq)
{
	hip_list_t *item, *tmp;
	struct hip_peer_addr_list_item *addr;
	int i = 0, err = 0;

	HIP_IFE(!func, -EINVAL);

	list_for_each_safe(item, tmp, spi_out->peer_addr_list, i)
		{
			addr = list_entry(item);
			HIP_IFE(func(entry, addr, spi_out, opaq), -1);
		}

 out_err:
	return err;
}

// Used in hip_update_locator_contains_item_old
int hip_update_locator_item_match_old(hip_ha_t *unused,
				  struct hip_locator_info_addr_item *item1,
				  void *_item2)
{
     struct hip_peer_addr_list_item *item2 = _item2;
     return !ipv6_addr_cmp(hip_get_locator_item_address(item1), &item2->address)
     	&& hip_get_locator_item_port(item1) == item2->port;;
}

// Used in hip_update_deprecate_unlisted_old
int hip_update_locator_contains_item_old(struct hip_locator *locator,
				     struct hip_peer_addr_list_item *item)
{
	return hip_for_each_locator_addr_item_old(hip_update_locator_item_match_old,
					      NULL, locator, item);
}

// Used in hip_handle_locator_parameter_old
int hip_update_deprecate_unlisted_old(hip_ha_t *entry,
				  struct hip_peer_addr_list_item *list_item,
				  struct hip_spi_out_item *spi_out,
				  void *_locator)
{
	int err = 0;
	uint32_t spi_in;
	struct hip_locator *locator = (void *) _locator;

	if (hip_update_locator_contains_item_old(locator, list_item))
		goto out_err;

	HIP_DEBUG_HIT("Deprecating address", &list_item->address);

	list_item->address_state = PEER_ADDR_STATE_DEPRECATED;
	/* 99999: REMOVE!
        spi_in = hip_get_spi_to_update_in_established_deprecated(entry,
						      &entry->our_addr);*/
        spi_in = entry->spi_inbound_current;

	default_ipsec_func_set.hip_delete_sa(entry->default_spi_out, &list_item->address,
					     &entry->our_addr, HIP_SPI_DIRECTION_OUT, entry);
	default_ipsec_func_set.hip_delete_sa(spi_in, &entry->our_addr, &list_item->address,
					     HIP_SPI_DIRECTION_IN, entry);

	list_del(list_item, entry->spis_out_old);
 out_err:
	return err;
}

// Used in hip_handle_locator_parameter_old
int hip_for_each_locator_addr_item_old(
	int (*func)
	(hip_ha_t *entry, struct hip_locator_info_addr_item *i, void *opaq),
	hip_ha_t *entry, struct hip_locator *locator, void *opaque)
{
	int i = 0, err = 0, n_addrs;
	struct hip_locator_info_addr_item *locator_address_item = NULL;

	n_addrs = hip_get_locator_addr_item_count(locator);
	HIP_IFEL((n_addrs < 0), -1, "Negative address count\n");

	HIP_DEBUG("LOCATOR has %d address(es), loc param len=%d\n",
		  n_addrs, hip_get_param_total_len(locator));

	HIP_IFE(!func, -1);

	locator_address_item = hip_get_locator_first_addr_item(locator);
	for (i = 0; i < n_addrs; i++ ) {
		locator_address_item = hip_get_locator_item(locator_address_item, i);
		HIP_IFEL(func(entry, locator_address_item, opaque), -1,
			 "Locator handler function returned error\n");
	}

 out_err:
	return err;
}

// Used in hip_update_add_peer_addr_item_old
int hip_update_test_locator_addr(in6_addr_t *addr)
{
	struct sockaddr_storage ss;

	memset(&ss, 0, sizeof(ss));
	if (IN6_IS_ADDR_V4MAPPED(addr)) {
		struct sockaddr_in *sin = (struct sockaddr_in *) &ss;
		IPV6_TO_IPV4_MAP(addr, &sin->sin_addr);
		sin->sin_family = AF_INET;
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &ss;
		memcpy(&sin6->sin6_addr, addr, sizeof(in6_addr_t));
		sin6->sin6_family = AF_INET6;
	}

	return filter_address((struct sockaddr *) &ss);
}

// Used in hip_handle_locator_parameter_old
int hip_update_add_peer_addr_item_old(
	hip_ha_t *entry, struct hip_locator_info_addr_item *locator_address_item,
	void *_spi)
{
	in6_addr_t *locator_address;
	uint32_t lifetime = ntohl(locator_address_item->lifetime);
	int is_preferred = htonl(locator_address_item->reserved) == (1 << 7);
	int err = 0, i, locator_is_ipv4, local_is_ipv4;
	uint32_t spi = *((uint32_t *) _spi);
	uint16_t port = hip_get_locator_item_port(locator_address_item);
	uint32_t priority = hip_get_locator_item_priority(locator_address_item);
	uint8_t kind = 0;

	HIP_DEBUG("LOCATOR priority: %ld \n", priority);

	HIP_DEBUG("LOCATOR type %d \n", locator_address_item->locator_type);
	if (locator_address_item->locator_type == HIP_LOCATOR_LOCATOR_TYPE_UDP) {

		locator_address =
			&((struct hip_locator_info_addr_item2 *)locator_address_item)->address;
		kind = ((struct hip_locator_info_addr_item2 *)locator_address_item)->kind;
	} else {
		locator_address = &locator_address_item->address;
		//hip_get_locator_item_address(hip_get_locator_item_as_one(locator_address_item, 0));
	}
	HIP_DEBUG_IN6ADDR("LOCATOR address", locator_address);
	HIP_DEBUG(" address: is_pref=%s reserved=0x%x lifetime=0x%x\n",
		  is_preferred ? "yes" : "no",
		  ntohl(locator_address_item->reserved),
		  lifetime);

	/* Removed this because trying to get interfamily handovers to work --Samu */
	// Check that addresses match, we doesn't support IPv4 <-> IPv6 update
	// communnications locator_is_ipv4 = IN6_IS_ADDR_V4MAPPED(locator_address);
	//local_is_ipv4 = IN6_IS_ADDR_V4MAPPED(&entry->our_addr);

	//if( locator_is_ipv4 != local_is_ipv4 ) {
	// One of the addresses is IPv4 another is IPv6
	//  goto out_err;
	//}

	/* Check that the address is a legal unicast or anycast
	   address */
	if (!hip_update_test_locator_addr(locator_address)) {
		err = -1;
		HIP_DEBUG_IN6ADDR("Bad locator type", locator_address);
		goto out_err;
	}

	/* Check if the address is already bound to the SPI +
	   add/update address */
//add by santtu
	//both address and port will be the key to compare
	//UDP port is supported in the peer_list_item
	if (ipv6_addr_cmp(locator_address, &entry->peer_addr) == 0
			&& port == entry->peer_udp_port) {
		HIP_IFE(hip_hadb_add_udp_addr_old(entry, locator_address,
						 0,
						 lifetime, 1, port,priority,kind), -1);
	} else {
		HIP_IFE(hip_hadb_add_udp_addr_old(entry, locator_address,
						 0,
						 lifetime, is_preferred, port,priority, kind), -1);
	}
//end add
/*
 // new interface is used for updating the address
	if (ipv6_addr_cmp(locator_address, &entry->peer_addr) == 0) {
		HIP_IFE(hip_hadb_add_addr_to_spi(entry, spi, locator_address,
						 0,
						 lifetime, 1), -1);
	} else {
		HIP_IFE(hip_hadb_add_addr_to_spi(entry, spi, locator_address,
						 0,
						 lifetime, is_preferred), -1);
	}
*/
#ifdef CONFIG_HIP_OPPORTUNISTIC
	/* Check and remove the IP of the peer from the opp non-HIP database */
	hip_oppipdb_delentry(&(entry->peer_addr));
#endif

 out_err:
	return err;
}

// Used in hip_handle_locator_parameter_old
int hip_update_peer_preferred_address(hip_ha_t *entry,
				      struct hip_peer_addr_list_item *addr,
				      uint32_t spi_in)
{
	int err = 0, i = 0;
	struct hip_spi_in_item *item, *tmp;
	hip_list_t *item_nd = NULL, *tmp_nd = NULL;
	struct netdev_address *n;
	in6_addr_t local_addr;

	HIP_DEBUG("Checking spi setting 0x%x\n",spi_in);

	HIP_DEBUG_HIT("hit our", &entry->hit_our);
	HIP_DEBUG_HIT("hit peer", &entry->hit_peer);
	HIP_DEBUG_IN6ADDR("local", &entry->our_addr);
	HIP_DEBUG_IN6ADDR("peer", &addr->address);

	/* spi_in = hip_get_spi_to_update_in_established(
	   entry, &entry->our_addr); */
	HIP_IFEL(spi_in == 0, -1, "No inbound SPI found for daddr\n");

	if (IN6_IS_ADDR_V4MAPPED(&entry->our_addr)
	    != IN6_IS_ADDR_V4MAPPED(&addr->address)) {
		HIP_DEBUG("AF difference in addrs, checking if possible to choose "\
			  "same AF\n");
		list_for_each_safe(item_nd, tmp_nd, addresses, i) {
			n = list_entry(item_nd);
			if (hip_sockaddr_is_v6_mapped(&n->addr)
			    == IN6_IS_ADDR_V4MAPPED(&addr->address) &
			    (ipv6_addr_is_teredo(hip_cast_sa_addr(&n->addr)) ==
			     ipv6_addr_is_teredo(&addr->address))) {
				HIP_DEBUG("Found addr with same AF\n");
				memset(&local_addr, 0, sizeof(in6_addr_t));
				memcpy(&local_addr, hip_cast_sa_addr(&n->addr),
				       sizeof(in6_addr_t));
				HIP_DEBUG_HIT("Using addr for SA", &local_addr);
				break;
			}
		}
	} else {
		/* same AF as in addr, use &entry->our_addr */
		memset(&local_addr, 0, sizeof(in6_addr_t));
		memcpy(&local_addr, &entry->our_addr, sizeof(in6_addr_t));
	}

	/** @todo Enabling 1s makes hard handovers work, but softhandovers fail. */
#if 1
	entry->hadb_ipsec_func->hip_delete_hit_sp_pair(&entry->hit_our,
                                                       &entry->hit_peer, IPPROTO_ESP, 1);

	default_ipsec_func_set.hip_delete_sa(entry->default_spi_out, &addr->address, &local_addr,
		      HIP_SPI_DIRECTION_OUT, entry);
#endif

#if 1
	entry->hadb_ipsec_func->hip_delete_hit_sp_pair(&entry->hit_peer,
                                                       &entry->hit_our, IPPROTO_ESP, 1);
#endif

	default_ipsec_func_set.hip_delete_sa(spi_in, &addr->address, &local_addr, HIP_SPI_DIRECTION_IN, entry);

	HIP_IFEL(entry->hadb_ipsec_func->hip_setup_hit_sp_pair(&entry->hit_our,
                                                               &entry->hit_peer,
				       &local_addr, &addr->address,
				       IPPROTO_ESP, 1, 0), -1,
		 "Setting up SP pair failed\n");

	entry->local_udp_port = entry->nat_mode ? hip_get_local_nat_udp_port() : 0;

	HIP_IFEL(entry->hadb_ipsec_func->hip_add_sa(&local_addr, &addr->address,
                                                    &entry->hit_our,
			    &entry->hit_peer, entry->default_spi_out,
			    entry->esp_transform, &entry->esp_out,
			    &entry->auth_out, 1, HIP_SPI_DIRECTION_OUT, 0, entry), -1,
		 "Error while changing outbound security association for new "\
		 "peer preferred address\n");

#if 1
	HIP_IFEL(entry->hadb_ipsec_func->hip_setup_hit_sp_pair(&entry->hit_peer,
                                                               &entry->hit_our,
				       &addr->address, &local_addr,
				       IPPROTO_ESP, 1, 0), -1,
		 "Setting up SP pair failed\n");
#endif

	HIP_IFEL(entry->hadb_ipsec_func->hip_add_sa(&addr->address, &local_addr,
			    &entry->hit_peer, &entry->hit_our,
			    spi_in, entry->esp_transform,
			    &entry->esp_in, &entry->auth_in, 1,
			    HIP_SPI_DIRECTION_IN, 0, entry), -1,
		 "Error while changing inbound security association for new "\
		 "preferred address\n");

 out_err:
	return err;
}

int hip_handle_locator_parameter_old(hip_ha_t *ha, struct hip_esp_info *esp_info,
        struct hip_locator *locator)
{
        int err = 0;
        int i = 0;
       	struct hip_locator_info_addr_item *locator_address_item;
        int is_our_preferred_addr_family_ipv4 = 0;
        int is_our_addr_family_ipv4 = 0;
        int is_peer_addr_family_ipv4 = 0;
        int locator_addr_count = 0;
        int same_addr_family = 0;
        union hip_locator_info_addr *locator_info_addr;
        struct in6_addr *peer_addr;
        struct hip_spi_out_item *spi_out;
        uint32_t old_spi = 0, new_spi = 0;
        hip_list_t *item = NULL, *tmplist = NULL;
        struct netdev_address *netdev_addr;
        struct hip_peer_addr_list_item addr;

        if (locator == NULL)
        {
                err = -1;
                HIP_ERROR("Locator parameter is empty.\n");
                goto out_err;
        }

       	old_spi = ntohl(esp_info->old_spi);
	new_spi = ntohl(esp_info->new_spi);
	HIP_DEBUG("LOCATOR SPI old=0x%x new=0x%x\n", old_spi, new_spi);

	/* If following does not exit, its a bug: outbound SPI must have been
	already created by the corresponding ESP_INFO in the same UPDATE
	packet */
	HIP_IFEL(!(spi_out = hip_hadb_get_spi_list_old(ha, new_spi)), -1,
			"Bug: outbound SPI 0x%x does not exist\n", new_spi);

        // Deprecate all peer addresses
        HIP_IFEL(hip_update_for_each_peer_addr_old(hip_update_deprecate_unlisted_old,
            		 ha, spi_out, locator), -1,
			 "Deprecating a peer address failed\n");

        is_our_addr_family_ipv4 =
		IN6_IS_ADDR_V4MAPPED(&ha->our_addr) ? AF_INET :AF_INET6;

        locator_address_item = hip_get_locator_first_addr_item(locator);
	locator_addr_count = hip_get_locator_addr_item_count(locator);
        for (i = 0; i < hip_get_locator_addr_item_count(locator); i++)
        {
                locator_info_addr = hip_get_locator_item(locator_address_item, i);
                peer_addr = hip_get_locator_item_address(locator_info_addr);
                is_peer_addr_family_ipv4 = IN6_IS_ADDR_V4MAPPED(peer_addr)
			? AF_INET : AF_INET6;

		if (is_peer_addr_family_ipv4 == is_our_addr_family_ipv4)
                {
			HIP_DEBUG("LOCATOR contained same family members as "\
					"local_address\n");
			same_addr_family = 1;
			break;
		}
	}

        if (same_addr_family != 0) {
		HIP_DEBUG("Did not find any address of same family\n");
		goto out_of_loop;
	}

	list_for_each_safe(item, tmplist, addresses, i) {
		netdev_addr = list_entry(item);
                is_our_addr_family_ipv4 = hip_sockaddr_is_v6_mapped(&netdev_addr->addr) ?
			AF_INET : AF_INET6;
		if (is_peer_addr_family_ipv4 == is_our_addr_family_ipv4) {
			HIP_DEBUG("Found a local address having the same family"
                                " as the peer address");
			/* Replace the local address to match the family */
			memcpy(&ha->our_addr,
					hip_cast_sa_addr(&netdev_addr->addr),
					sizeof(in6_addr_t));
			/* Replace the peer preferred address to match the family */
			locator_address_item = hip_get_locator_first_addr_item(locator);
			/* First should be OK, no opposite family in LOCATOR */

			memcpy(&ha->peer_addr,
					hip_get_locator_item_address(locator_address_item),
					sizeof(in6_addr_t));
			memcpy(&addr.address,
					hip_get_locator_item_address(locator_address_item),
					sizeof(in6_addr_t));
			HIP_IFEL(hip_update_peer_preferred_address(
					ha, &addr, new_spi), -1,
					"Setting peer preferred address failed\n");

			goto out_of_loop;
		}
	}

out_of_loop:
	if (locator) {
		HIP_IFEL(hip_for_each_locator_addr_item_old(hip_update_add_peer_addr_item_old,
						  ha, locator, &new_spi), -1,
						  "Locator handling failed\n");
        }

out_err:
        return err;
}

// Used in hip_update_check_simple_nat_old
int hip_update_find_address_match_old(hip_ha_t *entry,
				  struct hip_locator_info_addr_item *item,
				  void *opaque)
{
	in6_addr_t *addr = (in6_addr_t *) opaque;

	HIP_DEBUG_IN6ADDR("addr1", addr);
	HIP_DEBUG_IN6ADDR("addr2", &item->address);

	return !ipv6_addr_cmp(addr, &item->address);
}

// Used in hip_handle_update_plain_locator_old
int hip_update_check_simple_nat_old(in6_addr_t *peer_ip,
				struct hip_locator *locator)
{
	int err = 0, found;
	struct hip_locator_info_addr_item *item;

	found = hip_for_each_locator_addr_item_old(hip_update_find_address_match_old,
					       NULL, locator, peer_ip);
	HIP_IFEL(found, 0, "No address translation\n");

	/** @todo Should APPEND the address to locator. */

	HIP_IFEL(!(item = hip_get_locator_first_addr_item(locator)), -1,
		 "No addresses in locator\n");
	ipv6_addr_copy(&item->address, peer_ip);
	HIP_DEBUG("Assuming NATted peer, overwrote first locator\n");

 out_err:

	return err;
}

int hip_handle_update_plain_locator_old(hip_ha_t *entry, hip_common_t *msg,
				    in6_addr_t *src_ip,
				    in6_addr_t *dst_ip,
				    struct hip_esp_info *esp_info,
				    struct hip_seq *seq)
{
	int err = 0;
	uint16_t mask = 0;
	in6_addr_t *hits = &msg->hits, *hitr = &msg->hitr;
	hip_common_t *update_packet = NULL;
	struct hip_locator *locator;
	struct hip_peer_addr_list_item *list_item;
	u32 spi_in;
	u32 spi_out = ntohl(esp_info->new_spi);

	HIP_DEBUG("\n");

	locator = hip_get_param(msg, HIP_PARAM_LOCATOR);
	HIP_IFEL(locator == NULL, -1, "No locator!\n");
	HIP_IFEL(esp_info == NULL, -1, "No esp_info!\n");

	/* return value currently ignored, no need to abort on error? */
	/** @todo We should ADD the locator, not overwrite. */
	if (entry->nat_mode)
		hip_update_check_simple_nat_old(src_ip, locator);

	/* remove unused addresses from peer addr list */
	list_item = malloc(sizeof(struct hip_peer_addr_list_item));
	if (!list_item)
		goto out_err;
	ipv6_addr_copy(&list_item->address, &entry->peer_addr);
	HIP_DEBUG_HIT("Checking if preferred address was in locator",
		      &list_item->address);
	if (!hip_update_locator_contains_item_old(locator, list_item)) {
		HIP_DEBUG("Preferred address was not in locator, so changing it "\
			  "and removing SAs\n");
		spi_in = entry->spi_inbound_current;
		default_ipsec_func_set.hip_delete_sa(spi_in, &entry->our_addr,
						     &entry->peer_addr, HIP_SPI_DIRECTION_IN, entry);
		default_ipsec_func_set.hip_delete_sa(entry->default_spi_out, &entry->peer_addr,
						     &entry->our_addr, HIP_SPI_DIRECTION_OUT, entry);
		ipv6_addr_copy(&entry->peer_addr, src_ip);
	}

	/* 99999 REMOVE!!!
        if (!hip_hadb_get_spi_list_old(entry, spi_out)) {
		struct hip_spi_out_item spi_out_data;

		HIP_DEBUG("peer has a new SA, create a new outbound SA\n");
		memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
		spi_out_data.spi = spi_out;
		spi_out_data.seq_update_id = ntohl(seq->update_id);
		HIP_IFE(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_OUT,
					 &spi_out_data), -1);
		HIP_DEBUG("added SPI=0x%x to list of outbound SAs (SA not created "\
			  "yet)\n", spi_out);
	}
         */

	HIP_IFEL(hip_handle_locator_parameter_old(entry, locator, esp_info),
		 -1, "hip_handle_locator_parameter failed\n");

 out_err:
	if (update_packet)
		HIP_FREE(update_packet);
	if (list_item)
		HIP_FREE(list_item);
	HIP_DEBUG("end, err=%d\n", err);
	return err;
}

// Used in hip_update_send_echo_old
int hip_build_verification_pkt_old(hip_ha_t *entry, hip_common_t *update_packet,
			       struct hip_peer_addr_list_item *addr,
			       in6_addr_t *hits, in6_addr_t *hitr)
{
	int err = 0;
	uint32_t esp_info_old_spi = 0, esp_info_new_spi = 0;
	uint16_t mask = 0;
	HIP_DEBUG("building verification packet\n");
	hip_msg_init(update_packet);
	entry->hadb_misc_func->hip_build_network_hdr(
		update_packet, HIP_UPDATE, mask, hitr, hits);
	entry->update_id_out++;
	addr->seq_update_id = entry->update_id_out;

	_HIP_DEBUG("outgoing UPDATE ID for LOCATOR addr check=%u\n",
		   addr->seq_update_id);

	/* Reply with UPDATE(ESP_INFO, SEQ, ACK, ECHO_REQUEST) */

	/* ESP_INFO */
	esp_info_old_spi = entry->spi_outbound_current;
	esp_info_new_spi = esp_info_old_spi;
	HIP_IFEL(hip_build_param_esp_info(update_packet,
					  entry->current_keymat_index,
					  esp_info_old_spi,
					  esp_info_new_spi),
		 -1, "Building of ESP_INFO param failed\n");
	/* @todo Handle overflow if (!update_id_out) */
	/* Add SEQ */
	HIP_IFEBL2(hip_build_param_seq(update_packet,
				       addr->seq_update_id), -1,
		   return , "Building of SEQ failed\n");

	/* TODO: NEED TO ADD ACK */
	HIP_IFEL(hip_build_param_ack(update_packet, ntohl(addr->seq_update_id)),
		 -1, "Building of ACK failed\n");

	/* Add HMAC */
	HIP_IFEBL2(hip_build_param_hmac_contents(update_packet,
						 &entry->hip_hmac_out),
		   -1, return , "Building of HMAC failed\n");
	/* Add SIGNATURE */
	HIP_IFEBL2(entry->sign(entry->our_priv_key, update_packet),
		   -EINVAL, return , "Could not sign UPDATE\n");
	get_random_bytes(addr->echo_data, sizeof(addr->echo_data));

	/* Add ECHO_REQUEST */
	HIP_HEXDUMP("ECHO_REQUEST in LOCATOR addr check",
		    addr->echo_data, sizeof(addr->echo_data));
	HIP_IFEBL2(hip_build_param_echo(update_packet, addr->echo_data,
					sizeof(addr->echo_data), 0, 1),
		   -1, return , "Building of ECHO_REQUEST failed\n");
	HIP_DEBUG("sending addr verify pkt\n");

 out_err:
	if (update_packet && err)
		HIP_FREE(update_packet);
	HIP_DEBUG("end, err=%d\n", err);
	return err;


}

// Used in hip_hadb_add_udp_addr_old
int hip_update_send_echo_old(hip_ha_t *entry,
			 uint32_t spi_out,
			 struct hip_peer_addr_list_item *addr){

	int err = 0, i = 0;
	struct hip_common *update_packet = NULL;
        hip_list_t *item = NULL, *tmp = NULL;
        struct netdev_address *n;

	HIP_DEBUG_HIT("new addr to check", &addr->address);

	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "Update_packet alloc failed\n");

	HIP_IFEL(hip_build_verification_pkt_old(entry, update_packet, addr,
					    &entry->hit_peer, &entry->hit_our),
		 -1, "Building Echo Packet failed\n");

        /* Have to take care of UPDATE echos to opposite family */
        if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)&addr->address)
            == IN6_IS_ADDR_V4MAPPED(&entry->our_addr)) {
            HIP_IFEL(entry->hadb_xmit_func->
                     hip_send_pkt(&entry->our_addr, &addr->address,
                                  (entry->nat_mode ? hip_get_local_nat_udp_port() : 0), entry->peer_udp_port,
                                  update_packet, entry, 1),
                     -ECOMM, "Sending UPDATE packet with echo data failed.\n");
	} else {
            /* UPDATE echo is meant for opposite family of local_address*/
            /* check if we have one, otherwise let fail */
            list_for_each_safe(item, tmp, addresses, i) {
                n = list_entry(item);
                if (hip_sockaddr_is_v6_mapped(&n->addr)
                    != IN6_IS_ADDR_V4MAPPED(&entry->our_addr)) {
                    HIP_IFEL(entry->hadb_xmit_func->
                             hip_send_pkt(hip_cast_sa_addr(&n->addr),
                                          (struct in6_addr*)&addr->address,
                                          (entry->nat_mode ? hip_get_local_nat_udp_port() : 0), entry->peer_udp_port,
                                          update_packet, entry, 1),
                             -ECOMM, "Sending UPDATE packet with echo data failed.\n");
                }
            }
        }

 out_err:
	return err;

}
