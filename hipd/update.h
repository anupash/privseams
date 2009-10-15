/** @file
 * The header file for update.c
 *
 * @author  Baris Boyvat <baris#boyvat.com>
 * @version 0.1
 * @date    3.5.2009
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_UPDATE_H
#define HIP_UPDATE_H

#include "builder.h"
#include "hadb.h"

void hip_send_update_locator();

int hip_receive_update(hip_common_t* msg, in6_addr_t *src_addr,
        in6_addr_t *dst_addr, hip_ha_t *entry, hip_portpair_t *sinfo);

/**
 * @brief Receives an UPDATE packet.
 *
 * This is the initial function which is called when an UPDATE packet is
 * received. The UPDATE packet is only processed when the HIP state machine is
 * in state ESTABLISHED (see section 6.12. Receiving UPDATE Packets of RFC
 * 5201). However, if the state machine is in state R2-SENT and an UPDATE is
 * received, the state machine should move to state ESTABLISHED (see table 5
 * under section 4.4.2. HIP State Processes). Therefore this function processes
 * the received UPDATE packet in both of the states, R2-sent and ESTABLISHED.
 * When received in state R2-SENT, we move to state ESTABLISHED as instructed in
 * RFC 5201.
 *
 * If there is no corresponding HIP association (@c entry is NULL) or if the
 * state machine is in any other state than R2-SENT or ESTABLISHED the packet is
 * not processed and -1 is returned.
 *
 * The validity of the packet is checked and then this function acts
 * according to whether this packet is a reply or not.
 *
 * @param msg          a pointer to a HIP packet.
 * @param update_saddr a pointer to the UPDATE packet source IP address.
 * @param update_daddr a pointer to the UPDATE packet destination IP address.
 * @param entry        a pointer to a hadb entry.
 * @param sinfo        a pointer to a structure containing the UPDATE packet
 *                     source and destination ports.
 * @return             0 if successful (HMAC and signature (if needed) are
 *                     validated, and the rest of the packet is handled if
 *                     current state allows it), otherwise < 0.
 */
int hip_receive_update_old(hip_common_t *msg, in6_addr_t *update_saddr,
		       in6_addr_t *update_daddr, hip_ha_t *entry,
		       hip_portpair_t *sinfo);

/**
 * Handles address verification UPDATE.
 *
 * Handles UPDATE(SPI, SEQ, ACK, ECHO_REQUEST) or UPDATE(SPI, SEQ,
 * ECHO_REQUEST).
 *
 * @param entry  a pointer to a hadb entry corresponding to the peer.
 * @param msg    a pointer to a the HIP packet.
 * @param src_ip a pointer to a source IPv6 address to use in the UPDATE to be
 *               sent out.
 * @param dst_ip a pointer to a destination IPv6 address to use in the UPDATE
 *               to be sent out.
 * @return       0 if successful, otherwise < 0.
 * @note         @c entry must be is locked when this function is called.
 */
int hip_handle_update_addr_verify_old(hip_ha_t *entry, hip_common_t *msg,
				  in6_addr_t *src_ip, in6_addr_t *dst_ip);

/**
 * Handles UPDATE(LOCATOR, SEQ).
 *
 * For each address in the LOCATOR, we reply with ACK and
 * UPDATE(SPI, SEQ, ACK, ECHO_REQUEST).
 *
 * @param entry  a pointer to a hadb entry corresponding to the peer.
 * @param msg    a pointer to the HIP packet.
 * @param src_ip a pointer to the source IPv6 address to use in the UPDATE to be
 *               sent out.
 * @param dst_ip a pointer to the destination IPv6 address to use in the UPDATE
 *               to be sent out.
 * @return       0 if successful, otherwise < 0.
 * @note         @c entry must be is locked when this function is called.
 */
int hip_handle_update_plain_locator_old(hip_ha_t *entry, hip_common_t *msg,
				    in6_addr_t *src_ip, in6_addr_t *dst_ip,
				    struct hip_esp_info *esp_info,
				    struct hip_seq *seq);

/**
 * @brief Handles an incoming UPDATE packet received in ESTABLISHED state.
 *
 * This function handles case 7 in section 8.11 Processing UPDATE packets in
 * state ESTABLISHED of the base draft.
 *
 * @param entry  a pointer to a hadb entry corresponding to the peer.
 * @param msg    a pointer to a HIP packet.
 * @param src_ip source IPv6 address from where the UPDATE was sent.
 * @param dst_ip destination IPv6 address to which the UPDATE was sent.
 * @return       0 if successful, otherwise < 0.
 * @note         @c entry must be is locked when this function is called.
 */
int hip_handle_update_established_old(hip_ha_t *entry, hip_common_t *msg,
				  in6_addr_t *src_ip, in6_addr_t *dst_ip,
				  hip_portpair_t *update_info);

/**
 * Handles an incoming UPDATE packet received in REKEYING state.
 *
 * This function handles case 8 in section 8.11 Processing UPDATE
 * packets of the base draft.
 *
 * @param entry  a pointer to a hadb entry corresponding to the peer.
 * @param msg    a pointer to a the HIP packet.
 * @param src_ip a pointer to the source IPv6 address from where the UPDATE
 *               was sent.
 * @return       0 if successful, otherwise < 0.
 * @note         @c entry must be is locked when this function is called.
 */
int hip_handle_update_rekeying_old(hip_ha_t *entry, hip_common_t *msg,
			       in6_addr_t *src_ip);

/**
 * Sends address verification UPDATE.
 *
 * @param entry  a pointer to a hadb entry corresponding to the peer.
 * @param msg    a pointer to the HIP packet.
 * @param src_ip source IPv6 address to use in the UPDATE to be sent out
 * @param spi    outbound SPI in host byte order
 * @return       0 if successful, otherwise < 0.
 * @note         @c entry must be is locked when this function is called.
 */
int hip_update_send_addr_verify_deprecated(hip_ha_t *entry, hip_common_t *msg,
				in6_addr_t *src_ip, uint32_t spi);

/**
 * Handles UPDATE acknowledgement.
 *
 * @param entry    a pointer to a hadb entry corresponding to the peer.
 * @param ack      a pointer to ...
 * @param have_nes ...
 */
void hip_update_handle_ack_old(hip_ha_t *entry, struct hip_ack *ack, int have_nes);

/**
 * Sends an initial UPDATE packet to the peer.
 *
 * @param entry      a pointer to a hadb entry corresponding to the peer.
 * @param addr_list  a pointer to an address list. if non-NULL, LOCATOR
 *                   parameter is added to the UPDATE.
 * @param addr_count number of addresses in @c addr_list.
 * @param ifindex    interface number. If non-zero, the ifindex value of the
 *                   interface which caused the event.
 * @param flags      ...
 * @param is_add     ...
 * @param addr       a pointer to ...
 * @return           0 if UPDATE was sent, otherwise < 0.
 */
int hip_send_update_old(struct hip_hadb_state *entry,
		    struct hip_locator_info_addr_item *addr_list,
		    int addr_count, int ifindex, int flags, int is_add,
		    struct sockaddr* addr);

/**
 * Sends UPDATE packet to every peer.
 *
 * UPDATE is sent to the peer only if the peer is in established state. Add
 * LOCATOR parameter if @c addr_list is non-null. @c ifindex tells which device
 * caused the network device event.
 *
 * @param addr_list  if non-NULL, LOCATOR parameter is added to the UPDATE.
 * @param addr_count number of addresses in @c addr_list.
 * @param ifindex    if non-zero, the ifindex value of the interface which
 *                   caused the event.
 * @param flags      flags passed to @c hip_send_update.
 */
void hip_send_update_all_old(struct hip_locator_info_addr_item *addr_list,
			 int addr_count, int ifindex,  int flags, int is_add,
			 struct sockaddr* addr);

/**
 * Internal function copied originally from rea.c.
 *
 * @param entry a pointer to a hadb entry.
 * @param addr  op
 * @return      ...
 */
static int hip_update_get_all_valid_old(hip_ha_t *entry, void *op);


#endif /* HIP_UPDATE_H */