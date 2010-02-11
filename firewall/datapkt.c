/**
 * @file firewall/datapkt.c
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>
 *
 * Implementation of <a
 * href="tools.ietf.org/html/draft-ietf-hip-hiccups">HIP Immediate
 * Carriage and Conveyance of Upper-layer Protocol Signaling
 * (HICCUPS)</a>. In a nutshell, HICCUPS can be used to replace
 * encryption of data plane using IPsec symmetric key encryption with
 * public key encryption. The dataplane is carried over HIP control
 * packets until either end-host sends an R1 and then the end-hosts
 * switch to IPsec. An end-host can also switch to IPsec immediately
 * without processing any HICCUPS packet by sending an R1. This file
 * implements inbound and outbound processing of the dataplane similarly
 * to the userspace IPsec.
 *
 * @todo Some features from HICCUPS are still missing (switch to IPsec,
 *        SEQ numbers).
 * @todo The implementation is not optimized for speed
 *
 * @brief Implementation of HICCUPS extensions (data packets)
 *
 * @author Prabhu Patil
 **/

/* required for s6_addr32 */
#define _BSD_SOURCE

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "datapkt.h"
#include "user_ipsec_api.h"
#include "user_ipsec_esp.h"
#include "cache.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/builder.h"

static unsigned char *hip_data_packet = NULL;

/* sockets needed in order to reinject the DATA packet into the network stack */
static int raw_sock_v4                = 0;
static int raw_sock_v6                = 0;
/* allows us to make sure that we only init ones */
static int is_init                    = 0;


/**
 * Initialize raw sockets for HICCUPS
 *
 * @todo there might be some redundancy with the existing raw sockets
 *
 * @return 0 on success, -1 otherwise
 */
static int init_raw_sockets(void)
{
    int err = 0, on = 1;

    // open IPv4 raw socket
    raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    HIP_IFEL(raw_sock_v4 < 0, -1,
             "ipv4_raw_socket socket() error for raw socket\n");

    // this option allows us to add the IP header ourselves
    HIP_IFEL(setsockopt(raw_sock_v4, IPPROTO_IP, IP_HDRINCL, (char *) &on,
                        sizeof(on)) < 0, -1,
                        "setsockopt() error for IPv4 raw socket\n");

    // open IPv6 raw socket, no options needed here
    raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    HIP_IFEL(raw_sock_v6 < 0, -1,
             "ipv6_raw_socket socket() error for raw socket\n");

    // this option allows us to add the IP header ourselves
    HIP_IFEL(setsockopt(raw_sock_v6, IPPROTO_IPV6, IP_HDRINCL, (char *) &on,
                        sizeof(on)) < 0, -1,
             "setsockopt() error for IPv6 raw socket\n");

out_err:
    return err;
}

/**
 * Process an inbound HICCUPS data packet and remove the HIP header. Caller
 * is responsible to reinjecting the decapsulated message back to the networking
 * stack.
 *
 * @param ctx packet context
 * @param hip_packet the decapsulated packet will be placed here
 * @param hip_data_len length of the decapsulated packet will be placed here
 * @param preferred_local_addr local IP address for sending the packet
 * @param preferred_peer_addr remote IP address for sending the packet
 * @return zero on success and non-zero on error
 */
static int hip_data_packet_mode_input(const hip_fw_context_t *ctx,
                                      unsigned char *hip_packet,
                                      uint16_t *hip_data_len,
                                      struct in6_addr *preferred_local_addr,
                                      struct in6_addr *preferred_peer_addr)
{
    int next_hdr_offset             = 0;
    int transport_data_len          = 0;
    unsigned char *in_transport_hdr = NULL;
    int err                         = 0;
    uint8_t next_hdr                = 0;
    int data_header_len             = hip_get_msg_total_len((ctx->transport_hdr.hip));
    int packet_length               = ctx->ipq_packet->data_len;

    HIP_DEBUG("Total Packet length = %d   HIP Header has the total length = %d",
              packet_length, data_header_len);

    /* the extracted data will be placed behind the HIT-based IPv6 header */
    next_hdr_offset = sizeof(struct ip6_hdr);
    HIP_DEBUG("Next Header Offset : %d ", next_hdr_offset);

    /* below we need correctly deduct the size of hip header */
    if (ctx->ip_version == 4) {
        transport_data_len = packet_length  - sizeof(struct ip)
                             - data_header_len;
        in_transport_hdr   = ((unsigned char *) ctx->ipq_packet->payload)
                             + sizeof(struct ip) + data_header_len;
        next_hdr           = (ctx->transport_hdr.hip)->payload_proto;

        memcpy(preferred_local_addr, &(ctx->transport_hdr.hip->hitr),
               sizeof(struct in6_addr));
        memcpy(preferred_peer_addr, &(ctx->transport_hdr.hip->hits),
               sizeof(struct in6_addr));
        memcpy(hip_packet + next_hdr_offset, in_transport_hdr,
               transport_data_len);

        HIP_DEBUG("COPIED THE CONTENTS AND PAYLOAD FROM INCOMING HIP DATA PACKET, transport len = %d, next_hdr=%d",
                  transport_data_len, next_hdr);
    }

    *hip_data_len = next_hdr_offset + transport_data_len;

    HIP_DEBUG("Total Recovered packet size should be %d", *hip_data_len);

    /* now we know the next_hdr and can set up the IPv6 header */
    add_ipv6_header((struct ip6_hdr *) hip_packet, preferred_peer_addr,
                    preferred_local_addr, *hip_data_len, next_hdr);

    HIP_DEBUG("original packet length: %i\n", *hip_data_len);

    return err;
}

/**
 * Encapsulate a HIT-based transport packet from the hipfw into a HICCUPS packet
 *
 * @param packet context
 * @param preferred_local_addr local IP address for sending
 * @param preferred_peer_addr remote IP address for sending
 * @param hip_data_packet encapsulated packet will be written here
 * @param hip_packet_len length of the encapsulated packet is written here
 * @return zero on success and non-zero on error
 */
static int hip_data_packet_mode_output(const hip_fw_context_t *ctx,
                                       struct in6_addr *preferred_local_addr,
                                       struct in6_addr *preferred_peer_addr,
                                       unsigned char *hip_data_packet,
                                       uint16_t *hip_packet_len)
{
    struct ip *out_ip_hdr           = NULL;
    unsigned char *in_transport_hdr = NULL;
    uint8_t in_transport_type       = 0;
    int in_transport_len            = 0;
    int next_hdr_offset             = 0;
    int err                         = 0;
    struct hip_common *data_header  = NULL;
    int data_header_len             = 0;

    /* For time being we are just encapsulating the received IPv6 packet
     * containing HITS with another IPv4/v6 header and send it back */

    HIP_IFEL(!(data_header = hip_msg_alloc()), -1, "malloc\n");

    HIP_DEBUG("original packet length: %i \n", ctx->ipq_packet->data_len);

    /* distinguish between IPv4 and IPv6 output */
    if (IN6_IS_ADDR_V4MAPPED(preferred_peer_addr)) {
        /* NOTE: this does _not_ include IPv4 options for the original packet */
        /* calculate offset at which esp data should be located */
        out_ip_hdr        = (struct ip *) hip_data_packet;
        next_hdr_offset   = sizeof(struct ip);

        /* NOTE: we are only dealing with HIT-based (-> IPv6) data traffic */

        in_transport_hdr  = ((unsigned char *) ctx->ipq_packet->payload) + sizeof(struct ip6_hdr);
        in_transport_type = ((struct ip6_hdr *) ctx->ipq_packet->payload)->ip6_nxt;
        in_transport_len  = ctx->ipq_packet->data_len  - sizeof(struct ip6_hdr);

        err = hip_get_data_packet_header(&ctx->src, &ctx->dst,
                                         in_transport_type, data_header);
        if (err) {
            goto out_err;
        }

        data_header_len = hip_get_msg_total_len(data_header);
        HIP_DEBUG("\n HIP Header Length in Bytes = %d ", data_header_len);

        *hip_packet_len = next_hdr_offset + data_header_len + in_transport_len;
        HIP_DEBUG("Transport len = %d, type =%d, data_header_payload_type =%d, data_header_len = %d  Total_hip_packet_len = %d ",
                  in_transport_len, in_transport_type,
                  data_header->payload_proto, data_header_len, *hip_packet_len);

        memcpy(hip_data_packet + next_hdr_offset, data_header, data_header_len);
        memcpy(hip_data_packet + next_hdr_offset + data_header_len,
               in_transport_hdr, in_transport_len);

        HIP_DEBUG("Just Checking if we have copied the data correctly ... original packets next header in encapsulated packed = %d",
                  in_transport_type);

        //TESTING WITH ESP PROTO  NEED TO ADD OUR OWN PROTOCOL FIELD

        add_ipv4_header(out_ip_hdr, preferred_local_addr, preferred_peer_addr,
                        *hip_packet_len, IPPROTO_HIP);
        HIP_DEBUG("HIP data packet length %d ", *hip_packet_len);
    } else {
        HIP_DEBUG("We have other than IPv6 mapped");
    }

out_err:
    if (data_header) {
        free(data_header);
    }

    return err;
}

/**
 * Initialization of HICCUPS mode
 *
 * @return zero on success or non-zero on error
 */
int hip_datapacket_mode_init(void)
{
    int err = 0;

    HIP_DEBUG("\n");

    if (!is_init) {
        HIP_DEBUG("ESP_PACKET_SIZE is %i\n", ESP_PACKET_SIZE);

        // allocate memory for the packet buffers
        HIP_IFEL(!(hip_data_packet = (unsigned char *) malloc(ESP_PACKET_SIZE)),
                 -1, "failed to allocate memory");

        // create required sockets
        HIP_IFEL(init_raw_sockets(), -1, "raw sockets");

        is_init = 1;

        HIP_DEBUG("data packet mode successfully initialised\n");
    }

out_err:
    return err;
}

/**
 * Uninitialization for HICCUPS mode
 *
 * @return zero on success or non-zero on error
 */
int hip_datapacket_mode_uninit(void)
{
    int err = 0;

    // close sockets used for reinjection
    if (raw_sock_v4) {
        close(raw_sock_v4);
    }
    if (raw_sock_v6) {
        close(raw_sock_v6);
    }

    // free the members
    if (hip_data_packet) {
        free(hip_data_packet);
    }

    return err;
}

/**
 * A wrapper function to process an inbound HICCUPS packet and to reinject it to the stack
 *
 * @param ctx packet context
 * @return zero on success or non-zero on failure
 **/
int hip_fw_userspace_datapacket_input(const hip_fw_context_t *ctx)
{
    int err = 0;
    /* the routable addresses as used in HIPL */
    struct in6_addr preferred_local_addr;
    struct in6_addr preferred_peer_addr;
    struct sockaddr_storage local_sockaddr;
    uint16_t data_packet_len = 0;

    HIP_DEBUG("HIP DATA MODE INPUT\n");

    HIP_IFEL(hip_data_packet_mode_input(ctx, hip_data_packet,
                                        &data_packet_len, &preferred_local_addr, &preferred_peer_addr), 1,
             "failed to recreate original packet\n");

    HIP_HEXDUMP("restored original packet: ", hip_data_packet,
                data_packet_len);

    // create sockaddr for sendto
    hip_addr_to_sockaddr(&preferred_local_addr, &local_sockaddr);

    // re-insert the original HIT-based (-> IPv6) packet into the network stack
    err = sendto(raw_sock_v6, hip_data_packet, data_packet_len, 0,
                 (struct sockaddr *) &local_sockaddr,
                 hip_sockaddr_len(&local_sockaddr));

    if (err < 0) {
        HIP_DEBUG("sendto() failed\n");
    } else {
        HIP_DEBUG("SUCCESSFULLY RECEIVED THE PACKET");
    }

out_err:
    return err;
}

/**
 * A wrapper function to process an outbound HICCUPS packet and to reinject it to the stack
 *
 * @param ctx packet context
 * @return zero on success or non-zero on failure
 **/
int hip_fw_userspace_datapacket_output(const hip_fw_context_t *ctx)
{
    uint16_t data_packet_len = 0;
    struct in6_addr preferred_local_addr;
    struct in6_addr preferred_peer_addr;
    struct sockaddr_storage peer_sockaddr;
    int out_ip_version       = 0;
    int err                  = 0;

    /* Hip Daemon doesn't send the i1 packet, if data packet mode is on.
     * This gets preferred addresses in DB and returns */
    if (hip_firewall_cache_db_match(&ctx->src, &ctx->dst, NULL, NULL,
                                    &preferred_local_addr,
                                    &preferred_peer_addr, NULL)) {
        HIP_DEBUG("HIP_DATAPACKET MODE is Already Set so using DATA PACKET MODE for new connections\n");
    }

    HIP_DEBUG_HIT("preferred_local_addr", &preferred_local_addr);
    HIP_DEBUG_HIT("preferred_peer_addr", &preferred_peer_addr);

    // check preferred addresses for the address type of the output
    if (IN6_IS_ADDR_V4MAPPED(&preferred_local_addr)
        && IN6_IS_ADDR_V4MAPPED(&preferred_peer_addr)) {
        HIP_DEBUG("out_ip_version is IPv4\n");
        out_ip_version = 4;
    } else if (!IN6_IS_ADDR_V4MAPPED(&preferred_local_addr)
               && !IN6_IS_ADDR_V4MAPPED(&preferred_peer_addr)) {
        HIP_DEBUG("out_ip_version is IPv6\n");
        out_ip_version = 6;
    } else {
        HIP_ERROR("bad address combination\n");

        err = -1;
        goto out_err;
    }

    HIP_DEBUG("ESP_PACKET_SIZE is %i\n", ESP_PACKET_SIZE);

    HIP_IFEL(hip_data_packet_mode_output(ctx, &preferred_local_addr,
                                         &preferred_peer_addr, hip_data_packet,
                                         &data_packet_len),
                                         1,
                                         "failed to create HIP_DATA_PACKET_MODE packet");

    // create sockaddr for sendto
    hip_addr_to_sockaddr(&preferred_peer_addr, &peer_sockaddr);

    // reinsert the esp packet into the network stack
    if (out_ip_version == 4) {
        err = sendto(raw_sock_v4, hip_data_packet, data_packet_len, 0,
                     (struct sockaddr *) &peer_sockaddr,
                     hip_sockaddr_len(&peer_sockaddr));
    } else {
        err = sendto(raw_sock_v6, hip_data_packet, data_packet_len, 0,
                     (struct sockaddr *) &peer_sockaddr,
                     hip_sockaddr_len(&peer_sockaddr));
    }

    if (err < data_packet_len) {
        HIP_DEBUG("sendto() failed: sent %d  - received %d\n", data_packet_len,
                  err);

        err = -1;
        goto out_err;
    } else {
        HIP_DEBUG("new packet SUCCESSFULLY re-inserted into network stack\n");
        HIP_DEBUG("dropping original packet...\n");
        // the original packet has to be dropped
        err = 1;
        goto out_err;
    }

out_err:
    return err;
}

/**
 * Verify HICCUPS signature
 *
 * @param common The HICCUPS control packet
 * @return zero on success, or negative error value on failure
 */
int hip_handle_data_signature(struct hip_common *common)
{
    struct in6_addr hit;
    struct hip_host_id *host_id = NULL;
    // assume correct packet
    int err                     = 0;
    hip_tlv_len_t len           = 0;
    int orig_payload_proto      = common->payload_proto;

    HIP_DUMP_MSG(common);
    HIP_DEBUG("verifying hi -> hit mapping...\n");

    // handling HOST_ID param
    HIP_IFEL(!(host_id = (struct hip_host_id *)
            hip_get_param(common, HIP_PARAM_HOST_ID)), -1,
            "No HOST_ID found in control message\n");

    len = hip_get_param_total_len(host_id);

    // verify HI->HIT mapping
    HIP_IFEL(hip_host_id_to_hit(host_id, &hit, HIP_HIT_TYPE_HASH100) ||
             ipv6_addr_cmp(&hit, &common->hits),
             -1, "Unable to verify HOST_ID mapping to src HIT\n");

    /* @todo Due to some message.c constraints,
     * common->type_hdr was set to 1 when signing the data..
     * So set it to 1 when verifying and then reset it back */
    common->payload_proto = 1;

    HIP_IFEL(hip_verify_packet_signature(common, host_id), -EINVAL,
             "Verification of signature failed");

    HIP_DEBUG("verified HIP DATA signature\n");

out_err:
    /* Reset the payload_proto field */
    common->payload_proto = orig_payload_proto;

    return err;
}
