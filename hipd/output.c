/* @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * This file defines processing of outgoing packets for the Host
 * Identity Protocol (HIP).
 *
 * @author  Janne Lundberg
 * @author  Miika Komu
 * @author  Mika Kousa
 * @author  Kristian Slavov
 * @author  Samu Varjonen
 * @author  Rene Hummen
 */

#define _BSD_SOURCE

#include <netinet/icmp6.h>

#include "config.h"
#include "output.h"
#include "lib/core/performance.h"
#include "lib/core/hip_udp.h"
#include "lib/core/solve.h"
#include "lib/tool/checksum.h"

#ifdef CONFIG_HIP_MIDAUTH
#include "pisa.h"
#endif

enum number_dh_keys_t { ONE, TWO };

enum number_dh_keys_t number_dh_keys = TWO;

/**
 * @brief Sends a TCP packet through a raw socket.
 *
 * @param  hdr
 * @param  newSize
 * @param  trafficType 4 or 6 - standing for ipv4 and ipv6
 * @param  sockfd      a socket file descriptor
 * @param  addOption   adds the I1 option to a packet if required
 * @param  addHIT      adds the default HIT after the I1 option (if I1 option
 *                     should be added)
 * @return             ?
 */
int send_tcp_packet(void *hdr, int newSize, int trafficType, int sockfd,
                    int addOption, int addHIT)
{
    int on                      = 1, err = 0, off = 0, hdr_size = 0;
    int newHdr_size             = 0, twoHdrsSize = 0;
    char *HITbytes              = NULL;
    char *bytes                 = (char *) hdr;
    void *pointer               = NULL;
    struct tcphdr *tcphdr       = NULL, *newTcphdr = NULL;
    struct ip *iphdr            = NULL, *newIphdr = NULL;
    struct ip6_hdr *ip6_hdr     = NULL, *newIp6_hdr = NULL;
    struct pseudo_hdr *pseudo   = NULL;
    struct pseudo6_hdr *pseudo6 = NULL;
    struct sockaddr_in sin_addr;
    struct sockaddr_in6 sin6_addr;

    in6_addr_t *defaultHit      = (in6_addr_t *) malloc(sizeof(char) * 16);
    char newHdr[newSize + 4 * addOption + (sizeof(struct in6_addr)) * addHIT];

    if (addOption) {
        newSize = newSize + 4;
    }
    if (addHIT) {
        newSize = newSize + sizeof(struct in6_addr);
    }

    //initializing the headers and setting socket settings
    if (trafficType == 4) {
        //get the ip header
        iphdr               = (struct ip *) hdr;
        //get the tcp header
        hdr_size            = (iphdr->ip_hl * 4);
        tcphdr              = ((struct tcphdr *) (void *) (((char *) iphdr) + hdr_size));
        //socket settings
        sin_addr.sin_family = AF_INET;
        sin_addr.sin_port   = htons(tcphdr->dest);

        /* Is that right to copy address? */
        sin_addr.sin_addr   = iphdr->ip_dst;
    } else if (trafficType == 6)    {
        //get the ip header
        ip6_hdr               = (struct ip6_hdr *) hdr;
        //get the tcp header
        hdr_size              = sizeof(struct ip6_hdr);
        tcphdr                = ((struct tcphdr *) (void *) (((char *) ip6_hdr) + hdr_size));
        //socket settings
        sin6_addr.sin6_family = AF_INET6;
        sin6_addr.sin6_port   = htons(tcphdr->dest);
        sin6_addr.sin6_addr   = ip6_hdr->ip6_dst;
    }

    //measuring the size of ip and tcp headers (no options)
    twoHdrsSize = hdr_size + 4 * 5;

    //copy the ip header and the tcp header without the options
    memcpy(&newHdr[0], &bytes[0], twoHdrsSize);

    //get the default hit
    if (addHIT) {
        hip_get_default_hit(defaultHit);
        HITbytes = (char *) defaultHit;
    }

    //add the i1 option and copy the old options
    //add the HIT if required,
    if (tcphdr->doff == 5) {  //there are no previous options
        if (addOption) {
            newHdr[twoHdrsSize]     = (char) HIP_OPTION_KIND;
            newHdr[twoHdrsSize + 1] = (char) 2;
            newHdr[twoHdrsSize + 2] = (char) 1;
            newHdr[twoHdrsSize + 3] = (char) 1;
            if (addHIT) {
                //put the default hit
                memcpy(&newHdr[twoHdrsSize + 4], &HITbytes[0], 16);
            }
        } else {
            if (addHIT) {
                //put the default hit
                memcpy(&newHdr[twoHdrsSize], &HITbytes[0], 16);
            }
        }
    } else { //there are previous options
        if (addOption) {
            newHdr[twoHdrsSize]     = (char) HIP_OPTION_KIND;
            newHdr[twoHdrsSize + 1] = (char) 2;
            newHdr[twoHdrsSize + 2] = (char) 1;
            newHdr[twoHdrsSize + 3] = (char) 1;

            //if the HIT is to be sent, the
            //other options are not important
            if (addHIT) {
                //put the default hit
                memcpy(&newHdr[twoHdrsSize + 4], &HITbytes[0], 16);
            } else {
                memcpy(&newHdr[twoHdrsSize + 4], &bytes[twoHdrsSize], 4 * (tcphdr->doff - 5));
            }
        } else {
            //if the HIT is to be sent, the
            //other options are not important
            if (addHIT) {
                //put the default hit
                memcpy(&newHdr[twoHdrsSize], &HITbytes[0], 16);
            } else {
                memcpy(&newHdr[twoHdrsSize], &bytes[twoHdrsSize], 4 * (tcphdr->doff - 5));
            }
        }
    }

    pointer = &newHdr[0];
    //get pointers to the new packet
    if (trafficType == 4) {
        //get the ip header
        newIphdr    = (struct ip *) pointer;
        //get the tcp header
        newHdr_size = (iphdr->ip_hl * 4);
        newTcphdr   = ((struct tcphdr *) (void *) (((char *) newIphdr) + newHdr_size));
    } else if (trafficType == 6)    {
        //get the ip header
        newIp6_hdr  = (struct ip6_hdr *) pointer;
        //get the tcp header
        newHdr_size = (newIp6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen * 4);
        newTcphdr   = ((struct tcphdr *) (void *) (((char *) newIp6_hdr) + newHdr_size));
    }

    //change the values of the checksum and the tcp header length(+1)
    newTcphdr->check = 0;
    if (addOption) {
        newTcphdr->doff = newTcphdr->doff + 1;
    }
    if (addHIT) {
        newTcphdr->doff = newTcphdr->doff + 4;        //16 bytes HIT - 4 more words
    }
    //the checksum
    if (trafficType == 4) {
        pseudo = (struct pseudo_hdr *) (void *) ((uint8_t *) newTcphdr - sizeof(struct pseudo_hdr));

        pseudo->s_addr   = newIphdr->ip_src.s_addr;
        pseudo->d_addr   = newIphdr->ip_dst.s_addr;
        pseudo->zer0     = 0;
        pseudo->protocol = IPPROTO_TCP;
        pseudo->length   = htons(sizeof(struct tcphdr) + 4 * (newTcphdr->doff - 5) + 0);

        newTcphdr->check = in_cksum((unsigned short *) pseudo, sizeof(struct tcphdr) +
                                    4 * (newTcphdr->doff - 5) + sizeof(struct pseudo_hdr) + 0);
    } else if (trafficType == 6)    {
        pseudo6 = (struct pseudo6_hdr *) (void *) ((uint8_t *) newTcphdr - sizeof(struct pseudo6_hdr));

        pseudo6->s_addr   = newIp6_hdr->ip6_src;
        pseudo6->d_addr   = newIp6_hdr->ip6_dst;
        pseudo6->zer0     = 0;
        pseudo6->protocol = IPPROTO_TCP;
        pseudo6->length   = htons(sizeof(struct tcphdr) + 4 * (newTcphdr->doff - 5) + 0);

        newTcphdr->check  = in_cksum((unsigned short *) pseudo6, sizeof(struct tcphdr) +
                                     4 * (newTcphdr->doff - 5) + sizeof(struct pseudo6_hdr) + 0);
    }

    //replace the pseudo header bytes with the correct ones
    memcpy(&newHdr[0], &bytes[0], hdr_size);

    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *) &on, sizeof(on)) < 0) {
        HIP_DEBUG("Error setting an option to raw socket\n");
        return -1;
    }

    //finally send through the socket
    err = sendto(sockfd, &newHdr[0], newSize, 0, (struct sockaddr *) &sin_addr, sizeof(sin_addr));

    if (defaultHit) {
        HIP_FREE(defaultHit);
    }

    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *) &off, sizeof(off));

    return err;
}

/**
 * Send an I1 packet to the Responder. Used internally by hip_send_i1().
 *
 * @param i1         a pointer to a i1 packet common header with source and
 *                   destination HITs.
 * @param dst_hit    destination HIT (used only for the opportunistic TCP extension)
 * @param local_addr a pointer to our IPv6 or IPv4-in-IPv6 format IPv4 address.
 *                   If local_addr is NULL, the packet is sent from all addresses.
 * @param peer_addr  a pointer to peer IPv6 or IPv4-in-IPv6 format IPv4 address.
 * @param src_port   not used.
 * @param dst_port   not used.
 * @param entry      a pointer to the current host association database state.
 * @param retransmit a boolean value indicating if this is a retransmission
 *                   (@b zero if this is @b not a retransmission).
 * @return           zero on success, or negative error value on error.
 * @todo remove the dst_hit parameter? test with the opportunistic TCP extension
 */
static int hip_send_i1_pkt(struct hip_common *i1,
                           hip_hit_t *dst_hit,
                           struct in6_addr *local_addr,
                           struct in6_addr *peer_addr,
                           in_port_t src_port,
                           in_port_t dst_port,
                           hip_ha_t *entry,
                           int retransmit)
{
    int err = 0;

#ifdef CONFIG_HIP_OPPORTUNISTIC
    // if hitr is hashed null hit, send it as null on the wire
    if  (hit_is_opportunistic_hit(&i1->hitr)) {
        ipv6_addr_copy(&i1->hitr, &in6addr_any);
    }

    if (local_addr) {
        HIP_DEBUG_IN6ADDR("local", local_addr);
    }
    if (peer_addr) {
        HIP_DEBUG_IN6ADDR("peer", peer_addr);
    }

#endif // CONFIG_HIP_OPPORTUNISTIC

    HIP_DEBUG_HIT("BEFORE sending", peer_addr);
    err = hip_send_pkt(local_addr, peer_addr, src_port, dst_port, i1, entry, 1);

    HIP_DEBUG("err after sending: %d.\n", err);

    if (!err) {
        HIP_LOCK_HA(entry);
        entry->state = HIP_STATE_I1_SENT;
        HIP_UNLOCK_HA(entry);
    } else if (err == 1)   {
        err = 0;
    }

    return err;
}

/**
 * Send an I1 packet to the Responder
 *
 * @param src_hit a pointer to source host identity tag.
 * @param dst_hit a pointer to destination host identity tag.
 * @param entry   a pointer to a host association database state reserved for
 *                the peer.
 * @return        zero on success, or negative error value on error.
 */
int hip_send_i1(hip_hit_t *src_hit, hip_hit_t *dst_hit, hip_ha_t *entry)
{
    struct hip_common *i1       = 0;
    uint16_t mask               = 0;
    int err                     = 0;
    hip_list_t *item            = NULL, *tmp = NULL;
    struct hip_peer_addr_list_item *addr;
    int i                       = 0;
    struct in6_addr *local_addr = NULL;
    struct in6_addr peer_addr;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_I1_SEND, PERF_BASE\n");
    hip_perf_start_benchmark(perf_set, PERF_I1_SEND);
    hip_perf_start_benchmark(perf_set, PERF_BASE);
#endif

    HIP_IFEL((entry->state == HIP_STATE_ESTABLISHED), 0,
             "State established, not triggering bex\n");

    /* Assign a local private key, public key and HIT to HA */
    HIP_DEBUG_HIT("src_hit", src_hit);
    HIP_DEBUG_HIT("entry->src_hit", &entry->hit_our);
    HIP_IFEL(hip_init_us(entry, src_hit), -EINVAL,
             "Could not assign a local host id\n");
    HIP_DEBUG_HIT("entry->src_hit", &entry->hit_our);

    /* We don't need to use hip_msg_alloc(), since the I1
     * packet is just the size of struct hip_common. */

    /* ..except that when calculating the msg size, we need to have more
     * than just hip_common */

    /* So why don't we just have a hip_max_t struct to allow allocation of
     * maximum sized HIP packets from the stack? Not that it would make any
     * difference here, but playing with mallocs has always the chance of
     * leaks... */

    i1 = hip_msg_alloc();

    hip_build_network_hdr(i1, HIP_I1, mask, &entry->hit_our, dst_hit);

    /* Calculate the HIP header length */
    hip_calc_hdr_len(i1);

    HIP_DEBUG_HIT("HIT source", &i1->hits);
    HIP_DEBUG_HIT("HIT dest", &i1->hitr);

    HIP_DEBUG("Sending I1 to the following addresses:\n");
    hip_print_peer_addresses_to_be_added(entry);

    if (hip_shotgun_status == HIP_MSG_SHOTGUN_OFF ||
        (entry->peer_addr_list_to_be_added == NULL)) {
        HIP_IFEL(hip_hadb_get_peer_addr(entry, &peer_addr), -1,
                 "No preferred IP address for the peer.\n");

        local_addr = &entry->our_addr;
        err        = hip_send_i1_pkt(i1,
                                     dst_hit,
                                     local_addr,
                                     &peer_addr,
                                     entry->local_udp_port,
                                     entry->peer_udp_port,
                                     entry,
                                     1);
    } else {
        HIP_DEBUG("Number of items in the peer addr list: %d ",
                  ((struct lhash_st *) entry->peer_addr_list_to_be_added)->num_items);
        list_for_each_safe(item, tmp, entry->peer_addr_list_to_be_added, i)
        {
            addr = (struct hip_peer_addr_list_item *) list_entry(item);
            ipv6_addr_copy(&peer_addr, &addr->address);

            err  = hip_send_i1_pkt(i1,
                                   dst_hit,
                                   NULL,
                                   &peer_addr,
                                   entry->local_udp_port,
                                   entry->peer_udp_port,
                                   entry,
                                   1);

            /* Do not bail out on error with shotgun. Some
             * address pairs just might fail. */
        }
    }
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_I1_SEND\n");
    hip_perf_stop_benchmark(perf_set, PERF_I1_SEND);
    hip_perf_write_benchmark(perf_set, PERF_I1_SEND);
#endif

out_err:
    if (i1 != NULL) {
        free(i1);
    }
    return err;
}

/**
 * @brief Creates an I2 packet and sends it.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *ctx Pointer to the packet context, containing all
 *                    information for the packet handling
 *                    (received message, source and destination address, the
 *                    ports and the corresponding entry from the host
 *                    association database).
 *
 * @return zero on success, non-negative on error.
 */
int hip_send_i2(const uint8_t packet_type,
                const uint32_t ha_state,
                struct hip_packet_context *ctx)
{
    hip_transform_suite_t transform_hip_suite, transform_esp_suite;
    struct hip_spi_in_item spi_in_data;
    in6_addr_t daddr;
    struct hip_param *param                 = NULL;
    struct hip_esp_info *esp_info           = NULL;
    struct hip_host_id_entry *host_id_entry = NULL;
    char *enc_in_msg                        = NULL, *host_id_in_enc = NULL;
    unsigned char *iv                       = NULL;
    int err = 0, host_id_in_enc_len = 0;
    uint32_t spi_in = 0;

    HIP_IFEL(ctx->error,
             -1,
             "Abort packet processing.\n");

    /* We haven't handled REG_INFO parameter. We do that in hip_send_i2()
     * because we must create an REG_REQUEST parameter based on the data
     * of the REG_INFO parameter. */

    HIP_DEBUG("R1 source port %u, destination port %d\n",
              ctx->msg_ports->src_port,
              ctx->msg_ports->dst_port);

    HIP_ASSERT(ctx->hadb_entry);

    spi_in = ctx->hadb_entry->spi_inbound_current;

    /* TLV sanity checks are are already done by the caller of this
     * function. Now, begin to build I2 piece by piece. */

    /* Delete old SPDs and SAs, if present */
    hip_delete_security_associations_and_sp(ctx->hadb_entry);

    /********** R1 COUNTER (OPTIONAL) ********/
    /* we build this, if we have recorded some value (from previous R1s) */
    {
        uint64_t rtmp;

        HIP_LOCK_HA(ctx->hadb_entry);
        rtmp = ctx->hadb_entry->birthday;
        HIP_UNLOCK_HA(ctx->hadb_entry);

        HIP_IFEL(rtmp && hip_build_param_r1_counter(ctx->output_msg, rtmp), -1,
                 "Could not build R1 GENERATION parameter\n");
    }

    /********** HIP transform. **********/
    HIP_IFE(!(param = hip_get_param(ctx->input_msg, HIP_PARAM_HIP_TRANSFORM)),
            -ENOENT);
    HIP_IFEL((transform_hip_suite =
                  hip_select_hip_transform((struct hip_hip_transform *) param)) == 0,
             -EINVAL,
             "Could not find acceptable hip transform suite\n");

    /* Select only one transform */
    HIP_IFEL(hip_build_param_hip_transform(ctx->output_msg,
                                           &transform_hip_suite,
                                           1),
             -1,
             "Building of HIP transform failed\n");

    HIP_DEBUG("HIP transform: %d\n", transform_hip_suite);

    /************ Encrypted ***********/
    if (hip_encrypt_i2_hi) {
        switch (transform_hip_suite) {
        case HIP_HIP_AES_SHA1:
            HIP_IFEL(hip_build_param_encrypted_aes_sha1(ctx->output_msg,
                                                        (struct hip_tlv_common *) ctx->hadb_entry->our_pub),
                     -1,
                     "Building of param encrypted failed.\n");
            enc_in_msg     = hip_get_param(ctx->output_msg,
                                           HIP_PARAM_ENCRYPTED);
            HIP_ASSERT(enc_in_msg);             /* Builder internal error. */
            iv             = ((struct hip_encrypted_aes_sha1 *) enc_in_msg)->iv;
            get_random_bytes(iv, 16);
            host_id_in_enc = enc_in_msg + sizeof(struct hip_encrypted_aes_sha1);
            break;
        case HIP_HIP_3DES_SHA1:
            HIP_IFEL(hip_build_param_encrypted_3des_sha1(ctx->output_msg,
                                                         (struct hip_tlv_common *) ctx->hadb_entry->our_pub),
                     -1,
                     "Building of param encrypted failed.\n");
            enc_in_msg     = hip_get_param(ctx->output_msg,
                                           HIP_PARAM_ENCRYPTED);
            HIP_ASSERT(enc_in_msg);             /* Builder internal error. */
            iv             = ((struct hip_encrypted_3des_sha1 *) enc_in_msg)->iv;
            get_random_bytes(iv, 8);
            host_id_in_enc = enc_in_msg +
                             sizeof(struct hip_encrypted_3des_sha1);
            break;
        case HIP_HIP_NULL_SHA1:
            HIP_IFEL(hip_build_param_encrypted_null_sha1(ctx->output_msg,
                                                         (struct hip_tlv_common *) ctx->hadb_entry->our_pub),
                     -1,
                     "Building of param encrypted failed.\n");
            enc_in_msg     = hip_get_param(ctx->output_msg,
                                           HIP_PARAM_ENCRYPTED);
            HIP_ASSERT(enc_in_msg);             /* Builder internal error. */
            iv             = NULL;
            host_id_in_enc = enc_in_msg +
                             sizeof(struct hip_encrypted_null_sha1);
            break;
        default:
            HIP_IFEL(1, -ENOSYS, "HIP transform not supported (%d)\n",
                     transform_hip_suite);
        }
    } else {   /* add host id in plaintext without encrypted wrapper */
               /* Parameter HOST_ID. Notice that hip_get_public_key overwrites
                * the argument pointer, so we have to allocate some extra memory */

        HIP_IFEL(!(host_id_entry = hip_get_hostid_entry_by_lhi_and_algo(HIP_DB_LOCAL_HID,
                                                                        &ctx->input_msg->hitr,
                                                                        HIP_ANY_ALGO,
                                                                        -1)),
                   -1,
                   "Unknown HIT\n");

        _HIP_DEBUG("This HOST ID belongs to: %s\n",
                   hip_get_param_host_id_hostname(host_id_entry->host_id));

        HIP_IFEL(hip_build_param(ctx->output_msg, host_id_entry->host_id),
                 -1,
                 "Building of host id failed\n");
    }

    /* REG_INFO parameter. This builds a REG_REQUEST parameter in the I2
     * packet. */
    hip_handle_param_reg_info(ctx->hadb_entry,
                              ctx->input_msg,
                              ctx->output_msg);

    /********** ESP-ENC transform. **********/
    HIP_IFE(!(param = hip_get_param(ctx->input_msg,
                                    HIP_PARAM_ESP_TRANSFORM)),
            -ENOENT);

    /* Select only one transform */
    HIP_IFEL((transform_esp_suite =
                  hip_select_esp_transform((struct hip_esp_transform *) param)) == 0,
             -1, "Could not find acceptable hip transform suite\n");
    HIP_IFEL(hip_build_param_esp_transform(ctx->output_msg,
                                           &transform_esp_suite, 1), -1,
             "Building of ESP transform failed\n");

    /********** ESP-PROT anchor [OPTIONAL] **********/

    /** @todo Modularize esp_prot_* */
    HIP_IFEL(esp_prot_i2_add_anchor(ctx), -1,
             "failed to add esp protection anchor\n");

    /************************************************/

    if (hip_encrypt_i2_hi) {
        HIP_HEXDUMP("enc(host_id)",
                    host_id_in_enc,
                    hip_get_param_total_len(host_id_in_enc));

        /* Calculate the length of the host id inside the encrypted param */
        host_id_in_enc_len = hip_get_param_total_len(host_id_in_enc);

        /* Adjust the host id length for AES (block size 16).
         * build_param_encrypted_aes has already taken care that there is
         * enough padding */
        if (transform_hip_suite == HIP_HIP_AES_SHA1) {
            int remainder = host_id_in_enc_len % 16;
            if (remainder) {
                HIP_DEBUG("Remainder %d (for AES)\n", remainder);
                host_id_in_enc_len += remainder;
            }
        }

        _HIP_HEXDUMP("hostidinmsg", host_id_in_enc,
                     hip_get_param_total_len(host_id_in_enc));
        _HIP_HEXDUMP("encinmsg", enc_in_msg,
                     hip_get_param_total_len(enc_in_msg));
        HIP_HEXDUMP("enc key", &ctx->hadb_entry->hip_enc_out.key, HIP_MAX_KEY_LEN);
        _HIP_HEXDUMP("IV", iv, 16);         // or 8
        HIP_DEBUG("host id type: %d\n",
                  hip_get_host_id_algo((struct hip_host_id *) host_id_in_enc));
        _HIP_HEXDUMP("hostidinmsg 2", host_id_in_enc, x);


        HIP_IFEL(hip_crypto_encrypted(host_id_in_enc, iv,
                                      transform_hip_suite,
                                      host_id_in_enc_len,
                                      &ctx->hadb_entry->hip_enc_out.key,
                                      HIP_DIRECTION_ENCRYPT), -1,
                 "Building of param encrypted failed\n");

        _HIP_HEXDUMP("encinmsg 2", enc_in_msg,
                     hip_get_param_total_len(enc_in_msg));
        _HIP_HEXDUMP("hostidinmsg 2", host_id_in_enc, x);
    }

    /* Now that almost everything is set up except the signature, we can
     * try to set up inbound IPsec SA, similarly as in hip_send_r2 */

    HIP_DEBUG("src %d, dst %d\n",
              ctx->msg_ports->src_port,
              ctx->msg_ports->dst_port);

    ctx->hadb_entry->local_udp_port = ctx->msg_ports->src_port;
    ctx->hadb_entry->peer_udp_port  = ctx->msg_ports->dst_port;

    ctx->hadb_entry->hip_transform  = transform_hip_suite;

    /* XXX: -EAGAIN */
    HIP_DEBUG("set up inbound IPsec SA, SPI=0x%x (host)\n", spi_in);

    HIP_IFEL(hip_setup_hit_sp_pair(&ctx->input_msg->hits,
                                   &ctx->input_msg->hitr,
                                   ctx->src_addr, ctx->dst_addr,
                                   IPPROTO_ESP,
                                   1,
                                   1),
             -1,
             "Setting up SP pair failed\n");

    esp_info = hip_get_param(ctx->output_msg, HIP_PARAM_ESP_INFO);
    HIP_ASSERT(esp_info);     /* Builder internal error */
    esp_info->new_spi = htonl(spi_in);
    /* LSI not created, as it is local, and we do not support IPv4 */

    /********** ECHO_RESPONSE_SIGN (OPTIONAL) **************/
    /* must reply... */
    {
        struct hip_echo_request *ping;

        ping = hip_get_param(ctx->input_msg, HIP_PARAM_ECHO_REQUEST_SIGN);
        if (ping) {
            int ln = hip_get_param_contents_len(ping);
            HIP_IFEL(hip_build_param_echo(ctx->output_msg, ping + 1, ln, 1, 0), -1,
                     "Error while creating echo reply parameter\n");
        }
    }

    /************* HMAC ************/
    HIP_IFEL(hip_build_param_hmac_contents(ctx->output_msg,
                                           &ctx->hadb_entry->hip_hmac_out),
             -1,
             "Building of HMAC failed\n");

    /********** Signature **********/
    /* Build a digest of the packet built so far. Signature will
     * be calculated over the digest. */
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_SIGN\n");
    hip_perf_start_benchmark(perf_set, PERF_SIGN);
#endif
    HIP_IFEL(ctx->hadb_entry->sign(ctx->hadb_entry->our_priv_key,
                                          ctx->output_msg),
             -EINVAL,
             "Could not create signature\n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_SIGN\n");
    hip_perf_stop_benchmark(perf_set, PERF_SIGN);
#endif

    /********** ECHO_RESPONSE (OPTIONAL) ************/
    /* must reply */
    {
        struct hip_echo_request *ping;

        ping = hip_get_param(ctx->input_msg, HIP_PARAM_ECHO_REQUEST);
        if (ping) {
            int ln = hip_get_param_contents_len(ping);
            HIP_IFEL(hip_build_param_echo(ctx->output_msg, (ping + 1), ln, 0, 0), -1,
                     "Error while creating echo reply parameter\n");
        }
    }

    /********** I2 packet complete **********/
    memset(&spi_in_data, 0, sizeof(struct hip_spi_in_item));
    spi_in_data.spi     = spi_in;
    spi_in_data.ifindex = hip_devaddr2ifindex(ctx->dst_addr);
    HIP_LOCK_HA(ctx->hadb_entry);

    /* 99999 HIP_IFEB(hip_hadb_add_spi_old(ctx->hadb_entry,
                                           HIP_SPI_DIRECTION_IN, &spi_in_data),
                      -1,
                      HIP_UNLOCK_HA(ctx->hadb_entry));
    */

    ctx->hadb_entry->esp_transform = transform_esp_suite;
    HIP_DEBUG("Saving base exchange encryption data to hadb_entry \n");
    HIP_DEBUG_HIT("Our HIT: ", &ctx->hadb_entry->hit_our);
    HIP_DEBUG_HIT("Peer HIT: ", &ctx->hadb_entry->hit_peer);

    /** @todo Also store the keys that will be given to ESP later */
    HIP_IFE(hip_hadb_get_peer_addr(ctx->hadb_entry, &daddr), -1);

    /* R1 packet source port becomes the I2 packet destination port. */
    err = hip_send_pkt(ctx->dst_addr, &daddr,
                       (ctx->hadb_entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       ctx->msg_ports->src_port, ctx->output_msg, ctx->hadb_entry, 1);
    HIP_IFEL(err < 0, -ECOMM, "Sending I2 packet failed.\n");

    HIP_IFEL(err < 0, -1, "Creation of I2 failed\n");

    if (ctx->hadb_entry->state == HIP_STATE_I1_SENT) {
        ctx->hadb_entry->state = HIP_STATE_I2_SENT;
    }

out_err:
    if (ctx->output_msg) {
        HIP_FREE(ctx->output_msg);
    }

    return err;
}

/**
 * Construct a new R1 packet payload
 *
 * @param src_hit      a pointer to the source host identity tag used in the
 *                     packet.
 * @param sign         a funtion pointer to a signature funtion.
 * @param private_key  a pointer to the local host private key
 * @param host_id_pub  a pointer to the public host id of the local host
 * @param cookie_k     the difficulty value for the puzzle
 * @return             zero on success, or negative error value on error.
 */
struct hip_common *hip_create_r1(const struct in6_addr *src_hit,
                                 int (*sign)(void *key, struct hip_common *m),
                                 void *private_key,
                                 const struct hip_host_id *host_id_pub,
                                 int cookie_k)
{
    hip_common_t *msg = NULL;
    hip_srv_t service_list[HIP_TOTAL_EXISTING_SERVICES];
    uint8_t *dh_data1  = NULL, *dh_data2 = NULL;
    char order[] = "000";
    int err = 0, dh_size1 = 0, dh_size2 = 0, written1 = 0, written2 = 0;
    int mask = 0, i = 0;
    unsigned int service_count = 0;

    /* Supported HIP and ESP transforms. */
    hip_transform_suite_t transform_hip_suite[] = {
        HIP_HIP_AES_SHA1,
        HIP_HIP_3DES_SHA1,
        HIP_HIP_NULL_SHA1
    };
    hip_transform_suite_t transform_esp_suite[] = {
        HIP_ESP_AES_SHA1,
        HIP_ESP_3DES_SHA1,
        HIP_ESP_NULL_SHA1
    };

    /* change order if necessary */
    sprintf(order, "%d", hip_transform_order);
    for (i = 0; i < 3; i++) {
        switch (order[i]) {
        case '1':
            transform_hip_suite[i] = HIP_HIP_AES_SHA1;
            transform_esp_suite[i] = HIP_ESP_AES_SHA1;
            HIP_DEBUG("Transform order index %d is AES\n", i);
            break;
        case '2':
            transform_hip_suite[i] = HIP_HIP_3DES_SHA1;
            transform_esp_suite[i] = HIP_ESP_3DES_SHA1;
            HIP_DEBUG("Transform order index %d is 3DES\n", i);
            break;
        case '3':
            transform_hip_suite[i] = HIP_HIP_NULL_SHA1;
            transform_esp_suite[i] = HIP_ESP_NULL_SHA1;
            HIP_DEBUG("Transform order index %d is NULL_SHA1\n", i);
            break;
        }
    }

    _HIP_DEBUG("hip_create_r1() invoked.\n");
    HIP_IFEL(!(msg = hip_msg_alloc()), -ENOMEM, "Out of memory\n");

    /* Allocate memory for writing the first Diffie-Hellman shared secret */
    HIP_IFEL((dh_size1 = hip_get_dh_size(HIP_FIRST_DH_GROUP_ID)) == 0,
             -1, "Could not get dh_size1\n");
    HIP_IFEL(!(dh_data1 = HIP_MALLOC(dh_size1, GFP_ATOMIC)),
             -1, "Failed to alloc memory for dh_data1\n");
    memset(dh_data1, 0, dh_size1);

    _HIP_DEBUG("dh_size=%d\n", dh_size1);

    /* Allocate memory for writing the second Diffie-Hellman shared secret */
    HIP_IFEL((dh_size2 = hip_get_dh_size(HIP_SECOND_DH_GROUP_ID)) == 0,
             -1, "Could not get dh_size2\n");
    HIP_IFEL(!(dh_data2 = HIP_MALLOC(dh_size2, GFP_ATOMIC)),
             -1, "Failed to alloc memory for dh_data2\n");
    memset(dh_data2, 0, dh_size2);

    /* Ready to begin building of the R1 packet */

    /** @todo TH: hip_build_network_hdr has to be replaced with an
     *  appropriate function pointer */
    HIP_DEBUG_HIT("src_hit used to build r1 network header", src_hit);
    hip_build_network_hdr(msg, HIP_R1, mask, src_hit, NULL);

    /********** R1_COUNTER (OPTIONAL) *********/

    /********** PUZZLE ************/
    HIP_IFEL(hip_build_param_puzzle(msg, cookie_k,
                                    42 /* 2^(42-32) sec lifetime */, 0, 0),
             -1, "Cookies were burned. Bummer!\n");

    /* Parameter Diffie-Hellman */
    HIP_IFEL((written1 = hip_insert_dh(dh_data1, dh_size1,
                                       HIP_FIRST_DH_GROUP_ID)) < 0,
             -1, "Could not extract the first DH public key\n");

    if (number_dh_keys == TWO) {
        HIP_IFEL((written2 = hip_insert_dh(dh_data2, dh_size2,
                                           HIP_SECOND_DH_GROUP_ID)) < 0,
                 -1, "Could not extract the second DH public key\n");

        HIP_IFEL(hip_build_param_diffie_hellman_contents(msg,
                                                         HIP_FIRST_DH_GROUP_ID, dh_data1, written1,
                                                         HIP_SECOND_DH_GROUP_ID, dh_data2, written2), -1,
                 "Building of DH failed.\n");
    } else {
        HIP_IFEL(hip_build_param_diffie_hellman_contents(msg,
                                                         HIP_FIRST_DH_GROUP_ID, dh_data1, written1,
                                                         HIP_MAX_DH_GROUP_ID, dh_data2, 0), -1,
                 "Building of DH failed.\n");
    }

    /* Parameter HIP transform. */
    HIP_IFEL(hip_build_param_hip_transform(msg,
                                           transform_hip_suite,
                                           sizeof(transform_hip_suite) /
                                           sizeof(hip_transform_suite_t)), -1,
             "Building of HIP transform failed\n");

    /* Parameter HOST_ID */
    _HIP_DEBUG("This HOST ID belongs to: %s\n",
               hip_get_param_host_id_hostname(host_id_pub));
    HIP_IFEL(hip_build_param(msg, host_id_pub), -1,
             "Building of host id failed\n");

    /* Parameter REG_INFO */
    hip_get_active_services(service_list, &service_count);
    HIP_DEBUG("Found %d active service(s) \n", service_count);
    hip_build_param_reg_info(msg, service_list, service_count);

    /* Parameter ESP-ENC transform. */
    HIP_IFEL(hip_build_param_esp_transform(msg,
                                           transform_esp_suite,
                                           sizeof(transform_esp_suite) /
                                           sizeof(hip_transform_suite_t)), -1,
             "Building of ESP transform failed\n");

    /********** ESP-PROT transform (OPTIONAL) **********/

    HIP_IFEL(esp_prot_r1_add_transforms(msg), -1,
             "failed to add optional esp transform parameter\n");

    /********** ECHO_REQUEST_SIGN (OPTIONAL) *********/

    //HIP_HEXDUMP("Pubkey:", host_id_pub, hip_get_param_total_len(host_id_pub));

    /* Parameter Signature 2 */

    HIP_IFEL(sign(private_key, msg), -1, "Signing of R1 failed.\n");

    _HIP_HEXDUMP("R1", msg, hip_get_msg_total_len(msg));

    /* Parameter ECHO_REQUEST (OPTIONAL) */

    /* Fill puzzle parameters */
    {
        struct hip_puzzle *pz;
        uint64_t random_i;

        HIP_IFEL(!(pz = hip_get_param(msg, HIP_PARAM_PUZZLE)), -1,
                 "Internal error\n");

        // FIX ME: this does not always work:
        //get_random_bytes(pz->opaque, HIP_PUZZLE_OPAQUE_LEN);

        /* hardcode kludge */
        pz->opaque[0] = 'H';
        pz->opaque[1] = 'I';
        //pz->opaque[2] = 'P';
        /** @todo Remove random_i variable. */
        get_random_bytes(&random_i, sizeof(random_i));
        pz->I         = random_i;
    }

    /* Packet ready */

    //  if (host_id_pub)
    //      HIP_FREE(host_id_pub);
    if (dh_data1) {
        HIP_FREE(dh_data1);
    }
    if (dh_data2) {
        HIP_FREE(dh_data2);
    }

    //HIP_HEXDUMP("r1", msg, hip_get_msg_total_len(msg));

    return msg;

out_err:
    // if (host_id_pub)
    //      HIP_FREE(host_id_pub);
    if (msg) {
        HIP_FREE(msg);
    }
    if (dh_data1) {
        HIP_FREE(dh_data1);
    }
    if (dh_data2) {
        HIP_FREE(dh_data2);
    }

    return NULL;
}

/**
 * Transmit an R1 packet to the network.
 *
 * Send an R1 packet to the peer and store the cookie information that was
 * sent. The packet is sent either to @c i1_saddr or  @c dst_ip depending on the
 * value of @c dst_ip. If @c dst_ip is all zeroes (::/128) or NULL, R1 is sent
 * to @c i1_saddr; otherwise it is sent to @c dst_ip. In case the incoming I1
 * was relayed through a middlebox (e.g. rendezvous server) @c i1_saddr should
 * have the address of that middlebox.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *ctx Pointer to the packet context, containing all
 *                    information for the packet handling
 *                    (received message, source and destination address, the
 *                    ports and the corresponding entry from the host
 *                    association database).
 *
 * @return              zero on success, or negative error value on error.
 */
int hip_send_r1(const uint8_t packet_type,
                const uint32_t ha_state,
                struct hip_packet_context *ctx)
{
    int err = 0;
    hip_common_t *r1pkt     = NULL;
    struct in6_addr dst_ip = IN6ADDR_ANY_INIT,
                   *r1_dst_addr = NULL,
                   *local_plain_hit = NULL,
                   *r1_src_addr = ctx->dst_addr;
    in_port_t r1_dst_port    = 0;
    uint16_t relay_para_type = 0;

    HIP_IFEL(ctx->error,
             -1,
             "Abort packet processing and don't send R1 packet.\n")

    HIP_DEBUG_IN6ADDR("i1_saddr", ctx->src_addr);
    HIP_DEBUG_IN6ADDR("i1_daddr", ctx->dst_addr);
    HIP_DEBUG_IN6ADDR("dst_ip", &dst_ip);

    /* Get the final destination address and port for the outgoing R1.
     * dst_ip and dst_port have values only if the incoming I1 had
     * FROM/FROM_NAT parameter. */
    if (!ipv6_addr_any(&dst_ip) && relay_para_type) {
        //from RVS or relay
        if (relay_para_type == HIP_PARAM_RELAY_FROM) {
            HIP_DEBUG("Param relay from\n");
            //from relay
            r1_dst_addr = ctx->src_addr;
            r1_dst_port = ctx->msg_ports->src_port;
            // I---> NAT--> RVS-->R is not supported yet
            /*
             * r1_dst_addr =  dst_ip;
             * r1_dst_port = dst_port;
             */
        } else if (relay_para_type == HIP_PARAM_FROM)    {
            HIP_DEBUG("Param from\n");
            //from RVS, answer to I
            r1_dst_addr =  &dst_ip;
            if (ctx->msg_ports->src_port) {
                // R and RVS is in the UDP mode or I send UDP to RVS with incoming port hip_get_peer_nat_udp_port()
                r1_dst_port =  hip_get_peer_nat_udp_port();
            } else {
                // connection between R & RVS is in hip raw mode
                r1_dst_port =  0;
            }
        }
    } else {
        HIP_DEBUG("No RVS or relay\n");
        /* no RVS or RELAY found;  direct connection */
        r1_dst_addr = ctx->src_addr;
        r1_dst_port = ctx->msg_ports->src_port;
    }

/* removed by santtu because relay supported
 *      r1_dst_addr = (ipv6_addr_any(dst_ip) ? ctx->src_addr : dst_ip);
 *      r1_dst_port = (dst_port == 0 ? ctx->msg_info->src_port : dst_port);
 */
#ifdef CONFIG_HIP_OPPORTUNISTIC
    /* It should not be null hit, null hit has been replaced by real local
     * hit. */
    HIP_ASSERT(!hit_is_opportunistic_hit(&ctx->input_msg->hitr));
#endif

    /* Case: I ----->IPv4---> RVS ---IPv6---> R */
    if (IN6_IS_ADDR_V4MAPPED(r1_src_addr) !=
        IN6_IS_ADDR_V4MAPPED(r1_dst_addr)) {
        HIP_DEBUG_IN6ADDR("r1_src_addr", r1_src_addr);
        HIP_DEBUG_IN6ADDR("r1_dst_addr", r1_dst_addr);
        HIP_DEBUG("Different relayed address families\n");
        HIP_IFEL(hip_select_source_address(r1_src_addr, r1_dst_addr),
                 -1, "Failed to find proper src addr for R1\n");
        if (!IN6_IS_ADDR_V4MAPPED(r1_dst_addr)) {
            HIP_DEBUG("Destination IPv6, disabling UDP encap\n");
            r1_dst_port = 0;
        }
    }

    HIP_IFEL(!(r1pkt = hip_get_r1(r1_dst_addr, ctx->dst_addr,
                                  &ctx->input_msg->hitr, &ctx->input_msg->hits)),
             -ENOENT, "No precreated R1\n");

    if (&ctx->input_msg->hits) {
        ipv6_addr_copy(&r1pkt->hitr, &ctx->input_msg->hits);
    } else {
        memset(&r1pkt->hitr, 0, sizeof(struct in6_addr));
    }

    HIP_DEBUG_HIT("hip_xmit_r1(): ripkt->hitr", &r1pkt->hitr);

#ifdef CONFIG_HIP_RVS
    /* Build VIA_RVS or RELAY_TO parameter if the I1 packet was relayed
     * through a rvs. */
    /** @todo Parameters must be in ascending order, should this
     *  be checked here? Now we just assume that the VIA_RVS/RELAY_TO
     *  parameter is the last parameter. */
    /* If I1 had a FROM/RELAY_FROM, then we must build a RELAY_TO/VIA_RVS
     * parameter. */
    if (!ipv6_addr_any(&dst_ip) && relay_para_type) { // dst_port has the value of RELAY_FROM port.
                                                    //there is port no value for FROM parameter
                                                    //here condition is not enough
        if (relay_para_type == HIP_PARAM_RELAY_FROM) {
            HIP_DEBUG("Build param relay from\n");
            hip_build_param_relay_to(
                r1pkt, &dst_ip, r1_dst_port);
        } else if (relay_para_type == HIP_PARAM_FROM)    {
            HIP_DEBUG("Build param from\n");
            hip_build_param_via_rvs(r1pkt, ctx->src_addr);
        }
    }
#endif
    /* R1 is send on UDP if R1 destination port is hip_get_peer_nat_udp_port(). This is if:
     * a) the I1 was received on UDP.
     * b) the received I1 packet had a RELAY_FROM parameter. */
    if (r1_dst_port) {
        HIP_IFEL(hip_send_pkt(r1_src_addr, r1_dst_addr, hip_get_local_nat_udp_port(),
                              r1_dst_port, r1pkt, NULL, 0),
                 -ECOMM, "Sending R1 packet on UDP failed.\n");
    }
    /* Else R1 is send on raw HIP. */
    else {
        HIP_IFEL(hip_send_pkt(
                     r1_src_addr,
                     r1_dst_addr, 0, 0,
                     r1pkt, NULL, 0),
                 -ECOMM,
                 "Sending R1 packet on raw HIP failed.\n");
    }

out_err:
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_I1\n");
    hip_perf_stop_benchmark(perf_set, PERF_I1);
    hip_perf_write_benchmark(perf_set, PERF_I1);
#endif
    if (r1pkt) {
        HIP_FREE(r1pkt);
    }
    if (local_plain_hit) {
        HIP_FREE(local_plain_hit);
    }
    return err;
}

/**
 * Creates and transmits an R2 packet.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *ctx Pointer to the packet context, containing all
 *                    information for the packet handling
 *                    (received message, source and destination address, the
 *                    ports and the corresponding entry from the host
 *                    association database).
 *
 * @return zero on success, negative otherwise.
 */
int hip_send_r2(const uint8_t packet_type,
                const uint32_t ha_state,
                struct hip_packet_context *ctx)
{
    struct hip_crypto_key hmac;
    int err          = 0;
    uint16_t mask    = 0;

    HIP_IFEL(ctx->error,
             -1,
             "Abort packet processing and don't send R1 packet.\n")

    /* Build and send R2: IP ( HIP ( SPI, HMAC, HIP_SIGNATURE ) ) */
    HIP_IFEL(!(ctx->output_msg = hip_msg_alloc()), -ENOMEM, "No memory for R2\n");

    /* Just swap the addresses to use the I2's destination HIT as the R2's
     * source HIT. */
    hip_build_network_hdr(ctx->output_msg,
                          HIP_R2,
                          mask,
                          &ctx->hadb_entry->hit_our,
                          &ctx->hadb_entry->hit_peer);

    HIP_DUMP_MSG(ctx->output_msg);

    /* ESP_INFO */
    HIP_IFEL(hip_build_param_esp_info(ctx->output_msg,
                                      ctx->hadb_entry->esp_keymat_index,
                                      0,
                                      ctx->hadb_entry->spi_inbound_current),
             -1,
             "building of ESP_INFO failed.\n");

    /********** CHALLENGE_RESPONSE **********/
#ifdef CONFIG_HIP_MIDAUTH
    /** @todo no caching is done for PUZZLE_M parameters. This may be
     *        a DOS attack vector.
     */
    HIP_IFEL(hip_solve_puzzle_m(ctx->output_msg,
                                ctx->input_msg,
                                ctx->hadb_entry),
             -1,
             "Building of Challenge_Response failed\n");
    char *midauth_cert = hip_pisa_get_certificate();

    HIP_IFEL(hip_build_param(ctx->output_msg, ctx->hadb_entry->our_pub), -1,
             "Building of host id failed\n");

    /* For now we just add some random data to see if it works */
    HIP_IFEL(hip_build_param_cert(ctx->output_msg, 1, 1, 1, 1, midauth_cert, strlen(midauth_cert)),
            -1,
            "Building of cert failed\n");

#endif

    /********** ESP-PROT anchor [OPTIONAL] **********/
    HIP_IFEL(esp_prot_r2_add_anchor(ctx->output_msg, ctx->hadb_entry), -1,
             "failed to add esp protection anchor\n");
    /************************************************/

#if defined(CONFIG_HIP_RVS)
    /********** REG_REQUEST **********/
    /* This part should only be executed at server offering rvs or relay
     * services.
     */

    /* Handle REG_REQUEST parameter. */
    hip_handle_param_reg_request(ctx->hadb_entry, ctx->input_msg, ctx->output_msg);

#endif

#if defined(CONFIG_HIP_RVS)
    if (hip_relay_get_status() != HIP_RELAY_OFF) {
        hip_build_param_reg_from(ctx->output_msg, ctx->src_addr, ctx->msg_ports->src_port);
    }

#endif


    /* Create HMAC2 parameter. */
    if (ctx->hadb_entry->our_pub == NULL) {
        HIP_DEBUG("ctx->hadb_entry->our_pub is NULL.\n");
    } else {
        _HIP_HEXDUMP("Host ID for HMAC2", ctx->hadb_entry->our_pub,
                     hip_get_param_total_len(ctx->hadb_entry->our_pub));
    }

    memcpy(&hmac, &ctx->hadb_entry->hip_hmac_out, sizeof(hmac));
    HIP_IFEL(hip_build_param_hmac2_contents(ctx->output_msg,
                                            &hmac,
                                            ctx->hadb_entry->our_pub),
             -1,
             "Failed to build parameter HMAC2 contents.\n");

    /* Why is err reset to zero? -Lauri 11.06.2008 */
    if (err == 1) {
        err = 0;
    }

    HIP_IFEL(ctx->hadb_entry->sign(ctx->hadb_entry->our_priv_key,
                                          ctx->output_msg),
             -EINVAL,
             "Could not sign R2. Failing\n");

    err = hip_add_sa(ctx->dst_addr,
                     ctx->src_addr,
                     &ctx->input_msg->hitr,
                     &ctx->input_msg->hits,
                     ctx->hadb_entry->spi_outbound_current,
                     ctx->hadb_entry->esp_transform,
                     &ctx->hadb_entry->esp_out,
                     &ctx->hadb_entry->auth_out,
                     1,
                     HIP_SPI_DIRECTION_OUT,
                     0,
                     ctx->hadb_entry);
    if (err) {
        HIP_ERROR("Failed to setup outbound SA with SPI = %d.\n",
                  ctx->hadb_entry->spi_outbound_current);

        /* delete all IPsec related SPD/SA for this ctx->hadb_entry*/
        hip_delete_security_associations_and_sp(ctx->hadb_entry);
        goto out_err;
    }

    /* @todo Check if err = -EAGAIN... */
    HIP_DEBUG("Set up outbound IPsec SA, SPI=0x%x\n",
              ctx->hadb_entry->spi_outbound_new);

    err = hip_send_pkt(ctx->dst_addr,
                       ctx->src_addr,
                       (ctx->hadb_entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       ctx->hadb_entry->peer_udp_port,
                       ctx->output_msg,
                       ctx->hadb_entry,
                       1);

    if (err == 1) {
        err = 0;
    }

    HIP_IFEL(err, -ECOMM, "Sending R2 packet failed.\n");

out_err:
    if (ctx->output_msg) {
        free(ctx->output_msg);
    }
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_I2\n");
    hip_perf_stop_benchmark(perf_set, PERF_I2);
    hip_perf_write_benchmark(perf_set, PERF_I2);
#endif

    return err;
}

/**
 * Check if source and destination IP addresses are compatible for sending
 * packets between them
 *
 * @param src_addr  Source address
 * @param dst_addr  Destination address
 *
 * @return          non-zero on success, zero on failure
 */
int are_addresses_compatible(const struct in6_addr *src_addr,
                             const struct in6_addr *dst_addr)
{
    if (!IN6_IS_ADDR_V4MAPPED(src_addr) && IN6_IS_ADDR_V4MAPPED(dst_addr)) {
        return 0;
    }

    if (IN6_IS_ADDR_V4MAPPED(src_addr) && !IN6_IS_ADDR_V4MAPPED(dst_addr)) {
        return 0;
    }

    if (!IN6_IS_ADDR_LINKLOCAL(src_addr) && IN6_IS_ADDR_LINKLOCAL(dst_addr)) {
        return 0;
    }

    if (IN6_IS_ADDR_LINKLOCAL(src_addr) && !IN6_IS_ADDR_LINKLOCAL(dst_addr)) {
        return 0;
    }

    return 1;
};

/**
 * Cache a HIP packet for possible retransmission
 *
 * @param src_addr  a pointer to the packet source address.
 * @param peer_addr a pointer to the packet destination address.
 * @param msg       a pointer to a HIP packet common header with source and
 *                  destination HITs.
 * @param entry     a pointer to the current host association database state.
 * @return          zero on success, or negative error value on error.
 * @note currently the queue length is one and new packets replace old ones
 */
static int hip_queue_packet(const struct in6_addr *src_addr,
                            const struct in6_addr *peer_addr,
                            const struct hip_common *msg,
                            hip_ha_t *entry)
{
    int err = 0;
    int len = hip_get_msg_total_len(msg);

    _HIP_DEBUG("hip_queue_packet() invoked.\n");
    /* Not reusing the old entry as the new packet may have
     * different length */
    if (!entry) {
        goto out_err;
    }

    memset(entry->hip_msg_retrans.buf, 0, HIP_MAX_NETWORK_PACKET);

    memcpy(entry->hip_msg_retrans.buf, msg, len);
    memcpy(&entry->hip_msg_retrans.saddr, src_addr,
           sizeof(struct in6_addr));
    memcpy(&entry->hip_msg_retrans.daddr, peer_addr,
           sizeof(struct in6_addr));
    entry->hip_msg_retrans.count = HIP_RETRANSMIT_MAX;
    time(&entry->hip_msg_retrans.last_transmit);
out_err:
    return err;
}

/**
 * Send a HIP message using raw HIP from one source address. Don't use this
 * function directly,  instead use hip_send_pkt(). It's used by hip_send_raw internally.
 *
 * Sends a HIP message to the peer on HIP/IP. This function calculates the
 * HIP packet checksum.
 *
 * Used protocol suite is <code>IPv4(HIP)</code> or <code>IPv6(HIP)</code>.
 *
 * @param local_addr a pointer to our IPv6 or IPv4-in-IPv6 format IPv4 address.
 *                   If local_addr is NULL, the packet is sent from all addresses.
 * @param peer_addr  a pointer to peer IPv6 or IPv4-in-IPv6 format IPv4 address.
 * @param src_port   not used.
 * @param dst_port   not used.
 * @param msg        a pointer to a HIP packet common header with source and
 *                   destination HITs.
 * @param entry      a pointer to the current host association database state.
 * @param retransmit a boolean value indicating if this is a retransmission
 *                   (@b zero if this is @b not a retransmission).
 * @return           zero on success, or negative error value on error.
 * @note             This function should never be used directly. Use
 *                   hip_send_pkt_stateless() or the host association send
 *                   function pointed by the function pointer
 *                   hadb_xmit_func->send_pkt instead.
 * @note             If retransmit is set other than zero, make sure that the
 *                   entry is not NULL.
 * @todo             remove the sleep code (queuing is enough?)
 *
 * @see              hip_send_udp_from_one_src
 */
static int hip_send_raw_from_one_src(const struct in6_addr *local_addr,
                                     const struct in6_addr *peer_addr,
                                     const in_port_t src_port,
                                     const in_port_t dst_port,
                                     struct hip_common *msg,
                                     hip_ha_t *entry,
                                     const int retransmit)
{
    int err                   = 0, sa_size, sent, len = 0, dupl, try_again, udp = 0;
    struct sockaddr_storage src, dst;
    int src_is_ipv4           = 0, dst_is_ipv4 = 0, memmoved = 0;
    struct sockaddr_in6 *src6 = NULL, *dst6 = NULL;
    struct sockaddr_in *src4  = NULL, *dst4 = NULL;
    struct in6_addr my_addr;
    /* Points either to v4 or v6 raw sock */
    int hip_raw_sock_output   = 0;

    _HIP_DEBUG("hip_send_raw() invoked.\n");

    /* Verify the existence of obligatory parameters. */
    HIP_ASSERT(peer_addr != NULL && msg != NULL);

    HIP_DEBUG("Sending %s packet\n",
              hip_message_type_name(hip_get_msg_type(msg)));
    HIP_DEBUG_IN6ADDR("hip_send_raw(): local_addr", local_addr);
    HIP_DEBUG_IN6ADDR("hip_send_raw(): peer_addr", peer_addr);
    HIP_DEBUG("Source port=%d, destination port=%d\n", src_port, dst_port);
    HIP_DUMP_MSG(msg);

    //check msg length
    if (!hip_check_network_msg_len(msg)) {
        err = -EMSGSIZE;
        HIP_ERROR("bad msg len %d\n", hip_get_msg_total_len(msg));
        goto out_err;
    }

    dst_is_ipv4 = IN6_IS_ADDR_V4MAPPED(peer_addr);
    len         = hip_get_msg_total_len(msg);

    /* Some convinient short-hands to avoid too much casting (could be
     * an union as well) */
    src6        = (struct sockaddr_in6 *) &src;
    dst6        = (struct sockaddr_in6 *) &dst;
    src4        = (struct sockaddr_in *)  &src;
    dst4        = (struct sockaddr_in *)  &dst;

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    if (dst_port && dst_is_ipv4) {
        HIP_DEBUG("Using IPv4 UDP socket\n");
        hip_raw_sock_output = hip_nat_sock_output_udp;
        sa_size             = sizeof(struct sockaddr_in);
        udp                 = 1;
    } else if (dst_is_ipv4) {
        HIP_DEBUG("Using IPv4 raw socket\n");
        hip_raw_sock_output = hip_raw_sock_output_v4;
        sa_size             = sizeof(struct sockaddr_in);
    } else {
        HIP_DEBUG("Using IPv6 raw socket\n");
        hip_raw_sock_output = hip_raw_sock_output_v6;
        sa_size             = sizeof(struct sockaddr_in6);
    }

    if (local_addr) {
        HIP_DEBUG("local address given\n");
        memcpy(&my_addr, local_addr, sizeof(struct in6_addr));
    } else {
        HIP_DEBUG("no local address, selecting one\n");
        HIP_IFEL(hip_select_source_address(&my_addr, peer_addr), -1,
                 "Cannot find source address\n");
    }

    src_is_ipv4 = IN6_IS_ADDR_V4MAPPED(&my_addr);

    if (src_is_ipv4) {
        IPV6_TO_IPV4_MAP(&my_addr, &src4->sin_addr);
        src4->sin_family = AF_INET;
        HIP_DEBUG_INADDR("src4", &src4->sin_addr);
    } else {
        memcpy(&src6->sin6_addr, &my_addr,
               sizeof(struct in6_addr));
        src6->sin6_family = AF_INET6;
        HIP_DEBUG_IN6ADDR("src6", &src6->sin6_addr);
    }

    if (dst_is_ipv4) {
        IPV6_TO_IPV4_MAP(peer_addr, &dst4->sin_addr);
        dst4->sin_family = AF_INET;

        HIP_DEBUG_INADDR("dst4", &dst4->sin_addr);
    } else {
        memcpy(&dst6->sin6_addr, peer_addr, sizeof(struct in6_addr));
        dst6->sin6_family = AF_INET6;
        HIP_DEBUG_IN6ADDR("dst6", &dst6->sin6_addr);
    }

    if (src6->sin6_family != dst6->sin6_family) {
        /* @todo: Check if this may cause any trouble.
         * It happens every time we send update packet that contains few locators in msg, one is
         * the IPv4 address of the source, another is IPv6 address of the source. But even if one of
         * them is ok to send raw IPvX to IPvX raw packet, another one cause the trouble, and all
         * updates are dropped.  by Andrey "laser".
         *
         */
        err = -1;
        HIP_ERROR("Source and destination address families differ\n");
        goto out_err;
    }

    hip_zero_msg_checksum(msg);
    if (!udp) {
        msg->checksum = hip_checksum_packet((char *) msg,
                                            (struct sockaddr *) &src,
                                            (struct sockaddr *) &dst);
    }

    /* Note that we need the original (possibly mapped addresses here.
     * Also, we need to do queuing before the bind because the bind
     * can fail the first time during mobility events (duplicate address
     * detection). */
    if (retransmit) {
        HIP_IFEL(hip_queue_packet(&my_addr, peer_addr, msg, entry), -1,
                 "Queueing failed.\n");
    }

    /* Handover may cause e.g. on-link duplicate address detection
     * which may cause bind to fail. */

    HIP_IFEL(bind(hip_raw_sock_output, (struct sockaddr *) &src, sa_size),
             -1, "Binding to raw sock failed\n");

    if (HIP_SIMULATE_PACKET_LOSS && HIP_SIMULATE_PACKET_IS_LOST()) {
        HIP_DEBUG("Packet loss probability: %f\n", ((uint64_t) HIP_SIMULATE_PACKET_LOSS_PROBABILITY * RAND_MAX) / 100.f);
        HIP_DEBUG("Packet was lost (simulation)\n");
        goto out_err;
    }

    /* For some reason, neither sendmsg or send (with bind+connect)
     * do not seem to work properly. Thus, we use just sendto() */

    len = hip_get_msg_total_len(msg);
    _HIP_HEXDUMP("Dumping packet ", msg, len);

    if (udp) {
        struct udphdr *uh = (struct udphdr *) (void *) msg;

        /* Insert 32 bits of zero bytes between UDP and HIP */
        memmove(((char *) msg) + HIP_UDP_ZERO_BYTES_LEN + sizeof(struct udphdr), msg, len);
        memset(((char *) msg), 0, HIP_UDP_ZERO_BYTES_LEN  + sizeof(struct udphdr));
        len       += HIP_UDP_ZERO_BYTES_LEN + sizeof(struct udphdr);

        uh->source = htons(src_port);
        uh->dest   = htons(dst_port);
        uh->len    = htons(len);
        uh->check  = 0;
        memmoved   = 1;
    }

    _HIP_HEXDUMP("Dumping packet ", msg, len);

#if 0
    /* Kuptsov: multiple source addresses might not work properly without
     * the trick below. Note that you should find out the ifname with
     * getifaddr/if_nameindex. */
    HIP_IFEL(setsockopt(hip_raw_sock_output, SOL_SOCKET, SO_BINDTODEVICE,
                        ifname, strlen(ifname) + 1), -1, "Cannot set sockopt");
#endif

    for (dupl = 0; dupl < HIP_PACKET_DUPLICATES; dupl++) {
        for (try_again = 0; try_again < 2; try_again++) {
            sent = sendto(hip_raw_sock_output, msg, len, 0,
                          (struct sockaddr *) &dst, sa_size);
            if (sent != len) {
                HIP_ERROR("Could not send the all requested" \
                          " data (%d/%d)\n", sent, len);
                HIP_DEBUG("strerror %s\n", strerror(errno));
                sleep(2);
            } else {
                HIP_DEBUG("sent=%d/%d ipv4=%d\n",
                          sent, len, dst_is_ipv4);
                HIP_DEBUG("Packet sent ok\n");
                break;
            }
        }
    }
out_err:

    /* Reset the interface to wildcard or otherwise receiving
     * broadcast messages fails from the raw sockets. A better
     * solution would be to have separate sockets for sending
     * and receiving because we cannot receive a broadcast while
     * sending */
    if (dst_is_ipv4) {
        src4->sin_addr.s_addr = INADDR_ANY;
        src4->sin_family      = AF_INET;
        sa_size               = sizeof(struct sockaddr_in);
    } else {
        struct in6_addr any = IN6ADDR_ANY_INIT;
        src6->sin6_family = AF_INET6;
        ipv6_addr_copy(&src6->sin6_addr, &any);
        sa_size           = sizeof(struct sockaddr_in6);
    }
    bind(hip_raw_sock_output, (struct sockaddr *) &src, sa_size);

    if (udp && memmoved) {
        /* Remove 32 bits of zero bytes between UDP and HIP */
        len -= HIP_UDP_ZERO_BYTES_LEN + sizeof(struct udphdr);
        memmove((char *) msg, ((char *) msg) + HIP_UDP_ZERO_BYTES_LEN + sizeof(struct udphdr),
                len);
        memset(((char *) msg) + len, 0,
               HIP_UDP_ZERO_BYTES_LEN + sizeof(struct udphdr));
    }

    if (err) {
        HIP_ERROR("strerror: %s\n", strerror(errno));
    }

    return err;
}

/**
 * Send a HIP message using User Datagram Protocol (UDP) from one address.
 * Don't use this function directly, instead use hip_send_pkt()
 *
 * Sends a HIP message to the peer on UDP/IPv4. IPv6 is not supported, because
 * there are no IPv6 NATs deployed in the Internet yet. If either @c local_addr
 * or @c peer_addr is pure (not a IPv4-in-IPv6 format IPv4 address) IPv6
 * address, no message is send. IPv4-in-IPv6 format IPv4 addresses are mapped to
 * pure IPv4 addresses. In case of transmission error, this function tries to
 * retransmit the packet @c HIP_NAT_NUM_RETRANSMISSION times. The HIP packet
 * checksum is set to zero.
 *
 * Used protocol suite is <code>IPv4(UDP(HIP))</code>.
 *
 * @param local_addr a pointer to our IPv4-in-IPv6 format IPv4 address.
 * @param peer_addr  a pointer to peer IPv4-in-IPv6 format IPv4 address.
 * @param src_port   source port number to be used in the UDP packet header
 *                   (host byte order)
 * @param dst_port   destination port number to be used in the UDP packet header.
 *                   (host byte order).
 * @param msg        a pointer to a HIP packet common header with source and
 *                   destination HITs.
 * @param entry      a pointer to the current host association database state.
 * @param retransmit a boolean value indicating if this is a retransmission
 *                   (@b zero if this is @b not a retransmission).
 * @return           zero on success, or negative error value on error.
 * @note             This function should never be used directly. Use
 *                   hip_send_pkt_stateless() or the host association send
 *                   function pointed by the function pointer
 *                   hadb_xmit_func->send_pkt instead.
 * @note             If retransmit is set other than zero, make sure that the
 *                   entry is not NULL.
 * @note             Although this function is just a wrapper to send_raw,
 *                   we might keep it for portability reasons.
 * @todo             remove the sleep code (queuing is enough?)
 * @todo             Add support to IPv6 address family.
 * @see              hip_send_pkt
 */
static int hip_send_udp_from_one_src(const struct in6_addr *local_addr,
                                     const struct in6_addr *peer_addr,
                                     const in_port_t src_port,
                                     const in_port_t dst_port,
                                     struct hip_common *msg,
                                     hip_ha_t *entry,
                                     const int retransmit)
{
    return hip_send_raw_from_one_src(local_addr, peer_addr, src_port,
                                     dst_port, msg, entry, retransmit);
}

/**
 * Send a HIP message.
 *
 * Sends a HIP message to the peer on HIP/IP. This function also calculates the
 * HIP packet checksum.
 *
 * Used protocol suite is <code>IPv4(HIP)</code> or <code>IPv6(HIP)</code>.
 *
 * @param local_addr a pointer to our IPv6 or IPv4-in-IPv6 format IPv4 address.
 *                   If local_addr is NULL, the packet is sent from all addresses.
 * @param peer_addr  a pointer to peer IPv6 or IPv4-in-IPv6 format IPv4 address.
 * @param src_port   not used.
 * @param dst_port   not used.
 * @param msg        a pointer to a HIP packet common header with source and
 *                   destination HITs.
 * @param entry      a pointer to the current host association database state.
 * @param retransmit a boolean value indicating if this is a retransmission
 *                   (@b zero if this is @b not a retransmission).
 * @return           zero on success, or negative error value on error.
 * @note             This function should never be used directly. Use
 *                   hip_send_pkt_stateless() or the host association send
 *                   function pointed by the function pointer
 *                   hadb_xmit_func->send_pkt instead.
 * @note             If retransmit is set other than zero, make sure that the
 *                   entry is not NULL.
 * @todo             remove the sleep code (queuing is enough?)
 * @see              hip_send_udp
 */
int hip_send_pkt(const struct in6_addr *local_addr,
                 const struct in6_addr *peer_addr,
                 const in_port_t src_port,
                 const in_port_t dst_port,
                 struct hip_common *msg,
                 hip_ha_t *entry,
                 const int retransmit)
{
    int err                                = 0;
    struct netdev_address *netdev_src_addr = NULL;
    struct in6_addr *src_addr              = NULL;
    hip_list_t *item                       = NULL, *tmp = NULL;
    int i                                  = 0;

    _HIP_DEBUG_IN6ADDR("Destination address:", peer_addr);

    /* Notice that the shotgun logic requires us to check always the address family.
     *  Depending on the address family, we send the packet using UDP encapsulation or
     *  without it. Here's the current logic for UDP encapsulation (note that we
     *  assume that the port number is always > 0 when nat mode is > 0):
     *
     *               | IPv4 address | IPv6 address |
     *  -------------+--------------+--------------+
     *  nat_mode = 0 |    NONE      |    NONE      |
     *  nat_mode > 0 |    UDP       |    NONE      |
     *
     */

    if (hip_shotgun_status == HIP_MSG_SHOTGUN_OFF) {
        if (IN6_IS_ADDR_V4MAPPED(peer_addr) &&
            ((hip_get_nat_mode(entry) != HIP_NAT_MODE_NONE) || dst_port != 0)) {
            return hip_send_udp_from_one_src(local_addr, peer_addr,
                                             src_port, dst_port,
                                             msg, entry, retransmit);
        } else {
            return hip_send_raw_from_one_src(local_addr, peer_addr,
                                             src_port, dst_port,
                                             msg, entry, retransmit);
        }
    }

    list_for_each_safe(item, tmp, addresses, i)
    {
        netdev_src_addr = (struct netdev_address *) list_entry(item);
        src_addr = hip_cast_sa_addr((const struct sockaddr *) &netdev_src_addr->addr);

        if (!are_addresses_compatible(src_addr, peer_addr)) {
            continue;
        }

        HIP_DEBUG_IN6ADDR("Source address:", src_addr);
        HIP_DEBUG_IN6ADDR("Dest address:", peer_addr);

        /* Notice: errors from sending are suppressed intentiously because they occur often */
        if (IN6_IS_ADDR_V4MAPPED(peer_addr) && (hip_get_nat_mode(entry) != HIP_NAT_MODE_NONE || dst_port != 0)) {
            hip_send_udp_from_one_src(src_addr, peer_addr,
                                      src_port, dst_port,
                                      msg, entry, retransmit);
        } else {
            hip_send_raw_from_one_src(src_addr, peer_addr,
                                      src_port, dst_port,
                                      msg, entry, retransmit);
        }
    }

    return err;
};
