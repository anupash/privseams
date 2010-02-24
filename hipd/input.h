/** @file
 * A header file for input.c.
 *
 * @author  Janne Lundberg
 * @author  Miika Komu
 * @author  Mika Kousa
 * @author  Kristian Slavov
 * @author  Anthony D. Joseph
 * @author  Bing Zhou
 * @author  Tobias Heer
 * @author  Samu Varjonen
 * @author  Rene Hummen
 * @author  Tim Just
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_HIPD_INPUT_H
#define HIP_HIPD_INPUT_H

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#ifdef CONFIG_HIP_RVS
  #include "hiprelay.h"
#endif

#include "lib/core/debug.h"
#include "lib/core/protodefs.h"

struct pseudo_header6 {
    unsigned char src_addr[16];
    unsigned char dst_addr[16];
    u32           packet_length;
    unsigned char zero[3];
    u8            next_hdr;
};

struct pseudo_header {
    unsigned char src_addr[4];
    unsigned char dst_addr[4];
    u8            zero;
    u8            protocol;
    u16           packet_length;
};

/**
 * Checks for illegal controls in a HIP packet Controls field.
 *
 * <b>Do not confuse these controls with host association control fields.</b> HIP
 * packet Controls field values are dictated in RFCs/I-Ds. Therefore any bit
 * that is not dictated in these documents should not appear in the message and
 * should not be among legal values. Host association controls, on the other
 * hand are implementation specific values, and can be used as we please. Just
 * don't put those bits on wire!
 *
 * @param controls control value to be checked
 * @param legal    legal control values to check @c controls against
 * @return         1 if there are no illegal control values in @c controls,
 *                 otherwise 0.
 * @note           controls are given in host byte order.
 */
static inline int hip_controls_sane(u16 controls, u16 legal)
{
    _HIP_DEBUG("hip_controls_sane() invoked.\n");
    return ((controls & HIP_PACKET_CTRL_ANON) | legal) == legal;
}

int hip_verify_packet_hmac(struct hip_common *msg,
                           struct hip_crypto_key *crypto_key);

int hip_verify_packet_hmac_general(struct hip_common *msg,
                                   const struct hip_crypto_key *crypto_key,
                                   const hip_tlv_type_t parameter_type);

int hip_verify_packet_rvs_hmac(struct hip_common *msg,
                               struct hip_crypto_key *crypto_key);

int hip_receive_control_packet(struct hip_common *msg,
                               struct in6_addr *src_addr,
                               struct in6_addr *dst_addr,
                               hip_portpair_t *msg_info);

int hip_receive_udp_control_packet(struct hip_common *msg,
                                   struct in6_addr *saddr,
                                   struct in6_addr *daddr,
                                   hip_portpair_t *info);

void hip_drop_packet(const uint32_t packet_type,
                     const uint32_t ha_state,
                     struct hip_packet_context *packet_ctx);

int hip_receive_bos(struct hip_common *bos, struct in6_addr *bos_saddr,
                    struct in6_addr *bos_daddr, hip_ha_t *entry, hip_portpair_t *bos_info);

int hip_handle_i1(const uint32_t packet_type,
                  const uint32_t ha_state,
                  struct hip_packet_context *ctx);

int hip_handle_notify(const uint32_t packet_type,
                      const uint32_t ha_state,
                      struct hip_packet_context *ctx);

int hip_handle_r1(const uint32_t packet_type,
                  const uint32_t ha_state,
                  struct hip_packet_context *ctx);

int hip_handle_i2(const uint32_t packet_type,
                  const uint32_t ha_state,
                  struct hip_packet_context *ctx);

int hip_handle_r2(const uint32_t packet_type,
                  const uint32_t ha_state,
                  struct hip_packet_context *packet_ctx);

int hip_produce_keying_material(struct hip_common *msg, struct hip_context *ctx,
                                uint64_t I, uint64_t J, struct hip_dh_public_value **dhpv);

int hip_create_i2(struct hip_context *ctx, uint64_t solved_puzzle,
                  in6_addr_t *r1_saddr, in6_addr_t *r1_daddr, hip_ha_t *entry,
                  hip_portpair_t *r1_info, struct hip_dh_public_value *dhpv);

int hip_create_r2(struct hip_context *ctx, in6_addr_t *i2_saddr,
                  in6_addr_t *i2_daddr, hip_ha_t *entry, hip_portpair_t *i2_info,
                  in6_addr_t *dest, const in_port_t dest_port);

#endif /* HIP_HIPD_INPUT_H */
