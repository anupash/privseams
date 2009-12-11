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
 * @author	Rene Hummen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_INPUT_H
#define HIP_INPUT_H

#ifdef CONFIG_HIP_RVS
#  include "hiprelay.h"
#endif
#ifdef CONFIG_HIP_BLIND
#  include "hadb.h"
#endif

#include "oppdb.h"
#include "user.h"
#include "debug.h"
#include "hadb.h"
#include "keymat.h"
#include "crypto.h"
#include "builder.h"
#include "dh.h"
#include "misc.h"
#include "hidb.h"
#include "cookie.h"
#include "output.h"
#include "pk.h"
#include "netdev.h"
#include "util.h"
#include "state.h"
#include "oppdb.h"
#include "registration.h"
#include "esp_prot_hipd_msg.h"
#include "esp_prot_light_update.h"

#include "i3_client_api.h"
#include "oppipdb.h"

struct hi3_ipv4_addr {
	u8 sin_family;
	struct in_addr sin_addr;
};

struct hi3_ipv6_addr {
	u8 sin6_family;
	struct in6_addr sin6_addr;
};

struct pseudo_header6
{
        unsigned char src_addr[16];
        unsigned char dst_addr[16];
        u32 packet_length;
        char zero[3];
        u8 next_hdr;
};

struct pseudo_header
{
        unsigned char src_addr[4];
        unsigned char dst_addr[4];
        u8 zero;
        u8 protocol;
        u16 packet_length;
};

//void hip_inbound(cl_trigger *t, void *data, void *ctx);

extern int hip_icmp_sock;
extern int hip_encrypt_i2_hi;
extern int hip_icmp_interval;
extern int hip_icmp_sock;

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
 * @todo           If BLIND is in use we should include the BLIND bit
 *                 in legal values, shouldn't we?
 */

//FIXME this ist static but used in close.c and input.c 
static inline int hip_controls_sane(u16 controls, u16 legal)
{
     _HIP_DEBUG("hip_controls_sane() invoked.\n");
     return ((controls & HIP_PACKET_CTRL_ANON) | legal) == legal;
}

int hip_verify_packet_hmac(struct hip_common *, struct hip_crypto_key *);

int hip_verify_packet_hmac_general(struct hip_common *msg,
			   struct hip_crypto_key *crypto_key, hip_tlv_type_t parameter_type);

//FIXME implemented in input.c but only used in hiprelay.c 
int hip_verify_packet_rvs_hmac(struct hip_common *, struct hip_crypto_key *);

int hip_receive_control_packet(struct hip_common *, struct in6_addr *,
			       struct in6_addr *, hip_portpair_t *, int);

int hip_receive_udp_control_packet(struct hip_common *, struct in6_addr *,
				   struct in6_addr *, hip_portpair_t *);

//FIXME only used in input.c, also asigned to a function pointer in hadb.c 
//but function pointer is never used
int hip_receive_i1(struct hip_common *, struct in6_addr *, struct in6_addr *,
		   hip_ha_t *, hip_portpair_t *);

//FIXME only used in input.c, also asigned to a function pointer in hadb.c 
//but function pointer is never used
int hip_receive_r1(hip_common_t *r1, in6_addr_t *r1_saddr, in6_addr_t *r1_daddr,
		   hip_ha_t *entry, hip_portpair_t *r1_info);

//FIXME only used in input.c, also asigned to a function pointer in hadb.c 
//but function pointer is never used
int hip_receive_i2(hip_common_t *i2, in6_addr_t *i2_saddr, in6_addr_t *i2_daddr,
		   hip_ha_t *entry, hip_portpair_t *i2_info);

//FIXME only used in input.c, also asigned to a function pointer in hadb.c 
//but function pointer is never used
int hip_receive_r2(struct hip_common *, struct in6_addr *, struct in6_addr *,
		   hip_ha_t *, hip_portpair_t *);

//FIXME only used in input.c, also asigned to a function pointer in hadb.c 
//but function pointer is never used
int hip_receive_notify(const struct hip_common *, const struct in6_addr *,
		       const struct in6_addr *, hip_ha_t*);

//FIXME only used in input.c, also asigned to a function pointer in hadb.c 
//but function pointer is never used
int hip_receive_bos(struct hip_common *, struct in6_addr *, struct in6_addr *,
		    hip_ha_t*, hip_portpair_t *);

//FIXME declared here, implemented in close.c, function pointer in hadb.c
int hip_receive_close(struct hip_common *, hip_ha_t*);

//FIXME declared here, implemented in close.c, function pointer in hadb.c
int hip_receive_close_ack(struct hip_common *, hip_ha_t*);
/* @} */

/**
 * @addtogroup handle_functions
 * @{
 */

//FIXME only used in input.c, also asigned to a function pointer in hadb.c 
//but function pointer is never used
int hip_handle_i1(struct hip_common *, struct in6_addr *, struct in6_addr *,
		  hip_ha_t *, hip_portpair_t *);

//FIXME only used in input.c, also asigned to a function pointer in hadb.c 
//but function pointer is never used
int hip_handle_r1(hip_common_t *r1, in6_addr_t *r1_saddr, in6_addr_t *r1_daddr,
		  hip_ha_t *entry, hip_portpair_t *r1_info);

//FIXME only used in input.c, also asigned to a function pointer in hadb.c 
//but function pointer is never used
int hip_handle_i2(hip_common_t *i2, in6_addr_t *i2_saddr, in6_addr_t *i2_daddr,
		  hip_ha_t *ha, hip_portpair_t *i2_info);

//FIXME only used in input.c, also asigned to a function pointer in hadb.c 
//but function pointer is never used
int hip_handle_r2(hip_common_t *r2, in6_addr_t *r2_saddr, in6_addr_t *r2_daddr,
		  hip_ha_t *entry, hip_portpair_t *r2_info);

//FIXME not implemented in input.c, but in close.c and declared in
//close.h -> remove
int hip_handle_close_ack(struct hip_common *, hip_ha_t *);
/* @} */

//FIXME only used in input.c, also asigned to a function pointer in hadb.c 
//but function pointer is never used
int hip_produce_keying_material(struct hip_common *msg, struct hip_context *ctx,
				uint64_t I, uint64_t J,
				struct hip_dh_public_value **dhpv);

//FIXME only used in input.c, also asigned to a function pointer in hadb.c 
//but function pointer is never used
int hip_create_i2(struct hip_context *ctx, uint64_t solved_puzzle,
		  in6_addr_t *r1_saddr, in6_addr_t *r1_daddr, hip_ha_t *entry,
	          hip_portpair_t *r1_info, struct hip_dh_public_value *dhpv);

//FIXME only used in input.c, also asigned to a function pointer in hadb.c 
//but function pointer is never used
int hip_create_r2(struct hip_context *ctx, in6_addr_t *i2_saddr,
		  in6_addr_t *i2_daddr, hip_ha_t *entry,
		  hip_portpair_t *i2_info,
		  in6_addr_t *dest,
		  const in_port_t dest_port);

// 2007-02-26 oleg
// prototype
//FIXME implementet in hadb.c not in input.c
hip_rcv_func_set_t *hip_get_rcv_default_func_set();
// 2006-02-26 oleg
// prototype
//FIXME implemented in hadb.c not in input.c
hip_handle_func_set_t *hip_get_handle_default_func_set();

#endif /* HIP_INPUT_H */
