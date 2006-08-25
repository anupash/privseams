#ifndef HIP_INPUT_H
#define HIP_INPUT_H

#ifdef CONFIG_HIP_RVS
#  include "rvs.h"
#endif

#include "oppdb.h"
#include "user.h"
#include "debug.h"
#include "beet.h"
#include "hadb.h"
#include "keymat.h"
#include "crypto.h"
#include "builder.h"
#include "misc.h"
#include "hidb.h"
#include "cookie.h"
#include "output.h"
//#include "socket.h"
#include "pk.h"
#include "rvs.h"
#include "netdev.h"
#include "beet.h"
#if defined CONFIG_HIP_HI3
#include "i3_client_api.h"

struct hi3_ipv4_addr {
	u8 sin_family;
	struct in_addr sin_addr;
};

struct hi3_ipv6_addr {
	u8 sin6_family;
	struct in6_addr sin6_addr;
};

#endif


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

#ifdef CONFIG_HIP_HI3
void hip_inbound(cl_trigger *t, void *data, void *ctx);
u16 checksum_packet(char *data, struct sockaddr *src, struct sockaddr *dst);
int hip_verify_network_header(struct hip_common *hip_common,
			      struct sockaddr *src, struct sockaddr *dst, int len);
#endif

/**
 * Gets name for a message type
 * @param type the msg type
 *
 * @return HIP message type as a string.
 */
static inline const char *hip_msg_type_str(int type) 
{
        const char *str = "UNKNOWN";
        static const char *types[] =
	{ "", "I1", "R1", "I2", "R2", "CER", "UPDATE", 
	  "NOTIFY", "CLOSE", "CLOSE_ACK", "UNKNOWN", "BOS" };
        if (type >= 1 && type < ARRAY_SIZE(types))
                str = types[type];
        else if (type == HIP_PAYLOAD) {
		str = "PAYLOAD";
	}

	return str;
}

int hip_check_hip_ri_opportunistic_mode(struct hip_common *msg,
					struct in6_addr *src_addr,
					struct in6_addr *dst_addr,
					struct hip_stateless_info *msg_info,
					hip_ha_t *entry);

int hip_receive_control_packet(struct hip_common *msg,
			       struct in6_addr *src_addr,
			       struct in6_addr *dst_addr,
			       struct hip_stateless_info *msg_info);
			  
/* functions for receiving hip control messages*/ 
			       
int hip_verify_packet_hmac(struct hip_common *, 
			   struct hip_crypto_key *);
			   
int hip_receive_i1(struct hip_common *, 
		   struct in6_addr *, 
		   struct in6_addr *,
		   hip_ha_t *,
	           struct hip_stateless_info *);
		   
int hip_receive_r1(struct hip_common *, 
		   struct in6_addr *,
		   struct in6_addr *,
		   hip_ha_t *,
	           struct hip_stateless_info *);
		   
int hip_receive_i2(struct hip_common *, 
		   struct in6_addr *,
		   struct in6_addr *,
		   hip_ha_t *,
	           struct hip_stateless_info *);
		   
int hip_receive_r2(struct hip_common *, 
		   struct in6_addr *,
		   struct in6_addr *,
		   hip_ha_t *,
	           struct hip_stateless_info *);
		   
int hip_receive_notify(struct hip_common *,
		       struct in6_addr *, 
		       struct in6_addr *,
		       hip_ha_t*);
		      
int hip_receive_bos(struct hip_common *,
		    struct in6_addr *,
		    struct in6_addr *,
		    hip_ha_t*,
	           struct hip_stateless_info *);
		    
int hip_receive_close(struct hip_common *, 
		      hip_ha_t*);
			
int hip_receive_close_ack(struct hip_common *, 
		      	  hip_ha_t*);
		
			  	  
/* functions for handling received hip control messages
   these functions are called after the corresponding
   receive function has checked the state*/

int hip_handle_i1(struct hip_common *i1,
		  struct in6_addr *i1_saddr,
		  struct in6_addr *i1_daddr,
		  hip_ha_t *entry,
	           struct hip_stateless_info *);
		  
int hip_handle_r1(struct hip_common *r1,
		  struct in6_addr *r1_saddr,
		  struct in6_addr *r1_daddr,
		  hip_ha_t *entry,
	           struct hip_stateless_info *);  
		  
int hip_handle_i2(struct hip_common *i2,
		  struct in6_addr *i2_saddr,
		  struct in6_addr *i2_daddr,		  
		  hip_ha_t *ha,
	           struct hip_stateless_info *);
		  
int hip_handle_r2(struct hip_common *r2,
		  struct in6_addr *r2_saddr,
		  struct in6_addr *r2_daddr,		  
		  hip_ha_t *ha,
	           struct hip_stateless_info *);
		  	  
int hip_handle_close(struct hip_common *close,
		     hip_ha_t *entry);
		     
int hip_handle_close_ack(struct hip_common *close_ack, 
			 hip_ha_t *entry);	  
					     
int hip_produce_keying_material(struct hip_common *msg,
				struct hip_context *ctx,
				uint64_t I,
				uint64_t J);
				
int hip_create_i2(struct hip_context *ctx, uint64_t solved_puzzle, 
		  struct in6_addr *r1_saddr,
		  struct in6_addr *r1_daddr,
		  hip_ha_t *entry,
	           struct hip_stateless_info *);
int hip_create_r2(struct hip_context *ctx,
		  struct in6_addr *i2_saddr,
		  struct in6_addr *i2_daddr,
		  hip_ha_t *entry,
	           struct hip_stateless_info *);

 
/**
 * hip_controls_sane - check for illegal controls
 * @param controls control value to be checked
 * @param legal legal control values to check @controls against
 *
 * Controls are given in host byte order.
 *@return Returns 1 if there are no illegal control values in @controls,
 * otherwise 0.
 */
static inline int hip_controls_sane(u16 controls, u16 legal)
{
	return ((controls & (   HIP_CONTROL_HIT_ANON
#ifdef CONFIG_HIP_RVS
			      | HIP_CONTROL_RVS_CAPABLE //XX:FIXME
#endif
		)) | legal) == legal;
}


#endif /* HIP_INPUT_H */
