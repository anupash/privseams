#ifndef HIP_INPUT_H
#define HIP_INPUT_H

#ifdef CONFIG_HIP_RVS
#  include "rvs.h"
#endif

#include "workqueue.h"
#include "debug.h"
#include "beet.h"
#include "hadb.h"
#include "keymat.h"
#include "crypto.h"
#include "builder.h"
#include "hip.h"
#include "misc.h"
#include "workqueue.h"
#include "hidb.h"
#include "cookie.h"
#include "output.h"
//#include "socket.h"
#include "pk.h"
#include "rvs.h"
#include "netdev.h"
#include "blind.h"

#ifdef CONFIG_HIP_OPPORTUNISTIC
extern hip_opp_block_t *hip_oppdb_find_byhits(const hip_hit_t *hit_peer,
					      const hip_hit_t *hit_our);
int hip_check_hip_ri_opportunistic_mode(struct hip_common *msg,
					struct in6_addr *src_addr,
					struct in6_addr *dst_addr,
					struct hip_stateless_info *msg_info,
					hip_ha_t *entry);
#endif /* CONFIG_HIP_OPPORTUNISTIC */

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

int hip_handle_i1_blind(struct hip_common *i1,
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
					     
void hip_hwo_input_destructor(struct hip_work_order *hwo);

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

 
#endif /* HIP_INPUT_H */
