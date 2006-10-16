#ifndef BLIND_H
#define BLIND_H 

#include "debug.h"
#include "crypto.h"
#include "ife.h"

extern int hip_blind_status; //blind on/off flag

int hip_set_blind_on(void);
int hip_set_blind_off(void);
int hip_blind_get_status(void);
struct hip_common *hip_build_blinded_i1(hip_ha_t *entry, int *mask);
struct hip_common *hip_get_r1_blinded(struct in6_addr *ip_i, 
				      struct in6_addr *ip_r,
				      struct in6_addr *our_hit,
				      struct in6_addr *peer_hit);
int hip_blind_get_nonce(struct hip_common *msg, uint16_t *msg_nonce);
int hip_blind_fingerprints(hip_ha_t *entry);
int hip_plain_fingerprint(uint16_t *nonce, 
			  struct in6_addr *blind_hit, 
			  struct in6_addr *plain_hit);
int hip_blind_verify(uint16_t *nonce, 
		     struct in6_addr *plain_hit, 
		     struct in6_addr *blind_hit);
struct hip_common *hip_build_blinded_r2(struct hip_common *r2, hip_ha_t *entry, int *mask);
#endif
