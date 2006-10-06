#ifndef BLIND_H
#define BLIND_H 

#include "debug.h"
#include "crypto.h"

extern int hip_blind_status;

int hip_set_blind_on(void);
int hip_set_blind_off(void);

int hip_blind_get_status(void);
struct hip_common *hip_get_r1_blinded(struct in6_addr *ip_i, 
				      struct in6_addr *ip_r,
				      struct in6_addr *our_hit,
				      struct in6_addr *peer_hit);
#endif
