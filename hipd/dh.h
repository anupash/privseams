#ifndef HIP_SECURITY_H
#define HIP_SECURITY_H

#include "hadb.h"
#include "crypto.h"
#include "debug.h"
#include "hip.h"

int hip_insert_dh(u8 *buffer, int bufsize, int group_id);
void hip_regen_dh_keys(u32 bitmask);
void hip_dh_uninit(void);
int hip_calculate_shared_secret(struct hip_diffie_hellman *dhf, u8* buffer,
				int bufsize);

#endif /* HIP_SECURITY_H */
