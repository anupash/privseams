#ifndef HIP_SECURITY_H
#define HIP_SECURITY_H

#include "hadb.h"
#include "libhiptool/crypto.h"

int hip_insert_dh(u8 *buffer, int bufsize, int group_id);
void hip_dh_uninit(void);
int hip_calculate_shared_secret(uint8_t *public_value,
				uint8_t group_id,
				signed int len,
				unsigned char *buffer, 
				int bufsize);
#endif /* HIP_SECURITY_H */
