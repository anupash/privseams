#ifndef HIP_DH_H
#define HIP_DH_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include "mpi-defs.h"
#include "mpi-internal.h"
#include "gcrypt.h"
#include "kernel-interface.h"

typedef struct DH_str {
	MPI p;
	MPI g;
	MPI pub_key;
	MPI priv_key;
} DH;

#include <net/hip.h>
#include "../crypto.h"

int hip_gen_dh_shared_key(DH *dh, u8 *peer_key, size_t peer_len, u8 *out, size_t outlen);
int hip_encode_dh_publickey(DH *dh, u8 *out, int outlen);
DH *hip_generate_dh_key(int group_id);
DH *hip_dh_clone(DH *src);
void hip_free_dh(DH *target);
u16 hip_get_dh_size(u8 hip_dh_group_type);


#endif /* HIP_DH_H */
