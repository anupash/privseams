#ifndef DH_H
#define DH_H

#ifdef __KERNEL__
#  include <linux/types.h>
#  include <linux/kernel.h>
#  include <linux/module.h>
#  include <linux/errno.h>
#  include "kernel-interface.h"
#else
#  include <hip.h>
#  include <gcrypt.h>
#endif /* __KERNEL__ */

typedef struct DH_str {
	MPI p;
	MPI g;
	MPI pub_key;
	MPI priv_key;
} DH;

/* this should be consistent with the table length in dh.c */
#define HIP_MAX_DH_GROUP_ID 7 

int hip_gen_dh_shared_key(DH *dh, u8 *peer_key, size_t peer_len, u8 *out, size_t outlen);
int hip_encode_dh_publickey(DH *dh, u8 *out, int outlen);
DH *hip_generate_dh_key(int group_id);
DH *hip_dh_clone(DH *src);
void hip_free_dh_structure(DH *target);

#endif /* DH_H */
