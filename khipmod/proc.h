#ifndef HIP_PROC_H
#define HIP_PROC_H

#include <net/hip.h>
#include "hip.h"
#include "hidb.h"
#include "hadb.h"

#ifdef __KERNEL__
#  include <linux/types.h>
#endif

#if HIP_KERNEL_DAEMON

int hip_proc_read_hadb_state(char *page, char **start, off_t off,
			     int count, int *eof, void *data);
int hip_proc_read_hadb_peer_addrs(char *page, char **start, off_t off,
				  int count, int *eof, void *data);
int hip_proc_read_hadb_peer_addrs(char *page, char **start, off_t off,
				  int count, int *eof, void *data);
int hip_proc_read_hadb_state(char *page, char **start, off_t off,
				    int count, int *eof, void *data);
int hip_proc_read_lhi(char *page, char **start, off_t off,
		      int count, int *eof, void *data);

#endif /* HIP_KERNEL_DAEMON */

#ifdef CONFIG_PROC_FS
int hip_init_procfs(void);
void hip_uninit_procfs(void);
#endif

#endif /* HIP_PROC_H */
