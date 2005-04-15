#ifndef HIP_PROC_H
#define HIP_PROC_H

#ifndef CONFIG_HIP_USERSPACE
#include <linux/types.h>
#include <net/hip.h>
#include "hidb.h"

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

#if 0
/* for update packet testing */
int hip_proc_send_update(char *page, char **start, off_t off,
			 int count, int *eof, void *data);
/* for notify packet testing */
int hip_proc_send_notify(char *page, char **start, off_t off,
			 int count, int *eof, void *data);
#endif
#endif /* CONFIG_HIP_USERSPACE */

int hip_init_procfs(void);
void hip_uninit_procfs(void);

#endif /* HIP_PROC_H */
