#ifndef HIP_NSUPDATE_H
#define HIP_NSUPDATE_H

void hip_set_nsupdate_status(int status);
int hip_get_nsupdate_status(void);
int run_nsupdate_for_hit (struct hip_host_id_entry *entry, void *opaq);
int nsupdate();

#endif /* HIP_NSUPDATE_H */
