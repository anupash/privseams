#ifndef HIP_SYSCTL_H
#define HIP_SYSCTL_H

#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>

int hip_register_sysctl(void);
void hip_unregister_sysctl(void);
void hip_init_sys_config(void);
#endif
#endif
