#ifndef HIP_SYSCTL_H
#define HIP_SYSCTL_H

#include <linux/config.h>

#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#include "debug.h"
#include "hip.h"

struct hip_sys_config {
	int hip_cookie_max_k_r1;
};

int hip_register_sysctl(void);
void hip_unregister_sysctl(void);
void hip_init_sys_config(void);
u8 hip_sysconfig_get_max_k(void);
#endif
#endif
