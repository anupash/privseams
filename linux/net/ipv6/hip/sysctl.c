#include "sysctl.h"

#if defined(CONFIG_SYSCTL) || defined(CONFIG_SYSCTL_MODULE)
/* /proc/sys/net/hip */
int sysctl_hip_test = 0;
static struct ctl_table_header *hip_sysctl_header = NULL;

static int zero = 0, max_k = 64;  /* sysctl table wants pointers to ranges */

static struct hip_sys_config hip_sys_config;

static ctl_table hip_table[] = {
	{
		.ctl_name	= NET_HIP_COOKIE_MAX_K_R1,
		.procname	= "cookie_max_k_r1",
		.data		= &hip_sys_config.hip_cookie_max_k_r1,
		.maxlen		= sizeof (int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= &sysctl_intvec,
		.extra1		= &zero,
		.extra2		= &max_k
	},
	{ .ctl_name = 0 }
};

static ctl_table hip_net_table[] = {
	{
		.ctl_name	= NET_HIP,
		.procname	= "hip",
		.mode		= 0555,
		.child		= hip_table
	},
        { .ctl_name = 0 }
};

static ctl_table hip_root_table[] = {
	{
		.ctl_name	= CTL_NET,
		.procname	= "net",
		.mode		= 0555,
		.child		= hip_net_table
	},
        { .ctl_name = 0 }
};

int hip_register_sysctl(void)
{
	HIP_DEBUG("\n");
	hip_sysctl_header = register_sysctl_table(hip_root_table, 0);
	return (hip_sysctl_header ? 1 : 0);
}

void hip_unregister_sysctl(void)
{
	HIP_DEBUG("\n");
	if (hip_sysctl_header)
		unregister_sysctl_table(hip_sysctl_header);
}

u8 hip_sysconfig_get_max_k(void) {
	return hip_sys_config.hip_cookie_max_k_r1;
}

/**
 * hip_init_sys_config - Initialize HIP related sysctl variables to default values
 */
void hip_init_sys_config(void)
{
	hip_sys_config.hip_cookie_max_k_r1 = 20;
}
#endif

