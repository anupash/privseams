
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "init.h"
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include "debug.h"
#include <pwd.h>

extern struct hip_common *hipd_msg;
typedef struct __user_cap_header_struct capheader_t;
typedef struct __user_cap_data_struct capdata_t;


/******************************************************************************/
/** Catch SIGCHLD. */
void hip_sig_chld(int signum) 
{ 
	union wait status;
	int pid, i;
	
	signal(signum, hip_sig_chld);

	/* Get child process status, so it wont be left as zombie for long time. */
	while ((pid = wait3(&status, WNOHANG, 0)) > 0)
	{
		/* Maybe do something.. */
		_HIP_DEBUG("Child quit with pid %d\n", pid);
	}
}


void hip_load_configuration()
{
	const char *cfile = "default";
	struct stat status;
	pid_t pid;
	FILE *fp = NULL;
	size_t items = 0;
	int len_con = strlen(HIPD_CONFIG_FILE_EX), 
	  len_hos = strlen(HIPD_HOSTS_FILE_EX);

	/* HIPD_CONFIG_FILE, HIPD_CONFIG_FILE_EX, HIPD_HOSTS_FILE and 
	   HIPD_HOSTS_FILE_EX are defined in /libinet6/hipconf.h */

	/* Create config file if does not exist */

	if (stat(HIPD_CONFIG_FILE, &status) && errno == ENOENT) {
		errno = 0;
		fp = fopen(HIPD_CONFIG_FILE, "w" /* mode */);
		HIP_ASSERT(fp);
		items = fwrite(HIPD_CONFIG_FILE_EX, len_con, 1, fp);
		HIP_ASSERT(items > 0);
		fclose(fp);
	}

	/* Create /etc/hip/hosts file if does not exist */

	if (stat(HIPD_HOSTS_FILE, &status) && errno == ENOENT) {
		errno = 0;
		fp = fopen(HIPD_HOSTS_FILE, "w" /* mode */);
		HIP_ASSERT(fp);
		items = fwrite(HIPD_HOSTS_FILE_EX, len_hos, 1, fp);
		HIP_ASSERT(items > 0);
		fclose(fp);
	}

	/* Load the configuration. The configuration is loaded as a sequence
	   of hipd system calls. Assumably the user socket buffer is large
	   enough to buffer all of the hipconf commands.. */

	hip_conf_handle_load(NULL, ACTION_LOAD, &cfile, 1);
}

void hip_set_os_dep_variables()
{
	struct utsname un;
	int rel[4] = {0};

	uname(&un);

	HIP_DEBUG("sysname=%s nodename=%s release=%s version=%s machine=%s\n",
		  un.sysname, un.nodename, un.release, un.version, un.machine);

	sscanf(un.release, "%d.%d.%d.%d", &rel[0], &rel[1], &rel[2], &rel[3]);

	/*
	  2.6.19 and above introduced some changes to kernel API names:
	  - XFRM_BEET changed from 2 to 4
	  - crypto algo names changed
	*/

	if (rel[0] <= 2 && rel[1] <= 6 && rel[2] < 19) {
		hip_xfrm_set_beet(2);
		hip_xfrm_set_algo_names(0);
	} else {
		hip_xfrm_set_beet(4);
		hip_xfrm_set_algo_names(1);
	}

#ifdef CONFIG_HIP_BUGGYIPSEC
        hip_xfrm_set_default_sa_prefix_len(0);
#else
	/* This requires new kernel versions (the 2.6.18 patch) - jk */
        hip_xfrm_set_default_sa_prefix_len(128);
#endif
}


/**
 * Main initialization function for HIP daemon.
 */
int hipd_init(int flush_ipsec, int killold)
{
	int err = 0, fd;
	char str[64];
	struct sockaddr_un daemon_addr;
	extern struct addrinfo * opendht_serving_gateway;

	/* Open daemon lock file and read pid from it. */
//	unlink(HIP_DAEMON_LOCK_FILE);
	fd = open(HIP_DAEMON_LOCK_FILE, O_RDWR | O_CREAT, 0644);

	/* Write pid to file. */
	if (fd > 0)
	{
		if (lockf(fd, F_TLOCK, 0) < 0)
		{
			int pid = 0;
			memset(str, 0, sizeof(str));
			read(fd, str, sizeof(str) - 1);
			pid = atoi(str);
			
			if (!killold)
			{
				HIP_ERROR("HIP daemon already running with pid %d!\n", pid);
				HIP_ERROR("Use -k option to kill old daemon.\n");
				exit(1);
			}
		
			HIP_INFO("Daemon is already running with pid %d?"
			         "-k option given, terminating old one...\n", pid);
			kill(pid, SIGKILL);
		}
		
		sprintf(str, "%d\n", getpid());
		write(fd, str, strlen(str)); /* record pid to lockfile */
	}

	hip_init_hostid_db(NULL);

	hip_set_os_dep_variables();

	hip_probe_kernel_modules();

	/* Register signal handlers */
	signal(SIGINT, hip_close);
	signal(SIGTERM, hip_close);
	signal(SIGCHLD, hip_sig_chld);
 
	HIP_IFEL(hip_ipdb_clear(), -1,
	         "Cannot clear opportunistic mode IP database for non HIP capable hosts!\n");

	HIP_IFEL((hip_init_cipher() < 0), 1, "Unable to init ciphers.\n");

	HIP_IFE(init_random_seed(), -1);

	hip_init_hadb();

	hip_init_puzzle_defaults();

/* Initialize a hashtable for services, if any service is enabled. */
	hip_init_services();
#ifdef CONFIG_HIP_RVS
        hip_rvs_init_rvadb();
#endif	
#ifdef CONFIG_HIP_OPENDHT
        err = resolve_dht_gateway_info(OPENDHT_GATEWAY, &opendht_serving_gateway);
        if (err < 0) 
          HIP_DEBUG("Error resolving openDHT gateway!\n");
        err = 0;
#endif
#ifdef CONFIG_HIP_ESCROW
	hip_init_keadb();
	hip_init_kea_endpoints();
#endif
#ifdef CONFIG_HIP_HI3
	cl_init(i3_config);
#endif

#ifdef CONFIG_HIP_OPPORTUNISTIC
	hip_init_opp_db();
#endif

	/* Resolve our current addresses, afterwards the events from kernel
	   will maintain the list This needs to be done before opening
	   NETLINK_ROUTE! See the comment about address_count global var. */
	HIP_DEBUG("Initializing the netdev_init_addresses\n");
	hip_netdev_init_addresses(&hip_nl_ipsec);

	if (rtnl_open_byproto(&hip_nl_route,
	                      RTMGRP_LINK | RTMGRP_IPV6_IFADDR | IPPROTO_IPV6
	                      | RTMGRP_IPV4_IFADDR | IPPROTO_IP,
	                      NETLINK_ROUTE) < 0)
	{
		err = 1;
		HIP_ERROR("Routing socket error: %s\n", strerror(errno));
		goto out_err;
	}

	/* Open the netlink socket for address and IF events */
	if (rtnl_open_byproto(&hip_nl_ipsec, XFRMGRP_ACQUIRE, NETLINK_XFRM) < 0)
	{
		HIP_ERROR("Netlink address and IF events socket error: %s\n", strerror(errno));
		err = 1;
		goto out_err;
	}

#ifndef CONFIG_HIP_PFKEY
	hip_xfrm_set_nl_ipsec(&hip_nl_ipsec);
#endif

#if 0
	{
		const int ipsec_buf_size = 200000;
		socklen_t ipsec_buf_sizeof = sizeof(int);
		setsockopt(hip_nl_ipsec.fd, SOL_SOCKET, SO_RCVBUF,
			   &ipsec_buf_size, ipsec_buf_sizeof);
		setsockopt(hip_nl_ipsec.fd, SOL_SOCKET, SO_SNDBUF,
			   &ipsec_buf_size, ipsec_buf_sizeof);
	}
#endif

	HIP_IFEL(hip_init_raw_sock_v6(&hip_raw_sock_v6), -1, "raw sock v6\n");
	HIP_IFEL(hip_init_raw_sock_v4(&hip_raw_sock_v4), -1, "raw sock v4\n");
	HIP_IFEL(hip_init_nat_sock_udp(&hip_nat_sock_udp), -1, "raw sock udp\n");

	HIP_DEBUG("hip_raw_sock = %d\n", hip_raw_sock_v6);
	HIP_DEBUG("hip_raw_sock_v4 = %d\n", hip_raw_sock_v4);
	HIP_DEBUG("hip_nat_sock_udp = %d\n", hip_nat_sock_udp);

	if (flush_ipsec)
	{
		hip_flush_all_sa();
		hip_flush_all_policy();
	}

	HIP_DEBUG("Setting SP\n");
	hip_delete_default_prefix_sp_pair();
	HIP_IFE(hip_setup_default_sp_prefix_pair(), 1);

	HIP_DEBUG("Setting iface %s\n", HIP_HIT_DEV);
	set_up_device(HIP_HIT_DEV, 0);
	HIP_IFE(set_up_device(HIP_HIT_DEV, 1), 1);

	HIP_IFE(hip_init_host_ids(), 1);

	hip_user_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	HIP_IFEL((hip_user_sock < 0), 1, "Could not create socket for user communication.\n");
	bzero(&daemon_addr, sizeof(daemon_addr));
	daemon_addr.sun_family = AF_UNIX;
	strcpy(daemon_addr.sun_path, HIP_DAEMONADDR_PATH);
	unlink(HIP_DAEMONADDR_PATH);
	HIP_IFEL(bind(hip_user_sock, (struct sockaddr *)&daemon_addr,
	         /*sizeof(daemon_addr)*/
	         strlen(daemon_addr.sun_path) +
	         sizeof(daemon_addr.sun_family)),
	         1, "Bind on daemon addr failed.");
	HIP_IFEL(chmod(daemon_addr.sun_path, S_IRWXO),
	         1, "Changing permissions of daemon addr failed.")

	hip_agent_sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	HIP_IFEL(hip_agent_sock < 0, 1,
	         "Could not create socket for agent communication.\n");
	unlink(HIP_AGENTADDR_PATH);
	bzero(&hip_agent_addr, sizeof(hip_agent_addr));
	hip_agent_addr.sun_family = AF_LOCAL;
	strcpy(hip_agent_addr.sun_path, HIP_AGENTADDR_PATH);
	HIP_IFEL(bind(hip_agent_sock, (struct sockaddr *)&hip_agent_addr,
	              sizeof(hip_agent_addr)), -1, "Bind on agent addr failed.");
	chmod(HIP_AGENTADDR_PATH, 0777);
	
//	TODO: initialize firewall socket
	hip_firewall_sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	HIP_IFEL(hip_firewall_sock < 0, 1,
	         "Could not create socket for firewall communication.\n");
	unlink(HIP_FIREWALLADDR_PATH);
	bzero(&hip_firewall_addr, sizeof(hip_firewall_addr));
	hip_firewall_addr.sun_family = AF_LOCAL;
	strcpy(hip_firewall_addr.sun_path, HIP_FIREWALLADDR_PATH);
	HIP_IFEL(bind(hip_firewall_sock, (struct sockaddr *)&hip_firewall_addr,
	              sizeof(hip_firewall_addr)), -1, "Bind on firewall addr failed.");
	chmod(HIP_FIREWALLADDR_PATH, 0777);

	register_to_dht();
	hip_load_configuration();
	
	HIP_IFEL(hip_set_lowcapability(), -1, "Failed to set capabilities\n");

out_err:
	return err;
}


int hip_set_lowcapability() {
//-- BUG 172 -- try to lower the capabilities of the daemon 
	struct passwd *nobody_pswd;
	int err = 0;
#ifdef CONFIG_HIP_PRIVSEP
	uid_t ruid,euid;
	capheader_t header;
	capdata_t data;	

	header.pid=0;
	header.version = _LINUX_CAPABILITY_VERSION;
	data.effective = data.permitted = data.inheritable = 0;

	HIP_IFEL(prctl(PR_SET_KEEPCAPS, 1), -1, "prctl err\n");
	
	HIP_DEBUG("Now PR_SET_KEEPCAPS=%d\n", prctl(PR_GET_KEEPCAPS));

	HIP_IFEL(!(nobody_pswd = getpwnam(USER_NOBODY)), -1,
		 "Error while retrieving USER 'nobody' uid\n"); 

	HIP_IFEL(capget(&header, &data). -1,
		 "error while retrieving capabilities through 'capget()'");

	HIP_DEBUG("CAPABILITY value is  effective=%u, permitted = %u, inheritable=%u\n",
		  data.effective, data.permitted, data.inheritable);

	ruid=nobody_pswd->pw_uid; 
	euid=nobody_pswd->pw_uid; 
	HIP_DEBUG("Before setreuid(,) UID=%d and EFF_UID=%d\n", getuid(), geteuid());
  	
	HIP_IFEL(setreuid(ruid,euid), -1, "setruid failed\n");
	
	HIP_DEBUG("After setreuid(,) UID=%d and EFF_UID=%d\n", getuid(), geteuid());
	HIP_IFEL(capget(&header, &data), -1,
		 "error while retrieving capabilities through 'capget()'\n");

	HIP_DEBUG("CAPABILITY value is  effective=%u, permitted = %u, inheritable=%u\n",
		  data.effective,data.permitted, data.inheritable);
	HIP_DEBUG ("We are going to clear all capabilities except the ones we need:\n");
	data.effective = data.permitted = data.inheritable = 0;
  	// for CAP_NET_RAW capability 
	data.effective |= (1 <<CAP_NET_RAW );
  	data.permitted |= (1 <<CAP_NET_RAW );
  	// for CAP_NET_ADMIN capability 
	data.effective |= (1 <<CAP_NET_ADMIN );
  	data.permitted |= (1 <<CAP_NET_ADMIN );

	HIP_IFEL(capset(&header, &data), -1, 
		 "error while setting new capabilities through 'capset()'\n");

	HIP_DEBUG("UID=%d EFF_UID=%d\n", getuid(), geteuid());	
	HIP_DEBUG("CAPABILITY value is  effective=%u, permitted = %u, inheritable=%u\n",
		  data.effective, data. permitted,data.inheritable);
#endif /* CONFIG_HIP_PRIVSEP */

out_err:
	return err;
	
}

/**
 * Init host IDs.
 */
int hip_init_host_ids()
{
	int err = 0;
	struct stat status;
	struct hip_common *user_msg = NULL;

	/* We are first serializing a message with HIs and then
	   deserializing it. This building and parsing causes
	   a minor overhead, but as a result we can reuse the code
	   with hipconf. */

	HIP_IFE((!(user_msg = hip_msg_alloc())), -1);
		
	/* Create default keys if necessary. */

	if (stat(DEFAULT_CONFIG_DIR, &status) && errno == ENOENT)
	{
		hip_msg_init(user_msg);
		err = hip_serialize_host_id_action(user_msg,
						   ACTION_NEW, 0, 1,
						   NULL, NULL);
		if (err)
		{
			err = 1;
			HIP_ERROR("Failed to create keys to %s\n",
				  DEFAULT_CONFIG_DIR);
			goto out_err;
		}
	}
	
        /* Retrieve the keys to hipd */
	hip_msg_init(user_msg);
	err = hip_serialize_host_id_action(user_msg, ACTION_ADD, 0, 1, NULL, NULL);
	if (err)
	{
		HIP_ERROR("Could not load default keys\n");
		goto out_err;
	}
	
	err = hip_handle_add_local_hi(user_msg);
	if (err)
	{
		HIP_ERROR("Adding of keys failed\n");
		goto out_err;
	}

 out_err:

	if (user_msg)
		HIP_FREE(user_msg);

	return err;
}

/**
 * Init raw ipv6 socket.
 */
int hip_init_raw_sock_v6(int *hip_raw_sock_v6)
{
	int on = 1, off = 0, err = 0;

	*hip_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_HIP);
	HIP_IFEL(*hip_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

	/* see bug id 212 why RECV_ERR is off */
	err = setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt recverr failed\n");
	err = setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
	err = setsockopt(*hip_raw_sock_v6, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

 out_err:
	return err;
}

/**
 * Init raw ipv4 socket.
 */
int hip_init_raw_sock_v4(int *hip_raw_sock_v4)
{
	int on = 1, err = 0;
	int off = 0;

	*hip_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_HIP);
	HIP_IFEL(*hip_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

	/* see bug id 212 why RECV_ERR is off */
	err = setsockopt(*hip_raw_sock_v4, IPPROTO_IP, IP_RECVERR, &off, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
	err = setsockopt(*hip_raw_sock_v4, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
	err = setsockopt(*hip_raw_sock_v4, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
	err = setsockopt(*hip_raw_sock_v4, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

 out_err:
	return err;
}

/**
 * Init udp socket for nat usage.
 */
int hip_init_nat_sock_udp(int *hip_nat_sock_udp)
{
	int on = 1, err = 0;
	int off = 0;
	int encap_on = HIP_UDP_ENCAP_ESPINUDP_NONIKE;
	struct sockaddr_in myaddr;

	HIP_DEBUG("hip_init_nat_sock_udp() invoked.\n");

	if((*hip_nat_sock_udp = socket(AF_INET, SOCK_DGRAM, 0))<0)
	{
		HIP_ERROR("Can not open socket for UDP\n");
		return -1;
	}
	err = setsockopt(*hip_nat_sock_udp, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt udp pktinfo failed\n");
	/* see bug id 212 why RECV_ERR is off */
	err = setsockopt(*hip_nat_sock_udp, IPPROTO_IP, IP_RECVERR, &off, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt udp recverr failed\n");
	err = setsockopt(*hip_nat_sock_udp, SOL_UDP, HIP_UDP_ENCAP, &encap_on, sizeof(encap_on));
	HIP_IFEL(err, -1, "setsockopt udp encap failed\n");
	err = setsockopt(*hip_nat_sock_udp, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(encap_on));
	HIP_IFEL(err, -1, "setsockopt udp reuseaddr failed\n");

	myaddr.sin_family=AF_INET;
	/** @todo Change this inaddr_any -- Abi */
	myaddr.sin_addr.s_addr = INADDR_ANY;
	myaddr.sin_port=htons(HIP_NAT_UDP_PORT);

	err = bind(*hip_nat_sock_udp, (struct sockaddr *)&myaddr, sizeof(myaddr));
	if (err < 0)
	{
		HIP_ERROR("Unable to bind udp socket to port\n");
		err = -1;
		goto out_err;
	}

	HIP_DEBUG_INADDR("UDP socket created and binded to addr", &myaddr.sin_addr.s_addr);
	return 0;

out_err:
	return err;
}

/**
 * Start closing HIP daemon.
 */
void hip_close(int signal)
{
	static int terminate = 0;
	
	HIP_ERROR("Signal: %d\n", signal);
	terminate++;
	
	/* Close SAs with all peers */
	if (terminate == 1) {
		hip_send_close(NULL);
		hipd_set_state(HIPD_STATE_CLOSING);
		HIP_DEBUG("Starting to close HIP daemon...\n");
	} else if (terminate == 2) {
		HIP_DEBUG("Send still once this signal to force daemon exit...\n");
	} else if (terminate > 2) {
		HIP_DEBUG("Terminating daemon.\n");
		hip_exit(signal);
		exit(signal);
	}
}


/**
 * Cleanup and signal handler to free userspace and kernel space
 * resource allocations.
 */
void hip_exit(int signal)
{
	int alen;
	struct hip_common *msg = NULL;
	HIP_ERROR("Signal: %d\n", signal);

	hip_delete_default_prefix_sp_pair();
	/* Close SAs with all peers */
        // hip_send_close(NULL);

	if (hipd_msg)
		HIP_FREE(hipd_msg);
	
	hip_delete_all_sp();

	delete_all_addresses();

	set_up_device(HIP_HIT_DEV, 0);

	/* This is needed only if RVS or escrow is in use. */
	hip_uninit_services();

#ifdef CONFIG_HIP_OPPORTUNISTIC
	hip_oppdb_uninit();
#endif

#ifdef CONFIG_HIP_HI3
	cl_exit();
#endif

#ifdef CONFIG_HIP_RVS
        hip_rvs_uninit_rvadb();
#endif
#ifdef CONFIG_HIP_ESCROW
	hip_uninit_keadb();
	hip_uninit_kea_endpoints();
#endif

	if (hip_raw_sock_v6)
		close(hip_raw_sock_v6);
	if (hip_raw_sock_v4)
		close(hip_raw_sock_v4);
	if(hip_nat_sock_udp)
		close(hip_nat_sock_udp);
	if (hip_user_sock)
		close(hip_user_sock);
	if (hip_nl_ipsec.fd)
		rtnl_close(&hip_nl_ipsec);
	if (hip_nl_route.fd)
		rtnl_close(&hip_nl_route);

	hip_uninit_hadb();
	hip_uninit_host_id_dbs();

	msg = hip_msg_alloc();
	if (msg)
	{
	  hip_build_user_hdr(msg, HIP_DAEMON_QUIT, 0);
	}
	else HIP_ERROR("Failed to allocate memory for message\n");

	if (msg && hip_agent_sock)
	{
		alen = sizeof(hip_agent_addr);
		sendto(hip_agent_sock, msg, hip_get_msg_total_len(msg), 0,
		       (struct sockaddr *)&hip_agent_addr, alen);
	}
	close(hip_agent_sock);

	if (msg)
		free(msg);
	
	unlink(HIP_DAEMON_LOCK_FILE);

#ifdef CONFIG_HIP_OPENDHT
	if (opendht_serving_gateway)
		freeaddrinfo(opendht_serving_gateway);
#endif

	return;
}

/**
 * Initalize random seed.
 */
int init_random_seed()
{
	struct timeval tv;
	struct timezone tz;
	struct {
		struct timeval tv;
		pid_t pid;
		long int rand;
	} rand_data;
	int err = 0;

	err = gettimeofday(&tv, &tz);
	srandom(tv.tv_usec);

	memcpy(&rand_data.tv, &tv, sizeof(tv));
	rand_data.pid = getpid();
	rand_data.rand = random();

	RAND_seed(&rand_data, sizeof(rand_data));

	return err;
}

/**
 * Probe kernel modules.
 */
void hip_probe_kernel_modules()
{
	int count, err, status;
	char cmd[40];
	int mod_total;
	char *mod_name[] =
	{
		"xfrm6_tunnel", "xfrm4_tunnel",
		"ip6_tunnel", "ipip", "ip4_tunnel",
		"xfrm_user", "dummy", "esp6", "esp4",
		"ipv6", "aes", "crypto_null", "des",
		"xfrm4_mode_beet", "xfrm6_mode_beet", "sha1"
	};

	mod_total = sizeof(mod_name) / sizeof(char *);

	HIP_DEBUG("Probing for %d modules. When the modules are built-in, the errors can be ignored\n", mod_total);	

	for (count = 0; count < mod_total; count++)
	{
		snprintf(cmd, sizeof(cmd), "%s %s", "/sbin/modprobe", mod_name[count]);
		HIP_DEBUG("%s\n", cmd);
		err = fork();
		if (err < 0) HIP_ERROR("Failed to fork() for modprobe!\n");
		else if (err == 0)
		{
			/* Redirect stderr, so few non fatal errors wont show up. */
			stderr = freopen("/dev/null", "w", stderr);
			execlp("/sbin/modprobe", "/sbin/modprobe", mod_name[count], (char *)NULL);
		}
		else waitpid(err, &status, 0);
	}
	HIP_DEBUG("Probing completed\n");
}

