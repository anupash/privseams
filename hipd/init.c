/** @file
 * This file defines initialization functions for the HIP daemon.
 *
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @note    HIPU: BSD platform needs to be autodetected in hip_set_lowcapability
 */

#include "init.h"

#ifndef OPENWRT
//#include <sys/capability.h>
#endif
#include <sys/prctl.h>
#include "common_defines.h"
#include <sys/types.h>
#include "debug.h"
#include "hi3.h"

extern struct hip_common *hipd_msg;
extern struct hip_common *hipd_msg_v4;

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

#ifdef CONFIG_HIP_DEBUG
void hip_print_sysinfo()
{
	FILE *fp = NULL;
	char str[256];
	int pipefd[2];
	int stdout_fd;

	fp = fopen("/etc/debian_version", "r");
	if(!fp)
		fp = fopen("/etc/redhat-release", "r");

	if(fp) {

		while(fgets(str, sizeof(str), fp)) {
			HIP_DEBUG("version=%s", str);
		}
		if (fclose(fp))
			HIP_ERROR("Error closing version file\n");
		fp = NULL;

	}

	fp = fopen("/proc/cpuinfo", "r");
	if(fp) {

		HIP_DEBUG("Printing /proc/cpuinfo\n");
		while(fgets(str, sizeof(str), fp)) {
			HIP_DEBUG(str);
		}
		if (fclose(fp))
			HIP_ERROR("Error closing /proc/cpuinfo\n");
		fp = NULL;

	} else {
		HIP_ERROR("Failed to open file /proc/cpuinfo\n");
	}

	/* Route stdout into a pipe to capture lsmod output */

	stdout_fd = dup(1);
	if (stdout_fd < 0) {
		HIP_ERROR("Stdout backup failed\n");
		return;
	}
	if (pipe(pipefd)) {
		HIP_ERROR("Pipe creation failed\n");
		return;
	}
	if (dup2(pipefd[1], 1) < 0) {
		HIP_ERROR("Stdout capture failed\n");
		if (close(pipefd[1]))
			HIP_ERROR("Error closing write end of pipe\n");
		if (close(pipefd[0]))
			HIP_ERROR("Error closing read end of pipe\n");
		return;
	}

	system("lsmod");

	if (dup2(stdout_fd, 1) < 0)
		HIP_ERROR("Stdout restore failed\n");
	if (close(stdout_fd))
		HIP_ERROR("Error closing stdout backup\n");
	if (close(pipefd[1]))
		HIP_ERROR("Error closing write end of pipe\n");

	fp = fdopen(pipefd[0], "r");
	if(fp) {

		HIP_DEBUG("Printing lsmod output\n");
		while(fgets(str, sizeof(str), fp)) {
			HIP_DEBUG(str);
		}
		if (fclose(fp))
			HIP_ERROR("Error closing read end of pipe\n");

	} else {
		HIP_ERROR("Error opening pipe for reading\n");
		if (close(pipefd[0]))
			HIP_ERROR("Error closing read end of pipe\n");
	}
}
#endif

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

	hip_conf_handle_load(NULL, ACTION_LOAD, &cfile, 1, 1);
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

#ifndef CONFIG_HIP_PFKEY
	if (rel[0] <= 2 && rel[1] <= 6 && rel[2] < 19) {
		hip_xfrm_set_beet(2);
		hip_xfrm_set_algo_names(0);
	} else {
		hip_xfrm_set_beet(4);
		hip_xfrm_set_algo_names(1);
	}
#endif

#ifndef CONFIG_HIP_PFKEY
#ifdef CONFIG_HIP_BUGGYIPSEC
        hip_xfrm_set_default_sa_prefix_len(0);
#else
	/* This requires new kernel versions (the 2.6.18 patch) - jk */
        hip_xfrm_set_default_sa_prefix_len(128);
#endif
#endif
}

/**
 * Main initialization function for HIP daemon.
 */
int hipd_init(int flush_ipsec, int killold)
{
	hip_hit_t peer_hit;
	int err = 0, certerr = 0, dhterr = 0;
	char str[64];
	char mtu[16];
	struct sockaddr_in6 daemon_addr;
	extern int hip_opendht_sock_fqdn;
	extern int hip_opendht_sock_hit;
	extern int hip_icmp_sock;

	memset(str, 0, 64);
	memset(mtu, 0, 16);

	/* Make sure that root path is set up correcly (e.g. on Fedora 9).
	   Otherwise may get warnings from system() commands.
	   @todo: should append, not overwrite  */
	setenv("PATH", HIP_DEFAULT_EXEC_PATH, 1);

	/* Open daemon lock file and read pid from it. */
	HIP_IFEL(hip_create_lock_file(HIP_DAEMON_LOCK_FILE, killold), -1,
		 "locking failed\n");

	hip_init_hostid_db(NULL);

	hip_set_os_dep_variables();

	//#ifdef CONFIG_MEASURES
	hip_bex_timestamp_db_init();
	//#endif

#ifndef CONFIG_HIP_OPENWRT
#ifdef CONFIG_HIP_DEBUG
	hip_print_sysinfo();
#endif
	hip_probe_kernel_modules();
#endif

	/* Register signal handlers */
	signal(SIGINT, hip_close);
	signal(SIGTERM, hip_close);
	signal(SIGCHLD, hip_sig_chld);

#ifdef CONFIG_HIP_OPPORTUNISTIC
	HIP_IFEL(hip_init_oppip_db(), -1,
	         "Cannot initialize opportunistic mode IP database for "\
                 "non HIP capable hosts!\n");
#endif
	HIP_IFEL((hip_init_cipher() < 0), 1, "Unable to init ciphers.\n");

	HIP_IFE(init_random_seed(), -1);

	hip_init_hadb();
        /* hip_init_puzzle_defaults just returns, removed -samu  */
#if 0
	hip_init_puzzle_defaults();
#endif
	/* Service initialization. */
	hip_init_services();

#ifdef CONFIG_HIP_RVS
	HIP_INFO("Initializing HIP relay / RVS.\n");
	hip_relay_init();
#endif
#ifdef CONFIG_HIP_ESCROW
	hip_init_keadb();
	hip_init_kea_endpoints();
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
                int ret_sockopt = 0, value = 0;
                socklen_t value_len = sizeof(value);
		int ipsec_buf_size = 200000;
		socklen_t ipsec_buf_sizeof = sizeof(ipsec_buf_size);
                ret_sockopt = getsockopt(hip_nl_ipsec.fd, SOL_SOCKET, SO_RCVBUF,
                                         &value, &value_len);
                if (ret_sockopt != 0)
                    HIP_DEBUG("Getting receive buffer size of hip_nl_ipsec.fd failed\n");
                ipsec_buf_size = value * 2;
                HIP_DEBUG("Default setting of receive buffer size for hip_nl_ipsec was %d.\n"
                          "Setting it to %d.\n", value, ipsec_buf_size);
		ret_sockopt = setsockopt(hip_nl_ipsec.fd, SOL_SOCKET, SO_RCVBUF,
			   &ipsec_buf_size, ipsec_buf_sizeof);
                if (ret_sockopt !=0 )
                    HIP_DEBUG("Setting receive buffer size of hip_nl_ipsec.fd failed\n");
                ret_sockopt = 0;
		ret_sockopt = setsockopt(hip_nl_ipsec.fd, SOL_SOCKET, SO_SNDBUF,
			   &ipsec_buf_size, ipsec_buf_sizeof);
                if (ret_sockopt !=0 )
                    HIP_DEBUG("Setting send buffer size of hip_nl_ipsec.fd failed\n");
	}
#endif

	HIP_IFEL(hip_init_raw_sock_v6(&hip_raw_sock_v6), -1, "raw sock v6\n");
	HIP_IFEL(hip_init_raw_sock_v4(&hip_raw_sock_v4), -1, "raw sock v4\n");
	HIP_IFEL(hip_init_nat_sock_udp(&hip_nat_sock_udp), -1, "raw sock udp\n");
	HIP_IFEL(hip_init_icmp_v6(&hip_icmp_sock), -1, "icmpv6 sock\n");

	HIP_DEBUG("hip_raw_sock = %d\n", hip_raw_sock_v6);
	HIP_DEBUG("hip_raw_sock_v4 = %d\n", hip_raw_sock_v4);
	HIP_DEBUG("hip_nat_sock_udp = %d\n", hip_nat_sock_udp);
	HIP_DEBUG("hip_icmp_sock = %d\n", hip_icmp_sock);

	if (flush_ipsec)
	{
		default_ipsec_func_set.hip_flush_all_sa();
		default_ipsec_func_set.hip_flush_all_policy();
	}

	HIP_DEBUG("Setting SP\n");
	default_ipsec_func_set.hip_delete_default_prefix_sp_pair();
	HIP_IFE(default_ipsec_func_set.hip_setup_default_sp_prefix_pair(), -1);

	HIP_DEBUG("Setting iface %s\n", HIP_HIT_DEV);
	set_up_device(HIP_HIT_DEV, 0);
	HIP_IFE(set_up_device(HIP_HIT_DEV, 1), 1);
	HIP_DEBUG("Lowering MTU of dev " HIP_HIT_DEV " to %u\n", HIP_HIT_DEV_MTU);
	sprintf(mtu, "%u", HIP_HIT_DEV_MTU);
	strcpy(str, "ifconfig dummy0 mtu ");
	strcat(str, mtu);
	/* MTU is set using system call rather than in do_chflags to avoid
	 * chicken and egg problems in hipd start up. */
	system(str);

	HIP_IFE(hip_init_host_ids(), 1);

	hip_user_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	HIP_IFEL((hip_user_sock < 0), 1, "Could not create socket for user communication.\n");
	bzero(&daemon_addr, sizeof(daemon_addr));
	daemon_addr.sin6_family = AF_INET6;
	daemon_addr.sin6_port = htons(HIP_DAEMON_LOCAL_PORT);
	daemon_addr.sin6_addr = in6addr_loopback;

	HIP_IFEL(bind(hip_user_sock, (struct sockaddr *)& daemon_addr,
		      sizeof(daemon_addr)), -1,
		 "Bind on daemon addr failed\n");

	hip_load_configuration();

#ifdef CONFIG_HIP_HI3
	if( hip_use_i3 ) {
		hip_locator_status = SO_HIP_SET_LOCATOR_ON;
	}
#endif

	hip_opendht_sock_fqdn = init_dht_gateway_socket(hip_opendht_sock_fqdn);
	hip_opendht_sock_hit = init_dht_gateway_socket(hip_opendht_sock_hit);

	certerr = 0;
	certerr = hip_init_certs();
	if (certerr < 0) HIP_DEBUG("Initializing cert configuration file returned error\n");

#if 0
	/* init new tcptimeout parameters, added by Tao Wan on 14.Jan.2008*/

	HIP_IFEL(set_new_tcptimeout_parameters_value(), -1,
			"set new tcptimeout parameters error\n");
#endif

#ifdef CONFIG_HIP_PRIVSEP
	/* Fix to bug id 668 */
	getaddrinfo_disable_hit_lookup();
#endif /* CONFIG_HIP_PRIVSEP */

	HIP_IFEL(hip_set_lowcapability(0), -1, "Failed to set capabilities\n");

#ifdef CONFIG_HIP_HI3
	if( hip_use_i3 )
	{
//		hip_get_default_hit(&peer_hit);
		hip_i3_init(/*&peer_hit*/);
	}
#endif
	hip_firewall_sock_lsi_fd = hip_user_sock;

out_err:
	return err;
}

/**
 * Function initializes needed variables for the OpenDHT
 *
 * Returns positive on success negative otherwise
 */
int hip_init_dht()
{
        int err = 0, lineno = 0, i = 0, randomno = 0;
        extern struct addrinfo * opendht_serving_gateway;
        extern char opendht_name_mapping;
        extern int hip_opendht_inuse;
        extern int hip_opendht_error_count;
        extern int hip_opendht_sock_fqdn;
        extern int hip_opendht_sock_hit;
        char *serveraddr_str;
        char *servername_str;
        FILE *fp = NULL;
        char line[500];
        List list;

        if (hip_opendht_inuse == SO_HIP_DHT_ON) {
                hip_opendht_error_count = 0;
                /* check the condition of the sockets, we may have come here in middle
                 of something so re-initializing might be needed */
                if (hip_opendht_sock_fqdn > 0) {
                        close(hip_opendht_sock_fqdn);
                         hip_opendht_sock_fqdn = init_dht_gateway_socket(hip_opendht_sock_fqdn);
                         hip_opendht_fqdn_sent = STATE_OPENDHT_IDLE;
                }

                if (hip_opendht_sock_hit > 0) {
                        close(hip_opendht_sock_hit);
                         hip_opendht_sock_hit = init_dht_gateway_socket(hip_opendht_sock_hit);
                         hip_opendht_hit_sent = STATE_OPENDHT_IDLE;
                }

                fp = fopen(OPENDHT_SERVERS_FILE, "r");
                if (fp == NULL) {
                        HIP_DEBUG("No dhtservers file, using %s\n", OPENDHT_GATEWAY);
                        err = resolve_dht_gateway_info(OPENDHT_GATEWAY, &opendht_serving_gateway);
                        if (err < 0) HIP_DEBUG("Error resolving openDHT gateway!\n");
                        err = 0;
                        memset(&opendht_name_mapping, '\0', HIP_HOST_ID_HOSTNAME_LEN_MAX - 1);
                        if (gethostname(&opendht_name_mapping, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1))
                                HIP_DEBUG("gethostname failed\n");
                } else {
                        /* dhtservers exists */
                        while (fp && getwithoutnewline(line, 500, fp) != NULL) {
                                lineno++;
                        }
                        fclose(fp);
                        srand(time(NULL));
                        randomno = rand() % lineno;
                        fp = fopen(OPENDHT_SERVERS_FILE, "r");
                        for (i = 0; i <= randomno; i++)
                                getwithoutnewline(line, 500, fp);
                        initlist(&list);
                        extractsubstrings(line, &list);
                        servername_str = getitem(&list,0);
                        serveraddr_str = getitem(&list,1);
                        HIP_DEBUG("DHT gateway from dhtservers: %s (%s)\n",
                                  servername_str, serveraddr_str);
                        /* resolve it */
                        err = resolve_dht_gateway_info(serveraddr_str, &opendht_serving_gateway);
                        if (err < 0) HIP_DEBUG("Error resolving openDHT gateway!\n");
                        err = 0;
                        memset(&opendht_name_mapping, '\0', HIP_HOST_ID_HOSTNAME_LEN_MAX - 1);
                        if (gethostname(&opendht_name_mapping, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1))
                                HIP_DEBUG("gethostname failed\n");
			register_to_dht();
                        destroy(&list);
                }
        } else {
                HIP_DEBUG("DHT is not in use");
        }
 out_err:
        if (fp)
                fclose(fp);
        return (err);
}

/**
 * Init host IDs.
 */
int hip_init_host_ids()
{
	int err = 0;
	struct stat status;
	struct hip_common *user_msg = NULL;
	hip_hit_t default_hit;
	hip_lsi_t default_lsi;

	/* We are first serializing a message with HIs and then
	   deserializing it. This building and parsing causes
	   a minor overhead, but as a result we can reuse the code
	   with hipconf. */

	HIP_IFE(!(user_msg = hip_msg_alloc()), -1);

	/* Create default keys if necessary. */

	if (stat(DEFAULT_CONFIG_DIR "/" DEFAULT_HOST_RSA_KEY_FILE_BASE DEFAULT_PUB_HI_FILE_NAME_SUFFIX, &status) && errno == ENOENT) {
		//hip_msg_init(user_msg); already called by hip_msg_alloc()

	    HIP_IFEL(hip_serialize_host_id_action(user_msg, ACTION_NEW, 0, 1,
			NULL, NULL, RSA_KEY_DEFAULT_BITS, DSA_KEY_DEFAULT_BITS),
			1, "Failed to create keys to %s\n", DEFAULT_CONFIG_DIR);
	}

        /* Retrieve the keys to hipd */
	/* Three steps because multiple large keys will not fit in the same message */

	/* DSA keys and RSA anonymous are not loaded by default until bug id
	   522 is properly solved. Run hipconf add hi default if you want to
	   enable non-default HITs. */
#if 0
	/* dsa anon and pub */
	hip_msg_init(user_msg);
	if (err = hip_serialize_host_id_action(user_msg, ACTION_ADD,
						0, 1, "dsa", NULL, 0, 0)) {
		HIP_ERROR("Could not load default keys (DSA)\n");
		goto out_err;
	}
	if (err = hip_handle_add_local_hi(user_msg)) {
		HIP_ERROR("Adding of keys failed (DSA)\n");
		goto out_err;
	}

	/* rsa anon */
	hip_msg_init(user_msg);
	if (err = hip_serialize_host_id_action(user_msg, ACTION_ADD,
						1, 1, "rsa", NULL, 0, 0)) {
		HIP_ERROR("Could not load default keys (RSA anon)\n");
		goto out_err;
	}
	if (err = hip_handle_add_local_hi(user_msg)) {
		HIP_ERROR("Adding of keys failed (RSA anon)\n");
		goto out_err;
	}
#endif

	/* rsa pub */
	hip_msg_init(user_msg);
	if (err = hip_serialize_host_id_action(user_msg, ACTION_ADD,
						0, 1, "rsa", NULL, 0, 0)) {
		HIP_ERROR("Could not load default keys (RSA pub)\n");
		goto out_err;
	}

	if (err = hip_handle_add_local_hi(user_msg)) {
		HIP_ERROR("Adding of keys failed (RSA pub)\n");
		goto out_err;
	}

	HIP_DEBUG("Keys added\n");
	hip_get_default_hit(&default_hit);
	hip_get_default_lsi(&default_lsi);

	HIP_DEBUG_HIT("default_hit ", &default_hit);
	HIP_DEBUG_LSI("default_lsi ", &default_lsi);
	hip_hidb_associate_default_hit_lsi(&default_hit, &default_lsi);

	/*Initializes the hadb with the information contained in /etc/hip/hosts*/
	//hip_init_hadb_hip_host();

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
 * Init icmpv6 socket.
 */
int hip_init_icmp_v6(int *icmpsockfd)
{
	int err = 0, on = 1;
	struct sockaddr_in6 addr6;
	struct icmp6_filter filter;

	/* Make sure that hipd does not send icmpv6 immediately after base exchange */
	heartbeat_counter = hip_icmp_interval;

	*icmpsockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	HIP_IFEL(*icmpsockfd <= 0, 1, "ICMPv6 socket creation failed\n");

	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ICMPV6_ECHO_REPLY, &filter);
	err = setsockopt(*icmpsockfd, IPPROTO_ICMPV6, ICMPV6_FILTER, &filter,
			 sizeof(struct icmp6_filter));
	HIP_IFEL(err, -1, "setsockopt icmp ICMP6_FILTER failed\n");


	err = setsockopt(*icmpsockfd, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt icmp IPV6_RECVPKTINFO failed\n");

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
	int encap_on = HIP_UDP_ENCAP_ESPINUDP;
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
#ifndef CONFIG_HIP_OPENWRT
	err = setsockopt(*hip_nat_sock_udp, SOL_UDP, HIP_UDP_ENCAP, &encap_on, sizeof(encap_on));
	HIP_IFEL(err, -1, "setsockopt udp encap failed\n");
#endif
	err = setsockopt(*hip_nat_sock_udp, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt udp reuseaddr failed\n");
	err = setsockopt(*hip_nat_sock_udp, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt udp reuseaddr failed\n");

	myaddr.sin_family=AF_INET;
	/** @todo Change this inaddr_any -- Abi */
	myaddr.sin_addr.s_addr = INADDR_ANY;
	myaddr.sin_port=htons(HIP_NAT_UDP_PORT);

	err = bind(*hip_nat_sock_udp, (struct sockaddr *)&myaddr, sizeof(myaddr));
	if (err < 0)
	{
		HIP_PERROR("Unable to bind udp socket to port\n");
		err = -1;
		goto out_err;
	}

	HIP_DEBUG_INADDR("UDP socket created and bound to addr", &myaddr.sin_addr.s_addr);
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
	struct hip_common *msg = NULL;
	HIP_ERROR("Signal: %d\n", signal);

	default_ipsec_func_set.hip_delete_default_prefix_sp_pair();
	/* Close SAs with all peers */
        // hip_send_close(NULL);

#if 0
	/*reset TCP timeout to be original vaule , added By Tao Wan on 14.Jan.2008. */
	reset_default_tcptimeout_parameters_value();
#endif
	if (hipd_msg)
		HIP_FREE(hipd_msg);
        if (hipd_msg_v4)
        	HIP_FREE(hipd_msg_v4);

	hip_delete_all_sp();//empty

	delete_all_addresses();

	set_up_device(HIP_HIT_DEV, 0);

	/* Next line is needed only if RVS or escrow, hiprelay is in use. */
	hip_uninit_services();

#ifdef CONFIG_HIP_OPPORTUNISTIC
	hip_oppdb_uninit();
#endif

#ifdef CONFIG_HIP_HI3
	hip_hi3_clean();
#endif

#ifdef CONFIG_HIP_RVS
	HIP_INFO("Uninitializing RVS / HIP relay database and whitelist.\n");
	hip_relay_uninit();
#endif
#ifdef CONFIG_HIP_ESCROW
	hip_uninit_keadb();
	hip_uninit_kea_endpoints();
#endif

	if (hip_raw_sock_v6){
		HIP_INFO("hip_raw_sock_v6\n");
		close(hip_raw_sock_v6);
	}
	if (hip_raw_sock_v4){
		HIP_INFO("hip_raw_sock_v4\n");
		close(hip_raw_sock_v4);
	}
	if(hip_nat_sock_udp){
		HIP_INFO("hip_nat_sock_udp\n");
		close(hip_nat_sock_udp);
	}
	if (hip_user_sock){
		HIP_INFO("hip_user_sock\n");
		close(hip_user_sock);
	}
	if (hip_nl_ipsec.fd){
		HIP_INFO("hip_nl_ipsec.fd\n");
		rtnl_close(&hip_nl_ipsec);
	}
	if (hip_nl_route.fd){
		HIP_INFO("hip_nl_route.fd\n");
		rtnl_close(&hip_nl_route);
	}

	hip_uninit_hadb();
	hip_uninit_host_id_dbs();

	msg = hip_msg_alloc();
	if (msg)
	{
		hip_build_user_hdr(msg, SO_HIP_DAEMON_QUIT, 0);
		hip_send_agent(msg);
		free(msg);
	}

	hip_remove_lock_file(HIP_DAEMON_LOCK_FILE);

	if (opendht_serving_gateway)
		freeaddrinfo(opendht_serving_gateway);

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

	memcpy( (char *)&rand_data.tv, &tv, sizeof(tv));
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
		"ipv6", "crypto_null", "cbc",
		"blkcipher", "des", "aes",
		"xfrm4_mode_beet", "xfrm6_mode_beet", "sha1",
		"capability"
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

int hip_init_certs(void) {
	int err = 0;
	char hit[41];
	FILE * conf_file;
	struct hip_host_id_entry * entry;
	char hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];

	memset(hostname, 0, HIP_HOST_ID_HOSTNAME_LEN_MAX);
	HIP_IFEL(gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1), -1,
		 "gethostname failed\n");

	conf_file = fopen(HIP_CERT_CONF_PATH, "r");
	if (!conf_file) {
		HIP_DEBUG("Configuration file did NOT exist creating it and "
			  "filling it with default information\n");
		HIP_IFEL(!memset(hit, '\0', sizeof(hit)), -1,
			  "Failed to memset memory for hit presentation format\n");
		/* Fetch the first RSA HIT */
		entry = hip_return_first_rsa();
		if (entry == NULL) {
			HIP_DEBUG("Failed to get the first RSA HI");
			goto out_err;
		}
		hip_in6_ntop(&entry->lhi.hit, hit);
		conf_file = fopen(HIP_CERT_CONF_PATH, "w+");
		fprintf(conf_file,
			"# Section containing SPKI related information\n"
			"#\n"
			"# issuerhit = what hit is to be used when signing\n"
			"# days = how long is this key valid\n"
			"\n"
			"[ hip_spki ]\n"
			"issuerhit = %s\n"
			"days = %d\n"
			"\n"
			"# Section containing HIP related information\n"
			"#\n"
			"# issuerhit = what hit is to be used when signing\n"
			"# days = how long is this key valid\n"
			"\n"
			"[ hip_x509v3 ]\n"
			"issuerhit = %s\n"
			"days = %d\n"
			"\n"
			"#Section containing the name section for the x509v3 issuer name"
			"\n"
			"[ hip_x509v3_name ]\n"
			"issuerhit = %s\n"
                        "\n"
                        "# Uncomment this section to add x509 extensions\n"
                        "# to the certificate\n"
                        "#\n"
                        "# DO NOT use subjectAltName, issuerAltName or\n"
                        "# basicConstraints implementation uses them already\n"
                        "# All other extensions are allowed\n"
                        "\n"
                        "# [ hip_x509v3_extensions ]\n",
			hit, HIP_CERT_INIT_DAYS,
                        hit, HIP_CERT_INIT_DAYS,
			hit, hostname);
		fclose(conf_file);
	} else {
		HIP_DEBUG("Configuration file existed exiting hip_init_certs\n");
	}
out_err:
	return err;
}

struct hip_host_id_entry * hip_return_first_rsa(void) {
	hip_list_t *curr, *iter;
	struct hip_host_id_entry *tmp;
	int err = 0, c;
	uint16_t algo;

	HIP_READ_LOCK_DB(hip_local_hostid_db);

	list_for_each_safe(curr, iter, hip_local_hostid_db, c) {
		tmp = list_entry(curr);
		HIP_DEBUG_HIT("Found HIT", &tmp->lhi.hit);
		algo = hip_get_host_id_algo(tmp->host_id);
		HIP_DEBUG("hits algo %d HIP_HI_RSA = %d\n",
			  algo, HIP_HI_RSA);
		if (algo == HIP_HI_RSA) goto out_err;
	}

out_err:
	HIP_READ_UNLOCK_DB(hip_local_hostid_db);
	if (algo == HIP_HI_RSA) return (tmp);
	return NULL;
}
