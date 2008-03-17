/** @file
 * This file defines initialization functions for the HIP daemon.
 * 
 * @date    1.1.2007
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */
 
#include "init.h"
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include "debug.h"
#include <pwd.h>
#include "hi3.h"

extern struct hip_common *hipd_msg;
extern struct hip_common *hipd_msg_v4;
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
	int err = 0, fd, dhterr;
	char str[64];
	struct sockaddr_in6 daemon_addr;

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
 
	HIP_IFEL(hip_init_oppip_db(), -1,
	         "Cannot initialize opportunistic mode IP database for non HIP capable hosts!\n");

	HIP_IFEL((hip_init_cipher() < 0), 1, "Unable to init ciphers.\n");

	HIP_IFE(init_random_seed(), -1);

	hip_init_hadb();

	hip_init_puzzle_defaults();

/* Initialize a hashtable for services, if any service is enabled. */
	hip_init_services();
#ifdef CONFIG_HIP_RVS
	HIP_INFO("Initializing HIP UDP relay database.\n");
	if(hip_relht_init() == NULL)
	{
	     HIP_ERROR("Unable to initialize HIP UDP relay database.\n");
	}
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

#ifdef CONFIG_HIP_HI3
	if( hip_use_i3 ) {
		hip_locator_status = SO_HIP_SET_LOCATOR_ON;
	}
#endif
	HIP_IFE(hip_init_host_ids(), 1);

	hip_user_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	HIP_IFEL((hip_user_sock < 0), 1, "Could not create socket for user communication.\n");
	bzero(&daemon_addr, sizeof(daemon_addr));
	daemon_addr.sin6_family = AF_INET6;
	daemon_addr.sin6_port = HIP_DAEMON_LOCAL_PORT;
	daemon_addr.sin6_addr = in6addr_loopback;
	HIP_IFEL(bind(hip_user_sock, (struct sockaddr *)& daemon_addr,
		      sizeof(daemon_addr)), -1, "Bind on daemon addr failed\n");

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
	
        dhterr = 0;
        dhterr = hip_init_dht();
        if (dhterr < 0) HIP_DEBUG("Initializing DHT returned error\n");
	hip_load_configuration();
	
	/* init new tcptimeout parameters, added by Tao Wan on 14.Jan.2008*/

	HIP_IFEL(set_new_tcptimeout_parameters_value(), -1,
			"set new tcptimeout parameters error\n");


	HIP_IFEL(hip_set_lowcapability(), -1, "Failed to set capabilities\n");

#ifdef CONFIG_HIP_HI3
	if( hip_use_i3 ) 
	{
//		hip_get_default_hit(&peer_hit);
		hip_i3_init(/*&peer_hit*/);
	}
#endif

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

int hip_set_lowcapability() {
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

	HIP_IFEL(capget(&header, &data), -1,
		 "error while retrieving capabilities through capget()\n");

	HIP_DEBUG("effective=%u, permitted = %u, inheritable=%u\n",
		  data.effective, data.permitted, data.inheritable);

	ruid=nobody_pswd->pw_uid; 
	euid=nobody_pswd->pw_uid; 
	HIP_DEBUG("Before setreuid(,) UID=%d and EFF_UID=%d\n",
		  getuid(), geteuid());
  	
	HIP_IFEL(setreuid(ruid,euid), -1, "setruid failed\n");
	
	HIP_DEBUG("After setreuid(,) UID=%d and EFF_UID=%d\n",
		  getuid(), geteuid());
	HIP_IFEL(capget(&header, &data), -1,
		 "error while retrieving capabilities through 'capget()'\n");

	HIP_DEBUG("effective=%u, permitted = %u, inheritable=%u\n",
		  data.effective,data.permitted, data.inheritable);
	HIP_DEBUG ("Going to clear all capabilities except the ones needed\n");
	data.effective = data.permitted = data.inheritable = 0;
  	// for CAP_NET_RAW capability 
	data.effective |= (1 <<CAP_NET_RAW );
  	data.permitted |= (1 <<CAP_NET_RAW );
  	// for CAP_NET_ADMIN capability 
	data.effective |= (1 <<CAP_NET_ADMIN );
  	data.permitted |= (1 <<CAP_NET_ADMIN );

	HIP_IFEL(capset(&header, &data), -1, 
		 "error in capset (do you have capabilities kernel module?)");

	HIP_DEBUG("UID=%d EFF_UID=%d\n", getuid(), geteuid());	
	HIP_DEBUG("effective=%u, permitted = %u, inheritable=%u\n",
		  data.effective, data.permitted, data.inheritable);
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

	if (stat(DEFAULT_CONFIG_DIR "/" DEFAULT_HOST_RSA_KEY_FILE_BASE DEFAULT_PUB_HI_FILE_NAME_SUFFIX, &status) && errno == ENOENT)
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


	/*reset TCP timeout to be original vaule , added By Tao Wan on 14.Jan.2008. */
	reset_default_tcptimeout_parameters_value();


	if (hipd_msg)
		HIP_FREE(hipd_msg);
        if (hipd_msg_v4)
            HIP_FREE(hipd_msg_v4);
	
	hip_delete_all_sp();

	delete_all_addresses();

	set_up_device(HIP_HIT_DEV, 0);

	/* This is needed only if RVS or escrow, hiprelay is in use. */
	hip_uninit_services();

#ifdef CONFIG_HIP_OPPORTUNISTIC
	hip_oppdb_uninit();
#endif

#ifdef CONFIG_HIP_HI3
	hip_hi3_clean();
#endif

#ifdef CONFIG_HIP_RVS
	HIP_INFO("Uninitializing HIP UDP relay database.\n");
	hip_relht_uninit();
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

