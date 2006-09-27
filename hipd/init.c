
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

extern struct hip_common *hipd_msg;

/**
 * Main initialization function for HIP daemon.
 */
int hipd_init(int flush_ipsec)
{
	int err = 0;
	struct sockaddr_un daemon_addr;

	hip_probe_kernel_modules();

	/* Register signal handlers */
	signal(SIGINT, hip_close);
	signal(SIGTERM, hip_close);

	HIP_IFEL((hip_init_cipher() < 0), 1, "Unable to init ciphers.\n");

	HIP_IFE(init_random_seed(), -1);

	hip_init_hadb();

	hip_init_puzzle_defaults();

/* Initialize a hashtable for services, if any service is enabled. */
#if defined(CONFIG_HIP_RVS) || defined(CONFIG_HIP_ESCROW)
	hip_init_services();
#endif
#ifdef CONFIG_HIP_RVS
        hip_rvs_init_rvadb();
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
			      NETLINK_ROUTE) < 0) {
		err = 1;
		HIP_ERROR("Routing socket error: %s\n", strerror(errno));
		goto out_err;
	}

	/* Open the netlink socket for address and IF events */
	if (rtnl_open_byproto(&hip_nl_ipsec, XFRMGRP_ACQUIRE, NETLINK_XFRM) < 0) {
		HIP_ERROR("Netlink address and IF events socket error: %s\n", strerror(errno));
		err = 1;
		goto out_err;
	}

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
	//HIP_IFEL(hip_init_nat_sock_udp_data(&hip_nat_sock_udp_data), -1, "raw sock udp for data\n");

	HIP_DEBUG("hip_raw_sock = %d\n", hip_raw_sock_v6);
	HIP_DEBUG("hip_raw_sock_v4 = %d\n", hip_raw_sock_v4);
	HIP_DEBUG("hip_nat_sock_udp = %d\n", hip_nat_sock_udp);

	if (flush_ipsec) {
		hip_flush_all_sa();
		hip_flush_all_policy();
	}

	HIP_DEBUG("Setting SP\n");
	/*
	hip_delete_default_prefix_sp_pair();
	HIP_IFE(hip_setup_default_sp_prefix_pair(), 1);
	*/

	HIP_DEBUG("Setting iface %s\n", HIP_HIT_DEV);
	set_up_device(HIP_HIT_DEV, 0);
	HIP_IFE(set_up_device(HIP_HIT_DEV, 1), 1);

	HIP_IFE(hip_init_host_ids(), 1);

	hip_user_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	HIP_IFEL((hip_user_sock < 0), 1,
		 "Could not create socket for user communication.\n");
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
	HIP_IFEL((hip_agent_sock < 0), 1,
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
	HIP_IFEL((hip_firewall_sock < 0), 1,
		 "Could not create socket for firewall communication.\n");
	unlink(HIP_FIREWALLADDR_PATH);
	bzero(&hip_firewall_addr, sizeof(hip_firewall_addr));
	hip_firewall_addr.sun_family = AF_LOCAL;
	strcpy(hip_firewall_addr.sun_path, HIP_FIREWALLADDR_PATH);
	HIP_IFEL(bind(hip_firewall_sock, (struct sockaddr *)&hip_firewall_addr,
	              sizeof(hip_firewall_addr)), -1, "Bind on firewall addr failed.");
	chmod(HIP_FIREWALLADDR_PATH, 0777);
	
	register_to_dht();
	
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

	if (stat(DEFAULT_CONFIG_DIR, &status) && errno == ENOENT) {
		hip_msg_init(user_msg);
		err = hip_serialize_host_id_action(user_msg,
						   ACTION_NEW, 0, 1,
						   NULL, NULL);
		if (err) {
			err = 1;
			HIP_ERROR("Failed to create keys to %s\n",
				  DEFAULT_CONFIG_DIR);
			goto out_err;
		}
	}
	
        /* Retrieve the keys to hipd */
	hip_msg_init(user_msg);
	err = hip_serialize_host_id_action(user_msg, ACTION_ADD, 0, 1,
					   NULL, NULL);
	if (err) {
		HIP_ERROR("Could not load default keys\n");
		goto out_err;
	}
	
	err = hip_handle_add_local_hi(user_msg);
	if (err) {
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

	HIP_IFEL(((*hip_raw_sock_v6 = socket(AF_INET6, SOCK_RAW,
					 IPPROTO_HIP)) <= 0), 1,
		 "Raw socket creation failed. Not root?\n");

	/* see bug id 212 why RECV_ERR is off */
	HIP_IFEL(setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6, IPV6_RECVERR, &off,
		   sizeof(on)), -1, "setsockopt recverr failed\n");
	HIP_IFEL(setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6,
			    IPV6_2292PKTINFO, &on,
		   sizeof(on)), -1, "setsockopt pktinfo failed\n");

	HIP_IFEL(setsockopt(*hip_raw_sock_v6, SOL_SOCKET, SO_REUSEADDR, &on,
			    sizeof(on)), -1,
		 "setsockopt v6 reuseaddr failed\n");

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

	HIP_IFEL(((*hip_raw_sock_v4 = socket(AF_INET, SOCK_RAW,
	         IPPROTO_HIP)) <= 0), 1,
	         "Raw socket v4 creation failed. Not root?\n");
	/* see bug id 212 why RECV_ERR is off */
	HIP_IFEL(setsockopt(*hip_raw_sock_v4, IPPROTO_IP, IP_RECVERR, &off,
	         sizeof(on)), -1, "setsockopt v4 recverr failed\n");
	HIP_IFEL(setsockopt(*hip_raw_sock_v4, SOL_SOCKET, SO_BROADCAST, &on,
	         sizeof(on)), -1,
	         "setsockopt v4 failed to set broadcast \n");
	HIP_IFEL(setsockopt(*hip_raw_sock_v4, IPPROTO_IP, IP_PKTINFO, &on,
	         sizeof(on)), -1, "setsockopt v4 pktinfo failed\n");

	HIP_IFEL(setsockopt(*hip_raw_sock_v4, SOL_SOCKET, SO_REUSEADDR, &on,
	         sizeof(on)), -1,
	         "setsockopt v4 reuseaddr failed\n");

 out_err:
	return err;
}

/**
 * Init udp socket for nat usage.
 */
int hip_init_nat_sock_udp(int *hip_nat_sock_udp)
{
	HIP_DEBUG("hip_init_nat_sock_udp() invoked.\n");
	int on = 1, err = 0;
	int off = 0;
	int encap_on = HIP_UDP_ENCAP_ESPINUDP_NONIKE;
        struct sockaddr_in myaddr;

	if((*hip_nat_sock_udp = socket(AF_INET, SOCK_DGRAM, 0))<0)
        {
                HIP_ERROR("Can not open socket for UDP\n");
                return -1;
        }
	HIP_IFEL(setsockopt(*hip_nat_sock_udp, IPPROTO_IP, IP_PKTINFO, &on,
		   sizeof(on)), -1, "setsockopt udp pktinfo failed\n");
	/* see bug id 212 why RECV_ERR is off */
	HIP_IFEL(setsockopt(*hip_nat_sock_udp, IPPROTO_IP, IP_RECVERR, &off,
                   sizeof(on)), -1, "setsockopt udp recverr failed\n");
	HIP_IFEL(setsockopt(*hip_nat_sock_udp, SOL_UDP, HIP_UDP_ENCAP, &encap_on,
                   sizeof(encap_on)), -1, "setsockopt udp encap failed\n");
	HIP_IFEL(setsockopt(*hip_nat_sock_udp, SOL_SOCKET, SO_REUSEADDR, &on,
			    sizeof(encap_on)), -1,
		 "setsockopt udp reuseaddr failed\n");

        myaddr.sin_family=AF_INET;
	/** @todo Change this inaddr_any -- Abi */
        myaddr.sin_addr.s_addr = INADDR_ANY;
        myaddr.sin_port=htons(HIP_NAT_UDP_PORT);

        if( bind(*hip_nat_sock_udp, (struct sockaddr *)&myaddr, sizeof(myaddr))< 0 )
        {
                HIP_ERROR("Unable to bind udp socket to port\n");
                err = -1;
		goto out_err;
        }

	HIP_DEBUG_INADDR("UDP socket created and binded to addr",
			 &myaddr.sin_addr.s_addr);
        return 0;

 out_err:
	return err;

}

/**
 * Init udp socket for nat data usage.
 */
int hip_init_nat_sock_udp_data(int *hip_nat_sock_udp_data)
{
	HIP_DEBUG("hip_init_nat_sock_udp_data() invoked.\n");
	int on = HIP_UDP_ENCAP_ESPINUDP, err = 0;
	int off = 0;
	
	if((*hip_nat_sock_udp_data = socket(AF_INET, SOCK_DGRAM, 0))<0)
        {
                HIP_ERROR("Can not open socket for UDP\n");
                return -1;
        }
	
	HIP_IFEL(setsockopt(*hip_nat_sock_udp_data, SOL_UDP, HIP_UDP_ENCAP, &on,
			    sizeof(on)), -1, "setsockopt udp encap failed\n");
	
        struct sockaddr_in myaddr;
	
        myaddr.sin_family = AF_INET;
	/** @todo Change this inaddr_any -- Abi */
        myaddr.sin_addr.s_addr = INADDR_ANY;
        myaddr.sin_port=htons(HIP_UDP_DATA_PORT);

	if( bind(*hip_nat_sock_udp_data, (struct sockaddr *)&myaddr, sizeof(myaddr))< 0 )
        {
                HIP_ERROR("Unable to bind udp socket to port\n");
                err = -1;
		goto out_err;
        }
	
        HIP_DEBUG_INADDR("UDP data socket created and binded to addr",
			 &myaddr.sin_addr);
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
	if (terminate == 1)
	{
		hip_send_close(NULL);
		hipd_set_state(HIPD_STATE_CLOSING);
		HIP_DEBUG("Starting to close HIP daemon...\n");
	}
	else if (terminate == 2)
	{
		HIP_DEBUG("Send still once this signal to force daemon exit...\n");
	}
	else if (terminate > 2)
	{
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

	//hip_delete_default_prefix_sp_pair();

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
	if(hip_nat_sock_udp_data)
		close(hip_nat_sock_udp_data);
	if (hip_user_sock)
		close(hip_user_sock);
	if (hip_nl_ipsec.fd)
		rtnl_close(&hip_nl_ipsec);
	if (hip_nl_route.fd)
		rtnl_close(&hip_nl_route);

        hip_uninit_hadb();
	hip_uninit_host_id_dbs();

	msg = hip_msg_alloc();
	if (msg) {
	  hip_build_user_hdr(msg, HIP_DAEMON_QUIT, 0);
	} else {
	  HIP_ERROR("Failed to allocate memory for message\n");
	}

	if (msg && hip_agent_sock)
	{
		alen = sizeof(hip_agent_addr);
		sendto(hip_agent_sock, msg, hip_get_msg_total_len(msg), 0,
		       (struct sockaddr *)&hip_agent_addr, alen);
	}
	close(hip_agent_sock);

	if (msg)
		free(msg);
	
	return;
}

/**
 * Initalize random seed.
 */
int init_random_seed()
{
	struct timeval tv;
	struct timezone tz;
	int err = 0;

	err = gettimeofday(&tv, &tz);
	srandom(tv.tv_usec);

	return err;
}

/**
 * Probe kernel modules.
 */
void hip_probe_kernel_modules()
{
	int count;
	char cmd[40];
        /* update also this if you add more modules */
	const int mod_total = 10;
	char *mod_name[] = {"xfrm6_tunnel", "xfrm4_tunnel",
			    "xfrm_user", "dummy", "esp6", "esp4",
			    "ipv6", "aes", "crypto_null", "des"};

	HIP_DEBUG("Probing for modules. When the modules are built-in, the errors can be ignored\n");
	for (count = 0; count < mod_total; count++) {
		snprintf(cmd, sizeof(cmd), "%s %s", "modprobe",
			 mod_name[count]);
		HIP_DEBUG("%s\n", cmd);
		system(cmd);
	}
	HIP_DEBUG("Probing completed\n");
}
