/** @file
 * The HIPL main file containing the daemon main loop. 
 * 
 * @date 28.01.2008
 * @note Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */ 
#include "hipd.h" 

/* Defined as a global just to allow freeing in exit(). Do not use outside
   of this file! */
struct hip_common *hipd_msg = NULL;
struct hip_common *hipd_msg_v4 = NULL;

int is_active_handover = 1;  /**< Which handover to use active or lazy? */
int hip_blind_status = 0; /**< Blind status */

/** Suppress advertising of none, AF_INET or AF_INET6 address in UPDATEs.
    0 = none = default, AF_INET, AF_INET6 */
int suppress_af_family = 0;

/* For receiving of HIP control messages */
int hip_raw_sock_v6 = 0;
int hip_raw_sock_v4 = 0;
/** File descriptor of the socket used for HIP control packet NAT traversal on
    UDP/IPv4. */
int hip_nat_sock_udp = 0;
/** Specifies the NAT status of the daemon. This value indicates if the current
    machine is behind a NAT. */
int hip_nat_status = 0;

/** Specifies the HIP PROXY status of the daemon. This value indicates if the HIP PROXY is running. */
int hipproxy = 0;

/* Communication interface to userspace apps (hipconf etc) */
int hip_user_sock = 0;
struct sockaddr_un hip_user_addr;

/** For receiving netlink IPsec events (acquire, expire, etc) */
struct rtnl_handle hip_nl_ipsec  = { 0 };

/** For getting/setting routes and adding HITs (it was not possible to use
    nf_ipsec for this purpose). */
struct rtnl_handle hip_nl_route = { 0 };

int hip_agent_status = 0;

//#if 0
int hip_firewall_sock = -1;
//#endif
struct sockaddr_in6 hip_firewall_addr;

/* 
   HIP transform suite order 
   0 = AES_SHA1, 3DES_SHA1, NULL_SHA1
   1 = 3DES_SHA1, AES_SHA1, NULL_SHA1
   2 = AES_SHA1, NULL_SHA1, 3DES_SHA1
   3 = 3DES_SHA1, NULL_SHA1, AES_SHA1
   4 = NULL_SHA1, AES_SHA1, 3DES_SHA1
   5 = NULL_SHA1, 3DES_SHA1, AES_SHA1
*/
int hip_transform_order = 0; 

/* OpenDHT related variables */
int hip_opendht_sock_fqdn = -1; /* FQDN->HIT mapping */
int hip_opendht_sock_hit = -1; /* HIT->IP mapping */
int hip_opendht_fqdn_sent = STATE_OPENDHT_IDLE;
int hip_opendht_hit_sent = STATE_OPENDHT_IDLE;
int opendht_error = 0;
char opendht_response[1024];
struct addrinfo * opendht_serving_gateway = NULL;
int opendht_serving_gateway_port = OPENDHT_PORT;
int opendht_serving_gateway_ttl = OPENDHT_TTL;
char opendht_name_mapping[HIP_HOST_ID_HOSTNAME_LEN_MAX]; /* what name should be used as key */
#ifdef CONFIG_HIP_OPENDHT
int hip_opendht_inuse = SO_HIP_DHT_ON;
#else
int hip_opendht_inuse = SO_HIP_DHT_OFF;
#endif
int hip_opendht_error_count = 0; /* Error count, counting errors from libhipopendht */

/* Tells to the daemon should it build LOCATOR parameters to R1 and I2 */
int hip_locator_status = SO_HIP_SET_LOCATOR_OFF;


/* It tells the daemon to set tcp timeout parameters. Added By Tao Wan, on 09.Jan.2008 */
int hip_tcptimeout_status = SO_HIP_SET_TCPTIMEOUT_ON;

/* We are caching the IP addresses of the host here. The reason is that during
   in hip_handle_acquire it is not possible to call getifaddrs (it creates
   a new netlink socket and seems like only one can be open per process).
   Feel free to experiment by porting the required functionality from
   iproute2/ip/ipaddrs.c:ipaddr_list_or_flush(). It would make these global
   variable and most of the functions referencing them unnecessary -miika */

int address_count;
HIP_HASHTABLE *addresses;
time_t load_time;

char *hip_i3_config_file = NULL;
int hip_use_i3 = 0; // false

/*Define hip_use_userspace_ipsec variable to indicate whether use 
 * userspace ipsec or not. If it is 1, hip uses the user space ipsec.
 * It will not use if hip_use_userspace_ipsec = 0. Added By Tao Wan
 */
int hip_use_userspace_ipsec = 0;


#ifdef CONFIG_HIP_OPPTCP
int hip_use_opptcp = 0; // false

void hip_set_opportunistic_tcp_status(int newVal)

{
        if((newVal == 0) || (newVal == 1))
                hip_use_opptcp = newVal;
	else	
        	hip_use_opptcp = 0; /*default to 0 in case of error*/
}

int hip_get_opportunistic_tcp_status()
{
        return hip_use_opptcp;
}
#endif

void usage() {
	fprintf(stderr, "HIPL Daemon %.2f\n", HIPL_VERSION);
        fprintf(stderr, "Usage: hipd [options]\n\n");
	fprintf(stderr, "  -b run in background\n");
#ifdef CONFIG_HIP_HI3
	fprintf(stderr, "  -3 <i3 client configuration file>\n");
#endif
	fprintf(stderr, "\n");
}

int hip_send_agent(struct hip_common *msg) {
        struct sockaddr_in6 hip_agent_addr;
        int alen;

        memset(&hip_agent_addr, 0, sizeof(hip_agent_addr));
        hip_agent_addr.sin6_family = AF_INET6;
        hip_agent_addr.sin6_addr = in6addr_loopback;
        hip_agent_addr.sin6_port = htons(HIP_AGENT_PORT);

        alen = sizeof(hip_agent_addr);

        return sendto(hip_user_sock, msg, hip_get_msg_total_len(msg), 0,
                       (struct sockaddr *)&hip_agent_addr, alen);
}

/**
 * Receive message from agent socket.
 */
int hip_recv_agent(struct hip_common *msg)
{
	int n, err = 0;
	socklen_t alen;
	hip_hdr_type_t msg_type;
	hip_opp_block_t *entry;
	
	HIP_DEBUG("Received a message from agent\n");

	msg_type = hip_get_msg_type(msg);
	
	if (msg_type == SO_HIP_AGENT_PING)
	{
		memset(msg, 0, HIP_MAX_PACKET);
		hip_build_user_hdr(msg, SO_HIP_AGENT_PING_REPLY, 0);
		n = hip_send_agent(msg);
		HIP_IFEL(n < 0, 0, "sendto() failed on agent socket\n");

		if (err == 0)
		{
			HIP_DEBUG("HIP agent ok.\n");
			if (hip_agent_status == 0)
			{
				hip_agent_status = 1;
				hip_agent_update();
			}
			hip_agent_status = 1;
		}
	}
	else if (msg_type == SO_HIP_AGENT_QUIT)
	{
		HIP_DEBUG("Agent quit.\n");
		hip_agent_status = 0;
	}
	else if (msg_type == HIP_R1 || msg_type == HIP_I1)
	{
		struct hip_common *emsg;
		struct in6_addr *src_addr, *dst_addr;
		hip_portpair_t *msg_info;
		void *reject;

		emsg = hip_get_param_contents(msg, HIP_PARAM_ENCAPS_MSG);
		src_addr = hip_get_param_contents(msg, HIP_PARAM_SRC_ADDR);
		dst_addr = hip_get_param_contents(msg, HIP_PARAM_DST_ADDR);
		msg_info = hip_get_param_contents(msg, HIP_PARAM_PORTPAIR);
		reject = hip_get_param(msg, HIP_PARAM_AGENT_REJECT);

		if (emsg && src_addr && dst_addr && msg_info && !reject)
		{
			HIP_DEBUG("Received accepted I1/R1 packet from agent.\n");
			hip_receive_control_packet(emsg, src_addr, dst_addr, msg_info, 0);
		}
		else if (emsg && src_addr && dst_addr && msg_info)
		{
#ifdef CONFIG_HIP_OPPORTUNISTIC

			HIP_DEBUG("Received rejected R1 packet from agent.\n");
			err = hip_for_each_opp(hip_handle_opp_reject, src_addr);
			HIP_IFEL(err, 0, "for_each_ha err.\n");
#endif
		}
	}
	
out_err:
	return err;
}


/**
 * Daemon main function.
 */
int hipd_main(int argc, char *argv[])
{
	int ch, killold = 0;
	//	char buff[HIP_MAX_NETLINK_PACKET];
	fd_set read_fdset;
        fd_set write_fdset;
	int foreground = 1, highest_descriptor = 0, s_net, err = 0;
	struct timeval timeout;
	struct hip_work_order ping;

	struct msghdr sock_msg;
        /* The flushing is enabled by default. The reason for this is that
	   people are doing some very experimental features on some branches
	   that may crash the daemon and leave the SAs floating around to
	   disturb further base exchanges. Use -N flag to disable this. */
	int flush_ipsec = 1;

	/* Parse command-line options */
	while ((ch = getopt(argc, argv, ":bk3:")) != -1)
	{		
		switch (ch)
		{
		case 'b':
			foreground = 0;
			break;
		case 'k':
			killold = 1;
			break;
#ifdef CONFIG_HIP_HI3
		case '3':
		  HIP_INFO("hipd is stared with i3 config file: %s", optarg);
			hip_i3_config_file = strdup(optarg);
			hip_use_i3 = 1; // true;
			break;
#endif
		case 'N':
			flush_ipsec = 0;
			break;
		case '?':
		case 'h':
		default:
			usage();
			return err;
		}
	}

#ifdef CONFIG_HIP_HI3
        /* Note that for now the Hi3 host identities are not loaded in. */
	if( hip_use_i3 )
		HIP_IFEL(!hip_i3_config_file, 1,
		"Please do pass a valid i3 configuration file.\n");
#endif
	
	hip_set_logfmt(LOGFMT_LONG);

	/* Configuration is valid! Fork a daemon, if so configured */
	if (foreground)
	{
		hip_set_logtype(LOGTYPE_STDERR);
		HIP_DEBUG("foreground\n");
	}
	else
	{
		hip_set_logtype(LOGTYPE_SYSLOG);
		if (fork() > 0)
			return(0);
	}

	HIP_INFO("hipd pid=%d starting\n", getpid());
	time(&load_time);
	
	/* Default initialization function. */
	HIP_IFEL(hipd_init(flush_ipsec, killold), 1, "hipd_init() failed!\n");

	highest_descriptor = maxof(8, hip_nl_route.fd, hip_raw_sock_v6,
				   hip_user_sock, hip_nl_ipsec.fd,
				   hip_raw_sock_v4, hip_nat_sock_udp,
				   hip_opendht_sock_fqdn, hip_opendht_sock_hit);

	/* Allocate user message. */
	HIP_IFE(!(hipd_msg = hip_msg_alloc()), 1);
        HIP_IFE(!(hipd_msg_v4 = hip_msg_alloc()), 1);
	HIP_DEBUG("Daemon running. Entering select loop.\n");
	/* Enter to the select-loop */
	HIP_DEBUG_GL(HIP_DEBUG_GROUP_INIT, 
		     HIP_DEBUG_LEVEL_INFORMATIVE,
		     "Hipd daemon running.\n"
		     "Starting select loop.\n");
	hipd_set_state(HIPD_STATE_EXEC);
	while (hipd_get_state() != HIPD_STATE_CLOSED)
	{
		/* prepare file descriptor sets */
                if (hip_opendht_inuse == SO_HIP_DHT_ON) {
                        FD_ZERO(&write_fdset);
                        if (hip_opendht_fqdn_sent == STATE_OPENDHT_WAITING_CONNECT)
                                FD_SET(hip_opendht_sock_fqdn, &write_fdset);
                        if (hip_opendht_hit_sent == STATE_OPENDHT_WAITING_CONNECT)
                                FD_SET(hip_opendht_sock_hit, &write_fdset);
                }
		FD_ZERO(&read_fdset);
		FD_SET(hip_nl_route.fd, &read_fdset);
		FD_SET(hip_raw_sock_v6, &read_fdset);
		FD_SET(hip_raw_sock_v4, &read_fdset);
		FD_SET(hip_nat_sock_udp, &read_fdset);
		FD_SET(hip_user_sock, &read_fdset);
		FD_SET(hip_nl_ipsec.fd, &read_fdset);
		/* FD_SET(hip_firewall_sock, &read_fdset); */
		if (hip_opendht_fqdn_sent == STATE_OPENDHT_WAITING_ANSWER)
			FD_SET(hip_opendht_sock_fqdn, &read_fdset);
		if (hip_opendht_hit_sent == STATE_OPENDHT_WAITING_ANSWER)
			FD_SET(hip_opendht_sock_hit, &read_fdset);

		timeout.tv_sec = HIP_SELECT_TIMEOUT;
		timeout.tv_usec = 0;
		
		_HIP_DEBUG("select loop\n");
		/* wait for socket activity */

                /* If DHT is on have to use write sets for asynchronic communication */
                if (hip_opendht_inuse == SO_HIP_DHT_ON) {
                        if ((err = HIPD_SELECT((highest_descriptor + 1), &read_fdset, 
                                               &write_fdset, NULL, &timeout)) < 0) {
			HIP_ERROR("select() error: %s.\n", strerror(errno));
			goto to_maintenance;
                        } else if (err == 0) {
                                /* idle cycle - select() timeout */
                                _HIP_DEBUG("Idle.\n");
                                goto to_maintenance;
                        } 
                } else {
                        if ((err = HIPD_SELECT((highest_descriptor + 1), &read_fdset, 
                                               NULL, NULL, &timeout)) < 0) {
                                HIP_ERROR("select() error: %s.\n", strerror(errno));
                                goto to_maintenance;
                        } else if (err == 0) {
                                /* idle cycle - select() timeout */
                                _HIP_DEBUG("Idle.\n");
                                goto to_maintenance;
                        } 
                }

                /* see bugzilla bug id 392 to see why */
                if (FD_ISSET(hip_raw_sock_v6, &read_fdset) && 
                    FD_ISSET(hip_raw_sock_v4, &read_fdset)) {
                    int type, err_v6 = 0, err_v4 = 0;
                    struct in6_addr saddr, daddr;
                    struct in6_addr saddr_v4, daddr_v4;
                    hip_portpair_t pkt_info; 
                    HIP_DEBUG("Receiving messages on raw HIP from IPv6/HIP and IPv4/HIP\n");
                    hip_msg_init(hipd_msg);
                    hip_msg_init(hipd_msg_v4);
                    err_v4 = hip_read_control_msg_v4(hip_raw_sock_v4, hipd_msg_v4,
                                                     &saddr_v4, &daddr_v4, 
                                                     &pkt_info, IPV4_HDR_SIZE);
                    err_v6 = hip_read_control_msg_v6(hip_raw_sock_v6, hipd_msg,
                                                     &saddr, &daddr, &pkt_info, 0);
                    if (err_v4 > -1) {
                        type = hip_get_msg_type(hipd_msg_v4);
                        if (type == HIP_R2) {
				err = hip_receive_control_packet(hipd_msg_v4, &saddr_v4, 
                                                             &daddr_v4, &pkt_info, 1);
                            if (err) HIP_ERROR("hip_receive_control_packet()!\n");
                            err = hip_receive_control_packet(hipd_msg, &saddr, &daddr, 
                                                             &pkt_info, 1);
                            if (err) HIP_ERROR("hip_receive_control_packet()!\n");
                        } else {
                            err = hip_receive_control_packet(hipd_msg, &saddr, &daddr, 
                                                             &pkt_info, 1);
                            if (err) HIP_ERROR("hip_receive_control_packet()!\n");
                            err = hip_receive_control_packet(hipd_msg_v4, &saddr_v4, 
                                                             &daddr_v4, &pkt_info, 1);
                            if (err) HIP_ERROR("hip_receive_control_packet()!\n");
                        }
                    }
                } else {
                    if (FD_ISSET(hip_raw_sock_v6, &read_fdset)) {
                        /* Receiving of a raw HIP message from IPv6 socket. */
			struct in6_addr saddr, daddr;
			hip_portpair_t pkt_info;                        
			HIP_DEBUG("Receiving a message on raw HIP from "\
				  "IPv6/HIP socket (file descriptor: %d).\n",
				  hip_raw_sock_v6);
			hip_msg_init(hipd_msg);
			if (hip_read_control_msg_v6(hip_raw_sock_v6, hipd_msg,
			                            &saddr, &daddr, &pkt_info, 0)) {
                            HIP_ERROR("Reading network msg failed\n");
			} else { 
                            err = hip_receive_control_packet(hipd_msg, &saddr, &daddr, &pkt_info, 1);
                            if (err) HIP_ERROR("hip_receive_control_packet()!\n");
			} 
                    }
                    
                    if (FD_ISSET(hip_raw_sock_v4, &read_fdset)){
			/* Receiving of a raw HIP message from IPv4 socket. */
			struct in6_addr saddr, daddr;
			hip_portpair_t pkt_info;
			HIP_DEBUG("Receiving a message on raw HIP from "\
				  "IPv4/HIP socket (file descriptor: %d).\n",
				  hip_raw_sock_v4);
			hip_msg_init(hipd_msg);
			HIP_DEBUG("Getting a msg on v4\n");
			/* Assuming that IPv4 header does not include any
			   options */
			if (hip_read_control_msg_v4(hip_raw_sock_v4, hipd_msg,
			                            &saddr, &daddr, &pkt_info, IPV4_HDR_SIZE)) {
                            HIP_ERROR("Reading network msg failed\n");
			} else {
                            err = hip_receive_control_packet(hipd_msg, &saddr, &daddr, &pkt_info, 1);
                            if (err) HIP_ERROR("hip_receive_control_packet()!\n");
			}
                        
                    }
                }

		if (FD_ISSET(hip_nat_sock_udp, &read_fdset))
		{
			/* Data structures for storing the source and
			   destination addresses and ports of the incoming
			   packet. */
			struct in6_addr saddr, daddr;
			hip_portpair_t pkt_info;

			/* Receiving of a UDP message from NAT socket. */
			HIP_DEBUG("Receiving a message on UDP from NAT "\
				  "socket (file descriptor: %d).\n",
				  hip_nat_sock_udp);
			
			/* Initialization of the hip_common header struct. We'll
			   store the HIP header data here. */
			hip_msg_init(hipd_msg);
			
			/* Read in the values to hip_msg, saddr, daddr and
			   pkt_info. */
        		if (hip_read_control_msg_stun(hip_nat_sock_udp, hipd_msg,
						    &saddr, &daddr,
						    &pkt_info, HIP_UDP_ZERO_BYTES_LEN), &hip_external_ice_receive_pkt)) {
        		/* if ( hip_read_control_msg_v4(hip_nat_sock_udp, hipd_msg,&saddr, &daddr,&pkt_info, HIP_UDP_ZERO_BYTES_LEN) ) */
			if (err) 			
			{
                                HIP_ERROR("Reading network msg failed\n");
				/* If the values were read in succesfully, we
				   do the UDP specific stuff next. */
                                //hip_external_ice_receive_pkt(hipd_msg+1,hipd_msg->payload_len,&saddr,pkt_info.src_port);
                        } else {
				err =  hip_receive_udp_control_packet(
					hipd_msg, &saddr, &daddr, &pkt_info);
                        }

		}

		if (FD_ISSET(hip_user_sock, &read_fdset))
		{
			/* Receiving of a message from user socket. */
			struct sockaddr_storage app_src;
			HIP_DEBUG("Receiving user message.\n");
			hip_msg_init(hipd_msg);

			HIP_DEBUG("Receiving a message from user socket "\
				  "(file descriptor: %d).\n",
				  hip_user_sock);

			if (hip_read_user_control_msg(hip_user_sock, hipd_msg, &app_src,&hip_external_ice_receive_pkt))
				HIP_ERROR("Reading user msg failed\n");
			}
			else { 
				err = hip_handle_user_msg(hipd_msg, &app_src);
			}
		}
                /* DHT SOCKETS HANDLING */
                if (hip_opendht_inuse == SO_HIP_DHT_ON && hip_opendht_sock_fqdn != -1) {
                        if (FD_ISSET(hip_opendht_sock_fqdn, &read_fdset) &&
                            FD_ISSET(hip_opendht_sock_fqdn, &write_fdset) &&
                            (hip_opendht_inuse == SO_HIP_DHT_ON)) {
                                /* Error with the connect */
                                HIP_ERROR("Error OpenDHT socket is readable and writable\n");
                        } else if (FD_ISSET(hip_opendht_sock_fqdn, &write_fdset)) {
                                hip_opendht_fqdn_sent = STATE_OPENDHT_START_SEND; 
                        }
                        if (FD_ISSET(hip_opendht_sock_fqdn, &read_fdset) &&
                            (hip_opendht_inuse == SO_HIP_DHT_ON)) {
                                /* Receive answer from openDHT FQDN->HIT mapping */
                                if (hip_opendht_fqdn_sent == STATE_OPENDHT_WAITING_ANSWER) {
                                        memset(opendht_response, '\0', sizeof(opendht_response));
                                        opendht_error = opendht_read_response(hip_opendht_sock_fqdn, 
                                                                              opendht_response); 
                                        if (opendht_error == -1) {
                                                HIP_DEBUG("Put was unsuccesfull (FQDN->HIT)\n");
                                                hip_opendht_error_count++;
                                                HIP_DEBUG("DHT error count now %d/%d.\n", 
                                                          hip_opendht_error_count, OPENDHT_ERROR_COUNT_MAX);
                                        }
                                        else 
                                                HIP_DEBUG("Put was success (FQDN->HIT)\n");
                                        
                                        close(hip_opendht_sock_fqdn);
                                        hip_opendht_sock_fqdn = 0;
                                        hip_opendht_sock_fqdn = init_dht_gateway_socket(hip_opendht_sock_fqdn);
                                        hip_opendht_fqdn_sent = STATE_OPENDHT_IDLE;
                                        opendht_error = 0;
                                }
                        } 
                        if (FD_ISSET(hip_opendht_sock_hit, &read_fdset) &&
                            FD_ISSET(hip_opendht_sock_hit, &write_fdset) && 
                            (hip_opendht_inuse == SO_HIP_DHT_ON)) {
                                /* Error with the connect */
                                HIP_ERROR("Error OpenDHT socket is readable and writable\n");
                        } else if (FD_ISSET(hip_opendht_sock_hit, &write_fdset)) {
                                hip_opendht_hit_sent = STATE_OPENDHT_START_SEND;
                        }
                        if ((FD_ISSET(hip_opendht_sock_hit, &read_fdset)) && 
                            (hip_opendht_inuse == SO_HIP_DHT_ON)) {
                                /* Receive answer from openDHT HIT->IP mapping */
                                if (hip_opendht_hit_sent == STATE_OPENDHT_WAITING_ANSWER) {
                                        memset(opendht_response, '\0', sizeof(opendht_response));
                                        opendht_error = opendht_read_response(hip_opendht_sock_hit, 
                                                                              opendht_response); 
                                        if (opendht_error == -1) {
                                                HIP_DEBUG("Put was unsuccesfull (HIT->IP)\n");
                                                hip_opendht_error_count++;
                                                HIP_DEBUG("DHT error count now %d/%d.\n", 
                                                          hip_opendht_error_count, OPENDHT_ERROR_COUNT_MAX);
                                        }
                                        else 
                                                HIP_DEBUG("Put was success (HIT->IP)\n");
                                        close(hip_opendht_sock_hit);
                                        hip_opendht_sock_hit = 0;
                                        hip_opendht_sock_hit = init_dht_gateway_socket(hip_opendht_sock_hit);
                                        hip_opendht_hit_sent = STATE_OPENDHT_IDLE;
                                        opendht_error= 0;
                                }
                        }
                }
                /* END DHT SOCKETS HANDLING */
 
		if (FD_ISSET(hip_nl_ipsec.fd, &read_fdset))
		{
			/* Something on IF and address event netlink socket,
			   fetch it. */
			HIP_DEBUG("netlink receive\n");
			if (hip_netlink_receive(&hip_nl_ipsec,
						hip_netdev_event, NULL))
				HIP_ERROR("Netlink receiving failed\n");
		}
 
		if (FD_ISSET(hip_nl_route.fd, &read_fdset))
		{
			/* Something on IF and address event netlink socket,
			   fetch it. */
			HIP_DEBUG("netlink route receive\n");
			if (hip_netlink_receive(&hip_nl_route,
						hip_netdev_event, NULL))
				HIP_ERROR("Netlink receiving failed\n");
		} 

to_maintenance:
		err = periodic_maintenance();
		if (err)
		{
			HIP_ERROR("Error (%d) ignoring. %s\n", err,
				  ((errno) ? strerror(errno) : ""));
			err = 0;
		}
	}

out_err:
	/* free allocated resources */
	hip_exit(err);

	HIP_INFO("hipd pid=%d exiting, retval=%d\n", getpid(), err);

	return err;
}


int main(int argc, char *argv[])
{
	int err = 0;
	uid_t euid;

	euid = geteuid();
	HIP_IFEL((euid != 0), -1, "hipd must be started as root\n");

	HIP_IFE(hipd_main(argc, argv), -1);
	if (hipd_get_flag(HIPD_FLAG_RESTART))
	{
		HIP_INFO(" !!!!! HIP DAEMON RESTARTING !!!!! \n");
		hip_handle_exec_application(0, EXEC_LOADLIB_NONE, argc, argv);
	}
	
out_err:
	return err;
}

