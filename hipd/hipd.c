/** @file
 * The HIPL main file containing the daemon main loop.
 *
 * @date 28.01.2008
 * @note Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @note HIPU: libm.a is not availble on OS X. The functions are present in libSystem.dyld, though
 * @note HIPU: lcap is used by HIPD. It needs to be changed to generic posix functions.
 */
#include "hipd.h"

/* Defined as a global just to allow freeing in exit(). Do not use outside
 * of this file!
 */
struct hip_common *hipd_msg = NULL;
struct hip_common *hipd_msg_v4 = NULL;

int is_active_handover = 1;  /**< Which handover to use active or lazy? */

/** Suppress advertising of none, AF_INET or AF_INET6 address in UPDATEs.
 *  0 = none = default, AF_INET, AF_INET6
 */
int suppress_af_family = 0;

/* For sending HIP control messages */
int hip_raw_sock_output_v6 = 0;
int hip_raw_sock_output_v4 = 0;

/* For receiving HIP control messages */
int hip_raw_sock_input_v6 = 0;
int hip_raw_sock_input_v4 = 0;

/** File descriptor of the socket used for sending HIP control packet 
 *  NAT traversal on UDP/IPv4 
 */
int hip_nat_sock_output_udp = 0;

/** File descriptor of the socket used for receiving HIP control packet 
 *  NAT traversal on UDP/IPv4 
 */
int hip_nat_sock_input_udp = 0;

int hip_nat_sock_output_udp_v6 =0;
int hip_nat_sock_input_udp_v6 = 0;

/** Specifies the NAT status of the daemon. This value indicates if the current
    machine is behind a NAT. */
hip_transform_suite_t hip_nat_status = 0;

/** ICMPv6 socket and the interval 0 for interval means off **/
int hip_icmp_sock = 0;
int hip_icmp_interval = HIP_NAT_KEEP_ALIVE_INTERVAL;

/* Encrypt host id in I2 */
int hip_encrypt_i2_hi = 0;

/* Communication interface to userspace apps (hipconf etc) */
int hip_user_sock = 0;
struct sockaddr_un hip_user_addr;

/** For receiving netlink IPsec events (acquire, expire, etc) */
struct rtnl_handle hip_nl_ipsec  = { 0 };

/** For getting/setting routes and adding HITs (it was not possible to use
    nf_ipsec for this purpose). */
struct rtnl_handle hip_nl_route = { 0 };

struct sockaddr_in6 hip_firewall_addr;
int hip_firewall_sock = 0;

/* used to change the transform order see hipconf usage to see the usage
   This is set to AES, 3DES, NULL by default see hipconf trasform order for
   more information.
*/
int hip_transform_order = 123;

/* Create /etc/hip stuff and exit (used for binary hipfw packaging) */
int create_configs_and_exit = 0;

/* We are caching the IP addresses of the host here. The reason is that during
   in hip_handle_acquire it is not possible to call getifaddrs (it creates
   a new netlink socket and seems like only one can be open per process).
   Feel free to experiment by porting the required functionality from
   iproute2/ip/ipaddrs.c:ipaddr_list_or_flush(). It would make these global
   variable and most of the functions referencing them unnecessary -miika */

int address_count;
HIP_HASHTABLE *addresses;
time_t load_time;

/*Define hip_use_userspace_ipsec variable to indicate whether use
 * userspace ipsec or not. If it is 1, hip uses the user space ipsec.
 * It will not use if hip_use_userspace_ipsec = 0. Added By Tao Wan
 */
int hip_use_userspace_ipsec = 0;
int hip_use_userspace_data_packet_mode = 0 ;   //Prabhu  Data Packet mode supprt
int esp_prot_num_transforms = 0;
uint8_t esp_prot_transforms[NUM_TRANSFORMS];
int esp_prot_num_parallel_hchains = 0;

void usage() {
  //	fprintf(stderr, "HIPL Daemon %.2f\n", HIPL_VERSION);
	fprintf(stderr, "Usage: hipd [options]\n\n");
	fprintf(stderr, "  -b run in background\n");
	fprintf(stderr, "  -i <device name> add interface to the white list. Use additional -i for additional devices.\n");
	fprintf(stderr, "  -k kill existing hipd\n");
	fprintf(stderr, "  -N do not flush ipsec rules on exit\n");
	fprintf(stderr, "  -a fix alignment issues automatically(ARM)\n");
	fprintf(stderr, "\n");
}

int hip_sendto_firewall(const struct hip_common *msg){
#ifdef CONFIG_HIP_FIREWALL
	int n = 0;
	HIP_DEBUG("CONFIG_HIP_FIREWALL DEFINED AND STATUS IS %d\n", hip_get_firewall_status());
	struct sockaddr_in6 hip_firewall_addr;
	socklen_t alen = sizeof(hip_firewall_addr);

	bzero(&hip_firewall_addr, alen);
	hip_firewall_addr.sin6_family = AF_INET6;
	hip_firewall_addr.sin6_port = htons(HIP_FIREWALL_PORT);
	hip_firewall_addr.sin6_addr = in6addr_loopback;

	if (hip_get_firewall_status()) {
		n = sendto( hip_firewall_sock,
					msg,
					hip_get_msg_total_len(msg),
					0,
					&hip_firewall_addr, alen);
		return n;
	}
#else
	HIP_DEBUG("Firewall is disabled.\n");
	return 0;
#endif // CONFIG_HIP_FIREWALL
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

	struct msghdr sock_msg;
	/*  The flushing is enabled by default. The reason for this is that
		people are doing some very experimental features on some branches
		that may crash the daemon and leave the SAs floating around to
		disturb further base exchanges. Use -N flag to disable this. */
	int flush_ipsec = 1;

	int cc = 0, polling = 0;
	struct msghdr msg;

	/* Parse command-line options */
	while ((ch = getopt(argc, argv, ":bi:kNcha")) != -1)
	{
		switch (ch)
		{
		case 'b':
			foreground = 0;
			break;
		case 'i':
			if (hip_netdev_white_list_add(optarg)) {
				HIP_INFO("Successfully added device <%s> to white list.\n",
						 optarg);
			} else {
				/* Debug message is not correct: interface name looks strange */
				HIP_DIE("Error adding device <%s> to white list. Dying...\n",
						optarg);
			}
			break;
		case 'k':
			killold = 1;
			break;
		case 'N':
			flush_ipsec = 0;
			break;
		case 'c':
			create_configs_and_exit = 1;
			break;
		/* Explain why... */
#ifdef ANDROID_CHANGES
		case 'a':
			system("echo 3 > /proc/cpu/alignment");
			HIP_DEBUG("Setting alignment traps to 3(fix+ warn)\n");
			break;
#endif /* ANDROID_CHANGES */
		case '?':
		case 'h':
		default:
			usage();
			return err;
		}
	}

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

#ifdef HIP_CONFIG_TINY
	HIP_DEBUG("tiny HIP\n");
#endif

	HIP_INFO("hipd pid=%d starting\n", getpid());
	time(&load_time);
	
	HIP_IFEL(hipd_init(flush_ipsec, killold), 1, "hipd_init() failed!\n");

	HIP_IFEL(create_configs_and_exit, 0, "Configs created, exiting\n");

	highest_descriptor = maxof( 7,
								hip_nl_route.fd,
								hip_raw_sock_input_v6,
								hip_user_sock,
								hip_nl_ipsec.fd,
								hip_raw_sock_input_v4,
								hip_nat_sock_input_udp,
								hip_icmp_sock);

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

	while (hipd_get_state() != HIPD_STATE_CLOSED) {
		/* prepare file descriptor sets */
		FD_ZERO(&read_fdset);
		FD_SET(hip_nl_route.fd, &read_fdset);
		FD_SET(hip_raw_sock_input_v6, &read_fdset);
		FD_SET(hip_raw_sock_input_v4, &read_fdset);
		FD_SET(hip_nat_sock_input_udp, &read_fdset);
		FD_SET(hip_user_sock, &read_fdset);
		FD_SET(hip_nl_ipsec.fd, &read_fdset);
		FD_SET(hip_icmp_sock, &read_fdset);
		/* FD_SET(hip_firewall_sock, &read_fdset); */
		hip_firewall_sock = hip_user_sock;

		timeout.tv_sec = HIP_SELECT_TIMEOUT;
		timeout.tv_usec = 0;

		//HIP_DEBUG("select loop value hip_raw_socket_v4 = %d \n",hip_raw_sock_v4);
		/* wait for socket activity */
	
		err = select((highest_descriptor + 1),
					 &read_fdset,
					 NULL,
					 NULL,
					 &timeout);

		if (err < 0) {
			HIP_ERROR("select() error: %s.\n", strerror(errno));
			goto to_maintenance;
		} else if (err == 0) {
			/* idle cycle - select() timeout */
			_HIP_DEBUG("Idle.\n");
			goto to_maintenance;
		}

		/* see bugzilla bug id 392 to see why */
		if (FD_ISSET(hip_raw_sock_input_v6, &read_fdset) &&
			FD_ISSET(hip_raw_sock_input_v4, &read_fdset)) {

			int type, err_v6 = 0, err_v4 = 0;
			struct in6_addr saddr, daddr;
			struct in6_addr saddr_v4, daddr_v4;
			hip_portpair_t pkt_info;
			HIP_DEBUG("Receiving messages on raw HIP from IPv6/HIP and IPv4/HIP\n");

			hip_msg_init(hipd_msg);
			hip_msg_init(hipd_msg_v4);

			err_v4 = hip_read_control_msg_v4(hip_raw_sock_input_v4, hipd_msg_v4,
											 &saddr_v4, &daddr_v4,
											 &pkt_info, IPV4_HDR_SIZE);
			err_v6 = hip_read_control_msg_v6(hip_raw_sock_input_v6, hipd_msg,
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
			if (FD_ISSET(hip_raw_sock_input_v6, &read_fdset)) {
				/* Receiving of a raw HIP message from IPv6 socket. */
				struct in6_addr saddr, daddr;
				hip_portpair_t pkt_info;
				HIP_DEBUG("Receiving a message on raw HIP from "\
					  "IPv6/HIP socket (file descriptor: %d).\n",
					  hip_raw_sock_input_v6);
				hip_msg_init(hipd_msg);
				if (hip_read_control_msg_v6(hip_raw_sock_input_v6, hipd_msg,
										&saddr, &daddr, &pkt_info, 0)) {
					HIP_ERROR("Reading network msg failed\n");
				} else {
					err = hip_receive_control_packet(hipd_msg, &saddr, &daddr, &pkt_info, 1);
					if (err)
						HIP_ERROR("hip_receive_control_packet()!\n");
				}
			}

			if (FD_ISSET(hip_raw_sock_input_v4, &read_fdset)) {
				HIP_DEBUG("HIP RAW SOCKET\n");
				/* Receiving of a raw HIP message from IPv4 socket. */
				struct in6_addr saddr, daddr;
				hip_portpair_t pkt_info;
				HIP_DEBUG("Receiving a message on raw HIP from "\
					  "IPv4/HIP socket (file descriptor: %d).\n",
					  hip_raw_sock_input_v4);
				hip_msg_init(hipd_msg);
				HIP_DEBUG("Getting a msg on v4\n");
				/* Assuming that IPv4 header does not include any
				   options */
				if (hip_read_control_msg_v4(hip_raw_sock_input_v4, hipd_msg,
								&saddr, &daddr, &pkt_info, IPV4_HDR_SIZE)) {
					HIP_ERROR("Reading network msg failed\n");
				} else {
					err = hip_receive_control_packet(hipd_msg, &saddr, &daddr, &pkt_info, 1);
					if (err)
						HIP_ERROR("hip_receive_control_packet()!\n");
				}
			}
		}

		if (FD_ISSET(hip_icmp_sock, &read_fdset)) {
			HIP_IFEL(hip_icmp_recvmsg(hip_icmp_sock),
					 -1,
					 "Failed to recvmsg from ICMPv6\n");
		}

		if (FD_ISSET(hip_nat_sock_input_udp, &read_fdset)) {
			/* Data structures for storing the source and
			   destination addresses and ports of the incoming
			   packet. */
			struct in6_addr saddr, daddr;
			hip_portpair_t pkt_info;

			/* Receiving of a UDP message from NAT socket. */
			HIP_DEBUG("Receiving a message on UDP from NAT "\
					  "socket (file descriptor: %d).\n",
					  hip_nat_sock_input_udp);

			/* Initialization of the hip_common header struct. We'll
			   store the HIP header data here. */
			hip_msg_init(hipd_msg);

			/* Read in the values to hip_msg, saddr, daddr and
			   pkt_info. */
			/* if ( hip_read_control_msg_v4(hip_nat_sock_udp, hipd_msg,&saddr, &daddr,&pkt_info, 0) ) */
			err = hip_read_control_msg_v4(hip_nat_sock_input_udp, hipd_msg,&saddr, &daddr,&pkt_info, HIP_UDP_ZERO_BYTES_LEN);
			if (err) {
				HIP_ERROR("Reading network msg failed\n");
				/* If the values were read in succesfully, we
				   do the UDP specific stuff next. */
			} else {
				err =  hip_receive_udp_control_packet(hipd_msg, &saddr, &daddr, &pkt_info);
			}
		}

		if (FD_ISSET(hip_user_sock, &read_fdset)) {
			/* Receiving of a message from user socket. */
			struct sockaddr_storage app_src;

			HIP_DEBUG("Receiving user message.\n");

			hip_msg_init(hipd_msg);
			
			if (hip_read_user_control_msg(hip_user_sock, hipd_msg, &app_src)) {
				HIP_ERROR("Reading user msg failed\n");
			} else {
				err = hip_handle_user_msg(hipd_msg, &app_src);
			}
		}

		if (FD_ISSET(hip_nl_ipsec.fd, &read_fdset)) {
			/* Something on IF and address event netlink socket,
			   fetch it. */
			HIP_DEBUG("netlink receive\n");
			if (hip_netlink_receive(&hip_nl_ipsec,
						hip_netdev_event, NULL))
				HIP_ERROR("Netlink receiving failed\n");
		}

		if (FD_ISSET(hip_nl_route.fd, &read_fdset)) {
			/* Something on IF and address event netlink socket,
			   fetch it. */
			HIP_DEBUG("netlink route receive\n");
			if (hip_netlink_receive(&hip_nl_route,
						hip_netdev_event, NULL))
				HIP_ERROR("Netlink receiving failed\n");
		}

to_maintenance:
		err = periodic_maintenance();
		if (err) {
			HIP_ERROR("Error (%d) ignoring. %s\n", err, ((errno) ? strerror(errno) : ""));
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
	/* We need to recreate the NAT UDP sockets to bind to the new port. */
	HIP_IFEL((euid != 0), -1, "hipd must be started as root\n");

	HIP_IFE(hipd_main(argc, argv), -1);
	if (hipd_get_flag(HIPD_FLAG_RESTART)) {
		HIP_INFO(" !!!!! HIP DAEMON RESTARTING !!!!! \n");
		hip_handle_exec_application(0, EXEC_LOADLIB_NONE, argc, argv);
	}

out_err:
	return err;
}

