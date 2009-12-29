/** @file
 * HIP Firewall
 *
 * @note: This code is GNU/GPL.
 * @note: HIPU: requires libipq, might need pcap libraries
 */

#include <limits.h> /* INT_MIN, INT_MAX */
#include <netinet/in.h> /* in_addr, in6_addr */
#include <linux/netfilter_ipv4.h> /* NF_IP_LOCAL_IN, etc */

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "firewall.h" /* default include */
#include "proxy.h" /* HIP Proxy */
#include "opptcp.h" /* Opportunistic TCP */
// TODO move functions to opptcp
#include "cache.h" /* required by opptcp */
#include "cache_port.h" /* required by opptcp */
#include "lsi.h" /* LSI */
#include "libhipcore/hip_capability.h" /* Priviledge Separation */
#include "user_ipsec_api.h" /* Userspace IPsec */
#include "esp_prot_conntrack.h" /* ESP Tokens */
#include "sava_api.h" /* Sava */
#include "savah_gateway.h"
#include "sysopp.h" /* System-based Opportunistic HIP */
#include "datapkt.h"
#include "firewalldb.h"
#ifdef CONFIG_HIP_MIDAUTH
#include "pisa.h" /* PISA */
#endif
#ifdef CONFIG_HIP_PERFORMANCE
#include "performance/performance.h" /* Performance Analysis */
#endif
#include "helpers.h"


#include <sys/time.h>
#include <stdio.h>

/* packet types handled by the firewall */
#define OTHER_PACKET          0
#define HIP_PACKET            1
#define ESP_PACKET            2
#define TCP_PACKET            3
#define FW_PROTO_NUM          4 /* number of packet types */

/* location of the lock file */
#define HIP_FIREWALL_LOCK_FILE HIPL_LOCKDIR"/hip_firewall.lock"

/* default settings */
#define HIP_FW_FILTER_TRAFFIC_BY_DEFAULT 1
#define HIP_FW_ACCEPT_HIP_ESP_TRAFFIC_BY_DEFAULT 0
#define HIP_FW_ACCEPT_NORMAL_TRAFFIC_BY_DEFAULT 1


/* firewall-specific state */
static int foreground = 1;
static int statefulFiltering = 1;
static int accept_normal_traffic_by_default = HIP_FW_ACCEPT_NORMAL_TRAFFIC_BY_DEFAULT;
static int accept_hip_esp_traffic_by_default = HIP_FW_ACCEPT_HIP_ESP_TRAFFIC_BY_DEFAULT;
static int log_level = LOGDEBUG_NONE;
/* Default HIT - do not access this directly, call hip_fw_get_default_hit() */
static hip_hit_t default_hit;
/* Default LSI - do not access this directly, call hip_fw_get_default_lsi() */
static hip_lsi_t default_lsi;

/* definition of the function pointer (see below) */
typedef int (*hip_fw_handler_t)(hip_fw_context_t *);
/* The firewall handlers do not accept rules directly. They should return
 * zero when they transformed packet and the original should be dropped.
 * Non-zero means that there was an error or the packet handler did not
 * know what to do with the packet. */
static hip_fw_handler_t hip_fw_handler[NF_IP_NUMHOOKS][FW_PROTO_NUM];

static void system_print(char* str) {
	if( system(str) == -1 ) {
		HIP_ERROR("Could not execute system command %s", str);
	}
}

/* extension-specific state */
static int hip_userspace_ipsec = 0;
static int hip_esp_protection = 0;
static int hip_sava_router = 0;
static int hip_sava_client = 0;
static int restore_filter_traffic = HIP_FW_FILTER_TRAFFIC_BY_DEFAULT;
static int restore_accept_hip_esp_traffic = HIP_FW_ACCEPT_HIP_ESP_TRAFFIC_BY_DEFAULT;

/* externally used state */
// TODO try to decrease number of globally used variables
int filter_traffic = HIP_FW_FILTER_TRAFFIC_BY_DEFAULT;
int system_based_opp_mode = 0;
int hip_datapacket_mode = 0;
int hip_proxy_status = 0;
int hip_opptcp = 0;
int hip_kernel_ipsec_fallback = 0;
int hip_lsi_support = 0;
int esp_relay = 0;
#ifdef CONFIG_HIP_MIDAUTH
int use_midauth = 0;
#endif

/* Use this to send and receive responses to hipd. Notice that
 * firewall_control.c has a separate socket for receiving asynchronous
 * messages from hipd (i.e. messages that were not requests from hipfw).
 * The two sockets need to be kept separate because the hipfw might
 * mistake an asynchronous message from hipd to an response. The alternative
 * to two sockets are sequence numbers but it would have required reworking
 * too much of the firewall. -miika */
// TODO make accessible through send function, no-one should read on that
int hip_fw_sock = 0;
/* Use this socket *only* for receiving async messages from hipd */
// TODO make static, no-one should read on that
int hip_fw_async_sock = 0;

static void print_usage(){
	printf("HIP Firewall\n");
	printf("Usage: hipfw [-f file_name] [-d|-v] [-A] [-F] [-H] [-b] [-a] [-c] [-k] [-i|-I|-e] [-l] [-o] [-p] [-h]");
#ifdef CONFIG_HIP_MIDAUTH
	printf(" [-m]");
#endif
	printf("\n");
	printf("      -f file_name = is a path to a file containing firewall filtering rules\n");
	printf("      -d = debugging output\n");
	printf("      -v = verbose output\n");
	printf("      -A = accept all HIP traffic, still do HIP filtering (default: drop all non-authed HIP traffic)\n");
 	printf("      -F = accept all HIP traffic, deactivate HIP traffic filtering\n");
	printf("      -H = drop all non-HIP traffic (default: accept non-HIP traffic)\n");
	printf("      -b = fork the firewall to background\n");
	printf("      -k = kill running firewall pid\n");
 	printf("      -i = switch on userspace ipsec\n");
 	printf("      -I = as -i, also allow fallback to kernel ipsec when exiting hipfw\n");
 	printf("      -e = use esp protection extension (also sets -i)\n");
	printf("      -l = activate lsi support\n");
	printf("      -o = system-based opportunistic mode\n\n");
	printf("      -p = run with lowered priviledges. iptables rules will not be flushed on exit\n");
	printf("      -h = print this help\n");
#ifdef CONFIG_HIP_MIDAUTH
	printf("      -m = middlebox authentification\n");
	printf("      -w = IP address of web-based authentication server \n");
#endif
	printf("\n");
}


/*----------------INIT FUNCTIONS------------------*/

int hip_fw_init_sava_client() {
  int err = 0;
  restore_filter_traffic = filter_traffic;
  filter_traffic = 0;
  if (!hip_sava_client && !hip_sava_router) {
    hip_sava_client = 1;
    HIP_DEBUG(" hip_fw_init_sava_client() \n");
    HIP_IFEL(hip_sava_client_init_all(), -1,
	     "Error initializing SAVA client \n");
    /* IPv4 packets	*/
    system_print("iptables -I HIPFW-OUTPUT -p tcp ! -d 127.0.0.1 -j QUEUE 2>/dev/null");
    system_print("iptables -I HIPFW-OUTPUT -p udp ! -d 127.0.0.1 -j QUEUE 2>/dev/null");
    /* IPv6 packets	*/
    system_print("ip6tables -I HIPFW-OUTPUT -p tcp ! -d ::1 -j QUEUE 2>/dev/null");
    system_print("ip6tables -I HIPFW-OUTPUT -p udp ! -d ::1 -j QUEUE 2>/dev/null");
  }
out_err:
  return err;
}

int hip_fw_init_sava_router() {
        int err = 0;
 
	/* 
	 * We need to capture each and every packet 
	 * that passes trough the firewall to verify the packet's 
	 * source address
	 */
	if (!hip_sava_client && !hip_sava_router) {
	  hip_sava_router = 1;
	  filter_traffic = 1;
	  accept_hip_esp_traffic_by_default = 0;
	  if (hip_sava_router) {
	    HIP_DEBUG("Initializing SAVA client mode \n");
	    HIP_IFEL(hip_sava_init_all(), -1, 
		     "Error initializing SAVA IP DB \n");
	    
	    system("echo 1 >/proc/sys/net/ipv4/conf/all/forwarding");
	    system("echo 1 >/proc/sys/net/ipv6/conf/all/forwarding");
	    
	    system_print("iptables -I HIPFW-FORWARD -p tcp -j QUEUE 2>/dev/null"); 
	    system_print("iptables -I HIPFW-FORWARD -p udp -j QUEUE 2>/dev/null"); 
	    
	    /* IPv6 packets	*/
	    
	    system_print("ip6tables -I HIPFW-FORWARD -p tcp -j QUEUE 2>/dev/null");
	    system_print("ip6tables -I HIPFW-FORWARD -p udp -j QUEUE 2>/dev/null");
	    
	    /*	Queue HIP packets as well */
	    system_print("iptables -I HIPFW-INPUT -p 139 -j QUEUE 2>/dev/null");
	    system_print("ip6tables -I HIPFW-INPUT -p 139 -j QUEUE 2>/dev/null");
	    
	    iptables_do_command("iptables -t nat -N %s 2>/dev/null", SAVAH_PREROUTING);
	    iptables_do_command("ip6tables -N %s 2>/dev/null", SAVAH_PREROUTING);
	    
	    iptables_do_command("iptables -t nat -I PREROUTING 1 -m mark --mark %d  -j %s", FW_MARK_LOCKED, SAVAH_PREROUTING); 
	    iptables_do_command("ip6tables -I PREROUTING 1 -m mark --mark %d -j %s", FW_MARK_LOCKED, SAVAH_PREROUTING); 
	    //jump to SAVAH_PREROUTING chain if the packet was marked for FW_MARK_LOCKED
	    
	    iptables_do_command("iptables -t nat -I %s 1 -p tcp --dport 80 -j REDIRECT --to-ports 80", 
				SAVAH_PREROUTING); //this static IPs need to get mode dinamic nature
	    iptables_do_command("ip6tables -I %s 1 -p tcp --dport 80 -j REDIRECT --to-ports 80", 
				SAVAH_PREROUTING);//the same goes here
	  }
	}
 out_err:
	return err;
}

void hip_fw_uninit_sava_client() {
  filter_traffic = restore_filter_traffic;  
  if (hip_sava_client) {
    hip_sava_client = 0;
    /* IPv4 packets	*/
    system_print("iptables -D HIPFW-OUTPUT -p tcp ! -d 127.0.0.1 -j QUEUE 2>/dev/null");
    system_print("iptables -D HIPFW-OUTPUT -p udp ! -d 127.0.0.1 -j QUEUE 2>/dev/null");
    /* IPv6 packets	*/
    system_print("ip6tables -D HIPFW-OUTPUT -p tcp ! -d ::1 -j QUEUE 2>/dev/null");
    system_print("ip6tables -D HIPFW-OUTPUT -p udp ! -d ::1 -j QUEUE 2>/dev/null");
  }
}

void hip_fw_uninit_sava_router() {
  if (!hip_sava_client && !hip_sava_router) {
    hip_sava_router = 0;
    accept_hip_esp_traffic_by_default = 
      restore_accept_hip_esp_traffic;
    if (hip_sava_router) {
      HIP_DEBUG("Uninitializing SAVA server mode \n");
      /* IPv4 packets	*/
      system_print("iptables -D HIPFW-FORWARD -p tcp -j QUEUE 2>/dev/null");
      system_print("iptables -D HIPFW-FORWARD -p udp -j QUEUE 2>/dev/null");
      /* IPv6 packets	*/
      system_print("ip6tables -D HIPFW-FORWARD -p tcp -j QUEUE 2>/dev/null");
      system_print("ip6tables -D HIPFW-FORWARD -p udp -j QUEUE 2>/dev/null");
      
      /*	Stop queueing HIP packets */
      system_print("iptables -D HIPFW-INPUT -p 139 -j ACCEPT 2>/dev/null");
      system_print("ip6tables -D HIPFW-INPUT -p 139 -j ACCEPT 2>/dev/null");
      
      iptables_do_command("iptables -t nat -D PREROUTING -j %s 2>/dev/null", 
			  SAVAH_PREROUTING);
      iptables_do_command("ip6tables -D PREROUTING -j %s 2>/dev/null", 
			  SAVAH_PREROUTING);
      
      iptables_do_command("iptables -t nat -F %s 2>/dev/null", 
			  SAVAH_PREROUTING);
      iptables_do_command("ip6tables -F %s 2>/dev/null", 
			  SAVAH_PREROUTING);
      
      iptables_do_command("iptables -t nat -X %s 2>/dev/null", 
			  SAVAH_PREROUTING);
      iptables_do_command("ip6tables -X %s 2>/dev/null", 
			  SAVAH_PREROUTING);
    }
  }
  return;
}

void hip_fw_update_sava(struct hip_common * msg) {
  if (hip_sava_router || hip_sava_client)
    handle_sava_i2_state_update(msg);
}

// TODO this should be allowed to be static
int hip_fw_init_opptcp(){
	int err = 0;

	if (hip_opptcp) {
		HIP_DEBUG("\n");

		system_print("iptables -I HIPFW-INPUT -p 6 ! -d 127.0.0.1 -j QUEUE"); /* @todo: ! LSI PREFIX */ // proto 6 TCP and proto 17
		system_print("iptables -I HIPFW-OUTPUT -p 6 ! -d 127.0.0.1 -j QUEUE");  /* @todo: ! LSI PREFIX */

		system_print("ip6tables -I HIPFW-INPUT -p 6 ! -d 2001:0010::/28 -j QUEUE");
		system_print("ip6tables -I HIPFW-OUTPUT -p 6 ! -d 2001:0010::/28 -j QUEUE");
	}

	return err;
}

// TODO this should be allowed to be static
int hip_fw_uninit_opptcp(){
	int err = 0;

	if (hip_opptcp) {
		HIP_DEBUG("\n");

		system_print("iptables -D HIPFW-INPUT -p 6 ! -d 127.0.0.1 -j QUEUE 2>/dev/null");  /* @todo: ! LSI PREFIX */
		system_print("iptables -D HIPFW-OUTPUT -p 6 ! -d 127.0.0.1 -j QUEUE 2>/dev/null"); /* @todo: ! LSI PREFIX */
		system_print("ip6tables -D HIPFW-INPUT -p 6 ! -d 2001:0010::/28 -j QUEUE 2>/dev/null");
		system_print("ip6tables -D HIPFW-OUTPUT -p 6 ! -d 2001:0010::/28 -j QUEUE 2>/dev/null");
	}

	return err;
}

// TODO this should be allowed to be static
int hip_fw_init_proxy()
{
	int err = 0;

	if (hip_proxy_status) {
		system_print("iptables -I HIPFW-FORWARD -p tcp -j QUEUE");	
		system_print("iptables -I HIPFW-FORWARD -p udp -j QUEUE");

		system_print("ip6tables -I HIPFW-FORWARD -p tcp ! -d 2001:0010::/28 -j QUEUE");
		system_print("ip6tables -I HIPFW-FORWARD -p udp ! -d  2001:0010::/28 -j QUEUE");

		system_print("ip6tables -I HIPFW-INPUT -p tcp -d 2001:0010::/28 -j QUEUE");
		system_print("ip6tables -I HIPFW-INPUT -p udp -d 2001:0010::/28 -j QUEUE");

		HIP_IFEL(init_proxy(), -1, "failed to initialize proxy\n");
	}
out_err:

	return err;
}

// TODO this should be allowed to be static
int hip_fw_uninit_proxy(){
	int err = 0;

	if (hip_proxy_status) {
		hip_proxy_status = 0;

		system_print("iptables -D HIPFW-FORWARD -p 139 -j ACCEPT 2>/dev/null");
		system_print("iptables -D HIPFW-FORWARD -p 139 -j ACCEPT 2>/dev/null");

		system_print("iptables -D HIPFW-FORWARD -p tcp -j QUEUE 2>/dev/null");
		system_print("iptables -D HIPFW-FORWARD -p udp -j QUEUE 2>/dev/null");

		system_print("ip6tables -D HIPFW-FORWARD -p 139 -j ACCEPT 2>/dev/null");
		system_print("ip6tables -D HIPFW-FORWARD -p 139 -j ACCEPT 2>/dev/null");

		system_print("ip6tables -D HIPFW-FORWARD -p tcp ! -d 2001:0010::/28 -j QUEUE 2>/dev/null");
		system_print("ip6tables -D HIPFW-FORWARD -p udp ! -d  2001:0010::/28 -j QUEUE 2>/dev/null");

		system_print("ip6tables -D HIPFW-INPUT -p tcp -d 2001:0010::/28 -j QUEUE 2>/dev/null");
		system_print("ip6tables -D HIPFW-INPUT -p udp -d 2001:0010::/28 -j QUEUE 2>/dev/null");

		HIP_IFEL(uninit_proxy(), -1, "failed to uninitialize proxy\n");;
	}
out_err:
	return err;
}

static int hip_fw_init_userspace_ipsec(){
	int err = 0;
	int ver_c;
	struct utsname name;

	HIP_IFEL(uname(&name), -1, "Failed to retrieve kernel information: %s\n", strerror(err));
	ver_c = atoi(&name.release[4]);

	if (hip_userspace_ipsec)
	{
		if (ver_c >= 27)
			HIP_INFO("You are using kernel version %s. Userspace " \
			"ipsec is not necessary with version 2.6.27 or higher.\n",
			name.release);

		HIP_IFEL(userspace_ipsec_init(), -1,
				"failed to initialize userspace ipsec\n");

		// queue incoming ESP over IPv4 and IPv4 UDP encapsulated traffic
		system_print("iptables -I HIPFW-INPUT -p 50 -j QUEUE"); /*  */
		system_print("iptables -I HIPFW-INPUT -p 17 --dport 10500 -j QUEUE");
		system_print("iptables -I HIPFW-INPUT -p 17 --sport 10500 -j QUEUE");

		/* no need to queue outgoing ICMP, TCP and UDP sent to LSIs as
		 * this is handled elsewhere */

		/* queue incoming ESP over IPv6
		 *
		 * @note this is where you would want to add IPv6 UDP encapsulation */
		system_print("ip6tables -I HIPFW-INPUT -p 50 -j QUEUE");

		// queue outgoing ICMP, TCP and UDP sent to HITs
		system_print("ip6tables -I HIPFW-OUTPUT -p 58 -d 2001:0010::/28 -j QUEUE");
		system_print("ip6tables -I HIPFW-OUTPUT -p 6 -d 2001:0010::/28 -j QUEUE");
		system_print("ip6tables -I HIPFW-OUTPUT -p 1 -d 2001:0010::/28 -j QUEUE");
		system_print("ip6tables -I HIPFW-OUTPUT -p 17 -d 2001:0010::/28 -j QUEUE");
	} else if (ver_c < 27) {
		HIP_INFO("You are using kernel version %s. Userspace ipsec should" \
		" be used with versions below 2.6.27.\n", name.release);
	}

  out_err:
  	return err;
}


static int hip_fw_uninit_userspace_ipsec(){
	int err = 0;

	if (hip_userspace_ipsec)
	{
		// set global variable to off
		hip_userspace_ipsec = 0;

		HIP_IFEL(userspace_ipsec_uninit(), -1, "failed to uninit user ipsec\n");

		// delete all rules previously set up for this extension
		system_print("iptables -D HIPFW-INPUT -p 50 -j QUEUE 2>/dev/null"); /*  */
		system_print("iptables -D HIPFW-INPUT -p 17 --dport 10500 -j QUEUE 2>/dev/null");
		system_print("iptables -D HIPFW-INPUT -p 17 --sport 10500 -j QUEUE 2>/dev/null");

		system_print("ip6tables -D HIPFW-INPUT -p 50 -j QUEUE 2>/dev/null");

		system_print("ip6tables -D HIPFW-OUTPUT -p 58 -d 2001:0010::/28 -j QUEUE 2>/dev/null");
		system_print("ip6tables -D HIPFW-OUTPUT -p 6 -d 2001:0010::/28 -j QUEUE 2>/dev/null");
		system_print("ip6tables -D HIPFW-OUTPUT -p 17 -d 2001:0010::/28 -j QUEUE 2>/dev/null");
	}

  out_err:
  	return err;
}


static int hip_fw_init_esp_prot(){
	int err = 0;

	if (hip_esp_protection)
	{
		// userspace ipsec is a prerequisite for esp protection
		if (hip_userspace_ipsec)
		{
			HIP_IFEL(esp_prot_init(), -1, "failed to init esp protection\n");

		} else
		{
			HIP_ERROR("userspace ipsec needs to be turned on for this to work\n");

			err = 1;
			goto out_err;
		}
	}

  out_err:
    return err;
}

static int hip_fw_uninit_esp_prot(){
	int err = 0;

	if (hip_esp_protection)
	{
		// set global variable to off in fw
		hip_esp_protection = 0;

		HIP_IFEL(esp_prot_uninit(), -1, "failed to uninit esp protection\n");
	}

  out_err:
    return err;
}

static int hip_fw_init_esp_prot_conntrack(){
	int err = 0;

	if (filter_traffic)
	{
		HIP_IFEL(esp_prot_conntrack_init(), -1,
				"failed to init esp protection conntracking\n");
	}

  out_err:
    return err;
}

static int hip_fw_uninit_esp_prot_conntrack(){
	int err = 0;

	if (filter_traffic)
	{
		HIP_IFEL(esp_prot_conntrack_uninit(), -1,
				"failed to uninit esp protection conntracking\n");
	}

  out_err:
    return err;
}

static int hip_fw_init_lsi_support(){
	int err = 0;

	if (hip_lsi_support)
	{
		// add the rule
		system_print("iptables -I HIPFW-OUTPUT -d " HIP_FULL_LSI_STR " -j QUEUE");

		/* LSI support: incoming HIT packets, captured to decide if
		   HITs may be mapped to LSIs */
		system_print("ip6tables -I HIPFW-INPUT -d 2001:0010::/28 -j QUEUE");
	}

   	return err;
}

static int hip_fw_uninit_lsi_support() {
	int err = 0;

	if (hip_lsi_support)
	{
		// set global variable to off
		hip_lsi_support = 0;

		// remove the rule
		system_print("iptables -D HIPFW-OUTPUT -d " HIP_FULL_LSI_STR " -j QUEUE 2>/dev/null");

		system_print("ip6tables -D HIPFW-INPUT -d 2001:0010::/28 -j QUEUE 2>/dev/null");

		HIP_IFEL(uninit_lsi(), -1,
				"failed to uninit lsi extension\n");
	}

  out_err:
	return err;
}

static int hip_fw_init_system_based_opp_mode() {
	int err = 0;

	if (system_based_opp_mode)
	{
		system_print("iptables -N HIPFWOPP-INPUT");
		system_print("iptables -N HIPFWOPP-OUTPUT");

		system_print("iptables -I HIPFW-OUTPUT -d ! 127.0.0.1 -j QUEUE");
		system_print("ip6tables -I HIPFW-INPUT -d 2001:0010::/28 -j QUEUE");

		system_print("iptables -I HIPFW-INPUT -j HIPFWOPP-INPUT");
		system_print("iptables -I HIPFW-OUTPUT -j HIPFWOPP-OUTPUT");
	}

	return err;
}

static int hip_fw_uninit_system_based_opp_mode() {
	int err = 0;

	if (system_based_opp_mode)
	{
		system_based_opp_mode = 0;

		system_print("iptables -D HIPFW-INPUT -j HIPFWOPP-INPUT");
		system_print("iptables -D HIPFW-OUTPUT -j HIPFWOPP-OUTPUT");

		system_print("iptables -D HIPFW-OUTPUT -d ! 127.0.0.1 -j QUEUE");
		system_print("ip6tables -D HIPFW-INPUT -d 2001:0010::/28 -j QUEUE");

		system_print("iptables -F HIPFWOPP-INPUT");
		system_print("iptables -F HIPFWOPP-OUTPUT");
		system_print("iptables -X HIPFWOPP-INPUT");
		system_print("iptables -X HIPFWOPP-OUTPUT");
	}

	return err;
}


/*-------------------HELPER FUNCTIONS---------------------*/

/* Get default HIT and LSI */
static int hip_query_default_local_hit_from_hipd()
{
	int err = 0;
	struct hip_common *msg = NULL;
	struct hip_tlv_common *param = NULL;
	hip_hit_t *hit  = NULL;
	hip_lsi_t *lsi = NULL;

	HIP_IFE(!(msg = hip_msg_alloc()), -1);
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DEFAULT_HIT,0),-1,
		 "build user hdr\n");
	HIP_IFEL(hip_send_recv_daemon_info(msg, 0, hip_fw_sock), -1,
		 "send/recv daemon info\n");

	HIP_IFE(!(param = hip_get_param(msg, HIP_PARAM_HIT)), -1);
	hit = hip_get_param_contents_direct(param);
	ipv6_addr_copy(&default_hit, hit);

	HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_LSI)), -1,
		 "Did not find LSI\n");
	lsi = hip_get_param_contents_direct(param);
	ipv4_addr_copy(&default_lsi, lsi);

  out_err:
	if (msg)
		free(msg);

	return err;
}

static void hip_fw_flush_iptables()
{
	HIP_DEBUG("Firewall flush; may cause warnings on hipfw init\n");
	HIP_DEBUG("Deleting hipfw subchains from main chains\n");

	system_print("iptables -D INPUT -j HIPFW-INPUT 2>/dev/null");
	system_print("iptables -D OUTPUT -j HIPFW-OUTPUT 2>/dev/null");
	system_print("iptables -D FORWARD -j HIPFW-FORWARD 2>/dev/null");

	system_print("ip6tables -D INPUT -j HIPFW-INPUT 2>/dev/null");
	system_print("ip6tables -D OUTPUT -j HIPFW-OUTPUT 2>/dev/null");
	system_print("ip6tables -D FORWARD -j HIPFW-FORWARD 2>/dev/null");

	HIP_DEBUG("Flushing hipfw chains\n");

	/* Flush in case there are some residual rules */
	system_print("iptables -F HIPFW-INPUT 2>/dev/null");
	system_print("iptables -F HIPFW-OUTPUT 2>/dev/null");
	system_print("iptables -F HIPFW-FORWARD 2>/dev/null");
	system_print("ip6tables -F HIPFW-INPUT 2>/dev/null");
	system_print("ip6tables -F HIPFW-OUTPUT 2>/dev/null");
	system_print("ip6tables -F HIPFW-FORWARD 2>/dev/null");

	HIP_DEBUG("Deleting hipfw chains\n");

	system_print("iptables -X HIPFW-INPUT 2>/dev/null");
	system_print("iptables -X HIPFW-OUTPUT 2>/dev/null");
	system_print("iptables -X HIPFW-FORWARD 2>/dev/null");
	system_print("ip6tables -X HIPFW-INPUT 2>/dev/null");
	system_print("ip6tables -X HIPFW-OUTPUT 2>/dev/null");
	system_print("ip6tables -X HIPFW-FORWARD 2>/dev/null");
}

static void firewall_exit(){
	struct hip_common *msg = NULL;

	HIP_DEBUG("Firewall exit\n");

	msg = hip_msg_alloc();
	if (hip_build_user_hdr(msg, SO_HIP_FIREWALL_QUIT, 0) ||
	    hip_send_recv_daemon_info(msg, 0, hip_fw_sock))
		HIP_DEBUG("Failed to notify hipd of firewall shutdown.\n");
	free(msg);

	hip_fw_uninit_system_based_opp_mode();
	hip_fw_flush_iptables();
	/* rules have to be removed first, otherwise HIP packets won't pass through
	 * at this time any more */
	hip_fw_uninit_userspace_ipsec();
	hip_fw_uninit_esp_prot();
	hip_fw_uninit_esp_prot_conntrack();
	hip_fw_uninit_lsi_support();
	hip_fw_uninit_sava_router();
	
#ifdef CONFIG_HIP_PERFORMANCE
	/* Deallocate memory of perf_set after finishing all of tests */
	hip_perf_destroy(perf_set);
#endif

	hip_remove_lock_file(HIP_FIREWALL_LOCK_FILE);
}

static void firewall_close(const int signal){
#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Stop and write PERF_ALL\n");
	hip_perf_stop_benchmark(perf_set, PERF_ALL);
	hip_perf_write_benchmark(perf_set, PERF_ALL);
#endif
	HIP_DEBUG("Closing firewall...\n");
	//hip_uninit_proxy_db();
	//hip_uninit_conn_db();
	firewall_exit();
	exit(signal);
}

static void die(struct ipq_handle *h){
	HIP_DEBUG("dying\n");
	ipq_perror("passer");
	ipq_destroy_handle(h);
	firewall_close(1);
}

/**
 * Increases the netlink buffer capacity.
 *
 * The previous default values were:
 *
 * /proc/sys/net/core/rmem_default - 110592
 * /proc/sys/net/core/rmem_max     - 131071
 * /proc/sys/net/core/wmem_default - 110592
 * /proc/sys/net/core/wmem_max     - 131071
 *
 * The new value 1048576=1024*1024 was assigned to all of them
 */
static void firewall_increase_netlink_buffers(){
	HIP_DEBUG("Increasing the netlink buffers\n");

	system_print("echo 1048576 > /proc/sys/net/core/rmem_default");
	system_print("echo 1048576 > /proc/sys/net/core/rmem_max");
	system_print("echo 1048576 > /proc/sys/net/core/wmem_default");
	system_print("echo 1048576 > /proc/sys/net/core/wmem_max");
}

#if !defined(CONFIG_HIP_OPENWRT) && !defined(ANDROID_CHANGES)
/**
 * Loads several modules that are needed by the firewall.
 */
static void firewall_probe_kernel_modules(){
	int count, err, status;
	char cmd[40];
	int mod_total;
	char *mod_name[] =
	{ "ip_queue", "ip6_queue", "iptable_filter", "ip6table_filter" };

	mod_total = sizeof(mod_name) / sizeof(char *);

	HIP_DEBUG("Probing for %d modules. When the modules are built-in, the errors can be ignored\n", mod_total);

	for (count = 0; count < mod_total; count++)
	{
		snprintf(cmd, sizeof(cmd), "%s %s", "/sbin/modprobe",
				mod_name[count]);
		HIP_DEBUG("%s\n", cmd);
		err = fork();
		if (err < 0)
			HIP_ERROR("Failed to fork() for modprobe!\n");
		else if (err == 0)
		{
			/* Redirect stderr, so few non fatal errors wont show up. */
			if (freopen("/dev/null", "w", stderr) == NULL){
				HIP_ERROR("Could not freopen /dev/null");
			}
			execlp("/sbin/modprobe", "/sbin/modprobe",
					mod_name[count], (char *)NULL);
		}
		else
			waitpid(err, &status, 0);
	}
	HIP_DEBUG("Probing completed\n");
}
#endif /*!defined(CONFIG_HIP_OPENWRT) && !defined(ANDROID_CHANGES) */

/*-------------PACKET FILTERING FUNCTIONS------------------*/

static int match_hit(const struct in6_addr match_hit, const struct in6_addr packet_hit, const int boolean){
	int i = IN6_ARE_ADDR_EQUAL(&match_hit, &packet_hit);

	HIP_DEBUG("match_hit: hit1: %s hit2: %s bool: %d match: %d\n",
			addr_to_numeric(&match_hit), addr_to_numeric(&packet_hit), boolean, i);
	if (boolean)
		return i;
	else
		return !i;
}

static int match_int(const int match, const int packet, const int boolean){
	if (boolean)
		return match == packet;
	else
		return !(match == packet);
}


static int match_string(const char * match, const char * packet, const int boolean){
	if (boolean)
		return !strcmp(match, packet);
	else
		return strcmp(match, packet);
}

/* We only match the esp packet with the state in the connection
  * tracking. There is no need to match the rule-set again as we
  * already filtered the HIP control packets. If we wanted to
  * disallow a connection, we should do it there! */
static int filter_esp(const hip_fw_context_t * ctx)
{
	// drop packet by default
	int verdict = 0;

	if (filter_esp_state(ctx) > 0)
	{
		verdict = 1;

		HIP_DEBUG("ESP packet successfully passed filtering\n");

	} else
	{
		verdict = 0;

		HIP_DEBUG("ESP packet NOT authed in ESP filtering\n");
	}

  	return verdict;
}

/* filter hip packet according to rules.
 * return verdict
 */
static int filter_hip(const struct in6_addr * ip6_src,
               const struct in6_addr * ip6_dst,
               struct hip_common *buf,
               const unsigned int hook,
               const char * in_if,
               const char * out_if,
               hip_fw_context_t *ctx)
{
	// complete rule list for hook (== IN / OUT / FORWARD)
  	struct _DList * list = (struct _DList *) read_rules(hook);
  	struct rule * rule = NULL;
  	// assume match for current rule
  	int match = 1, print_addr = 0;
  	// assume packet has not yet passed connection tracking
  	int conntracked = 0;
  	// block traffic by default
  	int verdict = 0;

	HIP_DEBUG("\n");

  	//if dynamically changing rules possible

	if (!list) {
  		HIP_DEBUG("The list of rules is empty!!!???\n");
  	}

  	while (list != NULL) {
  		match = 1;
  		rule = (struct rule *) list->data;

  		HIP_DEBUG("HIP type number is %d\n", buf->type_hdr);

  		//print_rule(rule);
		if (buf->type_hdr == HIP_I1)
		{
			HIP_INFO("received packet type: I1\n");
			print_addr = 1;
		}
		else if (buf->type_hdr == HIP_R1)
		{
			HIP_INFO("received packet type: R1\n");
			print_addr = 1;
		}
		else if (buf->type_hdr == HIP_I2)
		{
			HIP_INFO("received packet type: I2\n");
			print_addr = 1;
		}
		else if (buf->type_hdr == HIP_R2)
		{
			HIP_INFO("received packet type: R2\n");
			print_addr = 1;
		}
		else if (buf->type_hdr == HIP_UPDATE)
		{
			HIP_INFO("received packet type: UPDATE\n");
			print_addr = 1;
		}
		else if (buf->type_hdr == HIP_CLOSE)
		{
			HIP_INFO("received packet type: CLOSE\n");
			print_addr = 1;
		}
		else if (buf->type_hdr == HIP_CLOSE_ACK)
		{
			HIP_INFO("received packet type: CLOSE_ACK\n");
			print_addr = 1;
		}
		else if (buf->type_hdr == HIP_NOTIFY)
			HIP_DEBUG("received packet type: NOTIFY\n");
		else if (buf->type_hdr == HIP_LUPDATE)
			HIP_DEBUG("received packet type: LIGHT UPDATE\n");
                //Added by Prabhu to support DATA Packets
		else if (buf->type_hdr == HIP_DATA )
			HIP_DEBUG("received packet type: HIP_DATA");
		else
			HIP_DEBUG("received packet type: UNKNOWN\n");

		if (print_addr)
		{
			HIP_INFO_HIT("src hit", &(buf->hits));
			HIP_INFO_HIT("dst hit", &(buf->hitr));
			HIP_INFO_IN6ADDR("src ip", ip6_src);
			HIP_INFO_IN6ADDR("dst ip", ip6_dst);
		}

		// check src_hit if defined in rule
		if(match && rule->src_hit) {
			HIP_DEBUG("src_hit\n");

			if(!match_hit(rule->src_hit->value,
				      buf->hits,
				      rule->src_hit->boolean)) {
				match = 0;
			}
		}

		// check dst_hit if defined in rule
		if(match && rule->dst_hit) {
			HIP_DEBUG("dst_hit\n");

			if(!match_hit(rule->dst_hit->value,
				      buf->hitr,
				      rule->dst_hit->boolean)) {
				match = 0;
			}
	  	}

		// check the HIP packet type (I1, UPDATE, etc.)
		if(match && rule->type) {
			HIP_DEBUG("type\n");
			if(!match_int(rule->type->value,
				      buf->type_hdr,
				      rule->type->boolean)) {
				match = 0;
			}

			HIP_DEBUG("type rule: %d, packet: %d, boolean: %d, match: %d\n",
				  rule->type->value,
				  buf->type_hdr,
				  rule->type->boolean,
				  match);
	  	}

		/* this checks, if the the input interface of the packet
		   matches the one specified in the rule */
		if(match && rule->in_if) {
			if(!match_string(rule->in_if->value, in_if,
					 rule->in_if->boolean)) {
				match = 0;
			}

			HIP_DEBUG("in_if rule: %s, packet: %s, boolean: %d, match: %d \n",
				  rule->in_if->value,
				  in_if, rule->in_if->boolean, match);
	  	}

		/* this checks, if the the output interface of the packet matches the
		 * one specified in the rule */
		if(match && rule->out_if) {
			if(!match_string(rule->out_if->value,
					 out_if,
					 rule->out_if->boolean))
			{
				match = 0;
			}

			HIP_DEBUG("out_if rule: %s, packet: %s, boolean: %d, match: %d \n",
				  rule->out_if->value, out_if, rule->out_if->boolean, match);
	  	}

/* NOTE: HI does not make sense as a filter criteria as filtering by HITs and matching to transmitted HI
 * 		 is supposed to provide a similar level of security. Furthermore, signature verification is done
 * 		 in conntracking.
 * 		 -- Rene
 * TODO think about removing this in firewall_control.conf as well
 */
#if 0
		// if HI defined in rule, verify signature now
		// - late as it's an expensive operation
		// - checks that the message src is the src defined in the _rule_
		if(match && rule->src_hi) {
			_HIP_DEBUG("src_hi\n");

			if(!match_hi(rule->src_hi, buf)) {
		  		match = 0;
			}
		}
#endif

		/* check if packet matches state from connection tracking
		   must be last, so not called if packet is going to be
		   dropped */
		if(match && rule->state)
	  	{
			/* we at least had some packet before -> check
			   this packet this will also check the signature of
			   the packet, if we already have a src_HI stored
			   for the _connection_ */
			if(!filter_state(ip6_src, ip6_dst, buf, rule->state, rule->accept, ctx)) {
				match = 0;
			} else
			{
				// if it is a valid packet, this also tracked the packet
				conntracked = 1;
			}

			HIP_DEBUG("state, rule %d, boolean %d, match %d\n",
				  rule->state->int_opt.value,
				  rule->state->int_opt.boolean,
				  match);
		}

		// if a match, no need to check further rules
		if(match)
		{
			HIP_DEBUG("match found\n");
			break;
 		}

		// else proceed with next rule
		list = list->next;
	}

  	// if we found a matching rule, use its verdict
  	if(rule && match)
	{
		HIP_DEBUG("packet matched rule, target %d\n", rule->accept);
		verdict = rule->accept;
	} else {
 		HIP_DEBUG("falling back to default HIP/ESP behavior, target %d\n",
			  accept_hip_esp_traffic_by_default);

 		verdict = accept_hip_esp_traffic_by_default;
 	}

  	//release rule list
  	read_rules_exit(0);

  	/* FIXME this actually verifies the packet and should be incorporated in the
  	 *       resulting verdict!!! */
  	// if packet will be accepted and connection tracking is used
  	// but there is no state for the packet in the conntrack module
  	// yet -> show the packet to conntracking
  	if (statefulFiltering && verdict && !conntracked) {
		conntrack(ip6_src, ip6_dst, buf, ctx);
  	}

  	return verdict;
}

/*
 * Rules:
 *
 * Output:
 *
 * - HIP:
 *   1. default rule checks for hip
 *   1. filter_hip
 *
 * - ESP:
 *   1. default rule checks for esp
 *   2. filter_esp
 *
 * - TCP:
 *   1. default rule checks for non-hip
 *   2.
 *   - destination is hit (userspace ipsec output)
 *   - destination is lsi (lsi output)
 *   - destination not hit or lsi
 *     1. opp tcp filtering (TBD)
 *
 * - Other
 *   - Same as with TCP except no opp tcp filtering
 *
 * Input:
 *
 * - HIP:
 *   1. default rule checks for hip
 *   2. filter_hip
 *
 * - ESP:
 *   1. default rule checks for hip
 *   2. filter_esp
 *   3. userspace_ipsec input
 *   4. lsi input
 *
 * - Other:
 *   - Same as with TCP except no opp tcp input
 *
 * - TCP:
 *   1. default rule checks for non-hip
 *   2. opp tcp input
 *   3. proxy input
  *
 * Forward:
 *
 * - HIP:
 *   1. None
 *
 * - ESP:
 *   1. None
 *
 * - TCP:
 *   1. Proxy input
 *
 * - Other:
 *   2. Proxy input
 *
 */
static int hip_fw_handle_hip_output(hip_fw_context_t *ctx){
        int err = 0;
	int verdict = accept_hip_esp_traffic_by_default;
	/*hip_common_t * buf = ctx->transport_hdr.hip;*/

	HIP_DEBUG("hip_fw_handle_hip_output \n");

	if (hip_userspace_ipsec)
		HIP_IFEL(hip_fw_userspace_ipsec_init_hipd(1), 0,
			 "Drop ESP packet until hipd is available\n");

	if (filter_traffic)
	{
	  if (hip_sava_router) {		  
	    hip_common_t * buf = ctx->transport_hdr.hip;
	    HIP_DEBUG("HIP packet type %d \n", buf->type_hdr);
	    if (buf->type_hdr == HIP_I2){
	      HIP_DEBUG("CHECK IP IN THE HIP_I2 STATE +++++++++++ \n");
	      if (sava_check_state(&ctx->src, &buf->hits) == 0) {
		goto out_err;
	      }
	    }
	  }

	  verdict = filter_hip(&ctx->src,
			       &ctx->dst,
			       ctx->transport_hdr.hip,
			       ctx->ipq_packet->hook,
			       ctx->ipq_packet->indev_name,
			       ctx->ipq_packet->outdev_name,
			       ctx);
	} else {
	  verdict = ACCEPT;
	}

	HIP_INFO("\n");

 out_err:
	/* zero return value means that the packet should be dropped */
	return verdict;
}

static int hip_fw_handle_esp_output(hip_fw_context_t *ctx){
	int verdict = accept_hip_esp_traffic_by_default;

	HIP_DEBUG("\n");

	if (filter_traffic)
	{
		verdict = filter_esp(ctx);
	} else
	{
		verdict = ACCEPT;
	}

	return verdict;
}

static int hip_fw_handle_other_output(hip_fw_context_t *ctx){
	struct ip      *iphdr = NULL;
	struct tcphdr  *tcphdr = NULL;
	char 	       *hdrBytes = NULL;
	int verdict = accept_normal_traffic_by_default;

	HIP_DEBUG("\n");

	if (hip_opptcp) {
		/* For TCP option only */
		iphdr = (struct ip *)ctx->ip_hdr.ipv4;
		tcphdr = ((struct tcphdr *) (((char *) iphdr) + ctx->ip_hdr_len));
		hdrBytes = ((char *) iphdr) + ctx->ip_hdr_len;
	}
	if (hip_sava_client &&
	    !hip_lsi_support &&
	    !hip_userspace_ipsec) {
		HIP_DEBUG("Handling normal traffic in SAVA mode \n ");
		verdict = hip_sava_handle_output(ctx);
	} else if (ctx->ip_version == 6 && (hip_userspace_ipsec || hip_datapacket_mode) )//Prabhu check for datapacket mode too
          {
		hip_hit_t *def_hit = hip_fw_get_default_hit();
		HIP_DEBUG_HIT("destination hit: ", &ctx->dst);
		// XX TODO: hip_fw_get_default_hit() returns an unfreed value
		if (def_hit)
			HIP_DEBUG_HIT("default hit: ", def_hit);
		// check if this is a reinjected packet
		if (def_hit && IN6_ARE_ADDR_EQUAL(&ctx->dst, def_hit)) {
			// let the packet pass through directly
			verdict = 1;
		} else {
			verdict = !hip_fw_userspace_ipsec_output(ctx);
		}
	} else if(ctx->ip_version == 4) {
		hip_lsi_t src_lsi, dst_lsi;

		IPV6_TO_IPV4_MAP(&(ctx->src), &src_lsi);
		IPV6_TO_IPV4_MAP(&(ctx->dst), &dst_lsi);

		/* LSI HOOKS */
		if (IS_LSI32(dst_lsi.s_addr) && hip_lsi_support) {
			if (hip_is_packet_lsi_reinjection(&dst_lsi)) {
				verdict = 1;
			} else {
				hip_fw_handle_outgoing_lsi(ctx->ipq_packet,
							   &src_lsi, &dst_lsi);
				verdict = 0; /* Reject the packet */
			}
		} else if (hip_opptcp && (ctx->ip_hdr.ipv4)->ip_p == 6 &&
			   tcp_packet_has_i1_option(hdrBytes, 4*tcphdr->doff)){
				verdict = 1;
		} else if (system_based_opp_mode) {
			   verdict = hip_fw_handle_outgoing_system_based_opp(ctx,
					   accept_normal_traffic_by_default);
		}
	}

	/* No need to check default rules as it is handled by the
	   iptables rules */
 	return verdict;
}

static int hip_fw_handle_tcp_output(hip_fw_context_t *ctx){

	HIP_DEBUG("\n");

	return hip_fw_handle_other_output(ctx);
}

static int hip_fw_handle_hip_forward(hip_fw_context_t *ctx){

	HIP_DEBUG("\n");

#ifdef CONFIG_HIP_MIDAUTH
	if (use_midauth)
		if (midauth_filter_hip(ctx) == NF_DROP)
			return NF_DROP;
#endif
	// for now forward and output are handled symmetrically
	return hip_fw_handle_hip_output(ctx);
}

static int hip_fw_handle_esp_forward(hip_fw_context_t *ctx){
	int verdict = accept_hip_esp_traffic_by_default;

	HIP_DEBUG("\n");
	if (filter_traffic)
	{
		// check if this belongs to one of the connections pass through
		verdict = filter_esp(ctx);
	} else
	{
		verdict = ACCEPT;
	}

 	return verdict;
}

static int hip_fw_handle_other_forward(hip_fw_context_t *ctx){

	int verdict = accept_normal_traffic_by_default;

	HIP_DEBUG("hip_fw_handle_other_forward()\n");

	if (hip_proxy_status && !ipv6_addr_is_hit(&ctx->dst))
	{
		verdict = handle_proxy_outbound_traffic(ctx->ipq_packet,
							&ctx->src,
							&ctx->dst,
							ctx->ip_hdr_len,
							ctx->ip_version);
	} else if (hip_sava_router) {
	  HIP_DEBUG("hip_sava_router \n");
	  verdict = hip_sava_handle_router_forward(ctx);
	}

	/* No need to check default rules as it is handled by the iptables rules */

	return verdict;
}

static int hip_fw_handle_tcp_forward(hip_fw_context_t *ctx){
	HIP_DEBUG("\n");

	return hip_fw_handle_other_forward(ctx);
}

static int hip_fw_handle_other_input(hip_fw_context_t *ctx){
	int verdict = accept_normal_traffic_by_default;
	int ip_hits = ipv6_addr_is_hit(&ctx->src) &&
		      ipv6_addr_is_hit(&ctx->dst);

	HIP_DEBUG("\n");

	if (ip_hits) {
		if (hip_proxy_status)
			verdict = handle_proxy_inbound_traffic(ctx->ipq_packet,
					&ctx->src);
	  	else if (hip_lsi_support || system_based_opp_mode) {
			verdict = hip_fw_handle_incoming_hit(ctx->ipq_packet,
							     &ctx->src,
							     &ctx->dst,
							     hip_lsi_support,
							     system_based_opp_mode);
	  	}
	}

	/* No need to check default rules as it is handled by the
	   iptables rules */
	return verdict;
}

static int hip_fw_handle_hip_input(hip_fw_context_t *ctx){

        int verdict = accept_hip_esp_traffic_by_default;

	HIP_DEBUG("hip_fw_handle_hip_input()\n");
	//Prabhu handle incoming datapackets

	verdict = hip_fw_handle_hip_output(ctx);
        if(hip_datapacket_mode && verdict)
              verdict = hip_fw_userspace_datapacket_input(ctx);

        return verdict;
}

static int hip_fw_handle_esp_input(hip_fw_context_t *ctx){
	int verdict = accept_hip_esp_traffic_by_default;

	HIP_DEBUG("\n");

	if (filter_traffic)
	{
		// first of all check if this belongs to one of our connections
		verdict = filter_esp(ctx);
	} else
	{
		verdict = ACCEPT;
	}

	if (verdict && hip_userspace_ipsec) {
		HIP_DEBUG("userspace ipsec input\n");
		// added by Tao Wan
		verdict = !hip_fw_userspace_ipsec_input(ctx);
	}

	return verdict;
}

static int hip_fw_handle_tcp_input(hip_fw_context_t *ctx){
	int verdict = accept_normal_traffic_by_default;

	HIP_DEBUG("\n");

	// any incoming plain TCP packet might be an opportunistic I1
	HIP_DEBUG_HIT("hit src", &ctx->src);
	HIP_DEBUG_HIT("hit dst", &ctx->dst);

	if(hip_opptcp && !ipv6_addr_is_hit(&ctx->dst)){
		verdict = hip_fw_examine_incoming_tcp_packet(ctx->ip_hdr.ipv4,
							     ctx->ip_version,
							     ctx->ip_hdr_len);
	} else
	{
		// as we should never receive TCP with HITs, this will only apply
		// to IPv4 TCP
		verdict = hip_fw_handle_other_input(ctx);
	}

	return verdict;
}


/*----------------MAIN FUNCTIONS----------------------*/

static int firewall_init_rules(){
	int err = 0;

	HIP_DEBUG("Initializing firewall\n");

	HIP_DEBUG("in=%d out=%d for=%d\n", NF_IP_LOCAL_IN, NF_IP_LOCAL_OUT, NF_IP_FORWARD);

	// funtion pointers for the respective packet handlers
	hip_fw_handler[NF_IP_LOCAL_IN][OTHER_PACKET] = hip_fw_handle_other_input;
	hip_fw_handler[NF_IP_LOCAL_IN][HIP_PACKET] = hip_fw_handle_hip_input;
	hip_fw_handler[NF_IP_LOCAL_IN][ESP_PACKET] = hip_fw_handle_esp_input;
	hip_fw_handler[NF_IP_LOCAL_IN][TCP_PACKET] = hip_fw_handle_tcp_input;

	hip_fw_handler[NF_IP_LOCAL_OUT][OTHER_PACKET] = hip_fw_handle_other_output;
	hip_fw_handler[NF_IP_LOCAL_OUT][HIP_PACKET] = hip_fw_handle_hip_output;
	hip_fw_handler[NF_IP_LOCAL_OUT][ESP_PACKET] = hip_fw_handle_esp_output;
	hip_fw_handler[NF_IP_LOCAL_OUT][TCP_PACKET] = hip_fw_handle_tcp_output;

	hip_fw_handler[NF_IP_FORWARD][OTHER_PACKET] = hip_fw_handle_other_forward;

	//apply rules for forwarded hip and esp traffic
	hip_fw_handler[NF_IP_FORWARD][HIP_PACKET] = hip_fw_handle_hip_forward;
	hip_fw_handler[NF_IP_FORWARD][ESP_PACKET] = hip_fw_handle_esp_forward;
	//do not drop those files by default
	hip_fw_handler[NF_IP_FORWARD][TCP_PACKET] = hip_fw_handle_tcp_forward;

	HIP_DEBUG("Enabling forwarding for IPv4 and IPv6\n");
	system_print("echo 1 >/proc/sys/net/ipv4/conf/all/forwarding");

	/* Flush in case previous hipfw process crashed */
	hip_fw_flush_iptables();

	system_print("iptables -N HIPFW-INPUT");
	system_print("iptables -N HIPFW-OUTPUT");
	system_print("iptables -N HIPFW-FORWARD");
	system_print("ip6tables -N HIPFW-INPUT");
	system_print("ip6tables -N HIPFW-OUTPUT");
	system_print("ip6tables -N HIPFW-FORWARD");

	/* Register signal handlers */
	signal(SIGINT, firewall_close);
	signal(SIGTERM, firewall_close);

	// TARGET (-j) QUEUE will transfer matching packets to userspace
	// these packets will be handled using libipq

	if(hip_proxy_status)
	{
		/* Note: this block radvd advertisements */
		system_print("echo 1 >/proc/sys/net/ipv6/conf/all/forwarding");
		hip_fw_init_proxy();
	}
	else
	{
		/* @todo: remove the following line */
		system_print("echo 0 >/proc/sys/net/ipv6/conf/all/forwarding");

		// this has to be set up first in order to be the default behavior
		if (!accept_normal_traffic_by_default)
		{
			// make DROP the default behavior of all chains
			// TODO don't drop LSIs -> else IPv4 apps won't work
			// -> also messaging between HIPd and firewall is blocked here
			system_print("iptables -I HIPFW-FORWARD ! -d 127.0.0.1 -j DROP");  /* @todo: ! LSI PREFIX */
			system_print("iptables -I HIPFW-INPUT ! -d 127.0.0.1 -j DROP");  /* @todo: ! LSI PREFIX */
			system_print("iptables -I HIPFW-OUTPUT ! -d 127.0.0.1 -j DROP");  /* @todo: ! LSI PREFIX */

			// but still allow loopback and HITs as destination
			system_print("ip6tables -I HIPFW-FORWARD ! -d 2001:0010::/28 -j DROP");
			system_print("ip6tables -I HIPFW-INPUT ! -d 2001:0010::/28 -j DROP");
			system_print("ip6tables -I HIPFW-OUTPUT ! -d 2001:0010::/28 -j DROP");
			system_print("ip6tables -I HIPFW-FORWARD -d ::1 -j ACCEPT");
			system_print("ip6tables -I HIPFW-INPUT -d ::1 -j ACCEPT");
			system_print("ip6tables -I HIPFW-OUTPUT -d ::1 -j ACCEPT");
		}

		if (filter_traffic)
		{
			// this will allow the firewall to handle HIP traffic
			// HIP protocol
			system_print("iptables -I HIPFW-FORWARD -p 139 -j QUEUE");
			// ESP protocol
			system_print("iptables -I HIPFW-FORWARD -p 50 -j QUEUE");
			// UDP encapsulation for HIP
			system_print("iptables -I HIPFW-FORWARD -p 17 --dport 10500 -j QUEUE");
			system_print("iptables -I HIPFW-FORWARD -p 17 --sport 10500 -j QUEUE");

			system_print("iptables -I HIPFW-INPUT -p 139 -j QUEUE");
			system_print("iptables -I HIPFW-INPUT -p 50 -j QUEUE");
			system_print("iptables -I HIPFW-INPUT -p 17 --dport 10500 -j QUEUE");
			system_print("iptables -I HIPFW-INPUT -p 17 --sport 10500 -j QUEUE");

			system_print("iptables -I HIPFW-OUTPUT -p 139 -j QUEUE");
			system_print("iptables -I HIPFW-OUTPUT -p 50 -j QUEUE");
			system_print("iptables -I HIPFW-OUTPUT -p 17 --dport 10500 -j QUEUE");
			system_print("iptables -I HIPFW-OUTPUT -p 17 --sport 10500 -j QUEUE");

			system_print("ip6tables -I HIPFW-FORWARD -p 139 -j QUEUE");
			system_print("ip6tables -I HIPFW-FORWARD -p 50 -j QUEUE");
			system_print("ip6tables -I HIPFW-FORWARD -p 17 --dport 10500 -j QUEUE");
			system_print("ip6tables -I HIPFW-FORWARD -p 17 --sport 10500 -j QUEUE");

			system_print("ip6tables -I HIPFW-INPUT -p 139 -j QUEUE");
			system_print("ip6tables -I HIPFW-INPUT -p 50 -j QUEUE");
			system_print("ip6tables -I HIPFW-INPUT -p 17 --dport 10500 -j QUEUE");
			system_print("ip6tables -I HIPFW-INPUT -p 17 --sport 10500 -j QUEUE");

			system_print("ip6tables -I HIPFW-OUTPUT -p 139 -j QUEUE");
			system_print("ip6tables -I HIPFW-OUTPUT -p 50 -j QUEUE");
			system_print("ip6tables -I HIPFW-OUTPUT -p 17 --dport 10500 -j QUEUE");
			system_print("ip6tables -I HIPFW-OUTPUT -p 17 --sport 10500 -j QUEUE");
		}
	}

	HIP_IFEL(hip_fw_init_system_based_opp_mode(), -1, "failed to load extension\n");
	HIP_IFEL(hip_fw_init_opptcp(), -1, "failed to load extension\n");
	HIP_IFEL(hip_fw_init_lsi_support(), -1, "failed to load extension\n");
	HIP_IFEL(hip_fw_init_userspace_ipsec(), -1, "failed to load extension\n");
	HIP_IFEL(hip_fw_init_esp_prot(), -1, "failed to load extension\n");
	HIP_IFEL(hip_fw_init_esp_prot_conntrack(), -1, "failed to load extension\n");

	// Initializing local database for mapping LSI-HIT in the firewall
	// FIXME never uninited -> memory leak
	firewall_init_hldb();
	// Initializing local cache database
	firewall_cache_init_hldb();
	// Initializing local port cache database
	firewall_port_cache_init_hldb();

	system_print("iptables -I INPUT -j HIPFW-INPUT");
	system_print("iptables -I OUTPUT -j HIPFW-OUTPUT");
	system_print("iptables -I FORWARD -j HIPFW-FORWARD");
	system_print("ip6tables -I INPUT -j HIPFW-INPUT");
	system_print("ip6tables -I OUTPUT -j HIPFW-OUTPUT");
	system_print("ip6tables -I FORWARD -j HIPFW-FORWARD");

 out_err:
	return err;
}

/**
 * Returns the packet type of an IP packet.
 *
 * Currently supported types:				type
 * - plain HIP control packet				  1
 * - ESP packet								  2
 * - TCP packet								  3 (for opportunistic TCP handshake)
 *
 * Unsupported types -> type 0
 *
 * @param  hdr        a pointer to a IP packet.
 * @param ipVersion	  the IP version for this packet
 * @return            One if @c hdr is a HIP packet, zero otherwise.
 */
static int hip_fw_init_context(hip_fw_context_t *ctx, const unsigned char *buf, const int ip_version)
{
	int ip_hdr_len, err = 0;
	// length of packet starting at udp header
	uint16_t udp_len = 0;
	struct udphdr *udphdr = NULL;
	int udp_encap_zero_bytes = 0;

	// default assumption
	ctx->packet_type = OTHER_PACKET;

	// same context memory as for packets before -> re-init
	memset(ctx, 0, sizeof(hip_fw_context_t));

	// add whole packet to context and ip version
	ctx->ipq_packet = ipq_get_packet(buf);

	// check if packet is to big for the buffer
	if (ctx->ipq_packet->data_len > HIP_MAX_PACKET)
	{
		HIP_ERROR("packet size greater than buffer\n");

		err = 1;
		goto end_init;
	}

	ctx->ip_version = ip_version;

	if(ctx->ip_version == 4){
		_HIP_DEBUG("IPv4 packet\n");

		struct ip *iphdr = (struct ip *) ctx->ipq_packet->payload;
		// add pointer to IPv4 header to context
		ctx->ip_hdr.ipv4 = iphdr;

		/* ip_hl is given in multiple of 4 bytes
		 *
		 * NOTE: not sizeof(struct ip) as we might have options */
		ip_hdr_len = (iphdr->ip_hl * 4);
		// needed for opportunistic TCP
		ctx->ip_hdr_len = ip_hdr_len;
		HIP_DEBUG("ip_hdr_len is: %d\n", ip_hdr_len);
		HIP_DEBUG("total length: %u\n", ntohs(iphdr->ip_len));
		HIP_DEBUG("ttl: %u\n", iphdr->ip_ttl);
		HIP_DEBUG("packet length (ipq): %u\n", ctx->ipq_packet->data_len);

		// add IPv4 addresses
		IPV4_TO_IPV6_MAP(&ctx->ip_hdr.ipv4->ip_src, &ctx->src);
		IPV4_TO_IPV6_MAP(&ctx->ip_hdr.ipv4->ip_dst, &ctx->dst);

		HIP_DEBUG_HIT("packet src", &ctx->src);
		HIP_DEBUG_HIT("packet dst", &ctx->dst);

		HIP_DEBUG("IPv4 next header protocol number is %d\n", iphdr->ip_p);

		// find out which transport layer protocol is used
		if(iphdr->ip_p == IPPROTO_HIP)
		{
			// we have found a plain HIP control packet
			HIP_DEBUG("plain HIP packet\n");

			ctx->packet_type = HIP_PACKET;
			ctx->transport_hdr.hip = (struct hip_common *) (((char *)iphdr) + ip_hdr_len);

			goto end_init;

		} else if (iphdr->ip_p == IPPROTO_ESP)
		{
			// this is an ESP packet
			HIP_DEBUG("plain ESP packet\n");

			ctx->packet_type = ESP_PACKET;
			ctx->transport_hdr.esp = (struct hip_esp *) (((char *)iphdr) + ip_hdr_len);

			goto end_init;

		} else if(iphdr->ip_p == IPPROTO_TCP)
		{
			// this might be a TCP packet for opportunistic mode
			HIP_DEBUG("plain TCP packet\n");

			ctx->packet_type = TCP_PACKET;
			ctx->transport_hdr.tcp = (struct tcphdr *) (((char *)iphdr) + ip_hdr_len);

			goto end_init;
		} else if (iphdr->ip_p != IPPROTO_UDP)
		{
			// if it's not UDP either, it's unsupported
			HIP_DEBUG("some other packet\n");

			goto end_init;
		}

		// need UDP header to look for encapsulated ESP
		udp_len = ntohs(iphdr->ip_len);
		udphdr = ((struct udphdr *) (((char *) iphdr) + ip_hdr_len));

		// add UDP header to context
		ctx->udp_encap_hdr = udphdr;

	} else if (ctx->ip_version == 6)
	{
		_HIP_DEBUG("IPv6 packet\n");

		struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)ctx->ipq_packet->payload;
		// add pointer to IPv4 header to context
		ctx->ip_hdr.ipv6 = ip6_hdr;

		// Ipv6 has fixed header length
		ip_hdr_len = sizeof(struct ip6_hdr);
		// needed for opportunistic TCP
		ctx->ip_hdr_len = ip_hdr_len;
		HIP_DEBUG("ip_hdr_len is: %d\n", ip_hdr_len);
		HIP_DEBUG("payload length: %u\n", ntohs(ip6_hdr->ip6_plen));
		HIP_DEBUG("ttl: %u\n", ip6_hdr->ip6_hlim);
		HIP_DEBUG("packet length (ipq): %u\n", ctx->ipq_packet->data_len);

		// add IPv6 addresses
		ipv6_addr_copy(&ctx->src, &ip6_hdr->ip6_src);
		ipv6_addr_copy(&ctx->dst, &ip6_hdr->ip6_dst);

		HIP_DEBUG_HIT("packet src: ", &ctx->src);
		HIP_DEBUG_HIT("packet dst: ", &ctx->dst);

		HIP_DEBUG("IPv6 next header protocol number is %d\n",
			  ip6_hdr->ip6_nxt);

		// find out which transport layer protocol is used
		if(ip6_hdr->ip6_nxt == IPPROTO_HIP)
		{
			// we have found a plain HIP control packet
			HIP_DEBUG("plain HIP packet\n");

			ctx->packet_type = HIP_PACKET;
			ctx->transport_hdr.hip = (struct hip_common *) (((char *)ip6_hdr) + sizeof(struct ip6_hdr));

			goto end_init;

		} else if (ip6_hdr->ip6_nxt == IPPROTO_ESP)
		{
			// we have found a plain ESP packet
			HIP_DEBUG("plain ESP packet\n");

			ctx->packet_type = ESP_PACKET;
			ctx->transport_hdr.esp = (struct hip_esp *) (((char *)ip6_hdr) + sizeof(struct ip6_hdr));

			goto end_init;

		} else if(ip6_hdr->ip6_nxt == IPPROTO_TCP)
		{
			// this might be a TCP packet for opportunistic mode
			HIP_DEBUG("plain TCP packet\n");

			ctx->packet_type = TCP_PACKET;
			ctx->transport_hdr.tcp = (struct tcphdr *) (((char *)ip6_hdr) + sizeof(struct ip6_hdr));

			goto end_init;

		} else if (ip6_hdr->ip6_nxt != IPPROTO_UDP)
		{
			// if it's not UDP either, it's unsupported
			HIP_DEBUG("some other packet\n");

			goto end_init;
		}

		/* for now these calculations are not necessary as UDP encapsulation
		 * is only used for IPv4 at the moment
		 *
		 * we keep them anyway in order to ease UDP encapsulation handling
		 * with IPv6
		 *
		 * NOTE: the length will include optional extension headers
		 * -> handle this */
		udp_len = ntohs(ip6_hdr->ip6_plen);
		udphdr = ((struct udphdr *) (((char *) ip6_hdr) + ip_hdr_len));

		// add udp header to context
		ctx->udp_encap_hdr = udphdr;
	}

	HIP_DEBUG("UDP header size  is %d\n", sizeof(struct udphdr));

	/* only handle IPv4 right now
	 * -> however this is the place to handle UDP encapsulated IPv6 */
	if (ctx->ip_version == 4)
	{
		// we might have only received a UDP packet with headers only
		if (udp_len >= sizeof(struct ip) + sizeof(struct udphdr) + HIP_UDP_ZERO_BYTES_LEN)
		{
			uint32_t *zero_bytes = NULL;

			// we can distinguish UDP encapsulated control and data traffic with 32 zero bits
			// behind UDP header
			zero_bytes = (uint32_t *) (((char *)udphdr) + sizeof(struct udphdr));

			HIP_HEXDUMP("zero_bytes: ", zero_bytes, 4);

			/* check whether next 32 bits are zero or not */
			if (*zero_bytes == 0)
			{
				udp_encap_zero_bytes = 1;

				HIP_DEBUG("Zero SPI found\n");
			}

			zero_bytes = NULL;
		} else
		{
			// only UDP header + payload < 32 bit -> neither HIP nor ESP
			HIP_DEBUG("UDP packet with < 32 bit payload\n");

			goto end_init;
		}
	}

	_HIP_DEBUG("udp hdr len %d\n", ntohs(udphdr->len));
	_HIP_HEXDUMP("hexdump ",udphdr, 20);

	// HIP packets have zero bytes (IPv4 only right now)
	if(ctx->ip_version == 4 && udphdr
			&& ((udphdr->source == ntohs(hip_get_local_nat_udp_port())) ||
		        (udphdr->dest == ntohs(hip_get_peer_nat_udp_port())))
		    && udp_encap_zero_bytes)

	{
		/* check if zero byte hint is correct and we are processing a
		 * HIP control message */
		if (!hip_check_network_msg((struct hip_common *) (((char *)udphdr)
								     +
								  sizeof(struct udphdr)
								  +
								  HIP_UDP_ZERO_BYTES_LEN)))
		{
			// we found an UDP encapsulated HIP control packet
			HIP_DEBUG("UDP encapsulated HIP control packet\n");

			// add to context
			ctx->packet_type = HIP_PACKET;
			ctx->transport_hdr.hip = (struct hip_common *) (((char *)udphdr)
									+ sizeof(struct udphdr)
									+ HIP_UDP_ZERO_BYTES_LEN);

			goto end_init;
		}
		HIP_ERROR("communicating with BROKEN peer implementation of UDP encapsulation,"
				" found zero bytes when receiving HIP control message\n");
	}

	// ESP does not have zero bytes (IPv4 only right now)
	else if (ctx->ip_version == 4 && udphdr
		 && ((udphdr->source == ntohs(hip_get_local_nat_udp_port())) ||
		     (udphdr->dest == ntohs(hip_get_peer_nat_udp_port())))
		 && !udp_encap_zero_bytes)
	{

		/* from the ports and the non zero SPI we can tell that this
		 * is an ESP packet */
		HIP_DEBUG("ESP packet. Todo: verify SPI from database\n");

		// add to context
		ctx->packet_type = ESP_PACKET;
		ctx->transport_hdr.esp = (struct hip_esp *) (((char *)udphdr)
							     + sizeof(struct udphdr));

		goto end_init;
	} else {
		/* normal UDP packet or UDP encapsulated IPv6 */
		HIP_DEBUG("normal UDP packet\n");
	}

end_init:
	return err;
}


/**
*
*/
static void allow_modified_packet(struct ipq_handle *handle, unsigned long packetId,
		size_t len, unsigned char *buf){
	ipq_set_verdict(handle, packetId, NF_ACCEPT, len, buf);
	HIP_DEBUG("Packet accepted with modifications\n\n");
}


/**
 * Allow a packet to pass
 *
 * @param handle	the handle for the packets.
 * @param packetId	the packet ID.
 * @return		nothing
 */
static void allow_packet(struct ipq_handle *handle, unsigned long packetId){
	ipq_set_verdict(handle, packetId, NF_ACCEPT, 0, NULL);

	HIP_DEBUG("Packet accepted \n\n");
}


/**
 * Not allow a packet to pass
 *
 * @param handle	the handle for the packets.
 * @param packetId	the packet ID.
 * @return		nothing
 */
static void drop_packet(struct ipq_handle *handle, unsigned long packetId){
	ipq_set_verdict(handle, packetId, NF_DROP, 0, NULL);

	HIP_DEBUG("Packet dropped \n\n");
}

/**
 * Analyzes packets.

 * @param *ptr	pointer to an integer that indicates
 * 		the type of traffic: 4 - ipv4; 6 - ipv6.
 * @return	nothing, this function loops forever,
 * 		until the firewall is stopped.
 */
static int hip_fw_handle_packet(unsigned char *buf,
		struct ipq_handle *hndl,
		const int ip_version,
		hip_fw_context_t *ctx){
	// assume DROP
	int verdict = 0;


	/* waits for queue messages to arrive from ip_queue and
	 * copies them into a supplied buffer */
	if (ipq_read(hndl, buf, HIP_MAX_PACKET, 0) < 0)
	{
		HIP_PERROR("ipq_read failed: ");
		// TODO this error needs to be handled seperately -> die(hndl)?
		goto out_err;
	}

	/* queued messages may be a packet messages or an error messages */
	switch (ipq_message_type(buf))
	{
		case IPQM_PACKET:
			HIP_DEBUG("Received ipqm packet\n");
			// no goto -> go on with processing the message below
			break;
		case NLMSG_ERROR:
			HIP_ERROR("Received error message (%d): %s\n", ipq_get_msgerr(buf), ipq_errstr());
			goto out_err;
			break;
		default:
			HIP_DEBUG("Unsupported libipq packet\n");
			goto out_err;
			break;
	}

	// set up firewall context
	if (hip_fw_init_context(ctx, buf, ip_version))
		goto out_err;

	HIP_DEBUG("packet hook=%d, packet type=%d\n", ctx->ipq_packet->hook, ctx->packet_type);

	// match context with rules
	if (hip_fw_handler[ctx->ipq_packet->hook][ctx->packet_type]) {
		verdict = (hip_fw_handler[ctx->ipq_packet->hook][ctx->packet_type])(ctx);
	} else {
		HIP_DEBUG("Ignoring, no handler for hook (%d) with type (%d)\n");
	}

 out_err:
	if (verdict) {
		if (ctx->modified == 0) {
			HIP_DEBUG("=== Verdict: allow packet ===\n");
			allow_packet(hndl, ctx->ipq_packet->packet_id);
		} else {
			HIP_DEBUG("=== Verdict: allow modified packet ===\n");
			allow_modified_packet(hndl, ctx->ipq_packet->packet_id, ctx->ipq_packet->data_len, ctx->ipq_packet->payload);
		}
	} else {
		HIP_DEBUG("=== Verdict: drop packet ===\n");
		drop_packet(hndl, ctx->ipq_packet->packet_id);
	}

	// nothing to clean up here as we re-use buf, hndl and ctx

	return 0;
}

static void hip_fw_wait_for_hipd() {

	hip_fw_flush_iptables();

	/* Hipfw should be started before hipd to make sure
	   that nobody can bypass ACLs. However, some hipfw
	   extensions (e.g. userspace ipsec) work consistently
	   only when hipd is started first. To solve this
	   chicken-and-egg problem, we are blocking all hipd
	   messages until hipd is running and firewall is set up */
	system_print("iptables -N HIPFW-INPUT");
	system_print("iptables -N HIPFW-OUTPUT");
	system_print("iptables -N HIPFW-FORWARD");
	system_print("ip6tables -N HIPFW-INPUT");
	system_print("ip6tables -N HIPFW-OUTPUT");
	system_print("ip6tables -N HIPFW-FORWARD");

	system_print("iptables -I HIPFW-INPUT -p 139 -j DROP");
	system_print("iptables -I HIPFW-OUTPUT -p 139 -j DROP");
	system_print("iptables -I HIPFW-FORWARD -p 139 -j DROP");
	system_print("ip6tables -I HIPFW-INPUT -p 139 -j DROP");
	system_print("ip6tables -I HIPFW-OUTPUT -p 139 -j DROP");
	system_print("ip6tables -I HIPFW-FORWARD -p 139 -j DROP");

	system_print("iptables -I INPUT -j HIPFW-INPUT");
	system_print("iptables -I OUTPUT -j HIPFW-OUTPUT");
	system_print("iptables -I FORWARD -j HIPFW-FORWARD");
	system_print("ip6tables -I INPUT -j HIPFW-INPUT");
	system_print("ip6tables -I OUTPUT -j HIPFW-OUTPUT");
	system_print("ip6tables -I FORWARD -j HIPFW-FORWARD");

	//HIP_IFEL(!(msg = hip_msg_alloc()), -1, "malloc\n");
	//HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_PING, 0), -1, "hdr\n")

	while (hip_fw_get_default_hit() == NULL) {
		HIP_DEBUG("Sleeping until hipd is running...\n");
		sleep(1);
	}

	/* Notice that firewall flushed the dropping rules later */
}

int main(int argc, char **argv){
	int err = 0, highest_descriptor, i;
	int status, n, len;
	struct ipq_handle *h4 = NULL, *h6 = NULL;
	int ch;
	char *rule_file = NULL;
	extern char *optarg;
	extern int optind, optopt;
	int errflg = 0, killold = 0;
	struct hip_common *msg = NULL;
	struct sockaddr_in6 sock_addr;
	socklen_t alen;
	fd_set read_fdset;
	struct timeval timeout;
	unsigned char buf[HIP_MAX_PACKET];
	hip_fw_context_t ctx;
	int limit_capabilities = 0;
	int is_root = 0, access_ok = 0, msg_type = 0;//variables for accepting user messages only from hipd

	/* Make sure that root path is set up correcly (e.g. on Fedora 9).
	   Otherwise may get warnings from system_print() commands.
	   @todo: should append, not overwrite  */
	setenv("PATH", HIP_DEFAULT_EXEC_PATH, 1);

	if (geteuid() != 0) {
		HIP_ERROR("firewall must be run as root\n");
		exit(-1);
	}

#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Creating perf set\n");
	perf_set = hip_perf_create(PERF_MAX_FIREWALL);

	check_and_create_dir("results", DEFAULT_CONFIG_DIR_MODE);

	/* To keep things simple, we use a subset of the performance set originally created for the HIP daemon. */
        //hip_perf_set_name(perf_set, PERF_I1_SEND, "results/PERF_I1_SEND.csv");
	hip_perf_set_name(perf_set, PERF_I1,"results/PERF_I1.csv");
	hip_perf_set_name(perf_set, PERF_R1,"results/PERF_R1.csv");
	hip_perf_set_name(perf_set, PERF_I2,"results/PERF_I2.csv");
	hip_perf_set_name(perf_set, PERF_R2,"results/PERF_R2.csv");
	//hip_perf_set_name(perf_set, PERF_DH_CREATE,"results/PERF_DH_CREATE.csv");
	//hip_perf_set_name(perf_set, PERF_SIGN,"results/PERF_SIGN.csv");
	//hip_perf_set_name(perf_set, PERF_DSA_SIGN_IMPL,"results/PERF_DSA_SIGN_IMPL.csv");
	hip_perf_set_name(perf_set, PERF_VERIFY,"results/PERF_VERIFY.csv");
	hip_perf_set_name(perf_set, PERF_BASE,"results/PERF_BASE.csv");
	hip_perf_set_name(perf_set, PERF_ALL,"results/PERF_ALL.csv");
	//hip_perf_set_name(perf_set, PERF_UPDATE_SEND,"results/PERF_UPDATE_SEND.csv");
	//hip_perf_set_name(perf_set, PERF_VERIFY_UPDATE,"results/PERF_VERIFY_UPDATE.csv");
	hip_perf_set_name(perf_set, PERF_UPDATE_COMPLETE,"results/PERF_UPDATE_COMPLETE.csv");
	//hip_perf_set_name(perf_set, PERF_HANDLE_UPDATE_ESTABLISHED,"results/PERF_HANDLE_UPDATE_ESTABLISHED.csv");
	//hip_perf_set_name(perf_set, PERF_HANDLE_UPDATE_REKEYING,"results/PERF_HANDLE_UPDATE_REKEYING.csv");
	//hip_perf_set_name(perf_set, PERF_UPDATE_FINISH_REKEYING,"results/PERF_UPDATE_FINISH_REKEYING.csv");
	hip_perf_set_name(perf_set, PERF_CLOSE_SEND,"results/PERF_CLOSE_SEND.csv");
	hip_perf_set_name(perf_set, PERF_HANDLE_CLOSE,"results/PERF_HANDLE_CLOSE.csv");
	hip_perf_set_name(perf_set, PERF_HANDLE_CLOSE_ACK,"results/PERF_HANDLE_CLOSE_ACK.csv");
	hip_perf_set_name(perf_set, PERF_HANDLE_UPDATE_1,"results/PERF_HANDLE_UPDATE_1.csv");
	//hip_perf_set_name(perf_set, PERF_HANDLE_UPDATE_2,"results/PERF_HANDLE_UPDATE_2.csv");
	hip_perf_set_name(perf_set, PERF_CLOSE_COMPLETE,"results/PERF_CLOSE_COMPLETE.csv");
	hip_perf_set_name(perf_set, PERF_DSA_VERIFY_IMPL,"results/PERF_DSA_VERIFY_IMPL.csv");
	hip_perf_set_name(perf_set, PERF_RSA_VERIFY_IMPL,"results/PERF_RSA_VERIFY_IMPL.csv");
	//hip_perf_set_name(perf_set, PERF_RSA_SIGN_IMPL,"results/PERF_RSA_SIGN_IMPL.csv");

	HIP_DEBUG("Opening perf set\n");
	hip_perf_open(perf_set);
	HIP_DEBUG("Start PERF_ALL\n");
	hip_perf_start_benchmark(perf_set, PERF_ALL);
#endif

	memset(&default_hit, 0, sizeof(default_hit));
	memset(&default_lsi, 0, sizeof(default_lsi));

	hip_set_logdebug(LOGDEBUG_ALL);

	while ((ch = getopt(argc, argv, "aAbcdef:FhHiIklmopv")) != -1)
	{
		switch (ch)
		{
		case 'A':
			accept_hip_esp_traffic_by_default = 1;
			restore_accept_hip_esp_traffic = 1;
			break;
		case 'b':
			foreground = 0;
			break;
		case 'd':
			log_level = LOGDEBUG_ALL;
			break;
		case 'e':
			hip_userspace_ipsec = 1;
			hip_esp_protection = 1;
			break;
		case 'f':
			rule_file = optarg;
			break;
		case 'F':
			filter_traffic = 0;
			restore_filter_traffic = filter_traffic;
			break;
		case 'h':
			print_usage();
			exit(2);
			break;
		case 'H':
			accept_normal_traffic_by_default = 0;
			break;
		case 'i':
			hip_userspace_ipsec = 1;
			hip_kernel_ipsec_fallback = 0;
			break;
		case 'I':
			hip_userspace_ipsec = 1;
			hip_kernel_ipsec_fallback = 1;
			break;
		case 'k':
			killold = 1;
			break;
		case 'l':
			hip_lsi_support = 1;
			break;
		case 'm':
#ifdef CONFIG_HIP_MIDAUTH
			filter_traffic = 1;
			use_midauth = 1;
			break;
#endif
		case 'o':
			system_based_opp_mode = 1;
			break;
		case 'p':
			limit_capabilities = 1;
			break;
		case 'v':
			log_level = LOGDEBUG_MEDIUM;
			hip_set_logfmt(LOGFMT_SHORT);
			break;
		case ':': /* option without operand */
			printf("Option -%c requires an operand\n", optopt);
			errflg++;
			break;
		case '?':
			printf("Unrecognized option: -%c\n", optopt);
			errflg++;
		}
	}

	if (errflg)
	{
		print_usage();
		printf("Invalid argument. Closing. \n\n");
		exit(2);
	}

	if (!foreground)
	{
		hip_set_logtype(LOGTYPE_SYSLOG);
		HIP_DEBUG("Forking into background\n");
		if (fork() > 0)
			return 0;
	}

	HIP_IFEL(hip_create_lock_file(HIP_FIREWALL_LOCK_FILE, killold), -1,
			"Failed to obtain firewall lock.\n");

	/* Request-response socket with hipfw */
	hip_fw_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	HIP_IFEL((hip_fw_sock < 0), 1, "Could not create socket for firewall.\n");
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = htons(HIP_FIREWALL_SYNC_PORT);
	sock_addr.sin6_addr = in6addr_loopback;

	for (i=0; i<2; i++) {
		err = bind(hip_fw_sock, (struct sockaddr *)& sock_addr,
			   sizeof(sock_addr));
		if (err == 0)
			break;
		else if (err && i == 0)
			sleep(2);
	}

	HIP_IFEL(err, -1, "Bind on firewall socket addr failed. Give -k option to kill old hipfw\n");
	HIP_IFEL(hip_daemon_connect(hip_fw_sock), -1,
		 "connecting socket failed\n");

	/* Only for receiving out-of-sync notifications from hipd  */
	hip_fw_async_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	HIP_IFEL((hip_fw_async_sock < 0), 1, "Could not create socket for firewall.\n");
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
	sock_addr.sin6_addr = in6addr_loopback;
	HIP_IFEL(bind(hip_fw_async_sock, (struct sockaddr *)& sock_addr,
		      sizeof(sock_addr)), -1, "Bind on firewall socket addr failed. Give -k option to kill old hipfw\n");
	HIP_IFEL(hip_daemon_connect(hip_fw_async_sock), -1,
		 "connecting socket failed\n");

	/* Starting hipfw does not always work when hipfw starts first -miika */
	if (hip_userspace_ipsec || hip_sava_router || hip_lsi_support || hip_proxy_status || system_based_opp_mode)
	{
		hip_fw_wait_for_hipd();
	}

	HIP_INFO("firewall pid=%d starting\n", getpid());

	//use by default both ipv4 and ipv6
	HIP_DEBUG("Using ipv4 and ipv6\n");

	read_rule_file(rule_file);
	HIP_DEBUG("starting up with rule_file: %s\n", rule_file);
	HIP_DEBUG("Firewall rule table: \n");
	print_rule_tables();

	firewall_increase_netlink_buffers();
#if !defined(CONFIG_HIP_OPENWRT) && !defined(ANDROID_CHANGES)
	firewall_probe_kernel_modules();
#endif

#ifdef CONFIG_HIP_MIDAUTH
	midauth_init();
#endif

	// create firewall queue handles for IPv4 traffic
	// FIXME died handle will still be used below
	// FIXME memleak - not free'd on exit
	h4 = ipq_create_handle(0, PF_INET);

	if (!h4)
		die(h4);

	HIP_DEBUG("IPv4 handle created\n");

	status = ipq_set_mode(h4, IPQ_COPY_PACKET, HIP_MAX_PACKET);

	if (status < 0)
		die(h4);
	HIP_DEBUG("IPv4 handle mode COPY_PACKET set\n");

	// create firewall queue handles for IPv6 traffic
	// FIXME died handle will still be used below
	// FIXME memleak - not free'd on exit
	h6 = ipq_create_handle(0, PF_INET6);

	_HIP_DEBUG("IPQ error: %s \n", ipq_errstr());

	if (!h6)
		die(h6);
	HIP_DEBUG("IPv6 handle created\n");
	status = ipq_set_mode(h6, IPQ_COPY_PACKET, HIP_MAX_PACKET);

	if (status < 0)
		die(h6);
	HIP_DEBUG("IPv6 handle mode COPY_PACKET set\n");
	// set up ip(6)tables rules
	HIP_IFEL(firewall_init_rules(), -1,
		 "Firewall init failed\n");

	/* Allocate message. */
	// FIXME memleak - not free'd on exit
	msg = hip_msg_alloc();
	if (!msg) {
		err = -1;
		return err;
	}

	HIP_IFEL(init_raw_sockets(), -1, "raw sockets");

#ifdef CONFIG_HIP_PRIVSEP
	if (limit_capabilities) {
		HIP_IFEL(hip_set_lowcapability(0), -1, "Failed to reduce priviledges");
	}
#endif
	//init_timeout_checking(timeout);

#ifdef CONFIG_HIP_HIPPROXY
	request_hipproxy_status(); //send hipproxy status request before the control thread running.
#endif /* CONFIG_HIP_HIPPROXY */

#if 0
	if (!hip_sava_client)
	  request_savah_status(SO_HIP_SAVAH_SERVER_STATUS_REQUEST);
	if(!hip_sava_router)
	  request_savah_status(SO_HIP_SAVAH_CLIENT_STATUS_REQUEST);
#endif
	highest_descriptor = maxof(3, hip_fw_async_sock, h4->fd, h6->fd);

	hip_msg_init(msg);
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_FIREWALL_START,0),-1,
		 "build user hdr\n");
	if (hip_send_recv_daemon_info(msg, 0, hip_fw_sock))
		HIP_DEBUG("Failed to notify hipd of firewall start.\n");
	hip_msg_init(msg);

	// let's show that the firewall is running even with debug NONE
	HIP_DEBUG("firewall running. Entering select loop.\n");

	// firewall started up, now respect the selected log level
	hip_set_logdebug(log_level);

	// do all the work here
	while (1) {
		// set up file descriptors for select
		FD_ZERO(&read_fdset);
		FD_SET(hip_fw_async_sock, &read_fdset);
		FD_SET(h4->fd, &read_fdset);
		FD_SET(h6->fd, &read_fdset);

		timeout.tv_sec = HIP_SELECT_TIMEOUT;
		timeout.tv_usec = 0;

		_HIP_DEBUG("HIP fw select\n");

		// get handle with queued packet and process
		/* @todo: using HIPD_SELECT blocks hipfw with R1 */
		if ((err = select((highest_descriptor + 1), &read_fdset,
				       NULL, NULL, &timeout)) < 0) {
			HIP_PERROR("select error, ignoring\n");
			continue;
		}

#ifdef CONFIG_HIP_MIDAUTH
		if (use_midauth)
			pisa_check_for_random_update();
#endif

		if (FD_ISSET(h4->fd, &read_fdset)) {
			HIP_DEBUG("received IPv4 packet from iptables queue\n");
			err = hip_fw_handle_packet(buf, h4, 4, &ctx);
		}

		if (FD_ISSET(h6->fd, &read_fdset)) {
			HIP_DEBUG("received IPv6 packet from iptables queue\n");
			err = hip_fw_handle_packet(buf, h6, 6, &ctx);
		}

		if (FD_ISSET(hip_fw_async_sock, &read_fdset)) {
			HIP_DEBUG("****** Received HIPD message ******\n");
			bzero(&sock_addr, sizeof(sock_addr));
			alen = sizeof(sock_addr);
			n = recvfrom(hip_fw_async_sock, msg, sizeof(struct hip_common), MSG_PEEK,
		             (struct sockaddr *)&sock_addr, &alen);
			if (n < 0)
			{
				HIP_ERROR("Error receiving message header from daemon.\n");
				err = -1;
				continue;
			}


			/*making sure user messages are received from hipd*/
			//resetting vars to 0 because it is a loop
			is_root = 0, access_ok = 0, msg_type = 0;
			msg_type = hip_get_msg_type(msg);
			is_root = (ntohs(sock_addr.sin6_port) < 1024);
			if(is_root){
				access_ok = 1;
			}else if( !is_root &&
				  (msg_type >= HIP_SO_ANY_MIN &&
				   msg_type <= HIP_SO_ANY_MAX)    ){
				access_ok = 1;
			}
			if(!access_ok){
				HIP_ERROR("The sender of the message is not trusted.\n");
				err = -1;
				continue;
			}


			_HIP_DEBUG("Header received successfully\n");
			alen = sizeof(sock_addr);
			len = hip_get_msg_total_len(msg);

			HIP_DEBUG("Receiving message type %d (%d bytes)\n",
				  hip_get_msg_type(msg), len);
			n = recvfrom(hip_fw_async_sock, msg, len, 0,
		             (struct sockaddr *)&sock_addr, &alen);

			if (n < 0)
			{
				HIP_ERROR("Error receiving message parameters from daemon.\n");
				err = -1;
				continue;
			}

			HIP_ASSERT(n == len);

			if (ntohs(sock_addr.sin6_port) != HIP_DAEMON_LOCAL_PORT) {
			  	int type = hip_get_msg_type(msg);
			        if (type == SO_HIP_FW_BEX_DONE){
				  HIP_DEBUG("SO_HIP_FW_BEX_DONE\n");
				  HIP_DEBUG("%d == %d\n", ntohs(sock_addr.sin6_port), HIP_DAEMON_LOCAL_PORT);
				}
				HIP_DEBUG("Drop, message not from hipd\n");
				err = -1;
				continue;

			}

			err = handle_msg(msg);
			if (err < 0){
				HIP_ERROR("Error handling message\n");
				continue;
				//goto out_err;
			}
		}
	}

 out_err:
	if (hip_fw_async_sock)
		close(hip_fw_async_sock);
	if (hip_fw_sock)
		close(hip_fw_sock);
	if (msg != NULL)
		HIP_FREE(msg);

	firewall_exit();
	return 0;
}

/*----------------EXTERNALLY USED FUNCTIONS-------------------*/

/* currently done in rule_management
 * delete rule needs checking for state options
 */
// FIXME this doesn't make sense. However, setting 0 prevents connection tracking.
void set_stateful_filtering(const int active){
	statefulFiltering = 1;
}

hip_hit_t *hip_fw_get_default_hit(void)
{
	// only query for default hit if global variable is not set
	if (ipv6_addr_is_null(&default_hit))
	{
		_HIP_DEBUG("Querying hipd for default hit\n");
		if (hip_query_default_local_hit_from_hipd())
			return NULL;
	}

	return &default_hit;
}

hip_lsi_t *hip_fw_get_default_lsi(void)
{
	// only query for default lsi if global variable is not set
	if (default_lsi.s_addr == 0)
	{
		_HIP_DEBUG("Querying hipd for default lsi\n");
		if (hip_query_default_local_hit_from_hipd())
			return NULL;
	}

	return &default_lsi;
}
