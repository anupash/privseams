#ifndef HIP_FIREWALL_H
#define HIP_FIREWALL_H

#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libipq.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <stdio.h>
#include <glib.h>
#include <glib/glist.h>
#include <string.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <linux/netfilter_ipv4.h>
#include <sys/types.h>
#include <pthread.h>
#include <libinet6/message.h>

#include "crypto.h"
#include "ife.h"
#include "state.h"
#include "firewall_control.h"
#include "firewall_defines.h"
#include "esp_decrypt.h"
#include "rule_management.h"
#include "debug.h"
#include "helpers.h"
#include "conntrack.h"
#include "utils.h"
#include "hip_usermode.h"
#include "misc.h"
#include "netdev.h"
#include "hip_sadb.h"

#define HIP_FW_DEFAULT_RULE_FILE "/etc/hip/firewall.conf"
#define HIP_FW_DEFAULT_TIMEOUT   1
#define HIP_FW_CONFIG_FILE_EX \
"# format: HOOK [match] TARGET\n"\
"#   HOOK   = INPUT, OUTPUT or FORWARD\n"\
"#   TARGET = ACCEPT or DROP\n"\
"#   match  = -src_hit [!] <hit value> --hi <file name>\n"\
"#            -dst_hit [!] <hit>\n"\
"#            -type [!] <hip packet type>\n"\
"#            -i [!] <incoming interface>\n"\
"#            -o [!] <outgoing interface>\n"\
"#            -state [!] <state> --verify_responder --accept_mobile --decrypt_contents\n"\
"#\n"\
"\n"

#define OTHER_PACKET          0
#define HIP_PACKET            1
#define ESP_PACKET            2
#define STUN_PACKET           3
#define TCP_PACKET            4
#define UDP_PACKET            5

#define FW_PROTO_NUM        4 /* Other, HIP, ESP, TCP */

typedef struct hip_fw_context {
	// queued packet
	ipq_packet_msg_t *packet;
	
	// IP layer information
	int ip_version; /* 4, 6 */
	struct in6_addr src, dst;
	union {
		struct ip6_hdr *ipv6;
		struct ip *ipv4;
	} network_hdr;
		
	// transport layer information
	int packet_type; /* HIP_PACKET, ESP_PACKET, etc  */
	union {
		struct hip_esp *esp;
		struct hip_common *hip;
		struct tcphdr *tcp;
	} transport_hdr;
	struct udphdr *udp_encap_hdr;
} hip_fw_context_t;

typedef struct hip_proxy_t {
	hip_hit_t hit_our;
	hip_hit_t hit_peer;
	hip_hit_t hit_proxy;
	struct in6_addr addr_our;
	struct in6_addr addr_peer;
	struct in6_addr addr_proxy;
	int state;
	int hip_capable;
} hip_proxy_t;

struct hip_conn_key {
	uint8_t protocol;
	uint16_t port_client;
	uint16_t port_peer;
	struct in6_addr hit_peer;
	struct in6_addr hit_proxy;
}  __attribute__ ((packed));

typedef struct hip_conn_t  {
	struct hip_conn_key key;
	int state;
	struct in6_addr addr_client; // addr_proxy_client	
	struct in6_addr addr_peer; // addr_proxy_peer	
} hip_conn_t;

#define HIP_FIREWALL_LOCK_FILE	"/var/lock/hip_firewall.lock"
struct in6_addr proxy_hit;
extern int hipproxy;

//made public for filter_esp_state function
int match_hit(struct in6_addr match_hit, 
	      struct in6_addr packet_hit, 
	      int boolean);
void set_stateful_filtering(int v);
int get_stateful_filtering();

int firewall_init();
void firewall_close(int signal);
void firewall_exit();
void firewall_probe_kernel_modules();
void firewall_increase_netlink_buffers();
void examine_incoming_tcp_packet(struct ipq_handle *, unsigned long, void *, int, int);
void hip_request_send_i1_to_hip_peer_from_hipd(struct in6_addr *peer_hit,
					       struct in6_addr *peer_ip);
void hip_request_unblock_app_from_hipd(const struct in6_addr *peer_ip);
void hip_request_oppipdb_add_entry(struct in6_addr *peer_ip);


void hip_firewall_userspace_ipsec_output(struct ipq_handle *handle,
					 unsigned long	    packetId,
					 void		   *hdr,
					 int		    trafficType,
					 ipq_packet_msg_t *ip_packet_in_the_queue);


void hip_firewall_userspace_ipsec_input();

int hip_esp_traffic_userspace_handler(pthread_t *hip_esp_userspace_id_param, 
				      void (*hip_esp_userspace_traffic)(void *), 
				      void *thread_param);
int hip_fw_handle_other_output(hip_fw_context_t *ctx);
int hip_fw_handle_hip_output(hip_fw_context_t *ctx);
int hip_fw_handle_esp_output(hip_fw_context_t *ctx);
int hip_fw_handle_tcp_output(hip_fw_context_t *ctx);

int hip_fw_handle_other_input(hip_fw_context_t *ctx);
int hip_fw_handle_hip_input(hip_fw_context_t *ctx);
int hip_fw_handle_esp_input(hip_fw_context_t *ctx);
int hip_fw_handle_tcp_input(hip_fw_context_t *ctx);

int hip_fw_handle_other_forward(hip_fw_context_t *ctx);
int hip_fw_handle_hip_forward(hip_fw_context_t *ctx);
int hip_fw_handle_esp_forward(hip_fw_context_t *ctx);
int hip_fw_handle_tcp_forward(hip_fw_context_t *ctx);


#endif

