#ifndef HIP_FIREWALL_H
#define HIP_FIREWALL_H

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libipq.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <stdio.h>

#include <string.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <sys/types.h>
#include <limits.h>
#include <linux/netfilter_ipv4.h>
#include <pthread.h>
#include <libinet6/message.h>
#include "common_types.h"
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
#include "misc.h"
#include "netdev.h"
#include "lsi.h"
// include of "ext_user_ipsec.h" at the bottom due to dependency

#define HIP_FW_DEFAULT_RULE_FILE "/etc/hip/firewall_conf"
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

struct firewall_hl {
	hip_lsi_t lsi;
	hip_hit_t hit_our;
        hip_hit_t hit_peer;
        int bex_state;
};

typedef struct firewall_hl firewall_hl_t;

#define OTHER_PACKET          0
#define HIP_PACKET            1
#define ESP_PACKET            2
#define TCP_PACKET            3
#define STUN_PACKET           4
#define UDP_PACKET            5

#define FW_PROTO_NUM          6 /* Other, HIP, ESP, TCP */

typedef struct hip_fw_context {
	// queued packet
	ipq_packet_msg_t *ipq_packet;
	
	// IP layer information
	int ip_version; /* 4, 6 */
	int ip_hdr_len;
	struct in6_addr src, dst;
	union {
		struct ip6_hdr *ipv6;
		struct ip *ipv4;
	} ip_hdr;
		
	// transport layer information
	int packet_type; /* HIP_PACKET, ESP_PACKET, etc  */
	union {
		struct hip_esp *esp;
		struct hip_common *hip;
		struct tcphdr *tcp;
	} transport_hdr;
	struct udphdr *udp_encap_hdr;
	//uint32_t spi;
	
	int modified;
} hip_fw_context_t;

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

typedef int (*hip_fw_handler_t)(hip_fw_context_t *);

#define HIP_FIREWALL_LOCK_FILE	"/var/lock/hip_firewall.lock"
struct in6_addr proxy_hit;
extern int hipproxy;
extern struct in6_addr default_hit;

void print_usage(void);
void set_stateful_filtering(int v);
int get_stateful_filtering(void);
void set_escrow_active(int active);
int is_escrow_active(void);
void hip_fw_init_opptcp(void);
void hip_fw_uninit_opptcp(void);
void hip_fw_init_proxy(void);
void hip_fw_uninit_proxy(void);
int hip_fw_init_userspace_ipsec(void);
int hip_fw_uninit_userspace_ipsec(void);
int hip_fw_init_esp_prot(void);
int hip_fw_uninit_esp_prot(void);
int firewall_init_rules(void);

void firewall_close(int signal);
void hip_fw_flush_iptables(void);
void firewall_exit(void);

int match_hit(struct in6_addr match_hit, struct in6_addr packet_hit, int boolean);
int match_hi(struct hip_host_id * hi, struct hip_common * packet);
int match_int(int match, int packet, int boolean);
int match_string(const char * match, const char * packet, int boolean);

static void die(struct ipq_handle *h);

int hip_fw_init_context(hip_fw_context_t *ctx, char *buf, int ip_version);

void allow_packet(struct ipq_handle *handle, unsigned long packetId);
void drop_packet(struct ipq_handle *handle, unsigned long packetId);

int filter_esp(const struct in6_addr * dst_addr, struct hip_esp * esp,
	       unsigned int hook);
int filter_hip(const struct in6_addr * ip6_src,
               const struct in6_addr * ip6_dst, 
               struct hip_common *buf, 
               unsigned int hook, 
               const char * in_if, 
               const char * out_if);

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

int hip_fw_handle_packet(char *buf, struct ipq_handle *hndl, int ip_version,
		hip_fw_context_t *ctx);

void check_and_write_default_config(void);
int main(int argc, char **argv);
void firewall_probe_kernel_modules();
void firewall_increase_netlink_buffers();

// dependent on typedefs in here
#include "user_ipsec.h"

#endif
