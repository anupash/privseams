#ifndef HIP_FIREWALL_H
#define HIP_FIREWALL_H

#include <limits.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libipq.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#ifndef ANDROID_CHANGES
#include <netinet/ip6.h>
#endif
#include <stdint.h>
#include <stdio.h>

#include <string.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <sys/types.h>
#include <limits.h>
#include <linux/netfilter_ipv4.h>
#include <pthread.h>
#include <libhipcore/message.h>
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
#include "libhipcore/utils.h"
#include "misc.h"
#include "netdev.h"
#include "lsi.h"
#include "fw_stun.h"
#include "pjnath.h"
#include "esp_prot_api.h"
#include "esp_prot_conntrack.h"
#include "datapkt.h"
#include "capability.h"
#include "savah_gateway.h"
// include of "user_ipsec.h" at the bottom due to dependency

#ifdef ANDROID_CHANGES
#define HIP_FW_DEFAULT_RULE_FILE "/data/hip/firewall_conf"
#ifndef s6_addr
#  define s6_addr                 in6_u.u6_addr8
#  define s6_addr16               in6_u.u6_addr16
#  define s6_addr32               in6_u.u6_addr32
#endif /* s6_addr */
#else
#define HIP_FW_DEFAULT_RULE_FILE "/etc/hip/firewall_conf"
#endif

#define HIP_FW_FILTER_TRAFFIC_BY_DEFAULT 1
#define HIP_FW_ACCEPT_HIP_ESP_TRAFFIC_BY_DEFAULT 0

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
#define TCP_PACKET            3
#define STUN_PACKET           4
#define UDP_PACKET            5

#define FW_PROTO_NUM          6 /* Other, HIP, ESP, TCP */

typedef int (*hip_fw_handler_t)(hip_fw_context_t *);

#ifndef ANDROID_CHANGES
#define HIP_FIREWALL_LOCK_FILE	"/var/lock/hip_firewall.lock"
#else
#define HIP_FIREWALL_LOCK_FILE	"/data/hip_firewall.lock"
#endif

struct in6_addr proxy_hit;
extern int hipproxy;
extern struct in6_addr default_hit;
extern int esp_relay;

/* FIXME why is this declared extern, you might want to include the .h in sava! */
//extern int request_savah_status(int mode);

void hip_fw_init_opptcp();
void hip_fw_uninit_opptcp();
void hip_fw_init_proxy();
void hip_fw_uninit_proxy();

void set_stateful_filtering(int v);
int hip_fw_sys_opp_set_peer_hit(struct hip_common *msg);
int hip_get_bex_state_from_IPs(struct in6_addr *src_ip,
		      	       struct in6_addr *dst_ip,
			       struct in6_addr *src_hit,
			       struct in6_addr *dst_hit,
			       hip_lsi_t       *src_lsi,
			       hip_lsi_t       *dst_lsi);

hip_hit_t *hip_fw_get_default_hit(void);
int hip_fw_hit_is_our(struct in6_addr *hit);

extern hip_lsi_t local_lsi;

// has been moved here for the following reason: dependent on typedefs above
#include "user_ipsec_api.h"
#include "sava_api.h"


#endif
