#ifndef HIP_FIREWALL_H
#define HIP_FIREWALL_H

#include <netinet/in.h>
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
#include <glib.h>
#include <glib/glist.h>
#include <string.h>
#include <netinet/tcp.h>
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

struct firewall_hl {
	hip_lsi_t lsi;
	hip_hit_t hit_our;
        hip_hit_t hit_peer;
        int bex_state;
};

typedef struct firewall_hl firewall_hl_t;

typedef struct pseudo_v6 {
       struct  in6_addr src;
        struct in6_addr dst;
        u16 length;
        u16 zero1;
        u8 zero2;
        u8 next;
} pseudo_v6;

//made public for filter_esp_state function
int match_hit(struct in6_addr match_hit, 
	      struct in6_addr packet_hit, 
	      int boolean);
void set_stateful_filtering(int v);
int get_stateful_filtering();

int firewall_init(char *rule_file);
void firewall_close(int signal);
void firewall_exit();
void firewall_probe_kernel_modules();

/*** Firewall database functions ***/

/*Initializes the firewall database*/
void firewall_init_hldb(void);

/*Comparation definition for the db structure*/
unsigned long hip_firewall_hash_lsi(const void *ptr);
int hip_firewall_match_lsi(const void *ptr1, const void *ptr2);

/*Consult/Modify operations in firewall database*/
firewall_hl_t *firewall_hit_lsi_db_match(hip_lsi_t *lsi_peer);
int firewall_add_hit_lsi(struct in6_addr *hit_our, struct in6_addr *hit_peer, hip_lsi_t *lsi);

/*Using raw_sockets injects the packet in the network with HITs*/
int reinject_packet(struct in6_addr src_hit, struct in6_addr dst_hit, ipq_packet_msg_t *m, int ipTraffic);
int firewall_trigger_outgoing_lsi(ipq_packet_msg_t *m, struct in_addr *ip_src, struct in_addr *ip_dst);
#endif
