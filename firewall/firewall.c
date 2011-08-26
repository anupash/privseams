/*
 * Copyright (c) 2010-2011 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file
 * All functionality that requires packet capture using libipq are contained in the
 * hipfw. The basic function of the hipfw is to track HIP packets and track associate
 * them with the related ESP connections with SPIs. This way, the hipfw can support access control
 * for mobile devices based on their public keys (or HITs). Please see the following documentation
 * on the basic funtionality of the hipfw:
 * - <a href="http://hipl.hiit.fi/papers/essi_dippa.pdf">E. Vehmersalo, Host Identity Protocol Enabled Firewall: A Prototype Implementation and Analysis, Master's thesis, September 2005</a>
 * - <a href="http://www.usenix.org/events/usenix07/poster.html">Lindqvist, Janne; Vehmersalo, Essi; Komu, Miika; Manner, Jukka, Enterprise Network Packet Filtering for Mobile Cryptographic Identities,
 * Usenix 2007 Annual Technical Conference, Santa Clara, CA, June 20, 2007</a>
 * - Rene Hummen. Secure Identity-based Middlebox Functions using the Host Identity Protocol. Master's thesis, RWTH Aachen, 2009.
 *
 * The hipfw supports additional extensions, such as LSIs, userspace IPsec and hiccups. See
 * the hyperlinks in the files that implement the extensions for more information.
 *
 * @brief HIP multipurpose firewall toolkit
 *
 * @note: HIPU: requires libipq, might need pcap libraries
 */

#define _BSD_SOURCE

#include <libipq.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <linux/netfilter_ipv4.h>

#include "lib/core/builder.h"
#include "lib/core/capability.h"
#include "lib/core/common.h"
#include "lib/core/debug.h"
#include "lib/core/filemanip.h"
#include "lib/core/hip_udp.h"
#include "lib/core/ife.h"
#include "lib/core/message.h"
#include "lib/core/performance.h"
#include "lib/core/prefix.h"
#include "lib/core/util.h"
#include "hipd/hipd.h"
#include "config.h"
#include "cache.h"
#include "common_types.h"
#include "conntrack.h"
#include "esp_prot_api.h"
#include "esp_prot_conntrack.h"
#include "firewall_control.h"
#include "firewall_defines.h"
#include "helpers.h"
#include "lsi.h"
#include "midauth.h"
#include "pisa.h"
#include "port_bindings.h"
#include "reinject.h"
#include "rule_management.h"
#include "user_ipsec_api.h"
#include "firewall.h"
#include "modules/signaling/firewall/signaling_hipfw_oslayer.h"
#include "modules/signaling/firewall/signaling_hipfw.h"

/* location of the lock file */
#define HIP_FIREWALL_LOCK_FILE HIPL_LOCKDIR "/hip_firewall.lock"

/* default settings */
#define HIP_FW_FILTER_TRAFFIC_BY_DEFAULT 1
#define HIP_FW_ACCEPT_HIP_ESP_TRAFFIC_BY_DEFAULT 0
#define HIP_FW_ACCEPT_NORMAL_TRAFFIC_BY_DEFAULT 1


/* firewall-specific state */
int accept_normal_traffic_by_default  = HIP_FW_ACCEPT_NORMAL_TRAFFIC_BY_DEFAULT;
int accept_hip_esp_traffic_by_default = HIP_FW_ACCEPT_HIP_ESP_TRAFFIC_BY_DEFAULT;
int log_level                         = LOGDEBUG_NONE;
/* Default HIT - do not access this directly, call hip_fw_get_default_hit() */
static hip_hit_t default_hit;
/* Default LSI - do not access this directly, call hip_fw_get_default_lsi() */
static hip_lsi_t default_lsi;

/* definition of the function pointer (see below) */
typedef int (*hip_fw_handler)(struct hip_fw_context *);
/* The firewall handlers do not accept rules directly. They should return
 * zero when they transformed packet and the original should be dropped.
 * Non-zero means that there was an error or the packet handler did not
 * know what to do with the packet. */
static hip_fw_handler fw_handlers[NF_IP_NUMHOOKS][FW_PROTO_NUM];

/* extension-specific state */
int hip_userspace_ipsec            = 0;
int restore_filter_traffic         = HIP_FW_FILTER_TRAFFIC_BY_DEFAULT;
int restore_accept_hip_esp_traffic = HIP_FW_ACCEPT_HIP_ESP_TRAFFIC_BY_DEFAULT;

/* externally used state */
// TODO try to decrease number of globally used variables
int filter_traffic            = HIP_FW_FILTER_TRAFFIC_BY_DEFAULT;
int hip_kernel_ipsec_fallback = 0;
int hip_lsi_support           = 0;
int esp_relay                 = 0;
int hip_esp_protection        = 0;
int esp_speedup               = 0; /**< Enable esp speedup via dynamic iptables usage (-u option). */
#ifdef CONFIG_HIP_MIDAUTH
int use_midauth = 0;
#endif

/** Use this to send and receive responses to hipd. Notice that
 * firewall_control.c has a separate socket for receiving asynchronous
 * messages from hipd (i.e. messages that were not requests from hipfw).
 * The two sockets need to be kept separate because the hipfw might
 * mistake an asynchronous message from hipd to an response. The alternative
 * to two sockets are sequence numbers but it would have required reworking
 * too much of the firewall.
 *
 * @todo make accessible through send function, no-one should read on that
 */
int hip_fw_sock = 0;
/**
 * Use this socket *only* for receiving async messages from hipd
 * @todo make static, no-one should read on that
 */
static int hip_fw_async_sock = 0;

/*----------------INIT FUNCTIONS------------------*/

/**
 * Initialize packet capture rules for userspace IPsec
 *
 * @return zero on success and non-zero on failure
 */
static int hip_fw_init_userspace_ipsec(void)
{
    int            err = 0;
    int            ver_c;
    struct utsname name;

    HIP_IFEL(uname(&name), -1, "Failed to retrieve kernel information: %s\n",
             strerror(errno));
    ver_c = atoi(&name.release[4]);

    if (hip_userspace_ipsec) {
        if (ver_c >= 27) {
            HIP_INFO("You are using kernel version %s. Userspace " \
                     "ipsec is not necessary with version 2.6.27 or higher.\n",
                     name.release);
        }

        HIP_IFEL(userspace_ipsec_init(), -1,
                 "failed to initialize userspace ipsec\n");

        // queue incoming ESP over IPv4 and IPv4 UDP encapsulated traffic
        system_print("iptables -I HIPFW-INPUT -p 50 -j QUEUE");
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

/**
 * Uninitialize packet capture rules for userspace IPsec
 *
 * @return zero on success and non-zero on failure
 */
static int hip_fw_uninit_userspace_ipsec(void)
{
    int err = 0;

    if (hip_userspace_ipsec) {
        // set global variable to off
        hip_userspace_ipsec = 0;

        HIP_IFEL(userspace_ipsec_uninit(), -1, "failed to uninit user ipsec\n");

        // delete all rules previously set up for this extension
        system_print("iptables -D HIPFW-INPUT -p 50 -j QUEUE 2> /dev/null");
        system_print("iptables -D HIPFW-INPUT -p 17 --dport 10500 -j QUEUE 2> /dev/null");
        system_print("iptables -D HIPFW-INPUT -p 17 --sport 10500 -j QUEUE 2> /dev/null");

        system_print("ip6tables -D HIPFW-INPUT -p 50 -j QUEUE 2> /dev/null");

        system_print("ip6tables -D HIPFW-OUTPUT -p 58 -d 2001:0010::/28 -j QUEUE 2> /dev/null");
        system_print("ip6tables -D HIPFW-OUTPUT -p 6 -d 2001:0010::/28 -j QUEUE 2> /dev/null");
        system_print("ip6tables -D HIPFW-OUTPUT -p 17 -d 2001:0010::/28 -j QUEUE 2> /dev/null");
    }

out_err:
    return err;
}

/**
 * Initialize packet capture rules for ESP protection extensions
 *
 * @return zero on success and non-zero on failure
 *
 */
static int hip_fw_init_esp_prot(void)
{
    int err = 0;

    // userspace ipsec is a prerequisite for esp protection
    if (hip_esp_protection) {
        if (hip_userspace_ipsec) {
            HIP_IFEL(esp_prot_init(), -1, "failed to init esp protection\n");
        } else {
            HIP_ERROR("userspace ipsec needs to be turned on for this to work\n");

            err = 1;
            goto out_err;
        }
    }

out_err:
    return err;
}

/**
 * Uninitialize packet capture rules for ESP protection extensions
 *
 * @return zero on success and non-zero on failure
 */
static int hip_fw_uninit_esp_prot(void)
{
    int err = 0;

    if (hip_esp_protection) {
        // set global variable to off in fw
        hip_esp_protection = 0;

        HIP_IFEL(esp_prot_uninit(), -1, "failed to uninit esp protection\n");
    }

out_err:
    return err;
}

/**
 * Initialize packet capture rules for ESP connection tracking
 *
 * @return zero on success and non-zero on failure
 */
static int hip_fw_init_esp_prot_conntrack(void)
{
    int err = 0;

    if (hip_esp_protection && filter_traffic) {
        HIP_IFEL(esp_prot_conntrack_init(), -1,
                 "failed to init esp protection conntracking\n");
    }

out_err:
    return err;
}

/**
 * Uninitialize rules for connection tracking for ESP-protection extensions
 *
 * @return zero on success and non-zero on failure
 */
static int hip_fw_uninit_esp_prot_conntrack(void)
{
    int err = 0;

    if (hip_esp_protection && filter_traffic) {
        HIP_IFEL(esp_prot_conntrack_uninit(), -1,
                 "failed to uninit esp protection conntracking\n");
    }

out_err:
    return err;
}

/**
 * Initialize packet capture rules for LSI support
 *
 * @return zero on success and non-zero on failure
 */
static int hip_fw_init_lsi_support(void)
{
    int err = 0;

    if (hip_lsi_support) {
        // add the rule
        system_print("iptables -I HIPFW-OUTPUT -d " HIP_FULL_LSI_STR " -j QUEUE");

        /* LSI support: incoming HIT packets, captured to decide if
         * HITs may be mapped to LSIs */
        system_print("ip6tables -I HIPFW-INPUT -d 2001:0010::/28 -j QUEUE");
    }

    return err;
}

/**
 * Uninitialize packet capture rules for LSI support
 *
 * @return zero on success and non-zero on failure
 */
static int hip_fw_uninit_lsi_support(void)
{
    int err = 0;

    if (hip_lsi_support) {
        // set global variable to off
        hip_lsi_support = 0;

        // remove the rule
        system_print("iptables -D HIPFW-OUTPUT -d " HIP_FULL_LSI_STR " -j QUEUE 2> /dev/null");

        system_print("ip6tables -D HIPFW-INPUT -d 2001:0010::/28 -j QUEUE 2> /dev/null");
    }

    return err;
}

/**
 * Initialize signaling extensions.
 *
 * @return zero on success and non-zero on failure
 */
static int hip_fw_init_signaling_extensions(void)
{
    int err = 0;

    OpenSSL_add_all_algorithms();

    if (filter_traffic) {
        HIP_IFEL(signaling_hipfw_init(NULL),
                 -1, "failed to init signaling firewall\n");
    } else {
        HIP_IFEL(signaling_hipfw_oslayer_init(),
                 -1, "failed to init signaling os layer\n");
    }

    if (!hip_userspace_ipsec) {
        // queue outgoing TCP and UDP packets sent to HITs
        system_print("ip6tables -I HIPFW-OUTPUT -p tcp -d 2001:0010::/28 -j QUEUE");
        system_print("ip6tables -I HIPFW-OUTPUT -p udp -d 2001:0010::/28 -j QUEUE");
    }

out_err:
    return err;
}

/**
 * Uninitialize signaling firewall application.
 *
 * @return zero on success and non-zero on failure
 */
static int hip_fw_uninit_signaling_extensions(void)
{
    int err = 0;

    if (filter_traffic) {
        HIP_IFEL(signaling_hipfw_uninit(), -1,
                 "failed to uninit signaling firewall\n");
    } else {
        HIP_IFEL(signaling_hipfw_oslayer_uninit(), -1,
                 "failed to uninit signaling os layer\n");
    }

out_err:
    return err;
}

/**
 * Initialize all basic and extended packet capture rules
 *
 */
static void firewall_init_filter_traffic(void)
{
    if (filter_traffic) {
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

/**
 * Uninitialize all basic and extended packet capture rules
 *
 */
static void firewall_uninit_filter_traffic(void)
{
    system_print("iptables -D HIPFW-FORWARD -p 139 -j QUEUE");
    system_print("iptables -D HIPFW-FORWARD -p 50 -j QUEUE");
    system_print("iptables -D HIPFW-FORWARD -p 17 --dport 10500 -j QUEUE");
    system_print("iptables -D HIPFW-FORWARD -p 17 --sport 10500 -j QUEUE");

    system_print("iptables -D HIPFW-INPUT -p 139 -j QUEUE");
    system_print("iptables -D HIPFW-INPUT -p 50 -j QUEUE");
    system_print("iptables -D HIPFW-INPUT -p 17 --dport 10500 -j QUEUE");
    system_print("iptables -D HIPFW-INPUT -p 17 --sport 10500 -j QUEUE");

    system_print("iptables -D HIPFW-OUTPUT -p 139 -j QUEUE");
    system_print("iptables -D HIPFW-OUTPUT -p 50 -j QUEUE");
    system_print("iptables -D HIPFW-OUTPUT -p 17 --dport 10500 -j QUEUE");
    system_print("iptables -D HIPFW-OUTPUT -p 17 --sport 10500 -j QUEUE");

    system_print("ip6tables -D HIPFW-FORWARD -p 139 -j QUEUE");
    system_print("ip6tables -D HIPFW-FORWARD -p 50 -j QUEUE");
    system_print("ip6tables -D HIPFW-FORWARD -p 17 --dport 10500 -j QUEUE");
    system_print("ip6tables -D HIPFW-FORWARD -p 17 --sport 10500 -j QUEUE");

    system_print("ip6tables -D HIPFW-INPUT -p 139 -j QUEUE");
    system_print("ip6tables -D HIPFW-INPUT -p 50 -j QUEUE");
    system_print("ip6tables -D HIPFW-INPUT -p 17 --dport 10500 -j QUEUE");
    system_print("ip6tables -D HIPFW-INPUT -p 17 --sport 10500 -j QUEUE");

    system_print("ip6tables -D HIPFW-OUTPUT -p 139 -j QUEUE");
    system_print("ip6tables -D HIPFW-OUTPUT -p 50 -j QUEUE");
    system_print("ip6tables -D HIPFW-OUTPUT -p 17 --dport 10500 -j QUEUE");
    system_print("ip6tables -D HIPFW-OUTPUT -p 17 --sport 10500 -j QUEUE");
}

/**
 * Initialize all basic and extended packet capture rules
 *
 * @return zero on success and non-zero on failure
 *
 */
static int firewall_init_extensions(void)
{
    int err = 0;

    // TARGET (-j) QUEUE will transfer matching packets to userspace
    // these packets will be handled using libipq

    // this has to be set up first in order to be the default behavior
    if (!accept_normal_traffic_by_default) {
        // make DROP the default behavior of all chains
        // TODO don't drop LSIs -> else IPv4 apps won't work
        // -> also messaging between HIPd and firewall is blocked here
        system_print("iptables -I HIPFW-FORWARD ! -d 127.0.0.1 -j DROP"); /* @todo: ! LSI PREFIX */
        system_print("iptables -I HIPFW-INPUT ! -d 127.0.0.1 -j DROP"); /* @todo: ! LSI PREFIX */
        system_print("iptables -I HIPFW-OUTPUT ! -d 127.0.0.1 -j DROP"); /* @todo: ! LSI PREFIX */

        // but still allow loopback and HITs as destination
        system_print("ip6tables -I HIPFW-FORWARD ! -d 2001:0010::/28 -j DROP");
        system_print("ip6tables -I HIPFW-INPUT ! -d 2001:0010::/28 -j DROP");
        system_print("ip6tables -I HIPFW-OUTPUT ! -d 2001:0010::/28 -j DROP");
        system_print("ip6tables -I HIPFW-FORWARD -d ::1 -j ACCEPT");
        system_print("ip6tables -I HIPFW-INPUT -d ::1 -j ACCEPT");
        system_print("ip6tables -I HIPFW-OUTPUT -d ::1 -j ACCEPT");
    }


    firewall_init_filter_traffic();
    // Initializing local cache database
    hip_firewall_cache_init_hldb();
    HIP_IFEL(hip_fw_init_lsi_support(), -1, "failed to load extension\n");
    HIP_IFEL(hip_fw_init_userspace_ipsec(), -1, "failed to load extension\n");
    HIP_IFEL(hip_fw_init_esp_prot(), -1, "failed to load extension\n");
    HIP_IFEL(hip_fw_init_esp_prot_conntrack(), -1, "failed to load extension\n");

#ifdef CONFIG_HIP_MIDAUTH
    midauth_init();
#endif

    // Initializing local port cache database
    hip_port_bindings_init(true);
    /* Initialize raw sockets for packet reinjection */
    hip_firewall_init_raw_sockets();

    /* Initialize signaling module */
    HIP_IFEL(hip_fw_init_signaling_extensions(), -1, "failed to load signaling extension\n");

out_err:
    return err;
}

/**
 * Initialize ESP relay extensions
 *
 * @return zero on success, non-zero on error
 *
 */
int hip_fw_init_esp_relay(void)
{
    int err = 0;

    esp_relay = 1;

    /* Required for ESP relay and might not be active */
    if (!filter_traffic) {
        filter_traffic = 1;
        /* Still accept HIP traffic as if the -A flag had been given
         * instead of -F */
        accept_hip_esp_traffic_by_default = 1;
        restore_accept_hip_esp_traffic    = 1;

        firewall_init_filter_traffic();
    }

    return err;
}

/**
 * uninitialize ESP relay extensions
 *
 */
void hip_fw_uninit_esp_relay(void)
{
    esp_relay = 0;

    if (restore_filter_traffic == 0) {
        filter_traffic = 0;
        firewall_uninit_filter_traffic();
    }
}

/*-------------------HELPER FUNCTIONS---------------------*/

/**
 * Ask default HIT and LSI from hipd
 *
 * @return zero on success and non-zero on failure
 */
static int hip_query_default_local_hit_from_hipd(void)
{
    int                          err   = 0;
    struct hip_common           *msg   = NULL;
    const struct hip_tlv_common *param = NULL;
    const hip_hit_t             *hit   = NULL;
    const hip_lsi_t             *lsi   = NULL;

    HIP_IFE(!(msg = hip_msg_alloc()), -1);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_GET_DEFAULT_HIT, 0), -1,
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
    free(msg);
    return err;
}

/**
 * Uninitialize all basic and extended packet capture rules
 */
static void hip_fw_flush_iptables(void)
{
    HIP_DEBUG("Firewall flush; may cause warnings on hipfw init\n");
    HIP_DEBUG("Deleting hipfw subchains from main chains\n");

    system_print("iptables -D INPUT -j HIPFW-INPUT 2> /dev/null");
    system_print("iptables -D OUTPUT -j HIPFW-OUTPUT 2> /dev/null");
    system_print("iptables -D FORWARD -j HIPFW-FORWARD 2> /dev/null");

    system_print("ip6tables -D INPUT -j HIPFW-INPUT 2> /dev/null");
    system_print("ip6tables -D OUTPUT -j HIPFW-OUTPUT 2> /dev/null");
    system_print("ip6tables -D FORWARD -j HIPFW-FORWARD 2> /dev/null");

    HIP_DEBUG("Flushing hipfw chains\n");

    /* Flush in case there are some residual rules */
    system_print("iptables -F HIPFW-INPUT 2> /dev/null");
    system_print("iptables -F HIPFW-OUTPUT 2> /dev/null");
    system_print("iptables -F HIPFW-FORWARD 2> /dev/null");
    system_print("ip6tables -F HIPFW-INPUT 2> /dev/null");
    system_print("ip6tables -F HIPFW-OUTPUT 2> /dev/null");
    system_print("ip6tables -F HIPFW-FORWARD 2> /dev/null");

    HIP_DEBUG("Deleting hipfw chains\n");

    system_print("iptables -X HIPFW-INPUT 2> /dev/null");
    system_print("iptables -X HIPFW-OUTPUT 2> /dev/null");
    system_print("iptables -X HIPFW-FORWARD 2> /dev/null");
    system_print("ip6tables -X HIPFW-INPUT 2> /dev/null");
    system_print("ip6tables -X HIPFW-OUTPUT 2> /dev/null");
    system_print("ip6tables -X HIPFW-FORWARD 2> /dev/null");
}

/**
 * Firewall signal handler (SIGINT, SIGTERM). Exit firewall gracefully
 * and clean up all packet capture rules.
 */
static void firewall_exit(void)
{
    struct hip_common *msg = NULL;

    HIP_DEBUG("Firewall exit\n");

    if ((msg = hip_msg_alloc()) != NULL) {
        if (hip_build_user_hdr(msg, HIP_MSG_FIREWALL_QUIT, 0) ||
            hip_send_recv_daemon_info(msg, 1, hip_fw_sock)) {
            HIP_DEBUG("Failed to notify hipd of firewall shutdown.\n");
        }
        free(msg);
    }

    hip_firewall_cache_delete_hldb(1);
    hip_port_bindings_uninit();
    hip_fw_flush_iptables();
    /* rules have to be removed first, otherwise HIP packets won't pass through
     * at this time any more */
    hip_fw_uninit_userspace_ipsec();
    hip_fw_uninit_esp_prot();
    hip_fw_uninit_esp_prot_conntrack();
    hip_fw_uninit_lsi_support();
    hip_fw_uninit_conntrack();
    hip_fw_uninit_signaling_extensions();

#ifdef CONFIG_HIP_PERFORMANCE
    /* Deallocate memory of perf_set after finishing all of tests */
    //hip_perf_destroy(perf_set);
#endif

    hip_remove_lock_file(HIP_FIREWALL_LOCK_FILE);
}

/**
 * Firewall signal handler wrapper (callback).
 * Exit firewall gracefully and clean up all packet capture rules.
 *
 * @param sig Signal number (currently SIGINT or SIGTERM).
 *
 * @see firewall_init()
 * @see firewall_exit()
 */
static void firewall_close(DBG const int sig)
{
    static unsigned int count = 0;

    HIP_DEBUG("Caught signal %d, closing firewall.\n", sig);

    count += 1;
    switch (count) {
    case 1:
        firewall_exit();
        exit(EXIT_SUCCESS);
        break;
    case 2:
        HIP_DEBUG("Received another signal\n");
        HIP_DEBUG("Send one more signal to force exit\n");
        break;
    default:
        HIP_DEBUG("Hard exit\n");
        exit(EXIT_FAILURE);
    }
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
static void firewall_increase_netlink_buffers(void)
{
    HIP_DEBUG("Increasing the netlink buffers\n");

    system_print("echo 1048576 > /proc/sys/net/core/rmem_default");
    system_print("echo 1048576 > /proc/sys/net/core/rmem_max");
    system_print("echo 1048576 > /proc/sys/net/core/wmem_default");
    system_print("echo 1048576 > /proc/sys/net/core/wmem_max");
}

/**
 * Loads several modules that are needed by the firewall.
 */
static void firewall_probe_kernel_modules(void)
{
    int         count, err, status;
    char        cmd[40];
    int         mod_total;
    const char *mod_name[] =
    { "ip_queue", "ip6_queue", "iptable_filter", "ip6table_filter" };

    mod_total = sizeof(mod_name) / sizeof(char *);

    HIP_DEBUG("Probing for %d modules. When the modules are built-in, the errors can be ignored\n", mod_total);

    for (count = 0; count < mod_total; count++) {
        snprintf(cmd, sizeof(cmd), "%s %s", "/sbin/modprobe",
                 mod_name[count]);
        HIP_DEBUG("%s\n", cmd);
        err = fork();
        if (err < 0) {
            HIP_ERROR("Failed to fork() for modprobe!\n");
        } else if (err == 0) {
            /* Redirect stderr, so few non fatal errors will not show up. */
            if (freopen("/dev/null", "w", stderr) == NULL) {
                HIP_ERROR("Could not freopen /dev/null");
            }
            execlp("/sbin/modprobe", "/sbin/modprobe",
                   mod_name[count], NULL);
        } else {
            waitpid(err, &status, 0);
        }
    }
    HIP_DEBUG("Probing completed\n");
}

/*-------------PACKET FILTERING FUNCTIONS------------------*/

/**
 * Test if two HITs match
 *
 * @param matching_hit the first HIT
 * @param packet_hit the second HIT
 * @param boolean boolean flag (0 or 1)
 *
 * @return 1 if HITs match and 0 otherwise when boolean is 1. The return value is reversed when the boolean
 *         value is 0.
 */
static int match_hit(const struct in6_addr matching_hit,
                     const struct in6_addr packet_hit,
                     const int boolean)
{
    int i = IN6_ARE_ADDR_EQUAL(&matching_hit, &packet_hit);

    HIP_DEBUG("match_hit: hit1: %s hit2: %s bool: %d match: %d\n",
              addr_to_numeric(&matching_hit), addr_to_numeric(&packet_hit),
              boolean, i);
    if (boolean) {
        return i;
    } else {
        return !i;
    }
}

/**
 * Test if two integers match
 *
 * @param match the first integer
 * @param packet the second integer
 * @param boolean boolean flag (0 or 1)
 *
 * @return 1 if integers match and 0 otherwise when the boolean is 1. The return
 *         value is reversed when the boolean value is 0.
 */
static int match_int(const int match, const int packet, const int boolean)
{
    if (boolean) {
        return match == packet;
    } else {
        return !(match == packet);
    }
}

/**
 * Test if two strings match
 *
 * @param match the first string
 * @param packet the second string
 * @param boolean boolean flag (0 or 1)
 *
 * @return 1 if strings match and 0 otherwise when the boolean is 1. The return
 *         value is reversed when the boolean value is 0.
 */
static int match_string(const char *match, const char *packet, const int boolean)
{
    if (boolean) {
        return !strcmp(match, packet);
    } else {
        return strcmp(match, packet);
    }
}

/**
 * A wrapper for filter_esp_state. Match the esp packet with the state
 * in the connection tracking. There is no need to match the rule-set
 * again as we already filtered the HIP control packets. If we wanted
 * to disallow a connection, we should do it in filter_hip.
 *
 * @param ctx packet context
 * @return the verdict (1 for pass and 0 for drop)
 */
static int filter_esp(const struct hip_fw_context *ctx)
{
    /* drop packet by default */
    int verdict = 0, ret;

    if (esp_relay && ctx->udp_encap_hdr &&
        ((ret = hipfw_relay_esp(ctx)) <= 0)) {
        /* 0: drop original and reinject new packet
         * -1: accept reinject packet and avoid filter_esp_state
         * 1: just let it pass => proceed to filter */
        if (ret == 0) {
            HIP_DEBUG("Drop original and reinject relayed ESP packet\n");
            verdict = 0;
        } else if (ret == -1) {
            HIP_DEBUG("Accept reinjected packet\n");
            verdict = 1;
        } else {
            HIP_ASSERT(0);
        }
    } else if (filter_esp_state(ctx) > 0) {
        verdict = 1;
        HIP_DEBUG("ESP packet successfully passed filtering\n");
    } else {
        verdict = 0;
        HIP_DEBUG("ESP packet NOT authed in ESP filtering\n");
    }

    return verdict;
}

/**
 * filter the hip packet according to the connection tracking rules
 *
 * @param buf the HIP control packet
 * @param hook ipqueue hook
 * @param in_if ipqueue input interface
 * @param out_if ipqueue output interface
 * @param ctx packet context
 *
 * @return the verdict (1 for pass and 0 for drop)
 */
static int filter_hip(struct hip_common *const buf,
                      const unsigned int hook,
                      const char *const in_if,
                      const char *const out_if,
                      struct hip_fw_context *const ctx)
{
    // complete rule list for hook (== IN / OUT / FORWARD)
    struct dlist *list = get_rule_list(hook);
    struct rule  *rule = NULL;
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

    HIP_DEBUG("HIP type number is %d\n", buf->type_hdr);

    if (buf->type_hdr == HIP_I1) {
        HIP_INFO("received packet type: I1\n");
        print_addr = 1;
    } else if (buf->type_hdr == HIP_R1) {
        HIP_INFO("received packet type: R1\n");
        print_addr = 1;
    } else if (buf->type_hdr == HIP_I2) {
        HIP_INFO("received packet type: I2\n");
        print_addr = 1;
    } else if (buf->type_hdr == HIP_R2) {
        HIP_INFO("received packet type: R2\n");
        print_addr = 1;
    } else if (buf->type_hdr == HIP_UPDATE) {
        HIP_INFO("received packet type: UPDATE\n");
        print_addr = 1;
    } else if (buf->type_hdr == HIP_CLOSE) {
        HIP_INFO("received packet type: CLOSE\n");
        print_addr = 1;
    } else if (buf->type_hdr == HIP_CLOSE_ACK) {
        HIP_INFO("received packet type: CLOSE_ACK\n");
        print_addr = 1;
    } else if (buf->type_hdr == HIP_NOTIFY) {
        HIP_DEBUG("received packet type: NOTIFY\n");
    } else if (buf->type_hdr == HIP_LUPDATE) {
        HIP_DEBUG("received packet type: LIGHT UPDATE\n");
    } else {
        HIP_DEBUG("received packet type: UNKNOWN\n");
    }

    if (print_addr) {
        HIP_INFO_HIT("src hit", &buf->hits);
        HIP_INFO_HIT("dst hit", &buf->hitr);
        HIP_INFO_IN6ADDR("src ip", &ctx->src);
        HIP_INFO_IN6ADDR("dst ip", &ctx->dst);
    }

    while (list != NULL) {
        match = 1;
        rule  = list->data;

        // check src_hit if defined in rule
        if (match && rule->src_hit) {
            HIP_DEBUG("src_hit\n");

            if (!match_hit(rule->src_hit->value,
                           buf->hits,
                           rule->src_hit->boolean)) {
                match = 0;
            }
        }

        // check dst_hit if defined in rule
        if (match && rule->dst_hit) {
            HIP_DEBUG("dst_hit\n");

            if (!match_hit(rule->dst_hit->value,
                           buf->hitr,
                           rule->dst_hit->boolean)) {
                match = 0;
            }
        }

        // check the HIP packet type (I1, UPDATE, etc.)
        if (match && rule->type) {
            HIP_DEBUG("type\n");
            if (!match_int(rule->type->value,
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
         * matches the one specified in the rule */
        if (match && rule->in_if) {
            if (!match_string(rule->in_if->value, in_if,
                              rule->in_if->boolean)) {
                match = 0;
            }

            HIP_DEBUG("in_if rule: %s, packet: %s, boolean: %d, match: %d \n",
                      rule->in_if->value,
                      in_if, rule->in_if->boolean, match);
        }

        /* this checks, if the the output interface of the packet matches the
         * one specified in the rule */
        if (match && rule->out_if) {
            if (!match_string(rule->out_if->value,
                              out_if,
                              rule->out_if->boolean)) {
                match = 0;
            }

            HIP_DEBUG("out_if rule: %s, packet: %s, boolean: %d, match: %d \n",
                      rule->out_if->value, out_if, rule->out_if->boolean,
                      match);
        }

        /* check if packet matches state from connection tracking
         * must be last, so not called if packet is going to be
         * dropped */
        if (match && rule->state) {
            int filter_state_verdict = filter_state(buf, rule->state, rule->accept, ctx);

            /* we at least had some packet before -> check
             * this packet this will also check the signature of
             * the packet, if we already have a src_HI stored
             * for the _connection_ */
            if (filter_state_verdict == 0 || filter_state_verdict == -1) {
                match = 0;
            } else {
                // if it is a valid packet, this also tracked the packet
                conntracked = 1;
            }

            HIP_DEBUG("state, rule %d, boolean %d, match %d\n",
                      rule->state->int_opt.value,
                      rule->state->int_opt.boolean,
                      match);
        }

        // if a match, no need to check further rules
        if (match) {
            HIP_DEBUG("match found\n");
            break;
        }

        // else proceed with next rule
        list = list->next;
    }

    // if we found a matching rule, use its verdict
    if (rule && match) {
        HIP_DEBUG("packet matched rule, target %d\n", rule->accept);
        verdict = rule->accept;
    } else {
        HIP_DEBUG("falling back to default HIP/ESP behavior, target %d\n",
                  accept_hip_esp_traffic_by_default);

        verdict = accept_hip_esp_traffic_by_default;
    }

    if (verdict && !conntracked) {
        verdict = conntrack(buf, ctx);
    }

    return verdict;
}

/**
 * Handle packet capture for outbound HIP packets.
 *
 * @note hooks HIP message filtering.
 *
 * @param ctx packet context
 *
 * @return the verdict (ACCEPT or DROP)
 */
static int hip_fw_handle_hip_output(struct hip_fw_context *ctx)
{
    int verdict = accept_hip_esp_traffic_by_default;

    if (filter_traffic) {
        verdict = filter_hip(ctx->transport_hdr.hip,
                             ctx->ipq_packet->hook,
                             ctx->ipq_packet->indev_name,
                             ctx->ipq_packet->outdev_name,
                             ctx);
    } else {
        verdict = ACCEPT;
    }

    /* zero return value means that the packet should be dropped */
    return verdict;
}

/**
 * Process an ESP packet from the outbound packet queue.
 *
 * @note hooks ESP filtering
 *
 * @param ctx the packet context
 *
 * @return the verdict (1 for pass and 0 for drop)
 */
static int hip_fw_handle_esp_output(struct hip_fw_context *ctx)
{
    int verdict = accept_hip_esp_traffic_by_default;

    HIP_DEBUG("\n");

    if (filter_traffic) {
        verdict = filter_esp(ctx);
    } else {
        verdict = ACCEPT;
    }

    return verdict;
}

/**
 * Process a TCP packet from the outbound packet capture queue
 *
 * @param ctx the packet context
 *
 * @return the verdict (1 for pass and 0 for drop)
 */
static int hip_fw_handle_tcp_output(struct hip_fw_context *ctx)
{
    HIP_DEBUG("\n");

    return hip_fw_handle_other_output(ctx);
}

/**
 * Process a TCP packet from the inbound packet capture queue
 *
 * @param ctx the packet context
 *
 * @return the verdict (1 for pass and 0 for drop)
 */
static int hip_fw_handle_tcp_input(struct hip_fw_context *ctx)
{
    int verdict = accept_normal_traffic_by_default;

    HIP_DEBUG("\n");

    // any incoming plain TCP packet might be an opportunistic I1
    HIP_DEBUG_HIT("hit src", &ctx->src);
    HIP_DEBUG_HIT("hit dst", &ctx->dst);

    // as we should never receive TCP with HITs, this will only apply
    // to IPv4 TCP
    verdict = hip_fw_handle_other_input(ctx);

    return verdict;
}

/**
 * Process any other packet from the outbound packet capture queue
 *
 * @note hooks userspace IPsec and LSI
 *
 * @param ctx the packet context
 *
 * @return the verdict (1 for pass and 0 for drop)
 */
static int hip_fw_handle_other_output(struct hip_fw_context *ctx)
{
    int verdict = accept_normal_traffic_by_default;

    HIP_DEBUG("accept_normal_traffic_by_default = %d\n",
              accept_normal_traffic_by_default);

    if (ctx->ip_version == 6 && hip_userspace_ipsec) {
        hip_hit_t *def_hit = hip_fw_get_default_hit();
        HIP_DEBUG_HIT("destination hit: ", &ctx->dst);

        // check if this is a reinjected packet
        if (def_hit && IN6_ARE_ADDR_EQUAL(&ctx->dst, def_hit)) {
            // let the packet pass through directly
            verdict = ACCEPT;
        } else {
            verdict = !hip_fw_userspace_ipsec_output(ctx);
        }
    } else if (ctx->ip_version == 4 && hip_lsi_support) {
        hip_lsi_t src_lsi, dst_lsi;

        IPV6_TO_IPV4_MAP(&(ctx->src), &src_lsi);
        IPV6_TO_IPV4_MAP(&(ctx->dst), &dst_lsi);

        /* LSI HOOKS */
        if (IS_LSI32(dst_lsi.s_addr) && hip_lsi_support) {
            if (hip_is_packet_lsi_reinjection(&dst_lsi)) {
                verdict = ACCEPT;
            } else {
                hip_fw_handle_outgoing_lsi(ctx->ipq_packet,
                                           &src_lsi, &dst_lsi);
                verdict = DROP;     /* Reject the packet */
            }
        }
    }

    /* No need to check default rules as it is handled by the
     * iptables rules */
    return verdict;
}

/**
 * Process a HIP packet from the forward packet capture queue
 *
 * @note hooks middlebox authentication
 *
 * @param ctx the packet context
 *
 * @return the verdict (1 for pass and 0 for drop)
 */
static int hip_fw_handle_hip_forward(struct hip_fw_context *ctx)
{
    int err = 1;
    /* Check with signaling module */
    if (!signaling_hipfw_conntrack(ctx)) {
        HIP_ERROR("Packet not conntracked, new BEX triggered.\n");
        return 0;
    }

#ifdef CONFIG_HIP_MIDAUTH
    if (use_midauth) {
        if (midauth_filter_hip(ctx) == NF_DROP) {
            return NF_DROP;
        }
    }
#endif

    // for now forward and output are handled symmetrically
    return hip_fw_handle_hip_output(ctx);
}

/* hip_fw_handle_esp_forward is the same as hip_fw_handle_esp_output */

/* no need for hip_fw_handle_other_forward */

/* hip_fw_handle_hip_input is the same as hip_fw_handle_hip_output */

/**
 * Process an ESP packet from the inbound packet capture queue
 *
 * @note hooks ESP filtering and userspace IPsec
 *
 * @param ctx the packet context
 *
 * @return the verdict (1 for pass and 0 for drop)
 */
static int hip_fw_handle_esp_input(struct hip_fw_context *ctx)
{
    int verdict = accept_hip_esp_traffic_by_default;

    HIP_DEBUG("\n");

    if (filter_traffic) {
        // first of all check if this belongs to one of our connections
        verdict = filter_esp(ctx);
    } else {
        verdict = ACCEPT;
    }

    if (verdict && hip_userspace_ipsec) {
        verdict = !hip_fw_userspace_ipsec_input(ctx);
    }

    return verdict;
}

/**
 * Process any other packet from the inbound packet capture queue.
 *
 * @note hooks LSI
 *
 * @param ctx the packet context
 *
 * @return the verdict (1 for pass and 0 for drop)
 */
static int hip_fw_handle_other_input(struct hip_fw_context *ctx)
{
    int verdict = accept_normal_traffic_by_default;

    HIP_DEBUG("\n");

    if (ipv6_addr_is_hit(&ctx->src) &&
        ipv6_addr_is_hit(&ctx->dst) &&
        hip_lsi_support) {
        verdict = hip_fw_handle_incoming_hit(ctx->ipq_packet,
                                             &ctx->src,
                                             &ctx->dst,
                                             hip_lsi_support);
    }

    /* No need to check default rules as it is handled by the
     * iptables rules */
    return verdict;
}

/*----------------MAIN FUNCTIONS----------------------*/

/**
 * Initialize the firewall datastructures and ipqueue rules
 *
 * @return zero on success or non-zero on failure
 */
static int firewall_init(void)
{
    int err = 0;

    HIP_DEBUG("Initializing firewall\n");

    HIP_DEBUG("in=%d out=%d for=%d\n", NF_IP_LOCAL_IN, NF_IP_LOCAL_OUT,
              NF_IP_FORWARD);

    // funtion pointers for the respective packet handlers
    fw_handlers[NF_IP_LOCAL_IN][OTHER_PACKET] = hip_fw_handle_other_input;
    fw_handlers[NF_IP_LOCAL_IN][HIP_PACKET]   = hip_fw_handle_hip_output;
    fw_handlers[NF_IP_LOCAL_IN][ESP_PACKET]   = hip_fw_handle_esp_input;
    fw_handlers[NF_IP_LOCAL_IN][TCP_PACKET]   = hip_fw_handle_tcp_input;

    fw_handlers[NF_IP_LOCAL_OUT][OTHER_PACKET] = hip_fw_handle_other_output;
    fw_handlers[NF_IP_LOCAL_OUT][HIP_PACKET]   = hip_fw_handle_hip_output;
    fw_handlers[NF_IP_LOCAL_OUT][ESP_PACKET]   = hip_fw_handle_esp_output;
    fw_handlers[NF_IP_LOCAL_OUT][TCP_PACKET]   = hip_fw_handle_tcp_output;

    //apply rules for forwarded hip and esp traffic
    fw_handlers[NF_IP_FORWARD][HIP_PACKET] = hip_fw_handle_hip_forward;
    fw_handlers[NF_IP_FORWARD][ESP_PACKET] = hip_fw_handle_esp_output;

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

    HIP_IFEL(firewall_init_extensions(), -1, "failed to start requested extensions");

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
 *
 * Initialize context for a packet. The context stores e.g. the packet type and
 * possibly encapsulating packet type. It also stores useful pointers IP and
 * transport layer headers where applicable to avoid redundant casting.
 *
 * Currently supported types:   type
 * - plain HIP control packet      1
 * - ESP packet                    2
 *
 * Unsupported types -> type 0
 *
 * @param  ctx        the context.
 * @param  buf        a pointer to a IP packet.
 * @param  ip_version the IP version for this packet
 * @return            One if @c hdr is a HIP packet, zero otherwise.
 */
static int hip_fw_init_context(struct hip_fw_context *ctx,
                               const unsigned char *buf,
                               const int ip_version)
{
    int err = 0;
    // length of packet starting at udp header
    uint16_t       udp_len              = 0;
    struct udphdr *udphdr               = NULL;
    int            udp_encap_zero_bytes = 0;

    // same context memory as for packets before -> re-init
    memset(ctx, 0, sizeof(struct hip_fw_context));

    // default assumption
    ctx->packet_type = OTHER_PACKET;

    // add whole packet to context and ip version
    ctx->ipq_packet = ipq_get_packet(buf);

    // check if packet is to big for the buffer
    if (ctx->ipq_packet->data_len > HIP_MAX_PACKET) {
        HIP_ERROR("packet size greater than buffer\n");

        err = 1;
        goto end_init;
    }

    ctx->ip_version = ip_version;

    if (ctx->ip_version == 4) {
        struct ip *iphdr = (struct ip *) ctx->ipq_packet->payload;
        // add pointer to IPv4 header to context
        ctx->ip_hdr.ipv4 = iphdr;

        /* ip_hl is given in multiple of 4 bytes
         *
         * NOTE: not sizeof(struct ip) as we might have options */
        ctx->ip_hdr_len = iphdr->ip_hl * 4;

        HIP_DEBUG("ip_hdr_len is: %d\n", ctx->ip_hdr_len);
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
        if (iphdr->ip_p == IPPROTO_HIP) {
            // we have found a plain HIP control packet
            HIP_DEBUG("plain HIP packet\n");

            ctx->packet_type       = HIP_PACKET;
            ctx->transport_hdr.hip = (struct hip_common *)
                                     (((char *) iphdr) + ctx->ip_hdr_len);

            goto end_init;
        } else if (iphdr->ip_p == IPPROTO_ESP) {
            // this is an ESP packet
            HIP_DEBUG("plain ESP packet\n");

            ctx->packet_type       = ESP_PACKET;
            ctx->transport_hdr.esp = (struct hip_esp *)
                                     (((char *) iphdr) + ctx->ip_hdr_len);

            goto end_init;
        } else if (iphdr->ip_p == IPPROTO_TCP) {
            // this might be a TCP packet for opportunistic mode
            HIP_DEBUG("plain TCP packet\n");

            ctx->packet_type       = TCP_PACKET;
            ctx->transport_hdr.tcp = (struct tcphdr *)
                                     (((char *) iphdr) + ctx->ip_hdr_len);

            HIP_DEBUG("src port: %u\n", ntohs(ctx->transport_hdr.tcp->source));
            HIP_DEBUG("dst port: %u\n", ntohs(ctx->transport_hdr.tcp->dest));

            goto end_init;
        } else if (iphdr->ip_p != IPPROTO_UDP) {
            // if it's not UDP either, it's unsupported
            HIP_DEBUG("some other packet\n");

            goto end_init;
        }

        // need UDP header to look for encapsulated ESP
        udp_len = ntohs(iphdr->ip_len);
        udphdr  = (struct udphdr *) (((char *) iphdr) + ctx->ip_hdr_len);

        // add UDP header to context
        ctx->udp_encap_hdr = udphdr;
    } else if (ctx->ip_version == 6) {
        struct ip6_hdr *ip6_hdr = (struct ip6_hdr *) ctx->ipq_packet->payload;
        // add pointer to IPv4 header to context
        ctx->ip_hdr.ipv6 = ip6_hdr;

        // Ipv6 has fixed header length
        ctx->ip_hdr_len = sizeof(struct ip6_hdr);

        HIP_DEBUG("ip_hdr_len is: %d\n", ctx->ip_hdr_len);
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
        if (ip6_hdr->ip6_nxt == IPPROTO_HIP) {
            // we have found a plain HIP control packet
            HIP_DEBUG("plain HIP packet\n");

            ctx->packet_type       = HIP_PACKET;
            ctx->transport_hdr.hip = (struct hip_common *)
                                     (((char *) ip6_hdr) + sizeof(struct ip6_hdr));

            goto end_init;
        } else if (ip6_hdr->ip6_nxt == IPPROTO_ESP) {
            // we have found a plain ESP packet
            HIP_DEBUG("plain ESP packet\n");

            ctx->packet_type       = ESP_PACKET;
            ctx->transport_hdr.esp = (struct hip_esp *)
                                     (((char *) ip6_hdr) + sizeof(struct ip6_hdr));

            goto end_init;
        } else if (ip6_hdr->ip6_nxt == IPPROTO_TCP) {
            // this might be a TCP packet for opportunistic mode
            HIP_DEBUG("plain TCP packet\n");

            ctx->packet_type       = TCP_PACKET;
            ctx->transport_hdr.tcp = (struct tcphdr *)
                                     (((char *) ip6_hdr) + sizeof(struct ip6_hdr));

            HIP_DEBUG("src port: %u\n", ntohs(ctx->transport_hdr.tcp->source));
            HIP_DEBUG("dst port: %u\n", ntohs(ctx->transport_hdr.tcp->dest));

            goto end_init;
        } else if (ip6_hdr->ip6_nxt != IPPROTO_UDP) {
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
        udphdr  = (struct udphdr *) (((char *) ip6_hdr) + ctx->ip_hdr_len);

        // add udp header to context
        ctx->udp_encap_hdr = udphdr;
    } else {
        HIP_DEBUG("neither ipv4 nor ipv6\n");
        goto end_init;
    }

    HIP_DEBUG("UDP header size is %d (in header: %u) \n",
              sizeof(struct udphdr), ntohs(udphdr->len));
    HIP_DEBUG("UDP src port: %u\n", ntohs(udphdr->source));
    HIP_DEBUG("UDP dst port: %u\n", ntohs(udphdr->dest));

    /* only handle IPv4 right now
     * -> however this is the place to handle UDP encapsulated IPv6 */
    if (ctx->ip_version == 4) {
        // we might have only received a UDP packet with headers only
        if (udp_len >= sizeof(struct ip) + sizeof(struct udphdr) + HIP_UDP_ZERO_BYTES_LEN) {
            uint32_t *zero_bytes = NULL;

            // we can distinguish UDP encapsulated control and data traffic with 32 zero bits
            // behind UDP header
            zero_bytes = (uint32_t *) (((char *) udphdr) + sizeof(struct udphdr));

            HIP_HEXDUMP("zero_bytes: ", zero_bytes, 4);

            /* check whether next 32 bits are zero or not */
            if (*zero_bytes == 0) {
                udp_encap_zero_bytes = 1;

                HIP_DEBUG("Zero SPI found\n");
            }

            zero_bytes = NULL;
        } else {
            // only UDP header + payload < 32 bit -> neither HIP nor ESP
            HIP_DEBUG("UDP packet with < 32 bit payload\n");

            goto end_init;
        }
    }

    // HIP packets have zero bytes (IPv4 only right now)
    if (ctx->ip_version == 4 && udphdr
        && ((udphdr->source == ntohs(hip_get_local_nat_udp_port())) ||
            (udphdr->dest == ntohs(hip_get_peer_nat_udp_port())))
        && udp_encap_zero_bytes) {
        /* check if zero byte hint is correct and we are processing a
         * HIP control message */
        if (!hip_check_network_msg((struct hip_common *) (((char *) udphdr)
                                                          + sizeof(struct udphdr)
                                                          + HIP_UDP_ZERO_BYTES_LEN))) {
            // we found an UDP encapsulated HIP control packet
            HIP_DEBUG("UDP encapsulated HIP control packet\n");

            // add to context
            ctx->packet_type       = HIP_PACKET;
            ctx->transport_hdr.hip = (struct hip_common *) (((char *) udphdr)
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
             && !udp_encap_zero_bytes) {
        /* from the ports and the non zero SPI we can tell that this
         * is an ESP packet */
        HIP_DEBUG("ESP packet. Todo: verify SPI from database\n");

        // add to context
        ctx->packet_type       = ESP_PACKET;
        ctx->transport_hdr.esp = (struct hip_esp *) (((char *) udphdr)
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
 * Set an accept verdict for a modified packet
 *
 * @param handle    ipqueue file handle
 * @param packet_id ipqueue packet id
 * @param len       length of buf
 * @param buf       the packet to be accepted
 *
 */
static void allow_modified_packet(struct ipq_handle *handle, unsigned long packet_id,
                                  size_t len, unsigned char *buf)
{
    ipq_set_verdict(handle, packet_id, NF_ACCEPT, len, buf);
    HIP_DEBUG("Packet accepted with modifications\n\n");
}

/**
 * Allow a packet to pass
 *
 * @param handle    the handle for the packets.
 * @param packet_id the packet ID.
 * @return          nothing
 */
static void allow_packet(struct ipq_handle *handle, unsigned long packet_id)
{
    ipq_set_verdict(handle, packet_id, NF_ACCEPT, 0, NULL);

    HIP_DEBUG("Packet accepted \n\n");
}

/**
 * Drop a packet
 *
 * @param handle    the handle for the packets.
 * @param packet_id the packet ID.
 * @return          nothing
 */
static void drop_packet(struct ipq_handle *handle, unsigned long packet_id)
{
    ipq_set_verdict(handle, packet_id, NF_DROP, 0, NULL);

    HIP_DEBUG("Packet dropped \n\n");
}

/**
 * Analyze a packet.
 *
 * @param buf the packet to be analyzed
 * @param hndl a file handle to the ipqueue
 * @param ip_version the type of traffic: 4 - ipv4; 6 - ipv6.
 * @param ctx packet context
 *
 * @return  nothing, this function loops forever,
 *          until the firewall is stopped.
 */
static int hip_fw_handle_packet(unsigned char *buf,
                                struct ipq_handle *hndl,
                                const int ip_version,
                                struct hip_fw_context *ctx)
{
    // assume DROP
    int verdict = 0;

    /* waits for queue messages to arrive from ip_queue and
     * copies them into a supplied buffer */
    if (ipq_read(hndl, buf, HIP_MAX_PACKET, 0) < 0) {
        HIP_PERROR("ipq_read failed: ");
        // TODO this error needs to be handled seperately -> die(hndl)?
        goto out_err;
    }

    /* queued messages may be a packet messages or an error messages */
    switch (ipq_message_type(buf)) {
    case IPQM_PACKET:
        HIP_DEBUG("Received ipqm packet\n");
        // no goto -> go on with processing the message below
        break;
    case NLMSG_ERROR:
        HIP_ERROR("Received error message (%d): %s\n", ipq_get_msgerr(buf),
                  ipq_errstr());
        goto out_err;
        break;
    default:
        HIP_DEBUG("Unsupported libipq packet\n");
        goto out_err;
        break;
    }

    // set up firewall context
    if (hip_fw_init_context(ctx, buf, ip_version)) {
        goto out_err;
    }

    HIP_DEBUG("packet hook=%d, packet type=%d\n", ctx->ipq_packet->hook,
              ctx->packet_type);

    // match context with rules
    if (fw_handlers[ctx->ipq_packet->hook][ctx->packet_type]) {
        verdict = (fw_handlers[ctx->ipq_packet->hook][ctx->packet_type])(ctx);
    } else {
        HIP_DEBUG("Ignoring, no handler for hook (%d) with type (%d)\n");
    }

out_err:
    if (verdict) {
        if (ctx->modified == 0) {
            HIP_DEBUG("=== Verdict: allow packet ===\n");
            allow_packet(hndl, ctx->ipq_packet->packet_id);
        } else {
            update_all_headers(ctx);
            HIP_DEBUG("=== Verdict: allow modified packet ===\n");
            allow_modified_packet(hndl, ctx->ipq_packet->packet_id,
                                  ctx->ipq_packet->data_len,
                                  ctx->ipq_packet->payload);
        }
    } else {
        HIP_DEBUG("=== Verdict: drop packet ===\n");
        drop_packet(hndl, ctx->ipq_packet->packet_id);
    }

    // nothing to clean up here as we re-use buf, hndl and ctx

    return 0;
}

/**
 * Receive and process one message from hipd.
 *
 * @param msg A previously allocated message buffer.
 * @return    Zero on success, -1 on error.
 *
 * @note The buffer @a msg is reused between calls because it is quite
 *       large.
 */
static int hip_fw_handle_hipd_message(struct hip_common *const msg)
{
    struct sockaddr_in6 sock_addr;
    int                 msg_type, len, n;
    int                 is_root, access_ok;
    socklen_t           alen;

    alen = sizeof(sock_addr);
    n    = recvfrom(hip_fw_async_sock, msg, sizeof(struct hip_common),
                    MSG_PEEK, (struct sockaddr *) &sock_addr, &alen);
    if (n < 0) {
        HIP_ERROR("Error receiving message header from daemon.\n");
        return -1;
    }

    // making sure user messages are received from hipd
    access_ok = 0;
    msg_type  = hip_get_msg_type(msg);
    is_root   = ntohs(sock_addr.sin6_port) < 1024;
    if (is_root) {
        access_ok = 1;
    } else if (!is_root &&
               (msg_type >= HIP_MSG_ANY_MIN &&
                msg_type <= HIP_MSG_ANY_MAX)) {
        access_ok = 1;
    }
    if (!access_ok) {
        HIP_ERROR("The sender of the message is not trusted.\n");
        return -1;
    }

    alen = sizeof(sock_addr);
    len  = hip_get_msg_total_len(msg);

    HIP_DEBUG("Receiving message type %d (%d bytes)\n",
              hip_get_msg_type(msg), len);
    n = recvfrom(hip_fw_async_sock, msg, len, 0,
                 (struct sockaddr *) &sock_addr, &alen);

    if (n < 0) {
        HIP_ERROR("Error receiving message parameters from daemon.\n");
        return -1;
    }

    HIP_ASSERT(n == len);

    if (ntohs(sock_addr.sin6_port) != HIP_DAEMON_LOCAL_PORT) {
        int type = hip_get_msg_type(msg);
        if (type == HIP_MSG_FW_BEX_DONE) {
            HIP_DEBUG("HIP_MSG_FW_BEX_DONE\n");
            HIP_DEBUG("%d == %d\n", ntohs(sock_addr.sin6_port),
                      HIP_DAEMON_LOCAL_PORT);
        }
        HIP_DEBUG("Drop, message not from hipd\n");
        return -1;
    }

    if (hip_handle_msg(msg) < 0) {
        HIP_ERROR("Error handling message\n");
        return -1;
    }

    return 0;
}

/**
 * Hipfw should be started before hipd to make sure
 * that nobody can bypass ACLs. However, some hipfw
 * extensions (e.g. userspace ipsec) work consistently
 * only when hipd is started first. To solve this
 * chicken-and-egg problem, we are blocking all hipd
 * messages until hipd is running and firewall is set up.
 */
static void hip_fw_wait_for_hipd(void)
{
    hip_fw_flush_iptables();

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

    while (hip_fw_get_default_hit() == NULL) {
        HIP_DEBUG("Sleeping until hipd is running...\n");
        sleep(1);
    }

    /* Notice that firewall flushed the dropping rules later */
}

/**
 * Main function that starts the single-threaded hipfw process.
 *
 * @param rule_file          Initial firewall rules are read from this file.
 * @param kill_old           If another hipfw instance is currently running,
 *                           (according to the lockfile), terminate it if set.
 *                           If unset, an error is returned in this case instead.
 * @param limit_capabilities Give up root privileges (capabilities) as soon as
 *                           possible if set.
 * @return                   Zero if successful, non-zero otherwise.
 */
int hipfw_main(const char *const rule_file,
               const bool        kill_old,
               const bool        limit_capabilities)
{
    int                   err       = 0, highest_descriptor, i;
    struct ipq_handle    *h4        = NULL, *h6 = NULL;
    struct hip_common    *msg       = NULL;
    struct sockaddr_in6   sock_addr = { 0 };
    fd_set                read_fdset;
    struct timeval        timeout;
    unsigned char         buf[HIP_MAX_PACKET];
    struct hip_fw_context ctx;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Creating perf set\n");
    perf_set = hip_perf_create(PERF_MAX_FIREWALL);

    check_and_create_dir("results", HIP_DIR_MODE);

    /* To keep things simple, we use a subset of the performance set originally
     * created for the HIP daemon. */
    hip_perf_set_name(perf_set, PERF_I1, "results/PERF_I1.csv");
    hip_perf_set_name(perf_set, PERF_R1, "results/PERF_R1.csv");
    hip_perf_set_name(perf_set, PERF_I2, "results/PERF_I2.csv");
    hip_perf_set_name(perf_set, PERF_R2, "results/PERF_R2.csv");
    hip_perf_set_name(perf_set, PERF_UPDATE, "results/PERF_UPDATE.csv");
    hip_perf_set_name(perf_set, PERF_VERIFY, "results/PERF_VERIFY.csv");
    hip_perf_set_name(perf_set, PERF_BASE, "results/PERF_BASE.csv");
    hip_perf_set_name(perf_set, PERF_CLOSE_SEND, "results/PERF_CLOSE_SEND.csv");
    hip_perf_set_name(perf_set, PERF_HANDLE_CLOSE, "results/PERF_HANDLE_CLOSE.csv");
    hip_perf_set_name(perf_set, PERF_HANDLE_CLOSE_ACK, "results/PERF_HANDLE_CLOSE_ACK.csv");
    hip_perf_set_name(perf_set, PERF_CLOSE_COMPLETE, "results/PERF_CLOSE_COMPLETE.csv");
    hip_perf_set_name(perf_set, PERF_DSA_VERIFY_IMPL, "results/PERF_DSA_VERIFY_IMPL.csv");
    hip_perf_set_name(perf_set, PERF_RSA_VERIFY_IMPL, "results/PERF_RSA_VERIFY_IMPL.csv");
    hip_perf_set_name(perf_set, PERF_NEW_CONN, "results/PERF_NEW_CONN.csv");
    hip_perf_set_name(perf_set, PERF_CONN_REQUEST, "results/PERF_CONN_REQUEST.csv");
    hip_perf_set_name(perf_set, PERF_SEND_CONN_REQUEST, "results/PERF_SEND_CONN_REQUEST.csv");
    hip_perf_set_name(perf_set, PERF_HIPFW_REQ1, "results/PERF_HIPFW_REQ1.csv");
    hip_perf_set_name(perf_set, PERF_HIPFW_REQ2, "results/PERF_HIPFW_REQ2.csv");
    hip_perf_set_name(perf_set, PERF_HIPFW_REQ3, "results/PERF_HIPFW_REQ3.csv");
    hip_perf_set_name(perf_set, PERF_HIPFW_R2_FINISH, "results/PERF_HIPFW_R2_FINISH.csv");
    hip_perf_set_name(perf_set, PERF_CTX_LOOKUP, "results/PERF_CTX_LOOKUP.csv");
    hip_perf_set_name(perf_set, PERF_NETSTAT_LOOKUP, "results/PERF_NETSTAT_LOOKUP.csv");
    hip_perf_set_name(perf_set, PERF_VERIFY_APPLICATION, "results/PERF_VERIFY_APPLICATION.csv");
    hip_perf_set_name(perf_set, PERF_X509AC_VERIFY_CERT_CHAIN, "results/PERF_X509AC_VERIFY_CERT_CHAIN.csv");
    hip_perf_set_name(perf_set, PERF_IP6TABLES, "results/PERF_IP6TABLES.csv");

    HIP_DEBUG("Opening perf set\n");
    hip_perf_open(perf_set);
#endif

    HIP_IFEL(hip_create_lock_file(HIP_FIREWALL_LOCK_FILE, kill_old), -1,
             "Failed to obtain firewall lock.\n");

    /* Request-response socket with hipfw */
    hip_fw_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    HIP_IFEL(hip_fw_sock < 0, 1, "Could not create socket for firewall.\n");
    sock_addr.sin6_family = AF_INET6;
    sock_addr.sin6_port   = htons(HIP_FIREWALL_SYNC_PORT);
    sock_addr.sin6_addr   = in6addr_loopback;

    for (i = 0; i < 2; i++) {
        err = bind(hip_fw_sock, (struct sockaddr *) &sock_addr,
                   sizeof(sock_addr));
        if (err == 0) {
            break;
        } else if (err && i == 0) {
            sleep(2);
        }
    }

    HIP_IFEL(err, -1, "Bind on firewall socket addr failed. Give -k option to kill old hipfw\n");
    HIP_IFEL(hip_daemon_connect(hip_fw_sock), -1, "connecting socket failed\n");

    /* Only for receiving out-of-sync notifications from hipd  */
    hip_fw_async_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    HIP_IFEL(hip_fw_async_sock < 0, 1, "Could not create socket for firewall.\n");
    sock_addr.sin6_family = AF_INET6;
    sock_addr.sin6_port   = htons(HIP_FIREWALL_PORT);
    sock_addr.sin6_addr   = in6addr_loopback;
    HIP_IFEL(bind(hip_fw_async_sock, (struct sockaddr *) &sock_addr, sizeof(sock_addr)), -1,
             "Bind on firewall socket addr failed. Give -k option to kill old hipfw\n");
    HIP_IFEL(hip_daemon_connect(hip_fw_async_sock), -1,
             "connecting socket failed\n");

    /* Starting hipfw does not always work when hipfw starts first -miika */
    if (hip_userspace_ipsec || hip_lsi_support) {
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
    firewall_probe_kernel_modules();

    // create firewall queue handles for IPv4 traffic
    HIP_IFEL(!(h4 = ipq_create_handle(0, PF_INET)), -1,
             "ipq_create_handle(): %s\n", ipq_errstr());
    HIP_IFEL(ipq_set_mode(h4, IPQ_COPY_PACKET, HIP_MAX_PACKET) == -1, -1,
             "ipq_set_mode(): %s\n", ipq_errstr());
    HIP_DEBUG("IPv4 handle created (mode COPY_PACKET)\n");

    // create firewall queue handles for IPv6 traffic
    HIP_IFEL(!(h6 = ipq_create_handle(0, PF_INET6)), -1,
             "ipq_create_handle(): %s\n", ipq_errstr());
    HIP_IFEL(ipq_set_mode(h6, IPQ_COPY_PACKET, HIP_MAX_PACKET) == -1, -1,
             "ipq_set_mode(): %s\n", ipq_errstr());
    HIP_DEBUG("IPv6 handle created (mode COPY_PACKET)\n");

    // set up ip(6)tables rules and firewall extensions
    HIP_IFEL(firewall_init(), -1, "Firewall init failed\n");

    if (limit_capabilities) {
        HIP_IFEL(hip_set_lowcapability(), -1, "Failed to reduce privileges\n");
    }

    highest_descriptor = hip_fw_async_sock > h4->fd ? hip_fw_async_sock : h4->fd;
    highest_descriptor = h6->fd > highest_descriptor ? h6->fd : highest_descriptor;

    /* Allocate message. */
    HIP_IFEL(!(msg = hip_msg_alloc()), -1, "Insufficient memory\n");

    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_FIREWALL_START, 0), -1,
             "build user hdr\n");
    if (hip_send_recv_daemon_info(msg, 1, hip_fw_sock)) {
        HIP_DEBUG("Failed to notify hipd of firewall start.\n");
    }

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

        timeout.tv_sec  = HIP_SELECT_TIMEOUT;
        timeout.tv_usec = 0;

        // get handle with queued packet and process
        /* @todo: using HIPD_SELECT blocks hipfw with R1 */
        if ((err = select((highest_descriptor + 1), &read_fdset,
                          NULL, NULL, &timeout)) < 0) {
            HIP_PERROR("select error, ignoring\n");
            continue;
        }

#ifdef CONFIG_HIP_MIDAUTH
        if (use_midauth) {
            pisa_check_for_random_update();
        }
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
            err = hip_fw_handle_hipd_message(msg);
        }

        hip_fw_conntrack_periodic_cleanup();

        /* Call to periodic maintenance function of firewall signaling extension. */
        signaling_firewall_maintenance();
    }

out_err:
    if (h4) {
        ipq_destroy_handle(h4);
    }
    if (h6) {
        ipq_destroy_handle(h6);
    }
    if (hip_fw_async_sock) {
        close(hip_fw_async_sock);
    }
    if (hip_fw_sock) {
        close(hip_fw_sock);
    }
    free(msg);

    firewall_exit();
    return err;
}

/*----------------EXTERNALLY USED FUNCTIONS-------------------*/

/**
 * Query the default HIT from the hipd. The HIT will be cached
 * for further calls for improved performance. Caller must NOT
 * do any deallocation for the HIT.
 *
 * @return a global pointer to the default HIT
 */
hip_hit_t *hip_fw_get_default_hit(void)
{
    // only query for default hit if global variable is not set
    if (ipv6_addr_is_null(&default_hit)) {
        if (hip_query_default_local_hit_from_hipd()) {
            return NULL;
        }
    }

    return &default_hit;
}

/**
 * Query the default LSI from the hipd. The LSI will be cached
 * for further calls for improved performance. Caller must NOT
 * do any deallocation for the LSI.
 *
 * @return a global pointer to the default LSI
 */
hip_lsi_t *hip_fw_get_default_lsi(void)
{
    // only query for default lsi if global variable is not set
    if (default_lsi.s_addr == 0) {
        if (hip_query_default_local_hit_from_hipd()) {
            return NULL;
        }
    }

    return &default_lsi;
}
