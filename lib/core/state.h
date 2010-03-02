/** @file
 * This file defines Host Identity Protocol (HIP) header and parameter related
 * constants and structures.
 *
 * @note Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_LIB_CORE_STATE_H
#define HIP_LIB_CORE_STATE_H

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#ifndef __KERNEL__
#include "hashtable.h"
#include "esp_prot_common.h"
#include "hip_statistics.h"

#endif

#include "lib/modularization/modularization.h"

#define HIP_ENDPOINT_FLAG_PUBKEY           0
#define HIP_ENDPOINT_FLAG_HIT              1
#define HIP_ENDPOINT_FLAG_ANON             2
#define HIP_HI_REUSE_UID                   4
#define HIP_HI_REUSE_GID                   8
#define HIP_HI_REUSE_ANY                  16
/* Other flags: keep them to the power of two! */

/** @addtogroup hip_ha_state
 * @{
 */
/* When adding new states update debug.h hip_state_str(). Doxygen comments to
 * these states are available at doc/doxygen.h */
#define HIP_STATE_NONE                   0
#define HIP_STATE_UNASSOCIATED           1
#define HIP_STATE_I1_SENT                2
#define HIP_STATE_I2_SENT                3
#define HIP_STATE_R2_SENT                4
#define HIP_STATE_ESTABLISHED            5
#define HIP_STATE_FAILED                 7
#define HIP_STATE_CLOSING                8
#define HIP_STATE_CLOSED                 9
/* @} */

/**
 * @todo add description
 */
#define HIP_MAX_HA_STATE                16

#define HIP_UPDATE_STATE_REKEYING        1 /**< @todo REMOVE */
#define HIP_UPDATE_STATE_DEPRECATING     2

#define PEER_ADDR_STATE_UNVERIFIED       1
#define PEER_ADDR_STATE_ACTIVE           2
#define PEER_ADDR_STATE_DEPRECATED       3

#define ADDR_STATE_ACTIVE                1
#define ADDR_STATE_WAITING_ECHO_REQ      2

#define HIP_LOCATOR_TRAFFIC_TYPE_DUAL    0
#define HIP_LOCATOR_TRAFFIC_TYPE_SIGNAL  1
#define HIP_LOCATOR_TRAFFIC_TYPE_DATA    2

#define HIP_LOCATOR_LOCATOR_TYPE_IPV6    0
#define HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI 1
//NAT branch
#define HIP_LOCATOR_LOCATOR_TYPE_UDP 2

#define HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI_PRIORITY 126
#define HIP_LOCATOR_LOCATOR_TYPE_REFLEXIVE_PRIORITY 120
/** for the triple nat mode*/
#define HIP_NAT_MODE_NONE               0
#define HIP_NAT_MODE_PLAIN_UDP          1

#define HIP_UPDATE_LOCATOR              0
#define HIP_UPDATE_ECHO_REQUEST         1
#define HIP_UPDATE_ECHO_RESPONSE        2
#define SEND_UPDATE_ESP_ANCHOR          3

#define HIP_SPI_DIRECTION_OUT           1
#define HIP_SPI_DIRECTION_IN            2

#define HIP_FLAG_CONTROL_TRAFFIC_ONLY 0x1

/**
 * HIP host association state.
 *
 * @todo remove HIP_HASTATE_SPIOK
 */
typedef enum {
    HIP_HASTATE_INVALID = 0,
    HIP_HASTATE_SPIOK   = 1,
    HIP_HASTATE_HITOK   = 2,
    HIP_HASTATE_VALID   = 3
} hip_hastate_t;

/**
 * A data structure for storing the source and destination ports of an incoming
 * packet.
 */
typedef struct hip_stateless_info {
    in_port_t src_port;     /**< The source port of an incoming packet. */
    in_port_t dst_port;     /**< The destination port of an incoming packet. */
} hip_portpair_t;

/**
 * A data structure for handling retransmission. Used inside host association
 * database entries.
 */
typedef struct hip_msg_retrans {
    int                count;
    time_t             last_transmit;
    struct in6_addr    saddr;
    struct in6_addr    daddr;
    struct hip_common *buf;
} hip_msg_retrans_t;

/**
 * A binder structure for storing an IPv6 address and transport layer port
 * number. This structure is used in hip_build_param_relay_to_old().
 *
 * @note This has to be packed since it is used in building @c RELAY_FROM and
 *       @c RELAY_TO parameters.
 * @note obsolete
 */
struct hip_in6_addr_port {
    struct in6_addr sin6_addr;     /**< IPv6 address. */
    in_port_t       sin6_port;     /**< Transport layer port number. */
} __attribute__ ((packed));

struct hip_context {
    //struct sk_buff *skb_in;         /* received skbuff */
    struct hip_common *   input;        /**< Received packet. */
    struct hip_common *   output;       /**< Packet to be built and sent. */
    struct hip_crypto_key hip_enc_out;
    struct hip_crypto_key hip_hmac_out;
    struct hip_crypto_key esp_out;
    struct hip_crypto_key auth_out;
    struct hip_crypto_key hip_enc_in;
    struct hip_crypto_key hip_hmac_in;
    struct hip_crypto_key esp_in;
    struct hip_crypto_key auth_in;
    char *                dh_shared_key;
    size_t                dh_shared_key_len;
    struct hip_esp_info * esp_info;

    uint16_t              current_keymat_index; /**< The byte offset index in draft
                                        * chapter HIP KEYMAT */
    unsigned char         current_keymat_K[HIP_AH_SHA_LEN];
    uint8_t               keymat_calc_index; /**< The one byte index number used
                                    * during the keymat calculation. */
    uint16_t              keymat_index; /**< KEYMAT offset. */
    uint16_t              esp_keymat_index; /**< A pointer to the esp keymat index. */

    int                   esp_prot_param;

    char                  hip_nat_key[HIP_MAX_KEY_LEN];
    int                   use_ice;
};

/*
 * Fixed start of this struct must match to struct hip_locator_info_addr_item
 * for the part of address item. It is used in hip_update_locator_match().
 */
/// @todo Check if all these fields are used and needed
struct hip_peer_addr_list_item {
//    hip_list_t list;
    uint32_t        padding;
    unsigned long   hash_key;
    struct in6_addr address;

    int             address_state;      /* current state of the
                                         * address (PEER_ADDR_STATE_xx) */
    int             is_preferred;       /* 1 if this address was set as
                                         * preferred address in the LOCATOR */
    uint32_t        lifetime;
    struct timeval  modified_time;      /* time when this address was
                                         * added or updated */
    uint32_t        seq_update_id;      /* the Update ID in SEQ parameter
                                         * this address is related to */
    uint8_t         echo_data[4];       /* data put into the ECHO_REQUEST parameter */
//NAT branch
    uint8_t         transport_protocol;             /*value 1 for UDP*/

    uint16_t        port /*port number for transport protocol*/;

    uint32_t        priority;

    uint8_t         kind;
//end NAT branch
};

/* for HIT-SPI hashtable only */
struct hip_hit_spi {
//    hip_list_t list;
    spinlock_t lock;
    atomic_t   refcnt;
    hip_hit_t  hit_our;
    hip_hit_t  hit_peer;
    uint32_t   spi;           /* this SPI spi belongs to the HIT hit */
};

struct hip_spi_in_item {
//    hip_list_t list;
    uint32_t      spi;
    uint32_t      new_spi;        /* SPI is changed to this when rekeying */
    /* ifindex if the netdev to which this is related to */
    int           ifindex;
    unsigned long timestamp;        /* when SA was created */
    int           updating;        /* UPDATE is in progress */
    uint32_t      esp_info_spi_out;        /* UPDATE, the stored outbound
                                            * SPI related to the inbound
                                            * SPI we sent in reply (useless?)*/
    uint16_t      keymat_index;        /* advertised keymat index */
    int           update_state_flags;        /* 0x1=received ack for
                                              * sent SEQ, 0x2=received
                                              * peer's ESP_INFO,
                                              * both=0x3=can move back
                                              * to established */
    /* the Update ID in SEQ parameter these SPI are related to */
    uint32_t                           seq_update_id;
    /* the corresponding esp_info of peer */
    struct hip_esp_info                stored_received_esp_info;
    /* our addresses this SPI is related to, reuse struct to ease coding */
    struct hip_locator_info_addr_item *addresses;
    int                                addresses_n; /* number of addresses */
};

#ifndef __KERNEL__
struct hip_spi_out_item {
//    hip_list_t list;
    uint32_t        spi;
    uint32_t        new_spi;        /* spi is changed to this when rekeying */

    /* USELESS, IF SEQ ID WILL BE RELATED TO ADDRESS ITEMS,
     * NOT OUTBOUND SPIS */
    /* the Update ID in SEQ parameter these SPI are related to */
    uint32_t        seq_update_id;

    HIP_HASHTABLE * peer_addr_list;    /* Peer's IPv6 addresses */
    struct in6_addr preferred_address;
};
#endif

/* this struct is here instead of hidb.h to avoid some weird compilation
 * warnings */
struct hip_host_id_entry {
    /* this needs to be first (list_for_each_entry, list
     * head being of different type) */
    //hip_list_t next;
    struct hip_lhi      lhi;
    hip_lsi_t           lsi;
    /* struct in6_addr ipv6_addr[MAXIP]; */
    struct hip_host_id *host_id;     /* allocated dynamically */
    void *              private_key; /* RSA or DSA */
    struct hip_r1entry *r1;     /* precreated R1s */
    /* Handler to call after insert with an argument, return 0 if OK*/
    int                 (*insert)(struct hip_host_id_entry *, void **arg);
    /* Handler to call before remove with an argument, return 0 if OK*/
    int                 (*remove)(struct hip_host_id_entry *, void **arg);
    void *              arg;
};
#ifndef __KERNEL__
/* If you need to add a new boolean type variable to this structure, consider
 * adding a control value to the local_controls and/or peer_controls bitmask
 * field(s) instead of adding yet another integer. Lauri 24.01.2008. */
/** A data structure defining host association database state i.e.\ a HIP
 *  association between two hosts. Each successful base exchange between two
 *  different hosts leads to a new @c hip_hadb_state with @c state set to
 *  @c HIP_STATE_ESTABLISHED. */
struct hip_hadb_state {
    /** Our Host Identity Tag (HIT). */
    hip_hit_t hit_our;
    /** Peer's Host Identity Tag (HIT). */
    hip_hit_t hit_peer;
    /** Information about the usage of the host association related to
     *  locking stuff which is currently unimplemented because the daemon
     *  is single threaded. When zero, the host association can be freed.
     *  @date 24.01.2008 */
    hip_hastate_t         hastate;
    /** Counter to tear down a HA in CLOSING or CLOSED state */
    int                   purge_timeout;
    /** The state of this host association. @see hip_ha_state */
    int                   state;
    /** This guarantees that retransmissions work properly also in
     *  non-established state.*/
    int                   retrans_state;
    /** A kludge to get the UPDATE retransmission to work.
     *  @todo Remove this kludge. */
    int                   update_state;
    /** Our control values related to this host association.
     *  @see hip_ha_controls */
    hip_controls_t        local_controls;
    /** Peer control values related to this host association.
     *  @see hip_ha_controls */
    hip_controls_t        peer_controls;
    /** If this host association is from a local HIT to a local HIT this
     *  is non-zero, otherwise zero. */
    int                   is_loopback;
    /** Default SPI for outbound SAs. */
    //uint32_t                     default_spi_out;
    /** Preferred peer IP address to use when sending data to peer. */
    struct in6_addr       peer_addr;
    /** Our IP address. */
    struct in6_addr       our_addr;
    /** Rendezvour server address used to connect to the peer; */
    struct in6_addr *     rendezvous_addr;
    /** Peer's Local Scope Identifier (LSI). A Local Scope Identifier is a
     *  32-bit localized representation for a Host Identity.*/
    hip_lsi_t             lsi_peer;
    /** Our Local Scope Identifier (LSI). A Local Scope Identifier is a
     *  32-bit localized representation for a Host Identity.*/
    hip_lsi_t             lsi_our;
    /** ESP transform type */
    int                   esp_transform;
    /** HIP transform type */
    int                   hip_transform;
    /** ESP extension protection transform */
    uint8_t               esp_prot_transform;
    /** ESP extension protection local_anchor */
    unsigned char         esp_local_anchors[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];
    /** another local anchor used for UPDATE messages */
    unsigned char         esp_local_update_anchors[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];
    /** ESP extension protection peer_anchor */
    unsigned char         esp_peer_anchors[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];
    /** another peer anchor used for UPDATE messages */
    unsigned char         esp_peer_update_anchors[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];
    /** needed for offset calculation when using htrees */
    uint32_t              esp_local_active_length;
    uint32_t              esp_local_update_length;
    uint32_t              esp_peer_active_length;
    uint32_t              esp_peer_update_length;
    /** root needed in case of hierarchical hchain linking */
    uint8_t               esp_root_length;
    unsigned char         esp_root[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];
    int                   hash_item_length;
    /** parameters needed for soft-updates of hchains */
    /** Stored outgoing UPDATE ID counter. */
    uint32_t              light_update_id_out;
    /** Stored incoming UPDATE ID counter. */
    uint32_t              light_update_id_in;
    /** retranmission */
    uint8_t               light_update_retrans;
    /** Something to do with the birthday paradox.
     *  @todo Please clarify what this field is. */
    uint64_t              birthday;
    /** A pointer to the Diffie-Hellman shared key. */
    char *                dh_shared_key;
    /** The length of the Diffie-Hellman shared key. */
    size_t                dh_shared_key_len;
    /** A boolean value indicating whether there is a NAT between this host
     *  and the peer. */
    hip_transform_suite_t nat_mode;
    /* this might seem redundant as dst_port == hip_get_nat_udp_port(), but it makes
     * port handling easier in other functions */
    in_port_t             local_udp_port;
    /** NAT mangled port (source port of I2 packet). */
    in_port_t             peer_udp_port;
    /* The Initiator computes the keys when it receives R1. The keys are
     * needed only when R2 is received. We store them here in the mean
     * time. */
    /** For outgoing HIP packets. */
    struct hip_crypto_key                      hip_enc_out;
    /** For outgoing HIP packets. */
    struct hip_crypto_key                      hip_hmac_out;
    /** For outgoing ESP packets. */
    struct hip_crypto_key                      esp_out;
    /** For outgoing ESP packets. */
    struct hip_crypto_key                      auth_out;
    /** For incoming HIP packets. */
    struct hip_crypto_key                      hip_enc_in;
    /** For incoming HIP packets. */
    struct hip_crypto_key                      hip_hmac_in;
    /** For incoming ESP packets. */
    struct hip_crypto_key                      esp_in;
    /** For incoming ESP packets. */
    struct hip_crypto_key                      auth_in;
    /** The byte offset index in draft chapter HIP KEYMAT. */
    uint16_t                                   current_keymat_index;
    /** The one byte index number used during the keymat calculation. */
    uint8_t                                    keymat_calc_index;
    /** For @c esp_info. */
    uint16_t                                   esp_keymat_index;
    /* Last Kn, where n is @c keymat_calc_index. */
    unsigned char                              current_keymat_K[HIP_AH_SHA_LEN];
    /** Our public host identity. */
    struct hip_host_id *                       our_pub;
    /** Our private host identity. */
    struct hip_host_id *                       our_priv;
    /** Keys in OpenSSL RSA or DSA format */
    void *                                     our_priv_key;
    void *                                     peer_pub_key;
    /** A function pointer to a function that signs our host identity. */
    int                                        (*sign)(void *, struct hip_common *);
    /** Peer's public host identity. */
    struct hip_host_id *                       peer_pub;
    /** A function pointer to a function that verifies peer's host identity. */
    int                                        (*verify)(void *, struct hip_common *);
    /** For retransmission. */
    uint64_t                                   puzzle_solution;
    /** LOCATOR parameter. Just tmp save if sent in R1 no @c esp_info so
     *  keeping it here 'till the hip_update_locator_parameter can be done.
     *  @todo Remove this kludge. */
    struct hip_locator *                       locator;
    /** For retransmission. */
    uint64_t                                   puzzle_i;
    /** Used for UPDATE and CLOSE. When we sent multiple identical UPDATE
     * packets between different address combinations, we don't modify
     * the opaque data. */
    char                                       echo_data[4];

    HIP_HASHTABLE *                            peer_addr_list_to_be_added;
    /** For storing retransmission related data. */
    hip_msg_retrans_t                          hip_msg_retrans;
    /** peer hostname */
    uint8_t                                    peer_hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
    /** Counters of heartbeats (ICMPv6s) */
    int                                        heartbeats_sent;
    statistics_data_t                          heartbeats_statistics;
    int                                        update_trigger_on_heartbeat_counter;

    struct timeval                             bex_start;
    struct timeval                             bex_end;

    uint32_t                                   pacing;
    uint8_t                                    ice_control_role;
    struct                       hip_esp_info *nat_esp_info;

    /** disable SAs on this HA (currently used only by full relay) */
    int                                        disable_sas;

    char                                       hip_nat_key[HIP_MAX_KEY_LEN];
    /**reflexive address(NAT box out bound) when register to relay or RVS */
    struct in6_addr                            local_reflexive_address;
    /**reflexive address port (NAT box out bound) when register to relay or RVS */
    in_port_t                                  local_reflexive_udp_port;

    /** These are used in the ICMPv6 heartbeat code. The hipd sends
     *  periodic ICMPv6 keepalives through IPsec tunnel. If the
     *  tunnel does not exist, a single threaded hipd will blocked
     *  forever */
    int outbound_sa_count;
    int inbound_sa_count;

    int spi_inbound_current;
    int spi_outbound_current;
    int spi_outbound_new;

    // Has struct hip_peer_addr_list_item s
    HIP_HASHTABLE *peer_addresses_old;

    /* modular state */
    struct modular_state *hip_modular_state;
};
#endif /* __KERNEL__ */

/** A data structure defining host association information that is sent
 *  to the userspace */
struct hip_hadb_user_info_state {
    hip_hit_t       hit_our;
    hip_hit_t       hit_peer;
    struct in6_addr ip_our;
    struct in6_addr ip_peer;
    hip_lsi_t       lsi_our;
    hip_lsi_t       lsi_peer;
    uint8_t         peer_hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
    int             state;
    int             heartbeats_on;
    int             heartbeats_sent;
    int             heartbeats_received;
    double          heartbeats_mean;
    double          heartbeats_variance;
    in_port_t       nat_udp_port_local;
    in_port_t       nat_udp_port_peer;
    int             shotgun_status;
    hip_controls_t  peer_controls;
    struct timeval  bex_duration;
};

struct hip_turn_info {
    uint32_t        spi;
    struct in6_addr peer_address;
    in_port_t       peer_port;
};

#endif /* HIP_LIB_CORE_STATE_H */
