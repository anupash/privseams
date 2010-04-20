/** @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
 * A header file for hiprelay.c.
 *
 * @author  Lauri Silvennoinen
 * @note    Related draft:
 *          <a href="http://www.ietf.org/internet-drafts/draft-ietf-hip-nat-traversal-03.txt">
 *          draft-ietf-hip-nat-traversal-03</a>
 */
#ifndef HIP_HIPD_HIPRELAY_H
#define HIP_HIPD_HIPRELAY_H

#include <time.h> /* For timing. */
#include <netinet/in.h> /* For IPv6 addresses etc. */
#include <arpa/inet.h> /* For nthos() */
#include <math.h> /* For pow() */

#include "config.h"
 /* For debuging macros. */
#include "registration.h" /* For lifetime conversions. */
#include "configfilereader.h"
#include "lib/core/state.h"

/**
 * The minimum lifetime the relay / RVS client is granted the service. This
 * value is used as a 8-bit integer value. The lifetime value in seconds is
 * calculated using the formula given in RFC 5203.
 * @note this is a fallback value if we are not able to read the configuration
 *       file.
 */
#define HIP_RELREC_MIN_LIFETIME 112 // Equals 64 seconds.
/**
 * The maximum lifetime the relay / RVS client is granted the service. This
 * value is used as a 8-bit integer value. The lifetime value in seconds is
 * calculated using the formula given in RFC 5203.
 * @note this is a fallback value if we are not able to read the configuration
 *       file.
 */
#define HIP_RELREC_MAX_LIFETIME 159 // Equals 3756 seconds.

/** HIP Relay record. These records are stored in the HIP Relay hashtable. */
typedef struct {
    /** The type of this relay record (full relay or rvs) */
    uint8_t          type;
    /** The lifetime of this record, seconds. */
    time_t           lifetime;
    /** Time when this record was created, seconds since epoch. */
    time_t           created;
    /** Time when this record was last used, seconds since epoch. */
    time_t           last_contact;
    /** HIT of Responder (Relay Client) */
    hip_hit_t        hit_r;
    /** IP address of Responder (Relay Client) */
    in6_addr_t       ip_r;
    /** Client UDP port received in I2 packet of registration. */
    in_port_t        udp_port_r;
    /** Integrity key established while registration occurred. */
    hip_crypto_key_t hmac_relay;
    /** Function pointer to send function (raw or udp). */
    hip_xmit_func_t  send_fn;
} hip_relrec_t;

/**
 * Relay record encapsulation modes used in a relay record. This mode is between
 * the Relay and the Responder.
 */
typedef enum { HIP_RELAY     = HIP_SERVICE_RELAY,
               HIP_FULLRELAY = HIP_SERVICE_FULLRELAY,
               HIP_RVSRELAY  = HIP_SERVICE_RENDEZVOUS } hip_relrec_type_t;
/** Possible states of the RVS / relay. */
typedef enum { HIP_RELAY_OFF = 0, HIP_RELAY_ON = 1, HIP_RELAY_FULL = 2 } hip_relay_status_t;
/** Possible states of the whitelist. */
typedef enum { HIP_RELAY_WL_OFF = 0, HIP_RELAY_WL_ON = 1 } hip_relay_wl_status_t;

hip_relay_status_t hip_relay_get_status(void);
void hip_relay_set_status(hip_relay_status_t status);
int hip_relay_init(void);
void hip_relay_uninit(void);
int hip_relay_reinit(void);
void hip_relrec_set_mode(hip_relrec_t *rec, const hip_relrec_type_t type);
void hip_relrec_set_lifetime(hip_relrec_t *rec, const uint8_t lifetime);
void hip_relrec_set_udpport(hip_relrec_t *rec, const in_port_t port);
void hip_relrec_info(const hip_relrec_t *rec);
int hip_relht_put(hip_relrec_t *rec);
hip_relrec_t *hip_relht_get(const hip_relrec_t *rec);
void hip_relht_rec_free_doall(hip_relrec_t *rec);
void hip_relht_rec_free_type_doall(hip_relrec_t *rec, const hip_relrec_type_t *type);
unsigned long hip_relht_size(void);
void hip_relht_maintenance(void);
hip_relrec_t *hip_relrec_alloc(const hip_relrec_type_t type,
                               const uint8_t lifetime,
                               const in6_addr_t *hit_r, const hip_hit_t *ip_r,
                               const in_port_t port,
                               const hip_crypto_key_t *hmac,
                               const hip_xmit_func_t func);
void hip_relht_free_all_of_type(const hip_relrec_type_t type);
int hip_relwl_compare(const hip_hit_t *hit1, const hip_hit_t *hit2);
hip_hit_t *hip_relwl_get(const hip_hit_t *hit);
hip_relay_wl_status_t hip_relwl_get_status(void);
int hip_rvs_validate_lifetime(uint8_t requested_lifetime,
                              uint8_t *granted_lifetime);
int hip_relay_forward(const hip_common_t *msg, const in6_addr_t *saddr,
                      const in6_addr_t *daddr, hip_relrec_t *rec,
                      const hip_portpair_t *info, const uint8_t type_hdr,
                      const hip_relrec_type_t relay_type);
int hip_relay_add_rvs_to_ha(hip_common_t *source_msg, hip_ha_t *entry);
int hip_relay_handle_from(hip_common_t *source_msg,
                          in6_addr_t *rvs_ip,
                          in6_addr_t *dest_ip, in_port_t *dest_port);
int hip_relay_handle_relay_from(hip_common_t *source_msg,
                                in6_addr_t *relay_ip,
                                in6_addr_t *dest_ip, in_port_t *dest_port);
int hip_relay_handle_relay_to_in_client(struct hip_common *msg,
                                        int msg_type,
                                        struct in6_addr *src_addr,
                                        struct in6_addr *dst_addr,
                                        hip_portpair_t *msg_info,
                                        hip_ha_t *entry);
int hip_relay_handle_relay_to(struct hip_common *msg,
                              int msg_type,
                              struct in6_addr *src_addr,
                              struct in6_addr *dst_addr,
                              hip_portpair_t *msg_info);

#endif /* HIP_HIPD_HIPRELAY_H */
