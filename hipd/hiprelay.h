/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
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
 * @author  Lauri Silvennoinen
 * @note    Related draft:
 *          <a href="http://www.ietf.org/internet-drafts/draft-ietf-hip-nat-traversal-03.txt">
 *          draft-ietf-hip-nat-traversal-03</a>
 */

#ifndef HIP_HIPD_HIPRELAY_H
#define HIP_HIPD_HIPRELAY_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "lib/core/protodefs.h"
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
struct hip_relrec {
    /** The type of this relay record (full relay or rvs) */
    uint8_t type;
    /** The lifetime of this record, seconds. */
    time_t lifetime;
    /** Time when this record was created, seconds since epoch. */
    time_t created;
    /** Time when this record was last used, seconds since epoch. */
    time_t last_contact;
    /** HIT of Responder (Relay Client) */
    hip_hit_t hit_r;
    /** IP address of Responder (Relay Client) */
    struct in6_addr ip_r;
    /** Client UDP port received in I2 packet of registration. */
    in_port_t udp_port_r;
    /** Integrity key established while registration occurred. */
    struct hip_crypto_key hmac_relay;
};

/**
 * Relay record encapsulation modes used in a relay record. This mode is between
 * the Relay and the Responder.
 */
enum hip_relrec_type { HIP_RELAY     = HIP_SERVICE_RELAY,
                       HIP_FULLRELAY = HIP_SERVICE_FULLRELAY,
                       HIP_RVSRELAY  = HIP_SERVICE_RENDEZVOUS };
/** Possible states of the RVS / relay. */
enum hip_relay_status { HIP_RELAY_OFF = 0, HIP_RELAY_ON = 1, HIP_RELAY_FULL = 2 };
/** Possible states of the whitelist. */
enum hip_relay_wl_status { HIP_RELAY_WL_OFF = 0, HIP_RELAY_WL_ON = 1 };

enum hip_relay_status hip_relay_get_status(void);
void hip_relay_set_status(enum hip_relay_status status);
int hip_relay_init(void);
void hip_relay_uninit(void);
int hip_relay_reinit(void);
int hip_relht_put(struct hip_relrec *rec);
struct hip_relrec *hip_relht_get(const struct hip_relrec *rec);
void hip_relht_rec_free_doall(struct hip_relrec *rec);
void hip_relht_rec_free_type_doall(struct hip_relrec *rec,
                                   const enum hip_relrec_type *type);
unsigned long hip_relht_size(void);
int hip_relht_maintenance(void);

struct hip_relrec *hip_relrec_alloc(const enum hip_relrec_type type,
                                    const uint8_t lifetime,
                                    const struct in6_addr *hit_r,
                                    const hip_hit_t *ip_r,
                                    const in_port_t port,
                                    const struct hip_crypto_key *hmac);
void hip_relht_free_all_of_type(const enum hip_relrec_type type);
int hip_relwl_compare(const hip_hit_t *hit1, const hip_hit_t *hit2);
hip_hit_t *hip_relwl_get(const hip_hit_t *hit);
enum hip_relay_wl_status hip_relwl_get_status(void);
int hip_rvs_validate_lifetime(uint8_t requested_lifetime,
                              uint8_t *granted_lifetime);
int hip_relay_add_rvs_to_ha(const struct hip_common *source_msg,
                            struct hip_hadb_state *entry);
int hip_relay_handle_relay_from(struct hip_common *source_msg,
                                struct in6_addr *relay_ip,
                                struct in6_addr *dest_ip, in_port_t *dest_port);

int hip_relay_handle_relay_to_in_client(const uint8_t packet_type,
                                        const uint32_t ha_state,
                                        struct hip_packet_context *ctx);

int hip_relay_handle_relay_to(const uint8_t packet_type,
                              const uint32_t ha_state,
                              struct hip_packet_context *ctx);

int hip_relay_forward(const struct hip_packet_context *ctx,
                      struct hip_relrec *rec,
                      const uint8_t type_hdr);

#endif /* HIP_HIPD_HIPRELAY_H */
