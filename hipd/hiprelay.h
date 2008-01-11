/** @file
 * A header file for hip_relay.c.
 *
 * The HIP relay combines the functionalites of an rendezvous server (RVS) and
 * a HIP UDP relay. The HIP relay consists of a hashtable for storing IP address
 * to HIT mappings and of functions that do the actual relaying action. The
 * hashtable is based on lhash library and its functionalites are the same
 * except that the HIP relay stores data (allocated memory for relay records)
 * instead of pointers.
 *
 * A few simple rules apply:
 * <ul>
 * <li>Allocate memory for relay records that are to be put into the hashtable
 * only with hip_relrec_alloc().</li>
 * <li>Once a relay record is <b>successfully</b> put into the hashtable, the
 * only way delete it is to call hip_relht_rec_free(). This will remove the
 * entry from the hashtable and free the memory allocated for the relay record.
 * </li>
 * </ul>
 *
 * Usage:
 * <ul>
 * <li>Inserting a new relay record:
 * <pre>
 * hip_relrec_t rr = hip_relrec_alloc(...);
 * hip_relht_put(rr);
 * if(hip_relht_get(rr) == NULL) // The put was unsuccessful.
 * {
 *   if(rr != NULL)
 *     free(rr);
 * }
 * </pre>
 * </li>
 * <li>Fetching a relay record. We do not need (but can use) a fully populated
 * relay record as a search key. A dummy record with hit_r field populated
 * is sufficient. Note that there is no need to re-put the relay record into the
 * hashtable once it has been succesfully inserted into the hashtable - except
 * if we change the hit_r field of the relay record. If a relay record with same
 * HIT is put into the hashtable, the existing element is deleted.
 *
 * <pre>
 * hip_relrec_t dummy, *fetch_record = NULL;
 * memcpy(&(dummy.hit_r), hit, sizeof(hit));
 * fetch_record = hip_relht_get(&dummy);
 * if(fetch_record != NULL)
 * {
 * // Do something with the record.
 * }
 * </pre>
 * </li>
 * <li>Deleting a relay record. A dummy record can be used:
 * <pre>
 * hip_relrec_t dummy;
 * memcpy(&(dummy.hit_r), hit, sizeof(hit));
 * hip_relht_rec_free(&dummy);
 * </pre>
 * </li>
 * </ul>
 * 
 * @author  Lauri Silvennoinen
 * @version 1.0
 * @date    27.09.2007
 * @note    Related drafts:
 *          <a href="http://www.ietf.org/internet-drafts/draft-ietf-hip-rvs-05.txt">
 *          draft-ietf-hip-rvs-05</a>
 *          <a href="http://www.ietf.org/internet-drafts/draft-ietf-hip-nat-traversal-02.txt">
 *          draft-ietf-hip-nat-traversal-02</a>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */
#ifndef HIP_HIPRELAY_H
#define HIP_HIPRELAY_H

#include <time.h> /* For timing. */
#include <openssl/lhash.h> /* For LHASH. */
#include <netinet/in.h> /* For IPv6 addresses etc. */
#include <arpa/inet.h> /* For nthos() */
#include <math.h> /* For pow() */
#include "misc.h" /* For hip_hash_hit and hip_match_hit. */

/** Default relay record life time in seconds. After this time, the record is
 *  deleted if it has been idle. */
#define HIP_RELREC_LIFETIME 600

/** HIP Relay record. These records are stored in the HIP Relay hashtable. */
typedef struct{
     /** The type of this relay record (full relay or rvs) */
     uint8_t type;
     /** The lifetime of this record, seconds. */
     double lifetime;
     /** Time when this record was last used, seconds since epoch. */
     time_t last_contact;
     /** HIT of Responder (Relay Client) */
     hip_hit_t hit_r;
     /** IP address of Responder (Relay Client) */
     in6_addr_t ip_r;
     /** Client UDP port received in I2 packet of registration. */
     in_port_t udp_port_r;
     /** Integrity key established while registration occurred. */
     hip_crypto_key_t hmac_relay;
     /** Function pointer to send function (raw or udp). */
     hip_xmit_func_t send_fn;
}hip_relrec_t;

/** 
 * Relay record encapsulation modes used in a relay record. This mode is between
 * the Relay and the Responder.
 * @enum hip_relrec_type_t
 */
typedef enum{HIP_FULLRELAY, HIP_RVSRELAY}hip_relrec_type_t;

/**
 * Initializes the global HIP relay hashtable. Allocates memory for hiprelay_ht.
 *
 * @return a pointer to a new hashtable, NULL if failed to init.
 */ 
LHASH *hip_relht_init();

/** 
 * Uninitializes the HIP relay hashtable. Frees the memory allocated for the hashtable
 * and for the relay records. Thus after calling this function, all memory allocated
 * from heap related to the relay records is freed.
 */
void hip_relht_uninit();

/**
 * The hash function of the hashtable. Calculates a hash from parameter relay record
 * HIT.
 * 
 * @param rec a pointer to a relay record.
 * @return    the calculated hash or zero if @c rec or hit_r is NULL.
 */
unsigned long hip_relht_hash(const hip_relrec_t *rec);

/**
 * The compare function of the hashtable. Compares the hash values calculated from
 * parameter @c rec1 and @c rec2.
 * 
 * @param rec1 a pointer to a relay record.
 * @param rec2 a pointer to a relay record.
 * @return     0 if keys are equal, non-zero otherwise.
 */
int hip_relht_compare(const hip_relrec_t *rec1, const hip_relrec_t *rec2);

/**
 * Puts a relay record in the hashtable. Puts the relay record pointed to by @c rec
 * into the hashtable. If there already is an entry with the same key, the old value
 * is replaced. Note that we store pointers here, the data are not copied. There
 * should be no need to put a relay record more than once into the hashtable. If
 * the fields of an individual relay record need to be changed, just retrieve the
 * record with @c hip_relht_get() and alter the fields of it, but do not re-put it.
 *
 * @param rec a pointer to a relay record to be inserted into the hashtable.
 * @note      <b style="color: #f00;">Do not put records allocated from stack into the
 *            hashtable.</b> Instead put only records created with hip_relrec_alloc().
 */
void hip_relht_put(hip_relrec_t *rec);

/**
 * Retrieves a relay record from the hashtable. The parameter record @c rec needs
 * only to have field @c hit_r populated.
 *
 * @param rec a pointer to a relay record.
 * @return    a pointer to a fully populated relay record if found, NULL otherwise.
 */
hip_relrec_t *hip_relht_get(const hip_relrec_t *rec);

/**
 * Deletes a single entry from the relay record hashtable and frees the memory allocated
 * for the element. The deletion is based on the hash calculated from the relay fecord
 * @c hit_r field, and therefore the parameter record does not need to be fully populated.
 * The parameter relay record is itself left untouched, it is only used as an search key.
 *
 * @param rec a pointer to a relay record. 
 */
void hip_relht_rec_free(hip_relrec_t *rec);

/**
 * Deletes a single entry from the relay record hashtable and frees the memory
 * allocated for the record, if the record has expired. The relay record is deleted if
 * it has been last contacted more than @c HIP_RELREC_LIFETIME seconds ago.
 */
void hip_relht_free_expired(hip_relrec_t *rec);

/**
 * Returns the number of relay records in the hashtable.
 * 
 * @return  number of relay records in the hashtable.
 */
unsigned long hip_relht_size();

/**
 * Periodic maintenance function of the hip relay. This function should be
 * called once in every maintenance cycle of the hip daemon. It clears the
 * expired relay records by calling @c hip_relht_free_expired() for every
 * element in the hashtable.
 * @todo a REG_RESPONSE with zero lifetime should be sent to each client whose
 *       registration is cancelled.
 */
void hip_relht_maintenance();

/**
 * Allocates a new relay record.
 * 
 * @param tyoe     the type of this relay record (RVS or HIPUDP).
 * @param lifetime the lifetime of this relayrecord as defined in registration
 *                 draft.
 * @param hit_r    a pointer to Responder (relay client) HIT.
 * @param ip_r     a pointer to Responder (relay client) IP address.
 * @param port     responder's UDP port.
 * @return         a pointer to a new relay record, or NULL if failed to
 *                 allocate.
 * @note           All records to be put in the hashtable should be created with
 *                 this function.
 */
hip_relrec_t *hip_relrec_alloc(const hip_relrec_type_t type,
			       const uint8_t lifetime,
			       const in6_addr_t *hit_r, const hip_hit_t *ip_r,
			       const in_port_t port,
			       const hip_crypto_key_t *hmac,
			       const hip_xmit_func_t func);
/**
 * Sets the mode of a relay record. This function sets the @c flags field of a
 * relay record.
 * 
 * @param rec  a pointer to a relay record. 
 * @param mode the mode to be set for the parameter record. One of the following:
 *             <ul>
 *             <li>HIP_REL_NONE</li>
 *             <li>HIP_REL_UDP</li>
 *             <li>HIP_REL_TCP</li>
 *             </ul>
 * @see        hip_relrec_t for a bitmap.
 */
void hip_relrec_set_mode(hip_relrec_t *rec, const hip_relrec_type_t type);

/**
 * Sets the lifetime of a relay record.
 * The service lifetime is set to 2^((lifetime - 64)/8) seconds.
 * 
 * @param rec      a pointer to a relay record. 
 * @param lifetime the lifetime of the above formula. 
 */
void hip_relrec_set_lifetime(hip_relrec_t *rec, const uint8_t lifetime);

/**
 * Sets the UDP port number of a relay record. 
 * 
 * @param rec  a pointer to a relay record. 
 * @param port UDP port number. 
 */
void hip_relrec_set_udpport(hip_relrec_t *rec, const in_port_t port);

/**
 * Prints info of the parameter relay record using @c HIP_INFO() macro.
 * 
 * @param rec a pointer to a relay record.
 */
void hip_relrec_info(const hip_relrec_t *rec);

/** 
 * A dummy function for development purposes.
 * This is only here for testing and development purposes. It allows the same
 * code to be used at the relay and at endhosts without C precompiler #ifdefs
 * 
 * @return zero if we are not an RVS or HIP RELAY, one otherwise.
 */
int hip_we_are_relay();

/**
 * Relays an incoming I1 packet.
 *
 * This function relays an incoming I1 packet to the next node on path
 * to receiver and inserts a @c FROM parameter encapsulating the source IP
 * address. In case there is a NAT between the sender (the initiator or previous
 * RVS) of the I1 packet, a @c RELAY_FROM parameter is inserted instead of a
 * @c FROM parameter. Next node on path is typically the responder, but if the
 * message is to travel multiple rendezvous servers en route to responder, next
 * node can also be another rendezvous server. In this case the @c FROM
 * (@c RELAY_FROM) parameter is appended after the existing ones. Thus current RVS
 * appends the address of previous RVS and the final RVS (n) in the RVS chain
 * sends @c FROM:I, @c FROM:RVS1, ... , <code>FROM:RVS(n-1)</code>. If initiator
 * is located behind a NAT, the first @c FROM parameter is replaced with a
 * @c RELAY_FROM parameter.
 * 
 * @param i1       a pointer to the I1 HIP packet common header with source and
 *                 destination HITs.
 * @param i1_saddr a pointer to the source address from where the I1 packet was
 *                 received.
 * @param i1_daddr a pointer to the destination address where the I1 packet was
 *                 sent to (own address).
 * @param rec      a pointer to a relay record matching the HIT of Responder.
 * @param i1_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error.
 * @note           This code has not been tested thoroughly with multiple RVSes.
 * @note           This function is a copy-paste from the previous RVS
 *                 implementation
 */
int hip_relay_rvs(const hip_common_t *i1,
		  const in6_addr_t *i1_saddr,
		  const in6_addr_t *i1_daddr, hip_relrec_t *rec,
		  const hip_portpair_t *i1_info);

/**
 * Handles a FROM/RELAY_FROM parameter.
 *
 * Checks if the parameter @c source_msg message has a FROM/RELAY_FROM
 * parameter. If a parameter is found, the values are copied to target buffers
 * @c dest_ip and @c dest_port. Next the hmac in RVS_HMAC is verified using
 * the host association created during registration. This host association
 * is searched using hitr from @c source_msg and @c rvs_ip as search keys. 
 *
 * @param  source_msg a pointer to the I1 HIP packet common header with source
 *                    and destination HITs.
 * @param rvs_ip      a pointer to the source address from where the I1 packet
 *                    was received.
 * @param dest_ip     a target buffer for the IP address in the FROM/RELAY_FROM
 *                    parameter.
 * @param dest_port   a target buffer for the port number in RELAY_FROM
 *                    parameter.
 * @return            zero 
 */ 
int hip_relay_handle_from(hip_common_t *source_msg,
			  in6_addr_t *rvs_ip,
			  in6_addr_t *dest_ip, in_port_t *dest_port);

#endif /* HIP_HIPRELAY_H */
