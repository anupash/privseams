/** @file
 * A header file for hip_relay.c.
 * 
 * @author  Lauri Silvennoinen
 * @version 1.0
 * @date    10.9.2007
 * @note    Related draft:
 *          <a href="http://www.ietf.org/internet-drafts/draft-ietf-hip-nat-traversal-02.txt">
 *          draft-ietf-hip-nat-traversal-02</a>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */
#ifndef HIP_HIPRELAY_H
#define HIP_HIPRELAY_H

#include <time.h> /* For timing. */
#include <openssl/lhash.h> /* For LHASH. */
#include <netinet/in.h> /* For IPv6 addresses etc. */
#include "hashtable.h" /* For hip hashtable commons. */
#include "misc.h" /* For hip_hash_hit and hip_match_hit. */

/** Default relay record life time in seconds. After this time, the record is
 *  deleted if it has been idle. */
#define HIP_RELREC_LIFETIME 600

/** HIP Relay record. These records are stored in the HIP Relay hashtable. */
typedef struct{
     /** Zero of the record is off, non-zero otherwise. */
     uint8_t on_off;
     /** Flags indicating the encapsulation mode of this record.
      *  <pre>
      *    bitmap: 0000 0000
      *            |||| |||+ RVS -> R UDP     0x01
      *            |||| ||+- RVS -> R TCP     0x02
      *            ++++-++-- Not used
      *  </pre>
      */
     uint8_t flags;
     /** The lifetime of this record, seconds. */
     time_t lifetime;
     /** Time when this record was last used, seconds since epoch. */
     time_t last_contact;
     /** HIT of Responder (Relay Client) */
     struct in6_addr hit_r;
     /** IP address of Responder (Relay Client) */
     struct in6_addr ip_r;
     /** Client UDP port received in I2 packet of registration. */
     in_port_t udp_port_r;
}hip_relrec_t;

/** 
 * Relay record encapsulation modes used in a relay record. This mode is between
 * the Relay and the Responder.
 * @enum
 */
typedef enum{HIP_REL_NONE, /**< I--(any)-->Relay--(none)-->R */
		  HIP_REL_UDP, /**< I--(any)-->Relay--(UDP)-->R */ 
		  HIP_REL_TCP, /**< I--(any)-->Relay--(TCP)-->R */ 
		  }hip_relrec_mode_t;

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
 * The hash function of the hashtable. Calculates a has from parameter relay record
 * HIT.
 * 
 * @param rec a pointer to a relay record.
 * @return    the calculated hash.
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
hip_relrec_t *hip_relht_get(hip_relrec_t *rec);

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
 * Periodic maintenance function of the hip relay. This function should be called once in
 * every maintenance cycle of the hip daemon. It clears the expired relay records by
 * calling @c hip_relht_free_expired() for every element in the hashtable.
 */
void hip_relht_maintenance();

/**
 * Switches on a relay record.
 */
void hip_relrec_switch_on(hip_relrec_t *rec);

/**
 * Switches off a relay record.
 */
void hip_relrec_switch_off(hip_relrec_t *rec);

/**
 * Allocates a new relay record.
 * 
 * @param hit_r a pointer to Responder (relay client) HIT.
 * @param ip_r  a pointer to Responder (relay client) IP address.
 * @param mode  the encapsulation mode of this record.
 * @param port  Responder's UDP port.
 * @return      a pointer to a new relay record, or NULL if failed to allocate.
 * @note        All records to be put in the hashtable should be created with this
 *              function.
 * @note        After calling this function, you should set the appropriate encapsulation
 *              mode for the @c record with hip_relrec_set_mode().
 */
hip_relrec_t *hip_relrec_alloc(struct in6_addr *hit_r, struct in6_addr *ip_r,
			       hip_relrec_mode_t mode, in_port_t port);

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
void hip_relrec_set_mode(hip_relrec_t *rec, hip_relrec_mode_t mode);

/**
 * Sets the lifetime of a relay record. 
 * 
 * @param rec  a pointer to a relay record. 
 * @param mode the lifetime in seconds. 
 */
void hip_relrec_set_lifetime(hip_relrec_t *rec, time_t secs);


/**
 * Sets the UDP port number of a relay record. 
 * 
 * @param rec  a pointer to a relay record. 
 * @param port UDP port number. 
 */
void hip_relrec_set_udpport(hip_relrec_t *rec, in_port_t port);

/**
 * Prints info of the parameter relay record using @c HIP_INFO() macro.
 * 
 * @param rec a pointer to a relay record.
 */
void hip_relrec_info(hip_relrec_t *rec);

#endif /* HIP_HIPRELAY_H */
