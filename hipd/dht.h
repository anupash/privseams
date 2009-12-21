#ifndef HIPD_DHT_H_
#define HIPD_DHT_H_

/** @file
 * A header file for dht.c
 *
 * All the necessary functionality for DHT (OpenDHT/OpenLookup) usage.
 *
 * @author Samu Varjonen
 */

#include <netinet/in.h>

#include "hipd.h"
#include "libhipcore/debug.h"
#include "libhipcore/ife.h"

#include "libhipopendht.h"
#include "libhipopendhtxml.h" 

void hip_init_dht_sockets(int *, int *);
void hip_register_to_dht(void);

int hip_publish_certificates(void);

int hip_verify_hdrr(struct hip_common *, struct in6_addr *);
void hip_dht_remove_current_hdrr(void);

void hip_send_packet_to_lookup_from_queue(void);

#endif /* HIPD_DHT_H_ */
