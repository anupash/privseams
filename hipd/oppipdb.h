/** @file
 * A header file for oppipdb.c.
 * 
 * @author  Antti Partanen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */
#ifndef HIP_OPPIPDB_H
#define HIP_OPPIPDB_H


#include "debug.h"
#include "hidb.h"


int hip_ipdb_clear(void);
int hip_ipdb_check(struct in6_addr *);
void hip_ipdb_add(struct in6_addr *);
void hip_ipdb_delentry(struct in6_addr *);


#endif /* HIP_OPPIPDB_H */

