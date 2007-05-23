/** @file
 * This file defines handling functions for opportunistic mode to remember
 * IP's which are not HIP capable. This means faster communication in second
 * connection attempts to these hosts. Otherwise it would always take the same
 * fallback timeout (about 5 secs) to make new connection to hosts which dont
 * support HIP.
 * 
 * @author  Antti Partanen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */
#include "oppipdb.h"


/** Contains the database of non HIP capable hosts. */
static struct in6_addr oppipdb[HIP_OPP_IP_DB_SIZE];
/** Index of oldest address in database. */
static int oppipdb_oldest = 0;


/**
 * Clear (initialize) database.
 * @return 0 on success.
 */
int hip_ipdb_clear(void)
{
	memset(oppipdb, 0, sizeof(oppipdb));
	
	return 0;
}


/**
 * Check whether given address is found from database. If 1 is returned,
 * it means that host which has this address, is not HIP capable.
 * 
 * @param addr Address to check.
 * @return 0 if not found, 1 if found.
 */
int hip_ipdb_check(struct in6_addr *addr)
{
	int i;
	
	HIP_DEBUG_IN6ADDR("Checking ip from ip database", addr);

	for (i = 0; i < HIP_OPP_IP_DB_SIZE; i++)
	{
		HIP_DEBUG_IN6ADDR("Comparing to", &oppipdb[i]);
		if (memcmp(&oppipdb[i], addr, sizeof(*addr)) == 0)
		{
			HIP_HEXDUMP("IP found from ip database, remote host not HIP capable: ",
			            addr, sizeof(*addr));
			return 1;
		}
	}
	
	return 0;
}


/**
 * Add new address to database. Remote host which uses this address, should
 * not be HIP capable. Overrides oldest address in the database.
 * 
 * @param addr Address of remote host.
 */
void hip_ipdb_add(struct in6_addr *addr)
{
	if (hip_ipdb_check(addr)) return;
	memcpy(&oppipdb[oppipdb_oldest], addr, sizeof(*addr));
	HIP_HEXDUMP("Added new non HIP capable remote host to ip database: ",
	            addr, sizeof(*addr));
	oppipdb_oldest++;
	if (oppipdb_oldest >= HIP_OPP_IP_DB_SIZE) oppipdb_oldest = 0;
}


