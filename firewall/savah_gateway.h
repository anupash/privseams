#ifndef SAVAH_GATEWAY_H
#define SAVAH_GATEWAY_H
#include <stdio.h>


//#define FW_ACCESS_ALLOW 1
//#define FW_ACCESS_DENY  2

#define IP_VERSION_4 4

#define SAVAH_PREROUTING "SAVAH_PREROUTING"

typedef enum fw_marks {
    FW_MARK_PROBATION = 1, /**< @brief The client is in probation period and must be authenticated 
			    @todo: VERIFY THAT THIS IS ACCURATE*/
    FW_MARK_KNOWN = 2,  /**< @brief The client is known to the firewall */ 
    FW_MARK_LOCKED = 254 /**< @brief The client has been locked out */
} fw_marks_t;

typedef enum fw_access {
  FW_ACCESS_ALLOW = 1,
  FW_ACCESS_DENY  = 2
} fw_access_t;

//typedef int fw_access_t;

int savah_fw_access(fw_access_t type, const char *ip, const char *mac, fw_marks_t tag, int ip_version);
char * arp_get(char * ip);
 
#endif

