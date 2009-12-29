#ifndef SAVAH_GATEWAY_H
#define SAVAH_GATEWAY_H

#include <stdio.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include "hipd/hidb.h"
#include "libhipcore/hashtable.h"

#define SAVAH_PREROUTING "SAVAH_PREROUTING"

typedef enum fw_marks {
  FW_MARK_PROBATION = 1, /**< @brief The client is in probation period and must be authenticated */
  FW_MARK_KNOWN     = 2,  /**< @brief The client is known to the firewall */ 
  FW_MARK_LOCKED    = 254 /**< @brief The client has been locked out */
} fw_marks_t;

typedef enum fw_access {
  FW_ACCESS_ALLOW = 1,
  FW_ACCESS_DENY  = 2
} fw_access_t;


int savah_fw_access(fw_access_t type, 
		    struct in6_addr *ip, 
		    const char *mac, 
		    fw_marks_t tag, 
		    int ip_version);
char * arp_get(struct in6_addr * ip);
int iptables_do_command(const char *format, ...);
 
#endif

