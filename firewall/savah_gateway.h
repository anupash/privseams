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

#include "hashtable.h"

#define IP_VERSION_4 4
#define IP_VERSION_6 6

#define SAVAH_PREROUTING "SAVAH_PREROUTING"

#define MAC_LENGTH 18

static DECLARE_LHASH_HASH_FN(hip_sava_mac_entry_hash, const hip_sava_mac_entry_t *);
static DECLARE_LHASH_COMP_FN(hip_sava_mac_entries_compare, const hip_sava_mac_entry_t *);

typedef enum fw_marks {
    FW_MARK_PROBATION = 1, /**< @brief The client is in probation period and must be authenticated 
			    @todo: VERIFY THAT THIS IS ACCURATE*/
    FW_MARK_KNOWN     = 2,  /**< @brief The client is known to the firewall */ 
    FW_MARK_LOCKED    = 254 /**< @brief The client has been locked out */
} fw_marks_t;

typedef enum fw_access {
  FW_ACCESS_ALLOW = 1,
  FW_ACCESS_DENY  = 2
} fw_access_t;

typedef struct hip_sava_mac_entry {
  struct in6_addr * ip;
  char * mac;
} hip_sava_mac_entry_t;

unsigned long hip_sava_mac_entry_hash(const hip_sava_mac_entry_t * entry);
int hip_sava_mac_entries_compare(const hip_sava_mac_entry_t * entry1,
				 const hip_sava_mac_entry_t * entry2);
int hip_sava_mac_db_init();
int hip_sava_mac_db_uninit();
hip_sava_mac_entry_t * hip_sava_mac_entry_find(struct in6_addr * ip);
int hip_sava_mac_entry_add(struct in6_addr *ip, char * mac);
int hip_sava_mac_entry_delete(struct in6_addr * ip);

int savah_fw_access(fw_access_t type, const char *ip, const char *mac, fw_marks_t tag, int ip_version);
char * arp_get_c(char * ip);
char * arp_get(struct in6_addr * ip);
char * savah_inet_ntop(struct in6_addr * addr);
int iptables_do_command(const char *format, ...);
 
#endif

