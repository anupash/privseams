#include <stdio.h>


#define FW_ACCESS_ALLOW 1
#define FW_ACCESS_DENY  2

#define IP_VERSION_4 4

#define SAVAH_PREROUTING "SAVAH_PREROUTING"

typedef int fw_access_t;

int savah_fw_access(fw_access_t type, const char *ip, const char *mac, int tag, int ip_version);
char * arp_get(char * ip);
 
