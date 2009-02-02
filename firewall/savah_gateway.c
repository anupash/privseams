#include "savah_gateway.h"



/** Set if a specific client has access through the firewall */
int savah_fw_access(fw_access_t type, const char *ip, const char *mac, fw_marks_t tag, int ip_version)
{
	int rc = 0;
	switch(type) {
		case FW_ACCESS_ALLOW:
		  if (ip_version == IP_VERSION_4) 
		    system("iptables -t mangle -A PREROUTING -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip, mac, tag);
		  else 
		    system("ip6tables -t mangle -A PREROUTING  -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip, mac, tag);
		  //rc = iptables_do_command("-t mangle -A " TABLE_WIFIDOG_INCOMING " -d %s -j ACCEPT", ip);
			break;
		case FW_ACCESS_DENY:
		  if (ip_version == IP_VERSION_4)
		    system("iptables -t mangle -D PREROUTING -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip, mac, tag);
		  else 
		    system("ip6tables -t mangle -D PREROUTING  -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip, mac, tag);
		  //rc = iptables_do_command("-t mangle -D " TABLE_WIFIDOG_INCOMING " -d %s -j ACCEPT", ip);
			break;
		default:
			rc = -1;
			break;
	}

	return rc;
}



/**
 * Get an IP's MAC address from the ARP cache.
 * Go through all the entries in /proc/net/arp until we find the requested
 * IP address and return the MAC address bound to it.
 * @todo Make this function portable (using shell scripts?)
 */
char * arp_get(char * req_ip)
{
  FILE           *proc;
  char ip[16];
  char mac[18];
  char * reply = NULL;
  
  if (!(proc = fopen("/proc/net/arp", "r"))) {
    return NULL;
  }
  
  /* Skip first line */
  while (!feof(proc) && fgetc(proc) != '\n');
  
  /* Find ip, copy mac in reply */
  reply = NULL;
  while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[A-F0-9:] %*s %*s", ip, mac) == 2)) {
    if (strcmp(ip, req_ip) == 0) {
      reply = strdup(mac);
      break;
    }
  }
  
  fclose(proc);
  
  return reply;
}
