#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "tools/debug.h"

int main(int argc,char *argv[]) {
  struct ifaddrs *g_ifaces = NULL, *g_iface;
  struct if_nameindex *i_ifaces = NULL, *i_iface;
  char *addr_str = NULL;
  int err = 0;
  char *default_str = "<unknown>";

  addr_str = malloc(INET6_ADDRSTRLEN+1);
  if (!addr_str) {
    err = 1;
    HIP_ERROR("malloc failed\n");
    goto out;
  }

  /* getifaddrs */
  
  err = getifaddrs(&g_ifaces);
  if (err) {
    HIP_ERROR("getifaddr failed\n");
    goto out;
  }
  
  printf("===getifaddrs===\n");
  for (g_iface = g_ifaces; g_iface; g_iface = g_iface->ifa_next) {
    char *default_str = "<unknown>";
    int maxlen;
    sa_family_t family = g_iface->ifa_addr->sa_family;
    void *addr;

    printf("name: %s, family: %d, address: ", g_iface->ifa_name, family);

    switch (family) {
    case AF_INET:
      maxlen = INET_ADDRSTRLEN;
      addr = &(((struct sockaddr_in *) g_iface->ifa_addr)->sin_addr);
      break;
    case AF_INET6:
      maxlen = INET6_ADDRSTRLEN;
      addr = &(((struct sockaddr_in6 *) g_iface->ifa_addr)->sin6_addr);
      break;
    default:
      maxlen = 0;
    }

    if (maxlen == 0) {
      memcpy(addr_str, default_str, strlen(default_str) + 1);
    } else {
      if (!inet_ntop(family, addr, addr_str, maxlen)) {
	err = 1;
	HIP_PERROR("inet_ntop");
	goto out;
      }
    }

    printf("%s\n", addr_str);
  }

  /* if_nameindex */

  printf("===nameindex===\n");
  i_ifaces = if_nameindex();
  for (i_iface = i_ifaces; i_iface->if_index; i_iface++) {
    printf("name: %s index: %d\n", i_iface->if_name, i_iface->if_index);
  }

 out:

  if (addr_str)
    free(addr_str);
  if (g_ifaces)
    freeifaddrs(g_ifaces);
  if (i_ifaces)
    if_freenameindex(i_ifaces);
}
