#include "netlink.h"

static int nl_sequence_number = 0;

/*
 * function hip_netlink_open()
 *
 * Opens and binds a Netlink socket, setting *s_net.
 *
 * Returns 0 on success, -1 otherwise.
 */
int hip_netlink_open(int *s_net)
{
     struct sockaddr_nl local;
        
     if (*s_net)
          close(*s_net);
     if ((*s_net = socket(AF_NETLINK, SOCK_RAW, NETLINK_HIP)) < 0)
          return(-1);

     memset(&local, 0, sizeof(local));
     local.nl_family = AF_NETLINK;
     /* subscribe to link, IPv4/IPv6 address notifications */
     local.nl_groups = 0; // FIXME: HIP -types
        
     if (bind(*s_net, (struct sockaddr *)&local, sizeof(local)) < 0)
          return(-1);
        
     nl_sequence_number = time(NULL);
     return(0);
}
